#!/usr/bin/env python3
"""syswatch_network — the NETWORK tab's machinery: passive device discovery
(ARPPassiveThread), the per-network device allowlist, the separate scan
trust (NetworkTrust / ScanTrustDialog) and the active ping sweep
(PingSweepThread), which only ever runs on a network the user explicitly
trusted for scanning."""

import curses
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import threading
import time

import syswatch_known_devices as known_devices
import syswatch_sensors as sensors
import syswatch_trusted_networks as trusted_networks
from syswatch_state import (DeviceInfo, _device_status, _name_or_none, _note,
                            _state, _state_lock, push_alert, settings)


_HOSTNAME_CACHE_TTL   = 3600.0  # seconds
_HOSTNAME_TIMEOUT     = 1.5     # seconds a caller waits for one lookup
_HOSTNAME_RETRY_AFTER = 60.0    # seconds before re-trying a timed-out lookup
_HOSTNAME_MAX_INFLIGHT = 8     # stuck lookups allowed to linger at once
_hostname_cache = {}  # ip -> (monotonic_ts, hostname, ttl)
_hostname_slots = threading.BoundedSemaphore(_HOSTNAME_MAX_INFLIGHT)


def _getnameinfo_bounded(ip, timeout):
    """socket.getnameinfo() on a daemon thread, waiting at most `timeout`.
    Returns the name, or None if it timed out or no worker slot was free.
    Daemon threads (not a ThreadPoolExecutor, whose workers are joined at
    interpreter exit) so a lookup still stuck in the resolver can never delay
    quitting; the semaphore caps how many of those can pile up."""
    if not _hostname_slots.acquire(blocking=False):
        return None
    box = {}

    def work():
        try:
            box["name"] = socket.getnameinfo((ip, 0), 0)[0]
        except Exception as e:
            box["err"] = e
        finally:
            _hostname_slots.release()

    t = threading.Thread(target=work, name="hostname-lookup", daemon=True)
    try:
        t.start()
    except Exception:
        _hostname_slots.release()  # work() never ran, so never released it
        raise
    t.join(timeout)
    if "err" in box:
        raise box["err"]
    return box.get("name")


def _resolve_hostname(ip: str) -> str:
    # Only ever called from ARPPassiveThread's single-threaded loop (and the
    # one-shot --trust-all-devices CLI path, which runs before any other
    # thread starts), so this plain dict cache needs no lock.
    cached = _hostname_cache.get(ip)
    if cached is not None and time.monotonic() - cached[0] < cached[2]:
        return cached[1]
    # socket.getnameinfo() is a blocking libc call with no timeout of its own
    # — socket.setdefaulttimeout() only governs socket *objects*, so the old
    # attempt to bound it that way did nothing. On a LAN with no reverse DNS a
    # lookup can block for many seconds, stalling ARPPassiveThread's whole
    # cycle. Run it on a worker thread and stop waiting after
    # _HOSTNAME_TIMEOUT; a lookup that times out is cached as the bare IP for
    # a short while so it's retried later rather than re-blocking every cycle.
    ttl = _HOSTNAME_CACHE_TTL
    try:
        name = _getnameinfo_bounded(ip, _HOSTNAME_TIMEOUT)
        if name:
            result = name
        else:
            result, ttl = ip, _HOSTNAME_RETRY_AFTER
    except Exception as e:
        _note("_resolve_hostname", e)
        result, ttl = ip, _HOSTNAME_RETRY_AFTER
    _hostname_cache[ip] = (time.monotonic(), result, ttl)
    return result


# ── ARPPassiveThread ───────────────────────────────────────────────────────────
class ARPPassiveThread(threading.Thread):
    """Reads /proc/net/arp and classifies discovered devices as Active/Recent/
    Idle/INTRUDER. A device is INTRUDER only if its MAC has never been seen
    on the *current* network (tracked via a persistent per-network allowlist
    at KNOWN_DEVICES_PATH — see syswatch_known_devices.py), so roaming to a
    new network doesn't carry over "known" status from a previous one. The
    first time a given network is seen, everything discovered within
    BASELINE_WINDOW seconds is learned silently instead of alerted on.
    """

    def __init__(self, trust=None):
        super().__init__(daemon=True)
        self._stop_event    = threading.Event()
        self._known         = known_devices.load(settings.KNOWN_DEVICES_PATH)
        self._trust         = trust if trust is not None else NetworkTrust()
        self._net_id        = None
        self._net_cidrs     = []
        self._net_seen      = False  # was self._net_id already in the allowlist when detected
        self._ip_json       = None   # None = untried, True = works, False = unusable
        self._baseline_until = 0.0
        self._dirty          = False  # unsaved change of any kind
        self._dirty_new      = False  # ...that adds a MAC (saved promptly)
        self._last_save      = 0.0
        # Guards self._known/_net_seen/_baseline_until/_dirty*: trust_all()
        # runs on the UI thread while run() mutates the same allowlist, and
        # without this a save()'s prune — which *replaces* self._known —
        # could land mid-trust and silently drop every device just trusted.
        # Reentrant because trust_all() may call _refresh_network_identity().
        # Lock order: this lock first, then _state_lock.
        self._known_lock = threading.RLock()

    # Refreshing last_seen on an already-known device is the only change most
    # cycles make; writing known_devices.json for it every ARP_REFRESH (2s)
    # meant ~43,000 rewrites a day — real wear on a Pi's SD card for a
    # timestamp only consulted by the 90-day retention prune. Those writes are
    # batched to this interval; anything that adds a device saves immediately.
    _LAST_SEEN_SAVE_INTERVAL = 300.0

    # Neighbour states that mean "this device answered recently". STALE
    # means the kernel hasn't confirmed it for a while — Linux keeps STALE
    # entries indefinitely on a small LAN (they're only garbage-collected
    # once the table holds more than gc_thresh1 = 128 entries), so treating
    # mere presence in the table as "seen now" kept switched-off devices
    # "Active" for days.
    _FRESH_STATES = {"REACHABLE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
    _DEAD_STATES  = {"FAILED", "INCOMPLETE"}

    def _parse_neigh_json(self, text):
        result = {}
        entries = json.loads(text)
        if not isinstance(entries, list):
            raise ValueError("ip -j neigh: expected a JSON array")
        for e in entries:
            if not isinstance(e, dict):
                continue
            ip, mac = e.get("dst"), e.get("lladdr")
            states = e.get("state") or []
            if isinstance(states, str):
                states = [states]
            states = {str(x).upper() for x in states}
            if not ip or not mac or mac == "00:00:00:00:00:00":
                continue
            if states & self._DEAD_STATES:
                continue
            result[mac.lower()] = {"ip": ip, "iface": e.get("dev", ""),
                                   "fresh": bool(states & self._FRESH_STATES)}
        return result

    def _parse_proc_arp(self):
        result = {}
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    ip, _hw, flags, mac, _mask, iface = parts[:6]
                    if flags == "0x0" or mac == "00:00:00:00:00:00":
                        continue
                    # /proc/net/arp has no neighbour state, so presence is
                    # all there is to go on.
                    result[mac.lower()] = {"ip": ip, "iface": iface, "fresh": True}
        except OSError as e:
            # /proc/net/arp should basically always be readable on Linux, so
            # unlike a genuinely absent sensor, this is worth surfacing.
            _note("ARPPassiveThread._parse_proc_arp", e)
        return result

    def _parse_arp_table(self):
        """{mac: {"ip", "iface", "fresh"}} — fresh is False for entries the
        kernel only holds as STALE. Uses `ip -4 -j neigh` (iproute2 ≥ 4.13,
        standard on Debian 10+) for the neighbour state, falling back to
        /proc/net/arp when that's unavailable."""
        if self._ip_json is not False:
            ip_path = shutil.which("ip")
            if ip_path:
                try:
                    r = subprocess.run([ip_path, "-4", "-j", "neigh", "show"],
                                       capture_output=True, text=True, timeout=2)
                    if r.returncode == 0:
                        parsed = self._parse_neigh_json(r.stdout or "[]")
                        self._ip_json = True
                        return parsed
                except Exception as e:
                    if self._ip_json:  # worked before, so this is a real failure
                        _note("ARPPassiveThread._parse_arp_table (ip neigh)", e)
            if not self._ip_json:
                self._ip_json = False  # absent / too old: stop trying
        return self._parse_proc_arp()

    def _refresh_network_identity(self, now):
        net_id, cidrs = current_network()
        with self._known_lock:
            return self._apply_network_identity(net_id, now, cidrs)

    def _apply_network_identity(self, net_id, now, cidrs=None):
        if cidrs is not None:
            self._net_cidrs = list(cidrs)
        if net_id != self._net_id:
            first = self._net_id is None
            self._net_id = net_id
            # Cached at the moment this network is detected, not re-derived
            # every cycle: baseline learning below writes newly-seen devices
            # into self._known within moments of arriving on a brand new
            # network, which would otherwise end the silent-learning window
            # almost immediately. (This only governs INTRUDER flagging; it
            # has nothing to do with scanning — see NetworkTrust.)
            self._net_seen = known_devices.has_network(self._known, net_id)
            # Only a genuinely unseen network gets a silent learning window —
            # a network we already have an allowlist for classifies devices
            # correctly (known vs. not) from the very first cycle.
            self._baseline_until = now + settings.BASELINE_WINDOW if not self._net_seen else 0.0
            if not first:
                # Devices listed for the previous network don't belong to
                # this one; leaving them would let [t] trust them *here*.
                with _state_lock:
                    _state["devices"] = {}
        self._publish_network_meta()
        return self._net_id

    def current_network_id(self):
        return self._net_id

    def publish_network_meta(self):
        """Re-publish after the scan trust changed, so the NETWORK tab
        reflects it immediately instead of on the next ARP cycle."""
        with self._known_lock:
            self._publish_network_meta()

    def _publish_network_meta(self):
        net_id = self._net_id
        meta = {
            "net_id":    net_id,
            "cidrs":     list(self._net_cidrs),
            "trusted":   self._trust.is_trusted(net_id),
            "trustable": trusted_networks.trustable(net_id),
            "scan_mode": settings.SCAN_MODE,
        }
        with _state_lock:
            _state["network_meta"] = meta

    def _save(self, now):
        # Callers hold self._known_lock (or own the instance outright, as the
        # one-shot CLI paths do).
        self._known = known_devices.prune(self._known, settings.KNOWN_DEVICES_RETENTION_DAYS, now)
        if known_devices.save(self._known, settings.KNOWN_DEVICES_PATH):
            # Written under sudo it would otherwise be root-owned inside the
            # user's home, which a later unprivileged run couldn't update.
            sensors.chown_to_invoking_user(
                os.path.dirname(settings.KNOWN_DEVICES_PATH), settings.KNOWN_DEVICES_PATH)
        else:
            # Genuine permanent breakage (unwritable path), not a transient
            # sensor hiccup — surface it rather than letting [t] look like it
            # worked while nothing is ever remembered across runs.
            _note(f"known_devices.save (allowlist not persisted to {settings.KNOWN_DEVICES_PATH})")
        self._dirty = self._dirty_new = False
        self._last_save = now

    def _maybe_save(self, now):
        if self._dirty_new or (
                self._dirty and now - self._last_save >= self._LAST_SEEN_SAVE_INTERVAL):
            self._save(now)

    def trust_all(self):
        """Mark every device currently listed on the NETWORK tab as known on
        the current network, and clear any INTRUDER flags. Called from the
        TUI key binding and (via a fresh instance) --trust-all-devices.
        Never enables scanning — that is NetworkTrust's job alone."""
        now = time.time()
        with self._known_lock:
            net_id = self._net_id or self._refresh_network_identity(now)
            with _state_lock:
                snapshot = list(_state["devices"].items())
            for mac, dev in snapshot:
                known_devices.remember(self._known, net_id, mac,
                                       _name_or_none(dev.hostname, dev.ip), now)
            with _state_lock:
                for dev in _state["devices"].values():
                    if dev.status == "INTRUDER":
                        dev.status = "Active"
            # Deliberately does NOT touch scan permission: trusting the
            # devices on a network only stops them being flagged INTRUDER.
            # Scanning needs its own confirmed action ([s] then [y]).
            self._save(now)

    def run(self):
        self._net_id = self._refresh_network_identity(time.time())
        while not self._stop_event.is_set():
            try:
                now    = time.time()
                net_id = self._refresh_network_identity(now)
                parsed = self._parse_arp_table()
                # Phase 1: under the lock, find which MACs are new. We hold the
                # lock only briefly here so readers (e.g. the render loop) never
                # stall on the slow DNS lookups that follow.
                with _state_lock:
                    devices  = _state["devices"]
                    new_macs = [mac for mac in parsed if mac not in devices]
                # Phase 2: resolve hostnames for the new IPs *outside* the lock —
                # a getnameinfo() call can block for seconds.
                hostnames = {mac: _resolve_hostname(parsed[mac]["ip"])
                             for mac in new_macs}
                # Phase 3: re-acquire the lock to insert the new devices and
                # refresh existing ones.
                with self._known_lock:
                    with _state_lock:
                        devices = _state["devices"]
                        for mac, info in parsed.items():
                            hostname = hostnames.get(mac, info["ip"])
                            if mac not in devices:
                                # Still new after the gap — classify it.
                                known    = known_devices.is_known(self._known, net_id, mac)
                                baseline = now < self._baseline_until
                                if known or baseline or not settings.INTRUDER_ALERTS:
                                    status = "Active"
                                    known_devices.remember(
                                        self._known, net_id, mac,
                                        _name_or_none(hostname, info["ip"]), now)
                                    self._dirty = True
                                    self._dirty_new = self._dirty_new or not known
                                else:
                                    status = "INTRUDER"
                                    push_alert(f"INTRUDER: {mac} at {info['ip']}")
                                devices[mac] = DeviceInfo(
                                    ip=info["ip"], mac=mac, hostname=hostname,
                                    first_seen=now, last_seen=now, status=status,
                                )
                            else:
                                # Either pre-existing, or it raced in between the two
                                # lock acquisitions — just update it. Only a
                                # neighbour entry the kernel confirmed recently
                                # counts as seeing the device now.
                                dev           = devices[mac]
                                dev.ip        = info["ip"]
                                if info.get("fresh", True):
                                    dev.last_seen = now
                                dev.status    = _device_status(dev)
                                if known_devices.is_known(self._known, net_id, mac):
                                    # dev.hostname, not `hostname`: only new MACs
                                    # are resolved each cycle, so `hostname` is
                                    # just the bare IP here and used to overwrite
                                    # the name remembered in known_devices.json.
                                    known_devices.remember(
                                        self._known, net_id, mac,
                                        _name_or_none(dev.hostname, dev.ip), now)
                                    self._dirty = True
                        # A device that has dropped out of the ARP table is never
                        # touched by the loop above, so it used to keep whatever
                        # status it last had — "Active" forever, next to a "3h
                        # ago" LAST SEEN. Age every absent device here too.
                        for mac, dev in devices.items():
                            if mac not in parsed:
                                dev.status = _device_status(dev)
                    self._maybe_save(now)
            except Exception as e:
                _note("ARPPassiveThread.run", e)
            self._stop_event.wait(settings.ARP_REFRESH)
        # Flush the batched last_seen refreshes on a clean shutdown.
        try:
            with self._known_lock:
                if self._dirty:
                    self._save(time.time())
        except Exception as e:
            _note("ARPPassiveThread.run (final save)", e)

    def stop(self):
        self._stop_event.set()


# ── network trust (scan permission) ──────────────────────────────────────────
def current_network():
    """(net_id, cidrs) for the network we're on *right now*, computed fresh.

    cidrs are only the local subnets that contain the default gateway — the
    network the gateway-MAC identity actually describes. A second interface
    on some other LAN (or a VPN) is not covered by trusting this network, so
    it's never offered for scanning under this identity."""
    try:
        nets = sensors.local_networks()
    except Exception as e:
        _note("current_network (local_networks)", e)
        nets = []
    net_id = known_devices.network_identity(nets)
    gw_ip, _mac = known_devices.default_gateway()
    cidrs = []
    if gw_ip:
        try:
            addr = ipaddress.IPv4Address(gw_ip)
            cidrs = [str(n) for n in nets if addr in n]
        except Exception as e:
            _note("current_network (gateway parse)", e)
    return net_id, cidrs


class NetworkTrust:
    """Thread-safe view of trusted_networks.json — the *only* thing that can
    permit an active sweep. Shared by the UI thread (which changes it, after
    the user confirms) and PingSweepThread (which consults it before every
    batch). Kept separate from the device allowlist on purpose: trusting the
    devices on a network ([t]) must never imply permission to scan it."""

    def __init__(self, path=None):
        self._path = path or settings.TRUSTED_NETWORKS_PATH
        self._lock = threading.Lock()
        self._data = trusted_networks.load(self._path)

    def is_trusted(self, net_id):
        with self._lock:
            return trusted_networks.is_trusted(self._data, net_id)

    def cidrs(self, net_id):
        with self._lock:
            return trusted_networks.trusted_cidrs(self._data, net_id)

    def _persist(self):
        if not trusted_networks.save(self._data, self._path):
            _note(f"trusted_networks.save (not persisted to {self._path})")
            return False
        sensors.chown_to_invoking_user(os.path.dirname(self._path), self._path)
        return True

    def trust(self, net_id, cidrs):
        """Returns None on success, or a human-readable reason it refused."""
        reason = trusted_networks.untrustable_reason(net_id)
        if reason:
            return reason
        if not cidrs:
            return ("no scannable local subnet contains this network's gateway "
                    "(subnets larger than /22 are never swept)")
        gw = net_id[3:]
        with self._lock:
            trusted_networks.trust(self._data, net_id, cidrs,
                                   label=f"{', '.join(cidrs)} via {gw}")
            if not self._persist():
                trusted_networks.untrust(self._data, net_id)
                return f"could not write {self._path}"
        return None

    def untrust(self, net_id):
        with self._lock:
            removed = trusted_networks.untrust(self._data, net_id)
            if removed:
                self._persist()
            return removed


class ScanTrustDialog:
    """The [s] key's two-step flow: open() shows what would be scanned,
    and only a following [y] changes anything. Every other key cancels.

    The network is captured when the dialog opens and re-checked (fresh, not
    cached) at confirm time, and while the dialog is open: if it changed in
    between, the confirmation is void — "yes" applies only to the network the
    user was actually shown."""

    def __init__(self, trust, network_fn=None, on_change=None):
        self._trust      = trust
        self._network_fn = network_fn or current_network
        self._on_change  = on_change or (lambda: None)
        self.pending     = None  # {"action", "net_id", "cidrs"} while open

    def open(self):
        if settings.SCAN_MODE == "never":
            push_alert("scanning is disabled in the config (scan = never) — nothing to trust")
            return False
        net_id, cidrs = self._network_fn()
        if self._trust.is_trusted(net_id):
            self.pending = {"action": "untrust", "net_id": net_id,
                            "cidrs": self._trust.cidrs(net_id)}
            return True
        reason = trusted_networks.untrustable_reason(net_id)
        if reason is None and not cidrs:
            reason = ("no scannable local subnet contains this network's gateway "
                      "(subnets larger than /22 are never swept)")
        if reason:
            push_alert(f"can't enable scanning: {reason}")
            return False
        self.pending = {"action": "trust", "net_id": net_id, "cidrs": list(cidrs)}
        return True

    def network_still_current(self):
        if not self.pending:
            return False
        net_id, cidrs = self._network_fn()
        if net_id != self.pending["net_id"]:
            return False
        return self.pending["action"] == "untrust" or list(cidrs) == self.pending["cidrs"]

    def check_network(self):
        """Call periodically while open: cancels if the network changed."""
        if self.pending and not self.network_still_current():
            self.pending = None
            push_alert("network changed — scan confirmation cancelled, nothing changed")

    def handle_key(self, ch, dialog_complete=True):
        """Returns True if the key closed the dialog."""
        if not self.pending or ch == -1 or ch == curses.KEY_RESIZE:
            return False
        pending, self.pending = self.pending, None
        if ch not in (ord("y"), ord("Y")):
            push_alert("cancelled — scan trust unchanged")
            return True
        if not dialog_complete:
            push_alert("cancelled — enlarge the terminal so the whole warning is visible")
            return True
        if not self._network_still_matches(pending):
            push_alert("network changed — scan confirmation cancelled, nothing changed")
            return True
        if pending["action"] == "untrust":
            self._trust.untrust(pending["net_id"])
            push_alert("network untrusted — active scanning stopped")
        else:
            reason = self._trust.trust(pending["net_id"], pending["cidrs"])
            if reason:
                push_alert(f"can't enable scanning: {reason}")
            else:
                push_alert(f"network trusted — active scanning of {', '.join(pending['cidrs'])} enabled")
        self._on_change()
        return True

    def _network_still_matches(self, pending):
        saved, self.pending = self.pending, pending
        try:
            return self.network_still_current()
        finally:
            self.pending = saved


# ── PingSweepThread ────────────────────────────────────────────────────────────
class PingSweepThread(threading.Thread):
    """Active ping sweep — the one thing syswatch does that a network can
    notice. It runs only when *all* of these hold, and they're re-checked from
    scratch before every single batch, not just once per cycle:

      * scan mode is "trusted" (there is no unconditional mode),
      * the network we're on right now — identity computed fresh here, not a
        cached copy from another thread — is in trusted_networks.json, which
        only an explicit, confirmed user action ever writes, and
      * each address pinged lies in a subnet that was confirmed when the
        network was trusted *and* is still local.

    There is no fallback target: if no trusted subnet is local, nothing is
    pinged (the old SCAN_SUBNET / "guess a /24 from our own IP" fallbacks
    could sweep a subnet unrelated to the network the user had trusted).
    """

    def __init__(self, scan_mode="trusted", trust=None, network_fn=None):
        super().__init__(daemon=True)
        self._stop_event = threading.Event()
        self._scan_mode  = scan_mode  # "trusted" | "never"
        self._trust      = trust if trust is not None else NetworkTrust()
        self._network_fn = network_fn or current_network
        # Resolved once at construction, not per-batch: the "nice ping ..." on
        # every batch used to mean a missing `ping` never raised
        # FileNotFoundError (the *wrapper*, "nice", was still found and would
        # itself exit 127) — so self._binary_available was never set False and
        # the thread spent its whole life spawning ping's that could never work.
        # Checking with shutil.which() up front detects `ping` correctly
        # regardless of whether `nice` happens to be installed, and lets the
        # sweep still run (just without the CPU-niceness) if only `nice` is
        # missing rather than disabling the whole feature for that reason.
        self._ping_path = shutil.which("ping")
        self._nice_path = shutil.which("nice")
        self._binary_available = self._ping_path is not None
        if not self._binary_available and scan_mode == "trusted":
            _note("PingSweepThread.__init__ (ping not found)")

    def _allowed_networks(self):
        """The subnets it's permitted to ping right now, or [] for none."""
        if not self._binary_available or self._scan_mode != "trusted":
            return []
        net_id, local = self._network_fn()
        if not self._trust.is_trusted(net_id):
            return []
        local = set(local)
        out = []
        for c in self._trust.cidrs(net_id):
            if c in local:
                try:
                    out.append(ipaddress.IPv4Network(c))
                except Exception as e:
                    _note("PingSweepThread._allowed_networks", e)
        return out

    def _should_scan(self):
        return bool(self._allowed_networks())

    def _kill_and_reap(self, p, timeout=1):
        # p.kill() alone leaves a zombie until something waits on it — every
        # caller of this must always follow up with wait(), never just kill().
        try:
            p.kill()
        except Exception:
            pass
        try:
            p.wait(timeout=timeout)
        except Exception:
            pass

    def _ping_batch(self, ips):
        procs = {}
        for ip in ips:
            if self._stop_event.is_set():
                break
            cmd = ([self._nice_path, "-n", "19", self._ping_path]
                   if self._nice_path else [self._ping_path])
            try:
                p = subprocess.Popen(
                    cmd + ["-c1", "-W1", "-q", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                procs[ip] = p
            except FileNotFoundError as e:
                # ping/nice existed at shutil.which() time but not now
                # (uninstalled mid-run) — stop trying rather than spin.
                self._binary_available = False
                _note("PingSweepThread._ping_batch (spawn, binary vanished)", e)
                return []
            except Exception as e:
                _note("PingSweepThread._ping_batch (spawn)", e)
        alive = []
        for ip, p in procs.items():
            if self._stop_event.is_set():
                # Shutting down: don't sit out the full per-process timeout
                # for every straggler still in flight, and never leave one
                # killed-but-unreaped (a zombie) behind.
                self._kill_and_reap(p)
                continue
            try:
                p.wait(timeout=2)
                if p.returncode == 0:
                    alive.append(ip)
            except subprocess.TimeoutExpired:
                self._kill_and_reap(p)
            except Exception as e:
                _note("PingSweepThread._ping_batch (wait)", e)
                self._kill_and_reap(p)
        return alive

    # While gated off, re-check this often rather than waiting out a full
    # PING_CYCLE — so a freshly confirmed trust starts sweeping promptly.
    _GATED_POLL = 5.0

    def run(self):
        while not self._stop_event.is_set():
            try:
                nets = self._allowed_networks()
            except Exception as e:
                _note("PingSweepThread.run (gate)", e)
                nets = []
            if not nets:
                wait = (self._GATED_POLL
                        if self._scan_mode == "trusted" and self._binary_available
                        else settings.PING_CYCLE)
                self._stop_event.wait(wait)
                continue
            try:
                ips   = [str(h) for net in nets for h in net.hosts()]
                delay = settings.PING_CYCLE / max(1, len(ips) / settings.PING_BATCH)
                for i in range(0, len(ips), settings.PING_BATCH):
                    if self._stop_event.is_set():
                        return
                    # Re-derive permission before every batch: a network
                    # change, an untrust, or a subnet that's no longer
                    # local stops the sweep within one batch.
                    allowed = self._allowed_networks()
                    batch = [ip for ip in ips[i:i + settings.PING_BATCH]
                             if any(ipaddress.IPv4Address(ip) in n for n in allowed)]
                    if len(batch) != len(ips[i:i + settings.PING_BATCH]):
                        break
                    alive = self._ping_batch(batch)
                    now   = time.time()
                    with _state_lock:
                        for ip in alive:
                            for dev in _state["devices"].values():
                                if dev.ip == ip:
                                    dev.last_seen = now
                                    dev.status    = _device_status(dev)
                    self._stop_event.wait(delay)
            except Exception as e:
                _note("PingSweepThread.run", e)
                self._stop_event.wait(settings.PING_CYCLE)

    def stop(self):
        self._stop_event.set()


