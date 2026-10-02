#!/usr/bin/env python3
"""syswatch_state — settings and state shared by syswatch's collector
threads, renderer and entry point.

`settings` holds every user-tunable value. Its attributes start at the
built-in defaults and are overwritten once by syswatch.main() from the merged
CLI/config result, before any thread or report code runs. It replaces the
mutable module globals syswatch.py used to have: with the code split across
modules, a `global` rebind in one module would be invisible to the others,
whereas everyone reading `settings.X` sees the same value.

`_state` is the snapshot the collector threads publish and the renderer
reads, always under `_state_lock` (see get_state()).
"""

import collections
import dataclasses
import threading
import time
import types
from datetime import datetime as _dt

import psutil

import syswatch_sensors as sensors


def _note(collector, exc=None):
    sensors.note_error(collector, exc)


NUM_CORES = psutil.cpu_count(logical=True) or 4

settings = types.SimpleNamespace(
    WATCHED_SERVICES             = [],
    THRESH                       = {},
    SCAN_MODE                    = "trusted",  # "trusted" | "never" — see PingSweepThread
    HISTORY                      = 60,
    REFRESH                      = 1.0,
    TOP_N                        = 5,
    ARP_REFRESH                  = 2.0,
    WATCHDOG_REFRESH             = 10.0,
    SDCARD_REFRESH               = 60.0,
    PING_CYCLE                   = 420,
    PING_BATCH                   = 10,
    INTRUDER_TTL                 = 600,
    ALERT_TTL                    = 30,
    INTRUDER_ALERTS              = True,
    BASELINE_WINDOW              = 60,
    KNOWN_DEVICES_RETENTION_DAYS = 90,
    # Sudo-aware, exactly like the config and metrics.csv: under `sudo
    # syswatch`, `~` is root's home, so this used to resolve to root's (empty)
    # allowlist — every device on the LAN flagged INTRUDER, and [t] writing
    # somewhere an unprivileged run would never look.
    KNOWN_DEVICES_PATH           = sensors.user_data_path("known_devices.json"),
    # Networks the user explicitly confirmed for active scanning — separate
    # from the device allowlist above; see syswatch_trusted_networks.py.
    TRUSTED_NETWORKS_PATH        = sensors.user_data_path("trusted_networks.json"),
)


# ── shared state ───────────────────────────────────────────────────────────────
_state = {
    "system":      None,
    "system_hist": None,
    "model":       sensors.platform_model(),
    "devices":     {},
    "logs":        collections.deque(maxlen=200),
    "log_errs":    collections.deque(maxlen=3600),
    "services":    [],
    "storage":     None,
    "backup":      None,
    "network_meta": None,  # {"net_id", "known", "scan_mode"} — see ARPPassiveThread
    # Active-sweep progress for the NETWORK tab — see PingSweepThread._publish.
    # Always replaced with a new dict, never mutated in place, so the shallow
    # copy get_state() takes is a consistent snapshot.
    "scan_status": None,
}
_state_lock = threading.Lock()
_alerts     = collections.deque(maxlen=5)


def push_alert(msg: str):
    _alerts.append((time.monotonic(), f"{_dt.now().strftime('%H:%M:%S')} {msg}"))


# Collector threads that have died. None of them ever exit run() on their own
# while syswatch is up — they loop until their stop event is set — so a thread
# that isn't alive during normal operation has crashed, and whatever panel it
# fed is frozen for the rest of the session.
#
# This is tracked separately from sensors.has_recent_errors() because that only
# reports errors from the last 15 seconds: threading.excepthook does record the
# crash, so the header's ⚠ appeared, but then cleared 15s later and the panel
# went on quietly showing stale data forever. Permanent breakage needs a
# permanent signal.
_dead_threads = set()


def scan_dead_threads(threads):
    """Record any collector thread that has died, alerting once per thread.
    Call only while syswatch is running, never during shutdown."""
    for t in threads:
        if t.is_alive():
            continue
        name = type(t).__name__
        if name not in _dead_threads:
            _dead_threads.add(name)
            push_alert(f"{name} died — that panel has stopped updating")
    return _dead_threads


def get_state():
    # A shallow dict(_state) would still share the live "devices" dict and the
    # "logs"/"log_errs"/"system_hist" deques with the background threads that
    # keep mutating them — a renderer iterating those later (outside the lock)
    # can crash with "dictionary changed size during iteration" or "deque
    # mutated during iteration". Snapshot each of them into fresh containers
    # here, while still holding the lock those threads mutate under.
    #
    # The "devices" dict itself gets a fresh dict(...), but that only copies
    # the mac->DeviceInfo mapping — the DeviceInfo *objects* it points to are
    # the very same instances ARPPassiveThread/PingSweepThread keep mutating
    # (dev.ip = ..., dev.last_seen = ..., dev.status = ...) after this
    # function returns. A renderer reading dev.ip, then dev.status, then
    # dev.last_seen as separate statements outside the lock could see a torn
    # mix of before/after values if a mutation lands between those reads.
    # dataclasses.replace() makes an independent copy of each record while
    # still holding the lock, so the snapshot is a true point-in-time view.
    with _state_lock:
        snap = dict(_state)
        snap["devices"]   = {mac: dataclasses.replace(dev)
                              for mac, dev in _state["devices"].items()}
        snap["logs"]      = list(_state["logs"])
        snap["log_errs"]  = list(_state["log_errs"])
        hist = _state.get("system_hist")
        if hist is not None:
            snap["system_hist"] = {k: list(v) for k, v in hist.items()}
        return snap


# ── device helpers ─────────────────────────────────────────────────────────────
@dataclasses.dataclass
class DeviceInfo:
    ip:         str
    mac:        str
    hostname:   str
    first_seen: float
    last_seen:  float
    status:     str


def _name_or_none(hostname, ip):
    """A resolved hostname worth remembering, or None when resolution just
    fell back to the IP — so a failed reverse lookup never overwrites a real
    name already stored in known_devices.json with a bare address."""
    return hostname if hostname and hostname != ip else None


def _device_status(dev: DeviceInfo) -> str:
    if dev.status == "INTRUDER":
        return "Idle" if time.time() - dev.last_seen > settings.INTRUDER_TTL else "INTRUDER"
    age = time.time() - dev.last_seen
    if age < 10:   return "Active"
    if age < 300:  return "Recent"
    return "Idle"


