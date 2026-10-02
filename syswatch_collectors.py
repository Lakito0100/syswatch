#!/usr/bin/env python3
"""syswatch_collectors — the background threads that sample the system
(CPU/memory/temperatures, journal, services, storage, backup status) and
publish into syswatch_state._state. Network discovery and scanning live in
syswatch_network.py."""

import collections
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime as _dt

import psutil

import syswatch_sensors as sensors
from syswatch_state import (NUM_CORES, _note, _state, _state_lock, push_alert,
                            settings)


# ── Metrics ────────────────────────────────────────────────────────────────────
class Metrics:
    def __init__(self):
        self.hist = {
            k: collections.deque(maxlen=settings.HISTORY)
            for k in ("cpu", "ram", "cpu_temp", "gpu_temp", "storage_temp",
                      "net_rx", "net_tx", "cpu_freq",
                      "disk_read", "disk_write")
        }
        self.core_hist = [collections.deque(maxlen=settings.HISTORY) for _ in range(NUM_CORES)]
        self._net0     = None;  self._net_t  = None
        self._disk0    = None;  self._disk_t = None
        self.model     = sensors.platform_model()
        psutil.cpu_percent(percpu=True)
        for p in psutil.process_iter(["cpu_percent"]):
            try: p.cpu_percent()
            except Exception: pass

    @staticmethod
    def _vcg(arg):
        if not shutil.which("vcgencmd"):
            return None
        try:
            r = subprocess.run(
                ["vcgencmd"] + arg.split(),
                capture_output=True, text=True, timeout=0.5,
            )
            return r.stdout.strip() if r.returncode == 0 else None
        except Exception as e:
            _note(f"Metrics._vcg({arg})", e)
            return None

    def _soc_temp(self):
        return sensors.cpu_temp()

    def _gpu_temp(self):
        return sensors.gpu_temp_c()

    def _voltage(self):
        raw = self._vcg("measure_volts core")
        if raw and raw.startswith("volt="):
            try: return float(raw[5:].rstrip("V"))
            except Exception as e: _note("Metrics._voltage (parse)", e)
        return None

    def _cpu_freq(self):
        raw = self._vcg("measure_clock arm")
        if raw and "=" in raw:
            try: return int(raw.split("=")[-1]) // 1_000_000
            except Exception as e: _note("Metrics._cpu_freq (vcgencmd parse)", e)
        try:
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq") as f:
                return int(f.read().strip()) // 1000
        except FileNotFoundError:
            # No cpufreq driver (VMs, containers, some ARM boards) — absent,
            # not broken, so it mustn't light the degraded ⚠ every second.
            return None
        except Exception as e:
            _note("Metrics._cpu_freq (sysfs fallback)", e)
            return None

    def _throttled(self):
        raw = self._vcg("get_throttled")
        if not raw or "throttled=" not in raw:
            return None
        try:
            val = int(raw.split("=")[-1], 16)
        except Exception as e:
            _note("Metrics._throttled (parse)", e)
            return None
        return {
            "uv_now":     bool(val & (1 << 0)),
            "freq_now":   bool(val & (1 << 1)),
            "throt_now":  bool(val & (1 << 2)),
            "temp_now":   bool(val & (1 << 3)),
            "uv_ever":    bool(val & (1 << 16)),
            "freq_ever":  bool(val & (1 << 17)),
            "throt_ever": bool(val & (1 << 18)),
            "temp_ever":  bool(val & (1 << 19)),
            "raw": val,
        }

    def _disk_io_rates(self):
        d   = psutil.disk_io_counters()
        now = time.monotonic()
        if d is None:
            self._disk0 = None; self._disk_t = now
            return 0.0, 0.0
        if self._disk0 is not None:
            dt = (now - self._disk_t) or 1
            r  = max(0.0, (d.read_bytes  - self._disk0.read_bytes)  / dt / 1024)
            w  = max(0.0, (d.write_bytes - self._disk0.write_bytes) / dt / 1024)
        else:
            r = w = 0.0
        self._disk0 = d; self._disk_t = now
        return r, w

    def _wifi_signal(self):
        try:
            with open("/proc/net/wireless") as f:
                for line in f:
                    if ":" in line and not line.strip().startswith(("Inter", "face")):
                        parts = line.split()
                        return {
                            "iface":   parts[0].rstrip(":"),
                            "signal":  float(parts[3].rstrip(".")),
                            "quality": float(parts[2].rstrip(".")),
                        }
        except FileNotFoundError:
            # Only present when the kernel has wireless extensions — i.e.
            # absent on most wired-only machines. Not an error.
            pass
        except Exception as e:
            _note("Metrics._wifi_signal", e)
        return None

    def _top_procs(self):
        procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
            try:
                info = p.info
                if info["cpu_percent"] is None:
                    info["cpu_percent"] = 0.0
                procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(procs, key=lambda x: x["cpu_percent"], reverse=True)[:50]

    def collect(self):
        """Sample every metric. Touches no shared state except this object's
        own rate-calculation baselines, so it runs *outside* _state_lock —
        it can take seconds (smartctl, nvidia-smi, vcgencmd, walking every
        process) and holding the lock that long froze the whole UI. The
        history deques are only appended to afterwards, by record(), under
        the lock."""
        s = {}
        cores = psutil.cpu_percent(percpu=True)
        s["cores"] = cores
        # psutil.cpu_percent(percpu=True) should never return an empty list on
        # a real system, but if it ever did, dividing by len(cores) would
        # raise ZeroDivisionError and (per the outer try/except in
        # SystemThread.run()) silently drop the whole cycle's update.
        avg = sum(cores) / len(cores) if cores else 0.0
        s["cpu_avg"] = avg

        mem  = psutil.virtual_memory()
        swap = psutil.swap_memory()
        s.update(
            ram_used=mem.used, ram_total=mem.total, ram_pct=mem.percent,
            swap_used=swap.used, swap_total=swap.total, swap_pct=swap.percent,
        )

        try:
            batt = psutil.sensors_battery()
        except Exception as e:
            _note("Metrics.collect (psutil.sensors_battery)", e)
            batt = None
        s["battery_pct"] = batt.percent if batt is not None else None

        is_pi    = sensors.is_pi()
        gpu_info = None if is_pi else sensors.gpu_temp()
        ct       = self._soc_temp()
        gt       = gpu_info["temp"] if gpu_info else self._gpu_temp()
        st       = sensors.storage_temp()
        freq     = self._cpu_freq()
        s["is_pi"]      = is_pi
        s["model"]      = self.model
        s["gpu_vendor"] = gpu_info["vendor"] if gpu_info else None
        s["cpu_temp"]  = ct;  s["gpu_temp"] = gt; s["storage_temp"] = st
        s["voltage"]   = self._voltage()   if is_pi else None
        s["cpu_freq"]  = freq
        s["throttled"] = self._throttled() if is_pi else None

        disk = psutil.disk_usage("/")
        s.update(disk_used=disk.used, disk_total=disk.total, disk_pct=disk.percent)
        dr, dw = self._disk_io_rates()
        s["disk_read"] = dr; s["disk_write"] = dw

        net = psutil.net_io_counters(); now = time.monotonic()
        rx = tx = 0.0
        if net is not None and self._net0 is not None:
            dt = (now - self._net_t) or 1
            rx = max(0.0, (net.bytes_recv - self._net0.bytes_recv) / dt / 1024)
            tx = max(0.0, (net.bytes_sent - self._net0.bytes_sent) / dt / 1024)
        if net is not None:
            self._net0 = net; self._net_t = now
        s["net_rx"] = rx
        s["net_tx"] = tx

        s["load_avg"]  = os.getloadavg()
        s["wifi"]      = self._wifi_signal()
        s["uptime"]    = time.time() - psutil.boot_time()
        s["top_procs"] = self._top_procs()
        return s

    def record(self, s):
        """Append one collect() result to the sparkline histories. Callers
        hold _state_lock — get_state() snapshots these deques under it."""
        for i, p in enumerate(s["cores"][:NUM_CORES]):
            self.core_hist[i].append(p)
        self.hist["cpu"].append(s["cpu_avg"])
        self.hist["ram"].append(s["ram_pct"])
        for key in ("cpu_temp", "gpu_temp", "storage_temp", "cpu_freq"):
            if s.get(key) is not None:
                self.hist[key].append(s[key])
        for key in ("disk_read", "disk_write", "net_rx", "net_tx"):
            self.hist[key].append(s[key])


# ── SystemThread ───────────────────────────────────────────────────────────────
class SystemThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._metrics           = Metrics()
        self._stop_event        = threading.Event()
        self._temp_alert_level  = 0  # 0=ok, 1=warning, 2=critical

    def _write_temp_alert(self, msg):
        # Shared with syswatch-logger; only one of them writes the file —
        # see sensors.append_alert.
        sensors.append_alert("temp_alerts.log", msg)

    def _check_temp_alert(self, snap):
        ct = snap.get("cpu_temp")
        if ct is None:
            return
        warn, crit = settings.THRESH["cpu_temp"]
        level = 2 if ct >= crit else 1 if ct >= warn else 0
        if level > self._temp_alert_level:
            label     = "CRITICAL" if level == 2 else "WARNING"
            threshold = crit if level == 2 else warn
            sys.stdout.write("\a")
            sys.stdout.flush()
            self._write_temp_alert(
                f"{label} cpu_temp={ct:.1f}C (threshold={threshold}C)"
            )
        self._temp_alert_level = level

    def run(self):
        while not self._stop_event.is_set():
            try:
                # Sampling (slow: subprocesses, a walk of every process) runs
                # unlocked; only the history appends and the publish below
                # need the lock get_state() snapshots under — otherwise a
                # reader could iterate a deque mid-append and crash with
                # "deque mutated during iteration".
                snap = self._metrics.collect()
                self._check_temp_alert(snap)
                with _state_lock:
                    self._metrics.record(snap)
                    _state["system"]      = snap
                    _state["system_hist"] = self._metrics.hist
                    _state["model"]       = self._metrics.model
            except Exception as e:
                _note("SystemThread.run", e)
            self._stop_event.wait(settings.REFRESH)

    def stop(self):
        self._stop_event.set()


# ── LogThread ──────────────────────────────────────────────────────────────────
class LogThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop_event = threading.Event()
        self._proc = None
        # Mirrors ServiceWatchdogThread._available: if journalctl genuinely
        # isn't installed, FileNotFoundError is unambiguous (nothing here
        # wraps it in another binary the way the old ping/nice pairing did),
        # but without this flag run() would still retry launching it every
        # 5s forever with zero chance of success.
        self._available = True

    def _launch(self):
        try:
            self._proc = subprocess.Popen(
                ["journalctl", "-f", "-n", "100", "--output=json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError as e:
            self._proc = None
            self._available = False
            _note("LogThread._launch (journalctl not found)", e)
        except Exception as e:
            self._proc = None
            _note("LogThread._launch", e)

    def _parse_line(self, raw):
        try:
            obj      = json.loads(raw)
            priority = int(obj.get("PRIORITY", "7"))
            unit     = obj.get("_SYSTEMD_UNIT") or obj.get("SYSLOG_IDENTIFIER", "unknown")
            unit     = unit.replace(".service", "")
            message  = obj.get("MESSAGE", "")
            if isinstance(message, list):
                message = "<binary>"
            elif isinstance(message, bytes):
                message = message.decode("utf-8", errors="replace")
            ts_us = obj.get("__REALTIME_TIMESTAMP", "0")
            ts    = float(ts_us) / 1_000_000
            return {
                "priority": priority,
                "unit":     unit,
                "message":  str(message),
                "ts":       ts,
                "ts_str":   _dt.fromtimestamp(ts).strftime("%H:%M:%S"),
            }
        except Exception as e:
            _note("LogThread._parse_line", e)
            return None

    def _reap(self):
        # Terminate and reap the journalctl child so it doesn't linger as a
        # zombie when its stream ends or errors out. Always clears self._proc.
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    # terminate() (SIGTERM) can be ignored; escalate rather
                    # than leaving an unreaped zombie behind.
                    proc.kill()
                    proc.wait(timeout=1)
            else:
                proc.wait(timeout=1)
        except Exception as e:
            _note("LogThread._reap", e)
        finally:
            # subprocess.run()'s pipes are closed for us automatically, but a
            # long-lived Popen like this one leaves its stdout pipe fd open
            # until something closes it or the object is garbage collected —
            # not a leak in practice (refcounting reclaims it promptly) but
            # not guaranteed, and closing it explicitly costs nothing.
            try:
                if proc.stdout is not None:
                    proc.stdout.close()
            except Exception:
                pass

    def run(self):
        self._launch()
        while not self._stop_event.is_set():
            if not self._available:
                self._stop_event.wait(5.0)
                continue
            if self._proc is None:
                self._stop_event.wait(5.0)
                self._launch()
                continue
            try:
                line = self._proc.stdout.readline()
            except Exception as e:
                _note("LogThread.run (readline)", e)
                self._reap()
                continue
            if line == b"":
                self._reap()
                self._stop_event.wait(5.0)
                continue
            entry = self._parse_line(line)
            if entry:
                now = time.time()
                with _state_lock:
                    _state["logs"].append(entry)
                    if entry["priority"] <= 3:
                        _state["log_errs"].append(now)
                if entry["priority"] <= 3:
                    push_alert(f"[{entry['unit']}] {entry['message'][:60]}")

    def stop(self):
        self._stop_event.set()
        # Capture into a local once: self._proc is mutated by this thread's
        # own run()/_reap() concurrently, and re-reading self._proc a second
        # time between the truthiness check and .terminate() could see it
        # already reset to None by a _reap() that ran in between, turning
        # this into an AttributeError that the broad except then silently
        # swallows — leaving the *actual* current process un-terminated and
        # this thread blocked in readline() until journalctl next emits a
        # line, well past the shutdown join() timeout.
        proc = self._proc
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass


# ── ServiceWatchdogThread ──────────────────────────────────────────────────────
class ServiceWatchdogThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop_event   = threading.Event()
        self._prev_states = {}
        self._available   = True

    def _query(self, unit):
        try:
            r = subprocess.run(
                ["systemctl", "show", unit,
                 "--property=ActiveState,SubState,ExecMainPID,"
                 "NRestarts,ActiveEnterTimestamp,Result",
                 "--no-pager", "--no-legend"],
                capture_output=True, text=True, timeout=2,
            )
            props = {"unit": unit}
            for line in r.stdout.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    props[k.strip()] = v.strip()
            return props
        except FileNotFoundError as e:
            self._available = False
            _note("ServiceWatchdogThread._query (systemctl not found)", e)
            return None
        except Exception as e:
            _note("ServiceWatchdogThread._query", e)
            return {"unit": unit, "ActiveState": "unknown"}

    def run(self):
        while not self._stop_event.is_set():
            if not self._available:
                with _state_lock:
                    _state["services"] = None
                self._stop_event.wait(settings.WATCHDOG_REFRESH)
                continue
            try:
                results = []
                for unit in settings.WATCHED_SERVICES:
                    # Each _query() call blocks up to its own 2s timeout;
                    # bailing out here as soon as shutdown is requested keeps
                    # a watchlist of several units from adding several more
                    # seconds on top of whichever call is already in flight.
                    if self._stop_event.is_set():
                        break
                    props = self._query(unit)
                    if props is None:
                        break
                    results.append(props)
                    active = props.get("ActiveState", "unknown")
                    prev   = self._prev_states.get(unit)
                    if active == "failed" and prev != "failed":
                        push_alert(f"FAILED: {unit}")
                    self._prev_states[unit] = active
                if self._available:
                    with _state_lock:
                        _state["services"] = results
            except Exception as e:
                _note("ServiceWatchdogThread.run", e)
            self._stop_event.wait(settings.WATCHDOG_REFRESH)

    def stop(self):
        self._stop_event.set()


# ── StorageThread ────────────────────────────────────────────────────────────
class StorageThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop_event = threading.Event()
        # 0=ok, 1=warning, 2=critical — per mount, mirrors _temp_alert_level.
        # The boot-mount key is added lazily once the mount is known.
        self._disk_alert_level = {"fs_root": 0}

    def _write_disk_alert(self, msg):
        sensors.append_alert("disk_alerts.log", msg)  # see _write_temp_alert

    def _check_disk_alert(self, mount_key, mount_label, fs):
        # Must never raise: run()'s bare try/except would otherwise drop the
        # whole _state["storage"] update for the cycle.
        if fs is None:
            return
        try:
            pct = fs["pct"]
            warn, crit = settings.THRESH["disk_pct"]
            level = 2 if pct >= crit else 1 if pct >= warn else 0
            prev = self._disk_alert_level.get(mount_key, 0)
            if level > prev:
                label     = "CRITICAL" if level == 2 else "WARNING"
                threshold = crit if level == 2 else warn
                sys.stdout.write("\a")
                sys.stdout.flush()
                self._write_disk_alert(
                    f"{label} disk={mount_label} {pct:.1f}% (threshold={threshold}%)"
                )
            self._disk_alert_level[mount_key] = level
        except Exception as e:
            _note("StorageThread._check_disk_alert", e)

    @staticmethod
    def _fs_stats(path):
        # Same arithmetic as `df` and psutil.disk_usage() (which the SYSTEM
        # tab and syswatch-logger use). The old `used = total - f_bavail`
        # counted the root-reserved blocks (5% by default on ext4, often far
        # more on thin-provisioned/quota'd volumes) as used, so the STORAGE
        # tab, --report and the disk alerts could disagree wildly with the
        # SYSTEM tab and df — e.g. 88% here vs 22% there for the same disk —
        # and fire false WARNING/CRITICAL alerts.
        try:
            st    = os.statvfs(path)
            total = st.f_blocks * st.f_frsize
            free  = st.f_bavail * st.f_frsize
            used  = (st.f_blocks - st.f_bfree) * st.f_frsize
            avail_total = used + free
            pct   = used / avail_total * 100 if avail_total else 0.0
            return {"total": total, "used": used, "free": free, "pct": pct}
        except Exception as e:
            _note("StorageThread._fs_stats", e)
            return None

    @staticmethod
    def _io_stats(base):
        if not base:
            return None
        try:
            with open(f"/sys/block/{base}/stat") as f:
                fields = f.read().split()
            return {
                "reads":          int(fields[0]),
                "read_sectors":   int(fields[2]),
                "writes":         int(fields[4]),
                "write_sectors":  int(fields[6]),
            }
        except FileNotFoundError:
            return None  # not a block device (overlay/network root) — absent
        except Exception as e:
            _note("StorageThread._io_stats", e)
            return None

    @staticmethod
    def _mmc_health_sysfs(base):
        """Read eMMC health registers from sysfs. Returns health string or None."""
        dev_base = f"/sys/block/{base}/device"
        try:
            with open(f"{dev_base}/pre_eol_info") as f:
                eol = int(f.read().strip(), 16)
            if eol == 0x03:
                return "URGENT"
            if eol == 0x02:
                return "WARNING"
            if eol == 0x01:
                return "GOOD"
        except Exception:
            pass
        try:
            with open(f"{dev_base}/life_time") as f:
                parts = [int(x, 16) for x in f.read().split()]
            if parts:
                worst = max(parts)
                if worst >= 0x0B:
                    return "URGENT"
                if worst >= 0x09:
                    return "WARNING"
                return "GOOD"
        except Exception:
            pass
        return None

    @staticmethod
    def _smart(base, kind):
        result = {"health": None, "power_on_hours": None, "attrs": []}
        # Absent smartmontools is a soft dependency, not a collector failure —
        # see the matching guard in sensors._read_storage_temp_smartctl. The
        # mmc sysfs fallback below still runs, so eMMC health is unaffected.
        if not shutil.which("smartctl"):
            if kind == "mmc":
                sysfs_health = StorageThread._mmc_health_sysfs(base)
                if sysfs_health is not None:
                    result["health"] = sysfs_health
            return result
        dev = f"/dev/{base}"
        smartctl_cmds = [["smartctl", "-a", dev, "--json"]]
        if kind == "mmc":
            smartctl_cmds.append(["smartctl", "-a", dev, "--device=mmc", "--json"])
        for cmd in smartctl_cmds:
            try:
                r    = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                data = json.loads(r.stdout)
                if not isinstance(data, dict):
                    raise json.JSONDecodeError("not a JSON object", r.stdout, 0)
                # smartctl emits explicit nulls for sections it couldn't read
                # (e.g. "ata_smart_attributes": null), so .get(key, {}) alone
                # isn't enough — a None there raised AttributeError, which
                # threw away everything already parsed for this device.
                smart_status = data.get("smart_status")
                passed = (smart_status.get("passed")
                          if isinstance(smart_status, dict) else None)
                if passed is True:
                    result["health"] = "PASSED"
                elif passed is False:
                    result["health"] = "FAILED"
                nvme_log = data.get("nvme_smart_health_information_log")
                if isinstance(nvme_log, dict):
                    if "percentage_used" in nvme_log:
                        used = nvme_log["percentage_used"]
                        result["attrs"].append({"name": "Percentage_Used", "value": used})
                        if result["health"] is None:
                            result["health"] = "WARNING" if used >= 90 else "GOOD"
                    if "power_on_hours" in nvme_log:
                        result["power_on_hours"] = nvme_log["power_on_hours"]
                    if nvme_log.get("media_errors"):
                        result["attrs"].append(
                            {"name": "Media_Errors", "value": nvme_log["media_errors"]})
                ata_attrs = data.get("ata_smart_attributes")
                table = ata_attrs.get("table") if isinstance(ata_attrs, dict) else None
                for attr in table or []:
                    if not isinstance(attr, dict):
                        continue
                    name = attr.get("name") or ""
                    raw  = attr.get("raw")
                    raw  = raw.get("value", 0) if isinstance(raw, dict) else 0
                    if name == "Power_On_Hours":
                        result["power_on_hours"] = raw
                    if any(k in name for k in ("Error", "Bad_Block", "Wear")):
                        result["attrs"].append({"name": name, "value": raw})
                if result["health"] is not None:
                    return result
            except (json.JSONDecodeError, KeyError):
                plain_cmd = [c for c in cmd if c != "--json"]
                plain_cmd[1] = "-H"
                try:
                    r2 = subprocess.run(
                        plain_cmd, capture_output=True, text=True, timeout=5,
                    )
                    for line in r2.stdout.splitlines():
                        if "SMART overall-health" in line:
                            result["health"] = "PASSED" if "PASSED" in line else "FAILED"
                    if result["health"] is not None:
                        return result
                except Exception as e:
                    _note("StorageThread._smart (plain-text fallback)", e)
            except Exception as e:
                _note("StorageThread._smart", e)
        if kind == "mmc":
            sysfs_health = StorageThread._mmc_health_sysfs(base)
            if sysfs_health is not None:
                result["health"] = sysfs_health
        return result

    @staticmethod
    def _card_type(base):
        try:
            with open(f"/sys/block/{base}/device/type") as f:
                return f.read().strip()
        except Exception as e:
            _note("StorageThread._card_type", e)
            return None

    @staticmethod
    def _dmesg_errors(base):
        """(device_errors, fs_errors) counted from the kernel ring buffer, or
        (None, None) when it couldn't be read at all.

        kernel.dmesg_restrict=1 is the default for unprivileged users on
        Debian/Ubuntu/Pop!_OS, where `dmesg` exits non-zero with an empty
        stdout. Ignoring the exit status made that indistinguishable from a
        clean buffer, so the STORAGE tab reported a confident "0 errors" on
        exactly the machines where it had read nothing — the opposite of what
        that panel exists to tell you. Unknown is now reported as unknown.
        """
        dev_errors = 0
        fs_errors  = 0
        dev_pat = re.escape(base) if base else r"mmcblk|mmc\d|nvme\d"
        try:
            r = subprocess.run(
                ["dmesg"], capture_output=True, text=True, timeout=3,
            )
            if r.returncode != 0:
                return None, None
            for line in r.stdout.splitlines():
                if re.search(dev_pat, line, re.I):
                    if re.search(r"error|EIO|timeout|failed|reset", line, re.I):
                        dev_errors += 1
                elif re.search(r"ext4|xfs|btrfs", line, re.I):
                    if re.search(r"error|corrupt|journal.*abort", line, re.I):
                        fs_errors += 1
        except Exception as e:
            _note("StorageThread._dmesg_errors", e)
        return dev_errors, fs_errors

    def run(self):
        while not self._stop_event.is_set():
            try:
                dev    = sensors.root_device()
                base   = dev["base"]
                kind   = dev["kind"]
                is_mmc = kind == "mmc"
                card_type = self._card_type(base) if is_mmc else None
                smart     = (self._smart(base, kind) if base
                             else {"health": None, "power_on_hours": None, "attrs": []})
                io        = self._io_stats(base)
                dev_err, fs_err = self._dmesg_errors(base)
                # SD/eMMC cards without wear-level registers: derive health from
                # observed errors — but only when the error counts are actually
                # known. With dmesg unreadable both counts are None, which would
                # otherwise be read as "not zero" and flag a perfectly healthy
                # card as WARNING; leaving health None renders an honest N/A.
                if is_mmc and smart["health"] is None and dev_err is not None:
                    smart["health"] = "GOOD" if (dev_err == 0 and fs_err == 0) else "WARNING"
                fs_root  = self._fs_stats("/")
                boot     = sensors.boot_mount()
                fs_boot  = self._fs_stats(boot) if boot else None
                snap = {
                    "device":           f"/dev/{base}" if base else None,
                    "kind":             kind,
                    "card_type":        card_type,
                    "smart_health":     smart["health"],
                    "power_on_hours":   smart["power_on_hours"],
                    "smart_attrs":      smart["attrs"],
                    "temp":             sensors.storage_temp(),
                    "fs_root":          fs_root,
                    "boot_mount":       boot,
                    "fs_boot":          fs_boot,
                    "dev_errors":       dev_err,
                    "fs_errors":        fs_err,
                    "io_reads":         io["reads"]         if io else None,
                    "io_writes":        io["writes"]        if io else None,
                    "io_read_sectors":  io["read_sectors"]  if io else None,
                    "io_write_sectors": io["write_sectors"] if io else None,
                    "bytes_written":    io["write_sectors"] * 512 if io else None,
                }
                with _state_lock:
                    _state["storage"] = snap
                self._check_disk_alert("fs_root", "/", fs_root)
                if boot:
                    self._check_disk_alert(boot, boot, fs_boot)
            except Exception as e:
                _note("StorageThread.run", e)
            self._stop_event.wait(settings.SDCARD_REFRESH)

    def stop(self):
        self._stop_event.set()


# ── BackupStatusThread ────────────────────────────────────────────────────────
class BackupStatusThread(threading.Thread):
    STATUS_FILE = "/var/log/project-backup-status.json"

    def __init__(self):
        super().__init__(daemon=True)
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            try:
                with open(self.STATUS_FILE) as f:
                    data = json.load(f)
                # project-backup writes this file; a stale/half-written or
                # unexpected-schema version (valid JSON, but not an object —
                # e.g. null, a list, a bare number) would otherwise crash
                # _render_backup's dict-only access on the next render.
                if not isinstance(data, dict):
                    data = None
                with _state_lock:
                    _state["backup"] = data
            except FileNotFoundError:
                # Installed but never run yet — the tab says so. Not an error:
                # noting it every 15s kept the header's degraded ⚠ lit.
                with _state_lock:
                    _state["backup"] = None
            except Exception as e:
                _note("BackupStatusThread.run", e)
                with _state_lock:
                    _state["backup"] = None
            self._stop_event.wait(15)

    def stop(self):
        self._stop_event.set()


