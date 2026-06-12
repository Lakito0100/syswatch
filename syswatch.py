#!/usr/bin/env python3
"""syswatch — deep space terminal system monitor"""

import sys
import os
import time
import subprocess
import collections
import signal
import socket
import threading
import curses
import json
import re
import dataclasses
import argparse
from datetime import datetime as _dt


def _bootstrap():
    import importlib.util as ilu
    missing = [p for p in ("psutil", "asciichartpy") if ilu.find_spec(p) is None]
    if missing:
        print(f"Installing: {', '.join(missing)} …")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet"] + missing)
        except subprocess.CalledProcessError:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet",
                 "--break-system-packages"] + missing)

_bootstrap()
import psutil
import asciichartpy


# ── CONFIG ─────────────────────────────────────────────────────────────────────
WATCHED_SERVICES = [
    "ssh", "networking", "cron", "bluetooth", "avahi-daemon", "triggerhappy",
]
SCAN_SUBNET = "192.168"   # fallback only: first two octets swept (.0.1–.1.254)
                          # when the Pi's own /24 cannot be auto-detected

# ── tunables ───────────────────────────────────────────────────────────────────
HISTORY        = 60
REFRESH        = 1.0
TOP_N          = 5
NUM_CORES      = psutil.cpu_count(logical=True) or 4
ARP_REFRESH      = 2.0
WATCHDOG_REFRESH = 10.0
SDCARD_REFRESH   = 60.0
PING_CYCLE       = 420
PING_BATCH     = 10
INTRUDER_TTL   = 600
ALERT_TTL      = 30
PROCESS_START  = time.time()

THRESH = {
    "cpu_pct":  (80, 95),
    "ram_pct":  (75, 90),
    "cpu_temp": (70, 80),
}

TABS = ["1:SYSTEM", "2:NETWORK", "3:LOGS", "4:SERVICES", "5:SD CARD", "6:BACKUP", "7:HISTORY"]

# ── color pair IDs ─────────────────────────────────────────────────────────────
CP_PRIMARY   = 1   # bright cyan-blue — main data color
CP_SECONDARY = 2   # medium grey — secondary labels
CP_ACCENT    = 3   # deep amber — warnings and highlights
CP_DIM       = 4   # very dark grey — inactive/background elements
CP_CRITICAL  = 5   # hard red — critical alerts only
CP_WARN      = 6   # amber-orange — warning state
CP_GOOD      = 7   # cold green — healthy/nominal state
CP_HDR       = 8   # black text on cyan-blue — header/footer bars
CP_MUTED     = 9   # dim grey — sparklines, inactive separators
CP_HILIGHT   = 10  # bright ice blue — active tab, selected items

SPARK_CHARS = " ▁▂▃▄▅▆▇█"


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    try:
        if curses.COLORS >= 256:
            curses.init_pair(CP_PRIMARY,   39,  -1)
            curses.init_pair(CP_SECONDARY, 244, -1)
            curses.init_pair(CP_ACCENT,    202, -1)
            curses.init_pair(CP_DIM,       237, -1)
            curses.init_pair(CP_CRITICAL,  196, -1)
            curses.init_pair(CP_WARN,      214, -1)
            curses.init_pair(CP_GOOD,      48,  -1)
            curses.init_pair(CP_HDR,       232, 39)
            curses.init_pair(CP_MUTED,     240, -1)
            curses.init_pair(CP_HILIGHT,   51,  -1)
        else:
            raise ValueError("8-color fallback")
    except Exception:
        curses.init_pair(CP_PRIMARY,   curses.COLOR_CYAN,    -1)
        curses.init_pair(CP_SECONDARY, curses.COLOR_WHITE,   -1)
        curses.init_pair(CP_ACCENT,    curses.COLOR_YELLOW,  -1)
        curses.init_pair(CP_DIM,       curses.COLOR_WHITE,   -1)
        curses.init_pair(CP_CRITICAL,  curses.COLOR_RED,     -1)
        curses.init_pair(CP_WARN,      curses.COLOR_YELLOW,  -1)
        curses.init_pair(CP_GOOD,      curses.COLOR_GREEN,   -1)
        curses.init_pair(CP_HDR,       curses.COLOR_BLACK,   curses.COLOR_CYAN)
        curses.init_pair(CP_MUTED,     curses.COLOR_WHITE,   -1)
        curses.init_pair(CP_HILIGHT,   curses.COLOR_CYAN,    -1)


def cp(pair_id, bold=False):
    attr = curses.color_pair(pair_id)
    return attr | curses.A_BOLD if bold else attr


def threshold_cp(val, key):
    t = THRESH.get(key)
    if t is None or val is None:
        return cp(CP_PRIMARY)
    if val >= t[1]: return cp(CP_CRITICAL, bold=True)
    if val >= t[0]: return cp(CP_WARN)
    return cp(CP_GOOD)


def fmtb(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


def fmtup(s):
    d = int(s // 86400); s %= 86400
    h = int(s // 3600);  s %= 3600
    m = int(s // 60);    s = int(s % 60)
    return (f"{d}d " if d else "") + f"{h:02}:{m:02}:{s:02}"


def sparkline(history, width):
    data = list(history)
    if not data or width <= 0:
        return " " * width
    hi = max(data) or 1
    data = data[-width:]
    chars = "".join(SPARK_CHARS[min(8, int(v / hi * 8))] for v in data)
    return chars.ljust(width)


# ── Metrics ────────────────────────────────────────────────────────────────────
class Metrics:
    def __init__(self):
        self.hist = {
            k: collections.deque(maxlen=HISTORY)
            for k in ("cpu", "ram", "cpu_temp", "gpu_temp",
                      "net_rx", "net_tx", "cpu_freq",
                      "disk_read", "disk_write")
        }
        self.core_hist = [collections.deque(maxlen=HISTORY) for _ in range(NUM_CORES)]
        self._net0     = None;  self._net_t  = None
        self._disk0    = None;  self._disk_t = None
        self.pi_model  = self._pi_model()
        psutil.cpu_percent(percpu=True)
        for p in psutil.process_iter(["cpu_percent"]):
            try: p.cpu_percent()
            except Exception: pass

    @staticmethod
    def _vcg(arg):
        try:
            r = subprocess.run(
                ["vcgencmd"] + arg.split(),
                capture_output=True, text=True, timeout=0.5,
            )
            return r.stdout.strip() if r.returncode == 0 else None
        except Exception:
            return None

    @staticmethod
    def _pi_model():
        try:
            with open("/proc/device-tree/model") as f:
                return f.read().strip("\x00").strip()
        except Exception:
            pass
        try:
            for line in open("/proc/cpuinfo"):
                if line.startswith("Model"):
                    return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return "Raspberry Pi"

    def _soc_temp(self):
        raw = self._vcg("measure_temp")
        if raw and "temp=" in raw:
            try: return float(raw.split("=")[1].strip("'C "))
            except Exception: pass
        try:
            with open("/sys/class/thermal/thermal_zone0/temp") as f:
                return round(int(f.read().strip()) / 1000, 1)
        except Exception:
            return None

    def _gpu_temp(self):
        raw = self._vcg("measure_temp pmic")
        if raw and "temp=" in raw:
            try: return float(raw.split("=")[1].strip("'C "))
            except Exception: pass
        return self._soc_temp()

    def _voltage(self):
        raw = self._vcg("measure_volts core")
        if raw and raw.startswith("volt="):
            try: return float(raw[5:].rstrip("V"))
            except Exception: pass
        return None

    def _cpu_freq(self):
        raw = self._vcg("measure_clock arm")
        if raw and "=" in raw:
            try: return int(raw.split("=")[-1]) // 1_000_000
            except Exception: pass
        try:
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq") as f:
                return int(f.read().strip()) // 1000
        except Exception:
            return None

    def _throttled(self):
        raw = self._vcg("get_throttled")
        if not raw or "throttled=" not in raw:
            return None
        try:
            val = int(raw.split("=")[-1], 16)
        except Exception:
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
        except Exception:
            pass
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
        s = {}
        cores = psutil.cpu_percent(percpu=True)
        s["cores"] = cores
        for i, p in enumerate(cores[:NUM_CORES]):
            self.core_hist[i].append(p)
        avg = sum(cores) / len(cores)
        self.hist["cpu"].append(avg); s["cpu_avg"] = avg

        mem  = psutil.virtual_memory()
        swap = psutil.swap_memory()
        self.hist["ram"].append(mem.percent)
        s.update(
            ram_used=mem.used, ram_total=mem.total, ram_pct=mem.percent,
            swap_used=swap.used, swap_total=swap.total, swap_pct=swap.percent,
        )

        ct   = self._soc_temp()
        gt   = self._gpu_temp()
        freq = self._cpu_freq()
        s["cpu_temp"]  = ct;  s["gpu_temp"] = gt
        s["voltage"]   = self._voltage()
        s["cpu_freq"]  = freq
        s["throttled"] = self._throttled()
        if ct   is not None: self.hist["cpu_temp"].append(ct)
        if gt   is not None: self.hist["gpu_temp"].append(gt)
        if freq is not None: self.hist["cpu_freq"].append(freq)

        disk = psutil.disk_usage("/")
        s.update(disk_used=disk.used, disk_total=disk.total, disk_pct=disk.percent)
        dr, dw = self._disk_io_rates()
        s["disk_read"] = dr; s["disk_write"] = dw
        self.hist["disk_read"].append(dr); self.hist["disk_write"].append(dw)

        net = psutil.net_io_counters(); now = time.monotonic()
        if net is not None and self._net0 is not None:
            dt = (now - self._net_t) or 1
            rx = max(0.0, (net.bytes_recv - self._net0.bytes_recv) / dt / 1024)
            tx = max(0.0, (net.bytes_sent - self._net0.bytes_sent) / dt / 1024)
            self.hist["net_rx"].append(rx); self.hist["net_tx"].append(tx)
        else:
            self.hist["net_rx"].append(0.0); self.hist["net_tx"].append(0.0)
        if net is not None:
            self._net0 = net; self._net_t = now
        s["net_rx"] = self.hist["net_rx"][-1]
        s["net_tx"] = self.hist["net_tx"][-1]

        s["load_avg"]  = os.getloadavg()
        s["wifi"]      = self._wifi_signal()
        s["uptime"]    = time.time() - psutil.boot_time()
        s["top_procs"] = self._top_procs()
        return s


# ── shared state ───────────────────────────────────────────────────────────────
_state = {
    "system":      None,
    "system_hist": None,
    "pi_model":    "Raspberry Pi",
    "devices":     {},
    "logs":        collections.deque(maxlen=200),
    "log_errs":    collections.deque(maxlen=3600),
    "services":    [],
    "sdcard":      None,
    "backup":      None,
}
_state_lock = threading.Lock()
_alerts     = collections.deque(maxlen=5)


def push_alert(msg: str):
    _alerts.append((time.monotonic(), f"{_dt.now().strftime('%H:%M:%S')} {msg}"))


def get_state():
    with _state_lock:
        return dict(_state)


# ── device helpers ─────────────────────────────────────────────────────────────
@dataclasses.dataclass
class DeviceInfo:
    ip:         str
    mac:        str
    hostname:   str
    first_seen: float
    last_seen:  float
    status:     str


def _resolve_hostname(ip: str) -> str:
    try:
        name = socket.getnameinfo((ip, 0), 0)[0]
        return name if name != ip else ip
    except Exception:
        return ip


def _device_status(dev: DeviceInfo) -> str:
    if dev.status == "INTRUDER":
        return "Idle" if time.time() - dev.last_seen > INTRUDER_TTL else "INTRUDER"
    age = time.time() - dev.last_seen
    if age < 10:   return "Active"
    if age < 300:  return "Recent"
    return "Idle"


# ── SystemThread ───────────────────────────────────────────────────────────────
class SystemThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._metrics           = Metrics()
        self._stop              = threading.Event()
        self._temp_alert_level  = 0  # 0=ok, 1=warning, 2=critical

    def _write_temp_alert(self, msg):
        try:
            log_dir = os.path.expanduser("~/.local/share/syswatch")
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, "temp_alerts.log")
            ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(log_path, "a") as f:
                f.write(f"{ts} {msg}\n")
        except Exception:
            pass

    def _check_temp_alert(self, snap):
        ct = snap.get("cpu_temp")
        if ct is None:
            return
        warn, crit = THRESH["cpu_temp"]
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
        while not self._stop.is_set():
            try:
                snap = self._metrics.collect()
                self._check_temp_alert(snap)
                with _state_lock:
                    _state["system"]      = snap
                    _state["system_hist"] = self._metrics.hist
                    _state["pi_model"]    = self._metrics.pi_model
            except Exception:
                pass
            self._stop.wait(REFRESH)

    def stop(self):
        self._stop.set()


# ── ARPPassiveThread ───────────────────────────────────────────────────────────
class ARPPassiveThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop = threading.Event()

    def _parse_arp_table(self):
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
                    result[mac] = {"ip": ip, "iface": iface}
        except OSError:
            pass
        return result

    def run(self):
        while not self._stop.is_set():
            try:
                now    = time.time()
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
                with _state_lock:
                    devices = _state["devices"]
                    for mac, info in parsed.items():
                        if mac not in devices:
                            # Still new after the gap — insert it.
                            is_intruder = (now - PROCESS_START) > 30
                            status      = "INTRUDER" if is_intruder else "Active"
                            devices[mac] = DeviceInfo(
                                ip=info["ip"], mac=mac,
                                hostname=hostnames.get(mac, info["ip"]),
                                first_seen=now, last_seen=now, status=status,
                            )
                            if is_intruder:
                                push_alert(f"INTRUDER: {mac} at {info['ip']}")
                        else:
                            # Either pre-existing, or it raced in between the two
                            # lock acquisitions — just update it.
                            dev           = devices[mac]
                            dev.ip        = info["ip"]
                            dev.last_seen = now
                            dev.status    = _device_status(dev)
            except Exception:
                pass
            self._stop.wait(ARP_REFRESH)

    def stop(self):
        self._stop.set()


# ── PingSweepThread ────────────────────────────────────────────────────────────
class PingSweepThread(threading.Thread):
    def __init__(self, enabled=True):
        super().__init__(daemon=True)
        self._stop    = threading.Event()
        self._enabled = enabled
        self._prefix  = None  # first three octets of the /24 to sweep

    @staticmethod
    def _detect_prefix():
        # Derive the local /24 from the Pi's own primary IPv4 address. The UDP
        # socket sends nothing; connecting just makes the kernel choose the
        # outbound interface so getsockname() reveals our address.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            finally:
                s.close()
            octets = ip.split(".")
            if len(octets) == 4:
                return ".".join(octets[:3])
        except Exception:
            pass
        return None

    def _all_ips(self):
        # Sweep the auto-detected /24 (e.g. 192.168.178.1–254). If detection
        # failed, fall back to the SCAN_SUBNET constant's two /24s.
        if self._prefix:
            return [f"{self._prefix}.{d}" for d in range(1, 255)]
        parts = SCAN_SUBNET.split(".")
        a, b  = parts[0], parts[1]
        ips   = []
        for c in range(0, 2):
            for d in range(1, 255):
                ips.append(f"{a}.{b}.{c}.{d}")
        return ips

    def _ping_batch(self, ips):
        procs = {}
        for ip in ips:
            try:
                p = subprocess.Popen(
                    ["nice", "-n", "19", "ping", "-c1", "-W1", "-q", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                procs[ip] = p
            except FileNotFoundError:
                self._enabled = False
                return []
            except Exception:
                pass
        alive = []
        for ip, p in procs.items():
            try:
                p.wait(timeout=2)
                if p.returncode == 0:
                    alive.append(ip)
            except subprocess.TimeoutExpired:
                p.kill()
        return alive

    def run(self):
        self._prefix = self._detect_prefix()
        while not self._stop.is_set():
            if not self._enabled:
                self._stop.wait(PING_CYCLE)
                continue
            try:
                ips   = self._all_ips()
                delay = PING_CYCLE / max(1, len(ips) / PING_BATCH)
                for i in range(0, len(ips), PING_BATCH):
                    if self._stop.is_set():
                        return
                    alive = self._ping_batch(ips[i:i + PING_BATCH])
                    now   = time.time()
                    with _state_lock:
                        for ip in alive:
                            for dev in _state["devices"].values():
                                if dev.ip == ip:
                                    dev.last_seen = now
                                    dev.status    = _device_status(dev)
                    self._stop.wait(delay)
            except Exception:
                self._stop.wait(PING_CYCLE)

    def stop(self):
        self._stop.set()


# ── LogThread ──────────────────────────────────────────────────────────────────
class LogThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop = threading.Event()
        self._proc = None

    def _launch(self):
        try:
            self._proc = subprocess.Popen(
                ["journalctl", "-f", "-n", "100", "--output=json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            self._proc = None

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
        except Exception:
            return None

    def _reap(self):
        # Terminate and reap the journalctl child so it doesn't linger as a
        # zombie when its stream ends or errors out. Always clears self._proc.
        if self._proc is not None:
            try:
                if self._proc.poll() is None:
                    self._proc.terminate()
                self._proc.wait(timeout=1)
            except Exception:
                pass
        self._proc = None

    def run(self):
        self._launch()
        while not self._stop.is_set():
            if self._proc is None:
                self._stop.wait(5.0)
                self._launch()
                continue
            try:
                line = self._proc.stdout.readline()
            except Exception:
                self._reap()
                continue
            if line == b"":
                self._reap()
                self._stop.wait(5.0)
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
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass


# ── ServiceWatchdogThread ──────────────────────────────────────────────────────
class ServiceWatchdogThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop        = threading.Event()
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
        except FileNotFoundError:
            self._available = False
            return None
        except Exception:
            return {"unit": unit, "ActiveState": "unknown"}

    def run(self):
        while not self._stop.is_set():
            if not self._available:
                with _state_lock:
                    _state["services"] = None
                self._stop.wait(WATCHDOG_REFRESH)
                continue
            try:
                results = []
                for unit in WATCHED_SERVICES:
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
            except Exception:
                pass
            self._stop.wait(WATCHDOG_REFRESH)

    def stop(self):
        self._stop.set()


# ── SDCardThread ───────────────────────────────────────────────────────────────
class SDCardThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop = threading.Event()

    @staticmethod
    def _soc_temp():
        try:
            with open("/sys/class/thermal/thermal_zone0/temp") as f:
                return round(int(f.read().strip()) / 1000, 1)
        except Exception:
            return None

    @staticmethod
    def _fs_stats(path):
        try:
            st    = os.statvfs(path)
            total = st.f_blocks * st.f_frsize
            free  = st.f_bavail * st.f_frsize
            used  = total - free
            pct   = used / total * 100 if total else 0.0
            return {"total": total, "used": used, "free": free, "pct": pct}
        except Exception:
            return None

    @staticmethod
    def _io_stats():
        try:
            with open("/sys/block/mmcblk0/stat") as f:
                fields = f.read().split()
            return {
                "reads":          int(fields[0]),
                "read_sectors":   int(fields[2]),
                "writes":         int(fields[4]),
                "write_sectors":  int(fields[6]),
            }
        except Exception:
            return None

    @staticmethod
    def _mmc_health_sysfs():
        """Read eMMC health registers from sysfs. Returns health string or None."""
        base = "/sys/block/mmcblk0/device"
        try:
            with open(f"{base}/pre_eol_info") as f:
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
            with open(f"{base}/life_time") as f:
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
    def _smart():
        result = {"health": None, "power_on_hours": None, "attrs": []}
        smartctl_cmds = [
            ["smartctl", "-a", "/dev/mmcblk0", "--json"],
            ["smartctl", "-a", "/dev/mmcblk0", "--device=mmc", "--json"],
        ]
        for cmd in smartctl_cmds:
            try:
                r    = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                data = json.loads(r.stdout)
                passed = data.get("smart_status", {}).get("passed")
                if passed is True:
                    result["health"] = "PASSED"
                elif passed is False:
                    result["health"] = "FAILED"
                for attr in data.get("ata_smart_attributes", {}).get("table", []):
                    name = attr.get("name", "")
                    raw  = attr.get("raw", {}).get("value", 0)
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
                except Exception:
                    pass
            except Exception:
                pass
        sysfs_health = SDCardThread._mmc_health_sysfs()
        if sysfs_health is not None:
            result["health"] = sysfs_health
        return result

    @staticmethod
    def _card_type():
        try:
            with open("/sys/block/mmcblk0/device/type") as f:
                return f.read().strip()
        except Exception:
            return None

    @staticmethod
    def _dmesg_errors():
        mmc_errors = 0
        fs_errors  = 0
        try:
            r = subprocess.run(
                ["dmesg"], capture_output=True, text=True, timeout=3,
            )
            for line in r.stdout.splitlines():
                if re.search(r"mmcblk|mmc\d", line, re.I):
                    if re.search(r"error|EIO|timeout|failed|reset", line, re.I):
                        mmc_errors += 1
                elif re.search(r"ext4", line, re.I):
                    if re.search(r"error|corrupt|journal.*abort", line, re.I):
                        fs_errors += 1
        except Exception:
            pass
        return mmc_errors, fs_errors

    def run(self):
        while not self._stop.is_set():
            try:
                has_mmcblk = os.path.exists("/dev/mmcblk0")
                card_type  = self._card_type() if has_mmcblk else None
                smart      = (self._smart() if has_mmcblk
                              else {"health": None, "power_on_hours": None, "attrs": []})
                io         = self._io_stats()
                mmc_err, fs_err = self._dmesg_errors()
                # SD cards expose no wear-level registers; derive health from observed errors
                if has_mmcblk and smart["health"] is None:
                    smart["health"] = "GOOD" if (mmc_err == 0 and fs_err == 0) else "WARNING"
                snap = {
                    "has_mmcblk":       has_mmcblk,
                    "card_type":        card_type,
                    "smart_health":     smart["health"],
                    "power_on_hours":   smart["power_on_hours"],
                    "smart_attrs":      smart["attrs"],
                    "temp":             self._soc_temp(),
                    "fs_root":          self._fs_stats("/"),
                    "fs_boot":          self._fs_stats("/boot"),
                    "mmc_errors":       mmc_err,
                    "fs_errors":        fs_err,
                    "io_reads":         io["reads"]         if io else None,
                    "io_writes":        io["writes"]        if io else None,
                    "io_read_sectors":  io["read_sectors"]  if io else None,
                    "io_write_sectors": io["write_sectors"] if io else None,
                    "bytes_written":    io["write_sectors"] * 512 if io else None,
                }
                with _state_lock:
                    _state["sdcard"] = snap
            except Exception:
                pass
            self._stop.wait(SDCARD_REFRESH)

    def stop(self):
        self._stop.set()


# ── BackupStatusThread ────────────────────────────────────────────────────────
class BackupStatusThread(threading.Thread):
    STATUS_FILE = "/var/log/project-backup-status.json"

    def __init__(self):
        super().__init__(daemon=True)
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                with open(self.STATUS_FILE) as f:
                    data = json.load(f)
                with _state_lock:
                    _state["backup"] = data
            except Exception:
                with _state_lock:
                    _state["backup"] = None
            self._stop.wait(15)

    def stop(self):
        self._stop.set()


# ── FullRenderer ───────────────────────────────────────────────────────────────
class FullRenderer:
    MIN_W = 40
    MIN_H = 12

    def __init__(self, win):
        self.win = win
        curses.curs_set(0)
        win.timeout(100)
        win.keypad(True)
        self._hist_cache = None  # (loaded_at: float, rows: list)

    # ── primitives ────────────────────────────────────────────────────────────

    def _add(self, y, x, text, attr=0):
        H, W = self.win.getmaxyx()
        if y < 0 or y >= H or x < 0 or x >= W:
            return
        text = str(text)[:max(0, W - x)]
        if not text:
            return
        try:
            self.win.addstr(y, x, text, attr)
        except curses.error:
            pass

    def _hline(self, y, x, char, n, attr=0):
        H, W = self.win.getmaxyx()
        n = min(n, W - x)
        if n <= 0 or y < 0 or y >= H:
            return
        try:
            self.win.addstr(y, x, char * n, attr)
        except curses.error:
            pass

    def _bar(self, y, x, pct, width, key=None):
        if width < 3:
            return
        inner  = width - 2
        filled = max(0, min(inner, int(pct / 100 * inner)))
        c      = threshold_cp(pct, key) if key else cp(CP_PRIMARY)
        self._add(y, x,                "[",                     cp(CP_SECONDARY))
        self._add(y, x + 1,            "▰" * filled,            c)
        self._add(y, x + 1 + filled,   "▱" * (inner - filled),  cp(CP_DIM))
        self._add(y, x + 1 + inner,    "]",                     cp(CP_SECONDARY))

    def _label(self, y, x, text, width=None):
        H, W = self.win.getmaxyx()
        w = width if width is not None else (W - x)
        self._hline(y, x, "─", w, cp(CP_DIM))
        label = f"┤ {text} ├"
        lx = x + 2
        if len(label) + 2 <= w:
            self._add(y, lx, label, cp(CP_PRIMARY, bold=True))

    def _spark_attr(self, history, key=None):
        data = list(history)
        if not data:
            return cp(CP_MUTED)
        latest = data[-1]
        if key:
            t = THRESH.get(key)
            if t:
                if latest >= t[1]: return cp(CP_CRITICAL, bold=True)
                if latest >= t[0]: return cp(CP_WARN)
        return cp(CP_GOOD)

    # ── structural elements ───────────────────────────────────────────────────

    def _render_header(self):
        H, W = self.win.getmaxyx()
        host  = socket.gethostname()
        now   = _dt.now()
        ts    = now.strftime("%H:%M:%S")
        date  = now.strftime("%Y-%m-%d")
        left  = "▸ SYSWATCH"
        right = f"{ts}  {date} "
        self._hline(0, 0, " ", W, cp(CP_HDR))
        self._add(0, 1, left, cp(CP_HDR, bold=True))
        cx = max(len(left) + 2, (W - len(host)) // 2)
        self._add(0, cx, host, cp(CP_HDR))
        rpos = max(cx + len(host) + 1, W - len(right))
        self._add(0, rpos, right, cp(CP_HDR))

    def _render_tab_bar(self, active_tab):
        H, W = self.win.getmaxyx()
        self._hline(1, 0, " ", W, cp(CP_DIM))
        x = 1
        for i, label in enumerate(TABS):
            padded = f"[ {label} ]"
            if x + len(padded) >= W:
                break
            if (i + 1) == active_tab:
                attr = cp(CP_HILIGHT, bold=True) | curses.A_UNDERLINE
            else:
                attr = cp(CP_SECONDARY)
            self._add(1, x, padded, attr)
            x += len(padded) + 1

    def _render_footer(self, state):
        H, W = self.win.getmaxyx()
        self._hline(H - 1, 0, " ", W, cp(CP_HDR))
        snap = (state or {}).get("system")
        left_end = 0
        if snap:
            la   = snap.get("load_avg", (0, 0, 0))
            up   = fmtup(snap.get("uptime", 0))
            text = f" UP {up}  LOAD {la[0]:.2f}/{la[1]:.2f}/{la[2]:.2f}"
            left_end = min(len(text), W * 60 // 100)
            self._add(H - 1, 0, text[:left_end], cp(CP_HDR))
        try:
            alert_str = None
            if _alerts:
                ts_pushed, candidate = _alerts[-1]
                if time.monotonic() - ts_pushed <= ALERT_TTL:
                    alert_str = candidate
            if alert_str is not None:
                alert_text = f"  \u26a0 {alert_str}"
                start = W * 60 // 100
                self._add(H - 1, start, alert_text[:W - start - 1],
                          cp(CP_CRITICAL, bold=True))
            else:
                mdl   = ((state or {}).get("pi_model") or "Raspberry Pi")[:32]
                right = f"  {mdl} "
                rpos  = max(left_end + 1, W - len(right))
                self._add(H - 1, rpos, right[:W - rpos], cp(CP_HDR))
        except (IndexError, Exception):
            pass

    # ── Tab 1: SYSTEM ─────────────────────────────────────────────────────────

    def _draw_cpu(self, y, x, h, w, snap, hist):
        self._label(y, x, "CPU", w)
        if not snap or h < 2:
            return
        cores = snap.get("cores", [])
        n     = min(len(cores), NUM_CORES, h - 3)
        lbl_w = 4
        pct_w = 7
        bw    = max(4, w - lbl_w - pct_w)
        for i in range(n):
            row = y + 1 + i
            if row >= y + h:
                break
            p = cores[i] if i < len(cores) else 0.0
            c = threshold_cp(p, "cpu_pct")
            self._add(row, x,               f"C{i:<2} ", cp(CP_SECONDARY))
            self._bar(row, x + lbl_w,       p, bw, "cpu_pct")
            self._add(row, x + lbl_w + bw,  f" {p:5.1f}%", c)
        avg_row = y + 1 + n
        if avg_row < y + h:
            avg = snap.get("cpu_avg", 0.0)
            c   = threshold_cp(avg, "cpu_pct")
            self._add(avg_row, x,              "AVG ", cp(CP_SECONDARY, bold=True))
            self._bar(avg_row, x + lbl_w,      avg, bw, "cpu_pct")
            self._add(avg_row, x + lbl_w + bw, f" {avg:5.1f}%", c)
        spark_row = y + 2 + n
        cpu_hist  = (hist or {}).get("cpu", [])
        if spark_row < y + h and len(cpu_hist) >= 2:
            spark_color = self._spark_attr(cpu_hist, "cpu_pct")
            self._add(spark_row, x, "    " + sparkline(cpu_hist, bw), spark_color)

    def _draw_memory(self, y, x, h, w, snap, hist):
        self._label(y, x, "MEMORY", w)
        if not snap or h < 2:
            return
        row = y + 1
        for lbl, uk, tk, pk in [
            ("RAM ", "ram_used",  "ram_total",  "ram_pct"),
            ("SWAP", "swap_used", "swap_total", "swap_pct"),
        ]:
            if row + 1 >= y + h:
                break
            pct  = snap.get(pk, 0)
            used = snap.get(uk, 0)
            tot  = snap.get(tk, 0)
            c    = threshold_cp(pct, "ram_pct")
            info = f"{fmtb(used):>8}/{fmtb(tot):<8}"
            self._add(row, x,         lbl,             cp(CP_SECONDARY, bold=True))
            self._add(row, x + 5,     info,            cp(CP_PRIMARY))
            self._add(row, x + w - 7, f"{pct:5.1f}%", c)
            row += 1
            self._bar(row, x, pct, w, "ram_pct")
            row += 1
        ram_hist = (hist or {}).get("ram", [])
        if row < y + h and len(ram_hist) >= 2:
            spark_color = self._spark_attr(ram_hist, "ram_pct")
            self._add(row, x, sparkline(ram_hist, w), spark_color)

    def _draw_temp(self, y, x, h, w, snap):
        self._label(y, x, "TEMP & THROTTLE", w)
        if not snap or h < 2:
            return
        bw  = max(4, w - 20)
        row = y + 1
        for label, key in (("CPU TEMP", "cpu_temp"), ("GPU TEMP", "gpu_temp")):
            if row >= y + h:
                break
            v = snap.get(key)
            c = threshold_cp(v, "cpu_temp")
            self._add(row, x, f"{label:<9}", cp(CP_SECONDARY))
            if v is not None:
                self._bar(row, x + 9, min(100.0, v / 90.0 * 100), bw)
                self._add(row, x + 9 + bw, f" {v:.1f}°C", c)
            else:
                self._add(row, x + 9, "▱" * bw + " N/A", cp(CP_DIM))
            row += 1
        if row < y + h:
            freq  = snap.get("cpu_freq")
            volt  = snap.get("voltage")
            f_str = f"{freq} MHz" if freq else "N/A    "
            v_str = f"  {volt:.4f}V" if volt else ""
            self._add(row, x, f"FREQ {f_str}{v_str}", cp(CP_PRIMARY))
            row += 1
        if row < y + h:
            th    = snap.get("throttled") or {}
            flags = [
                ("UV",    th.get("uv_now",    False), th.get("uv_ever",    False)),
                ("FREQ",  th.get("freq_now",  False), th.get("freq_ever",  False)),
                ("THROT", th.get("throt_now", False), th.get("throt_ever", False)),
                ("TEMP",  th.get("temp_now",  False), th.get("temp_ever",  False)),
            ]
            self._add(row, x, "THROT: ", cp(CP_SECONDARY))
            col = x + 7
            for lbl, now_f, ever in flags:
                if now_f:
                    dot, c = "●", cp(CP_CRITICAL, bold=True)
                elif ever:
                    dot, c = "●", cp(CP_WARN)
                else:
                    dot, c = "○", cp(CP_DIM)
                self._add(row, col, f"{dot}{lbl} ", c)
                col += len(lbl) + 2

    def _draw_network_sys(self, y, x, h, w, snap, hist):
        self._label(y, x, "NETWORK", w)
        if not snap or h < 2:
            return
        row = y + 1
        rx  = snap.get("net_rx", 0)
        tx  = snap.get("net_tx", 0)
        if row < y + h:
            self._add(row, x, f"↓ RX  {rx:8.1f} KB/s", cp(CP_PRIMARY, bold=True))
            row += 1
        if row < y + h:
            self._add(row, x, f"↑ TX  {tx:8.1f} KB/s", cp(CP_ACCENT))
            row += 1
        wifi = snap.get("wifi")
        if wifi and row < y + h:
            sig   = wifi["signal"]
            wc    = CP_GOOD if sig > -60 else (CP_WARN if sig > -75 else CP_CRITICAL)
            wpct  = max(0.0, min(100.0, (sig + 90) / 60 * 100))
            iface = wifi.get("iface", "WiFi").upper()[:8]
            bw    = max(4, w - 15)
            self._add(row, x, f"{iface} {sig:.0f}dBm ", cp(wc))
            self._bar(row, x + 14, wpct, bw)
            row += 1
        rx_hist = (hist or {}).get("net_rx", [])
        tx_hist = (hist or {}).get("net_tx", [])
        if row < y + h and len(rx_hist) >= 2:
            mid      = w // 2
            rx_color = self._spark_attr(rx_hist)
            tx_color = self._spark_attr(tx_hist)
            self._add(row, x,       sparkline(rx_hist, mid),     rx_color)
            self._add(row, x + mid, sparkline(tx_hist, w - mid), tx_color)

    def _draw_disk(self, y, x, h, w, snap, hist):
        self._label(y, x, "DISK /", w)
        if not snap or h < 2:
            return
        row  = y + 1
        pct  = snap.get("disk_pct", 0)
        used = snap.get("disk_used", 0)
        tot  = snap.get("disk_total", 0)
        c    = threshold_cp(pct, "ram_pct")
        dr   = snap.get("disk_read", 0)
        dw_  = snap.get("disk_write", 0)
        if row < y + h:
            info = f"{fmtb(used):>8}/{fmtb(tot):<8}"
            self._add(row, x,         info,          cp(CP_PRIMARY))
            self._add(row, x + w - 7, f"{pct:5.1f}%", c)
            row += 1
        if row < y + h:
            self._bar(row, x, pct, w, "ram_pct")
            row += 1
        if row < y + h:
            self._add(row, x,        f"↓ {dr:6.1f} KB/s",  cp(CP_PRIMARY))
            self._add(row, x + w//2, f"↑ {dw_:6.1f} KB/s", cp(CP_SECONDARY))
            row += 1
        dr_hist = (hist or {}).get("disk_read",  [])
        dw_hist = (hist or {}).get("disk_write", [])
        if row < y + h and len(dr_hist) >= 2:
            mid      = w // 2
            dr_color = self._spark_attr(dr_hist)
            dw_color = self._spark_attr(dw_hist)
            self._add(row, x,       sparkline(dr_hist, mid),     dr_color)
            self._add(row, x + mid, sparkline(dw_hist, w - mid), dw_color)

    def _draw_procs(self, y, x, h, w, snap):
        self._label(y, x, "PROCESSES", w)
        if not snap or h < 2:
            return
        procs = snap.get("top_procs", [])
        row   = y + 1
        if row < y + h:
            hdr = f"{'PID':>6}  {'NAME':<14}  {'CPU%':>5}  {'MEM%':>5}  STAT"
            self._add(row, x, hdr[:w], cp(CP_ACCENT, bold=True))
            row += 1
        show_n = max(TOP_N, h - 2)
        for p in procs[:show_n]:
            if row >= y + h:
                break
            cpu  = p.get("cpu_percent") or 0.0
            mem  = p.get("memory_percent") or 0.0
            name = (p.get("name") or "")[:14]
            stat = (p.get("status") or "")[:4].upper()
            c    = threshold_cp(cpu, "cpu_pct")
            line = f"{p['pid']:>6}  {name:<14}  {cpu:5.1f}  {mem:5.1f}  {stat}"
            self._add(row, x, line[:w], c)
            row += 1

    def _render_system(self, state):
        H, W = self.win.getmaxyx()
        snap = state.get("system")
        hist = state.get("system_hist")
        cy   = 2
        ch   = H - 3
        if not snap:
            msg = "COLLECTING DATA…"
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2),
                      msg, cp(CP_PRIMARY, bold=True))
            return
        div_x = W * 52 // 100
        lw    = div_x - 1
        rx    = div_x + 1
        rw    = W - rx
        for row in range(cy, cy + ch):
            try:
                self.win.addch(row, div_x, curses.ACS_VLINE, cp(CP_DIM))
            except curses.error:
                pass
        cpu_h = min(NUM_CORES + 4, ch * 55 // 100)
        mem_h = ch - cpu_h
        cpu_y = cy
        mem_y = cy + cpu_h
        temp_h = min(6, ch * 27 // 100)
        net_h  = min(5, ch * 23 // 100)
        disk_h = min(5, ch * 23 // 100)
        proc_h = ch - temp_h - net_h - disk_h
        temp_y = cy
        net_y  = cy + temp_h
        disk_y = net_y + net_h
        proc_y = disk_y + disk_h
        self._draw_cpu(         cpu_y,  0,  cpu_h,  lw, snap, hist)
        self._draw_memory(      mem_y,  0,  mem_h,  lw, snap, hist)
        self._draw_temp(        temp_y, rx, temp_h, rw, snap)
        self._draw_network_sys( net_y,  rx, net_h,  rw, snap, hist)
        self._draw_disk(        disk_y, rx, disk_h, rw, snap, hist)
        self._draw_procs(       proc_y, rx, proc_h, rw, snap)

    # ── Tab 2: NETWORK SCANNER ────────────────────────────────────────────────

    def _render_network(self, state):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3
        self._label(cy, 0, "NETWORK SCANNER")
        devices = state.get("devices") or {}
        if not devices:
            msg = "SCANNING…  (ARP TABLE EMPTY OR UNAVAILABLE)"
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_MUTED))
            return
        sorted_devs = sorted(devices.values(), key=lambda d: d.last_seen, reverse=True)
        count_str   = f"  {len(sorted_devs)} device(s)"
        self._add(cy, max(0, W - len(count_str) - 1), count_str, cp(CP_SECONDARY))
        hdr_row = cy + 1
        self._add(hdr_row, 0,
                  f"{'IP':<15}  {'MAC':<17}  {'HOSTNAME':<20}  {'LAST SEEN':<12}  STATUS",
                  cp(CP_PRIMARY, bold=True))
        self._hline(hdr_row + 1, 0, "─", W, cp(CP_DIM))
        row = hdr_row + 2
        now = time.time()
        for dev in sorted_devs:
            if row >= cy + ch:
                break
            status = dev.status
            if status == "INTRUDER":
                c = cp(CP_CRITICAL, bold=True) | curses.A_BLINK
            elif status == "Active":
                c = cp(CP_GOOD)
            elif status == "Recent":
                c = cp(CP_PRIMARY)
            else:
                c = cp(CP_DIM)
            age = now - dev.last_seen
            if age < 60:
                age_str = f"{int(age)}s ago"
            elif age < 3600:
                age_str = f"{int(age // 60)}m ago"
            else:
                age_str = f"{int(age // 3600)}h ago"
            hn   = (dev.hostname if dev.hostname != dev.ip else "-")[:20]
            line = (f"{dev.ip:<15}  {dev.mac:<17}  {hn:<20}  "
                    f"{age_str:<12}  {status}")
            self._add(row, 0, line[:W], c)
            row += 1

    # ── Tab 3: LOGS ───────────────────────────────────────────────────────────

    @staticmethod
    def _prio_attr(priority):
        if priority <= 2:   return cp(CP_CRITICAL, bold=True)
        if priority == 3:   return cp(CP_CRITICAL)
        if priority == 4:   return cp(CP_WARN)
        if priority <= 6:   return cp(CP_PRIMARY)
        return cp(CP_MUTED)

    @staticmethod
    def _error_sparkline(log_errs, width=30):
        now     = time.time()
        buckets = [0] * 60
        for ts in list(log_errs):
            age = int(now - ts)
            if 0 <= age < 60:
                buckets[59 - age] += 1
        peak   = max(buckets) or 1
        normed = [b / peak for b in buckets[-width:]]
        return sparkline(normed, width)

    def _render_logs(self, state, log_filter=""):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3
        log_errs = state.get("log_errs") or collections.deque()
        err_60   = sum(1 for ts in list(log_errs) if (time.time() - ts) < 60)
        spark    = self._error_sparkline(log_errs, min(30, W // 3))
        self._label(cy, 0, "LOGS")
        label_end = 2 + len("┤ LOGS ├")
        err_info  = f"  ERR/60s: {err_60}  "
        self._add(cy, label_end, err_info, cp(CP_CRITICAL, bold=True))
        self._add(cy, label_end + len(err_info), spark, cp(CP_CRITICAL))
        if log_filter:
            flt_str = f"  FILTER:{log_filter} "
            self._add(cy, max(label_end + len(err_info) + len(spark) + 1,
                              W - len(flt_str) - 1),
                      flt_str, cp(CP_HILIGHT, bold=True))
        logs = list(state.get("logs") or [])
        if not logs:
            msg = "AWAITING JOURNAL DATA…"
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_MUTED))
            return
        hdr_row = cy + 1
        self._add(hdr_row, 0,
                  f"{'SERVICE':<16}  {'TIME':<8}  MESSAGE",
                  cp(CP_PRIMARY, bold=True))
        self._hline(hdr_row + 1, 0, "─", W, cp(CP_DIM))
        content_start = cy + 3
        content_rows  = ch - 3
        if content_rows <= 0:
            return
        if log_filter:
            flt     = log_filter.lower()
            visible = [e for e in logs
                       if flt in e.get("unit", "").lower()
                       or flt in e.get("message", "").lower()]
        else:
            visible = logs
        visible = visible[-content_rows:]
        for i, entry in enumerate(visible):
            row = content_start + i
            if row >= cy + ch:
                break
            attr    = self._prio_attr(entry.get("priority", 7))
            unit    = entry.get("unit", "")[:15]
            ts_str  = entry.get("ts_str", "")
            message = entry.get("message", "")
            line    = f"{unit:<16}  {ts_str:<8}  {message}"
            self._add(row, 0, line[:W], attr)

    # ── Tab 4: SERVICES ───────────────────────────────────────────────────────

    def _render_services(self, state):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3
        self._label(cy, 0, "SERVICE WATCHDOG")
        services = state.get("services")
        if services is None:
            msg = "SYSTEMCTL NOT AVAILABLE"
            sub = "(systemd not detected on this system)"
            mid = cy + ch // 2
            self._add(mid,     max(0, (W - len(msg)) // 2), msg, cp(CP_SECONDARY, bold=True))
            self._add(mid + 1, max(0, (W - len(sub)) // 2), sub, cp(CP_MUTED))
            return
        if not WATCHED_SERVICES:
            msg = "No services configured. Edit WATCHED_SERVICES at the top of this file."
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_MUTED))
            return
        row = cy + 1
        hdr = (f"{'NAME':<16}  {'STATE':<10}  {'SUB':<10}  "
               f"{'PID':>7}  {'RESTARTS':>8}  {'ACTIVE SINCE':<16}  RESULT")
        if row < cy + ch:
            self._add(row, 0, hdr[:W], cp(CP_PRIMARY, bold=True))
            row += 1
        if row < cy + ch:
            self._hline(row, 0, "─", W, cp(CP_DIM))
            row += 1
        now = time.time()
        _REST_X = 51
        for svc in (services or []):
            if row >= cy + ch:
                break
            unit   = svc.get("unit", "")
            active = svc.get("ActiveState", "unknown")
            sub    = svc.get("SubState", "")
            pid    = svc.get("ExecMainPID", "0")
            nrest  = svc.get("NRestarts", "N/A")
            result = svc.get("Result", "")
            since  = svc.get("ActiveEnterTimestamp", "")
            if active == "active" and sub == "running":
                c = cp(CP_GOOD)
            elif active == "active":
                c = cp(CP_PRIMARY)
            elif active == "failed":
                c = cp(CP_CRITICAL, bold=True)
            else:
                c = cp(CP_DIM)
            since_str = "N/A"
            if since and since.lower() not in ("n/a", ""):
                try:
                    parts = since.split()
                    if len(parts) >= 3:
                        ts  = _dt.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
                        age = now - ts.timestamp()
                        if age >= 0:
                            since_str = fmtup(age)
                except Exception:
                    since_str = since[:16]
            try:
                nr = int(nrest)
                if nr > 5:
                    rest_str, rest_c = str(nr), cp(CP_CRITICAL, bold=True)
                elif nr > 0:
                    rest_str, rest_c = str(nr), cp(CP_WARN)
                else:
                    rest_str, rest_c = "0", cp(CP_DIM)
            except (ValueError, TypeError):
                rest_str, rest_c = "N/A", cp(CP_DIM)
            pid_str = pid if pid not in ("0", "") else "-"
            line = (f"{unit:<16}  {active:<10}  {sub:<10}  "
                    f"{pid_str:>7}  {rest_str:>8}  {since_str:<16}  {result}")
            self._add(row, 0, line[:W], c)
            self._add(row, _REST_X, f"{rest_str:>8}", rest_c)
            row += 1

    # ── Tab 5: SD CARD ────────────────────────────────────────────────────────

    def _render_sdcard(self, state):
        H, W = self.win.getmaxyx()
        cy   = 2
        ch   = H - 3
        self._label(cy, 0, "SD CARD HEALTH")
        snap = state.get("sdcard")
        if snap is None:
            msg = "COLLECTING DATA…"
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2),
                      msg, cp(CP_PRIMARY, bold=True))
            return
        row  = cy + 1
        half = W // 2
        if not snap.get("has_mmcblk"):
            notice = "NO SD CARD DETECTED — system may be USB/NVMe booted"
            self._add(row, max(0, (W - len(notice)) // 2),
                      notice, cp(CP_WARN, bold=True))
            row += 1
        lw = half - 1
        if row < cy + ch:
            health    = snap.get("smart_health")
            card_type = snap.get("card_type") or ""
            suffix    = f" ({card_type})" if card_type else ""
            if health is None:
                h_str, h_c = "N/A",              cp(CP_MUTED)
            elif health in ("PASSED", "GOOD"):
                h_str, h_c = health + suffix,     cp(CP_GOOD, bold=True)
            elif health == "WARNING":
                h_str, h_c = "WARNING" + suffix,  cp(CP_WARN, bold=True)
            else:
                h_str, h_c = health + suffix,     cp(CP_CRITICAL, bold=True)
            self._add(row, 0,  "SMART HEALTH: ", cp(CP_SECONDARY))
            self._add(row, 14, h_str,             h_c)
            mmc_err = snap.get("mmc_errors", 0)
            mmc_c   = cp(CP_CRITICAL, bold=True) if mmc_err > 0 else cp(CP_DIM)
            self._add(row, half,      "MMC ERRORS (this boot): ", cp(CP_SECONDARY))
            self._add(row, half + 24, str(mmc_err),               mmc_c)
            row += 1
        if row < cy + ch:
            temp = snap.get("temp")
            self._add(row, 0, "TEMPERATURE:  ", cp(CP_SECONDARY))
            if temp is not None:
                bw = max(4, lw - 22)
                self._bar(row, 14, min(100.0, temp / 90.0 * 100), bw)
                self._add(row, 14 + bw, f" {temp:.1f}°C",
                          threshold_cp(temp, "cpu_temp"))
            else:
                self._add(row, 14, "N/A", cp(CP_DIM))
            fs_err = snap.get("fs_errors", 0)
            fs_c   = cp(CP_CRITICAL, bold=True) if fs_err > 0 else cp(CP_DIM)
            self._add(row, half,      "FS ERRORS  (this boot): ", cp(CP_SECONDARY))
            self._add(row, half + 24, str(fs_err),                fs_c)
            row += 1
        if row < cy + ch:
            poh = snap.get("power_on_hours")
            if poh is not None:
                self._add(row, 0,
                          f"POWER ON:     {poh}h ({poh // 24}d)", cp(CP_PRIMARY))
            else:
                self._add(row, 0, "POWER ON:     N/A", cp(CP_DIM))
            bw_val = snap.get("bytes_written")
            if bw_val is not None:
                self._add(row, half,
                          f"WRITTEN (this boot):    {fmtb(bw_val)}", cp(CP_PRIMARY))
            else:
                self._add(row, half, "WRITTEN (this boot):    N/A", cp(CP_DIM))
            row += 1
        if row < cy + ch:
            self._label(row, 0, "FILESYSTEM USAGE")
            row += 1
        for mount, key in (("/", "fs_root"), ("/boot", "fs_boot")):
            if row >= cy + ch:
                break
            fs = snap.get(key)
            if fs is None:
                self._add(row, 0, f"{mount:<7}  N/A", cp(CP_DIM))
                row += 1
                continue
            pct  = fs["pct"]
            lbl  = f"{mount:<7} "
            info = f" {fmtb(fs['used']):>8}/{fmtb(fs['total']):<8}  {pct:5.1f}%  "
            bar_x = len(lbl) + len(info)
            bw    = max(4, W - bar_x - 1)
            self._add(row, 0,        lbl,  cp(CP_SECONDARY, bold=True))
            self._add(row, len(lbl), info, cp(CP_PRIMARY))
            self._bar(row, bar_x, pct, bw, "ram_pct")
            row += 1
        if row < cy + ch:
            self._label(row, 0, "I/O COUNTERS (since boot)")
            row += 1
        io_reads = snap.get("io_reads")
        if io_reads is not None:
            if row < cy + ch:
                self._add(row, 0,
                          f"Reads:  {io_reads:>10} ops   "
                          f"Sectors: {snap.get('io_read_sectors', 0):>12}",
                          cp(CP_PRIMARY))
                row += 1
            if row < cy + ch:
                self._add(row, 0,
                          f"Writes: {snap.get('io_writes', 0):>10} ops   "
                          f"Sectors: {snap.get('io_write_sectors', 0):>12}",
                          cp(CP_SECONDARY))
                row += 1
        else:
            if row < cy + ch:
                self._add(row, 0,
                          "I/O stats unavailable (/sys/block/mmcblk0/stat not found)",
                          cp(CP_MUTED))

    # ── Tab 6: BACKUP ─────────────────────────────────────────────────────────

    def _render_backup(self, state):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3

        backup = state.get("backup")

        if backup is None:
            msg1 = "project-backup not installed or has not run yet"
            msg2 = "Run: sudo bash install-project-backup.sh"
            mid = cy + ch // 2
            self._add(mid,     max(0, (W - len(msg1)) // 2), msg1, cp(CP_DIM))
            self._add(mid + 1, max(0, (W - len(msg2)) // 2), msg2, cp(CP_DIM))
            return

        row = cy

        # ── Section 1: Last Run ───────────────────────────────────────────────
        self._label(row, 0, "LAST BACKUP")
        row += 1

        last_run = backup.get("last_run")

        if last_run is None:
            if row < cy + ch:
                msg = "NO BACKUP HAS RUN YET"
                self._add(row, max(0, (W - len(msg)) // 2), msg, cp(CP_DIM))
            row += 4
        else:
            half = W // 2
            status          = last_run.get("status", "")
            timestamp       = last_run.get("timestamp", "N/A")
            duration_s      = last_run.get("duration_s")
            files_xfer      = last_run.get("files_transferred", 0)
            files_unch      = last_run.get("files_unchanged", 0)
            total_size_h    = last_run.get("total_size_human", "N/A")

            if status == "ok":
                s_str, s_c = "OK",    cp(CP_GOOD, bold=True)
            elif status == "error":
                s_str, s_c = "ERROR", cp(CP_CRITICAL, bold=True)
            else:
                s_str, s_c = status,  cp(CP_WARN)

            if duration_s is not None:
                if duration_s >= 60:
                    m, s = int(duration_s // 60), int(duration_s % 60)
                    dur_str = f"{m}m{s}s"
                else:
                    dur_str = f"{int(duration_s)}s"
            else:
                dur_str = "N/A"

            if row < cy + ch:
                self._add(row, 0,        "STATUS:    ",      cp(CP_SECONDARY))
                self._add(row, 11,       s_str,              s_c)
                self._add(row, half,     "FILES COPIED:    ", cp(CP_SECONDARY))
                self._add(row, half + 17, f"{files_xfer:,}", cp(CP_PRIMARY))
                row += 1

            if row < cy + ch:
                self._add(row, 0,        "TIMESTAMP: ",           cp(CP_SECONDARY))
                self._add(row, 11,       str(timestamp),           cp(CP_PRIMARY))
                self._add(row, half,     "FILES UNCHANGED: ",      cp(CP_SECONDARY))
                self._add(row, half + 17, f"{files_unch:,}",       cp(CP_MUTED))
                row += 1

            if row < cy + ch:
                self._add(row, 0,        "DURATION:  ",        cp(CP_SECONDARY))
                self._add(row, 11,       dur_str,               cp(CP_SECONDARY))
                self._add(row, half,     "TOTAL SIZE:    ",     cp(CP_SECONDARY))
                self._add(row, half + 15, str(total_size_h),   cp(CP_PRIMARY))
                row += 1

        # ── Section 2: Sources ────────────────────────────────────────────────
        if row < cy + ch:
            self._label(row, 0, "SOURCES")
            row += 1

        config  = backup.get("config") or {}
        sources = config.get("sources") or []
        for path in sources:
            if row >= cy + ch:
                break
            exists = os.path.exists(path)
            if exists:
                self._add(row, 2, path,           cp(CP_GOOD))
                self._add(row, 2 + len(path), "  \u2713 EXISTS",  cp(CP_GOOD))
            else:
                self._add(row, 2, path,           cp(CP_WARN))
                self._add(row, 2 + len(path), "  \u2717 MISSING", cp(CP_WARN))
            row += 1

        # ── Section 3: Run History ────────────────────────────────────────────
        if row < cy + ch:
            self._label(row, 0, "RUN HISTORY")
            row += 1

        history = backup.get("history") or []

        if not history:
            if row < cy + ch:
                msg = "No history yet \u2014 run: sudo project-backup"
                self._add(row, max(0, (W - len(msg)) // 2), msg, cp(CP_DIM))
            return

        if row < cy + ch:
            hdr = (f"{'DATE':<12}{'TIME':<10}{'STATUS':<10}"
                   f"{'COPIED':>10}  {'SIZE':<12}DURATION")
            self._add(row, 0, hdr[:W], cp(CP_PRIMARY, bold=True))
            row += 1

        if row < cy + ch:
            self._hline(row, 0, "─", W, cp(CP_DIM))
            row += 1

        for entry in history:
            if row >= cy + ch:
                break
            ts       = entry.get("timestamp", "")
            date     = ts[:10] if len(ts) >= 10 else ts
            time_str = ts[11:19] if len(ts) >= 19 else ""
            estatus  = entry.get("status", "")
            efiles   = entry.get("files_transferred", 0)
            esize    = entry.get("total_size_human", "")
            edur_s   = entry.get("duration_s")

            if edur_s is not None:
                if edur_s >= 60:
                    m, s = int(edur_s // 60), int(edur_s % 60)
                    edur_str = f"{m}m{s}s"
                else:
                    edur_str = f"{int(edur_s)}s"
            else:
                edur_str = "N/A"

            if estatus == "ok":
                c = cp(CP_GOOD)
            elif estatus == "error":
                c = cp(CP_CRITICAL, bold=True)
            else:
                c = cp(CP_DIM)

            line = (f"{date:<12}{time_str:<10}{estatus.upper():<10}"
                    f"{efiles:>10,}  {esize:<12}{edur_str}")
            self._add(row, 0, line[:W], c)
            row += 1

        if len(history) >= 2 and row < cy + ch:
            label    = "TRANSFER HISTORY  "
            spark_w  = W - len(label)
            if spark_w > 0:
                spark_data = [e.get("files_transferred", 0) for e in history]
                self._add(row, 0,          label,                      cp(CP_MUTED))
                self._add(row, len(label), sparkline(spark_data, spark_w), cp(CP_PRIMARY))

    # ── Tab 7: HISTORY ───────────────────────────────────────────────────────

    _HIST_CSV = os.path.expanduser("~/.local/share/syswatch/metrics.csv")
    _HIST_TTL = 10.0

    def _hist_csv_path(self):
        # Normal case: the per-user metrics file under the caller's home.
        if os.path.exists(self._HIST_CSV):
            return self._HIST_CSV
        # When syswatch is launched with sudo, ~ expands to /root and the
        # logger's data (written as the real user) would be missed. Fall back
        # to the invoking user's home if that file exists.
        try:
            if os.geteuid() == 0:
                sudo_user = os.environ.get("SUDO_USER")
                if sudo_user:
                    alt = f"/home/{sudo_user}/.local/share/syswatch/metrics.csv"
                    if os.path.exists(alt):
                        return alt
        except Exception:
            pass
        return self._HIST_CSV

    def _load_history(self):
        now = time.monotonic()
        if (self._hist_cache is not None
                and now - self._hist_cache[0] < self._HIST_TTL):
            return self._hist_cache[1]
        rows = []
        try:
            with open(self._hist_csv_path()) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(",")
                    if len(parts) != 5:
                        continue
                    try:
                        ts       = _dt.fromisoformat(parts[0])
                        cpu_temp = float(parts[3]) if parts[3] else None
                        rows.append({
                            "ts":       ts,
                            "cpu_pct":  float(parts[1]),
                            "ram_pct":  float(parts[2]),
                            "cpu_temp": cpu_temp,
                            "disk_pct": float(parts[4]),
                        })
                    except Exception:
                        pass
        except Exception:
            pass
        self._hist_cache = (now, rows)
        return rows

    def _render_history(self, history_window):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3

        window_labels = ["1 HOUR", "8 HOURS", "24 HOURS", "7 DAYS", "30 DAYS"]
        window_secs   = [3600, 28800, 86400, 604800, 2592000]
        wlabel        = window_labels[history_window]

        self._label(cy, 0, f"HISTORY — {wlabel}  [h] next window")

        rows = self._load_history()
        if not rows:
            msg1 = "No history data yet."
            msg2 = "Start syswatch-logger to begin collecting metrics."
            mid  = cy + ch // 2
            self._add(mid,     max(0, (W - len(msg1)) // 2), msg1, cp(CP_SECONDARY, bold=True))
            self._add(mid + 1, max(0, (W - len(msg2)) // 2), msg2, cp(CP_MUTED))
            return

        now_ts   = _dt.now().timestamp()
        win_secs = window_secs[history_window]
        cutoff   = now_ts - win_secs
        filtered = [r for r in rows if r["ts"].timestamp() >= cutoff]
        if not filtered:
            msg = f"No data in the last {wlabel.lower()}."
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_MUTED))
            return

        # Time-axis timestamps, shared across every chart in this window.
        oldest_ts = filtered[0]["ts"]
        newest_ts = filtered[-1]["ts"]

        # Estimate the logger's sample interval from the data (median of the
        # deltas between consecutive samples) so gap detection and the coverage
        # check adapt to a non-default --interval. Needs ≥3 rows to be
        # meaningful; otherwise assume the 120s default.
        if len(filtered) >= 3:
            deltas = sorted(
                filtered[i]["ts"].timestamp() - filtered[i - 1]["ts"].timestamp()
                for i in range(1, len(filtered)))
            n = len(deltas)
            sample_interval = (deltas[n // 2] if n % 2
                               else (deltas[n // 2 - 1] + deltas[n // 2]) / 2)
        else:
            sample_interval = 120.0

        def _fmt_axis(dt_obj):
            # 1h / 8h / 24h windows use clock time; 7d / 30d use calendar date.
            if history_window <= 2:
                return dt_obj.strftime("%H:%M")
            return dt_obj.strftime("%b %d")

        row = cy + 1

        # Data-coverage indicator: shown only while the window is not yet full.
        # Jitter tolerance is one estimated sample interval plus a 25% margin.
        window_start = now_ts - win_secs
        if oldest_ts.timestamp() - window_start > sample_interval * 1.25:
            span_secs = newest_ts.timestamp() - oldest_ts.timestamp()
            if span_secs < 7200:
                span_str = f"{int(round(span_secs / 60))}m"
            elif span_secs < 172800:
                span_str = f"{span_secs / 3600:.1f}h"
            else:
                span_str = f"{span_secs / 86400:.1f}d"
            short_labels = ["1h", "8h", "24h", "7d", "30d"]
            # Multi-day windows (7d / 30d) need the date too, not just the time.
            cov_fmt  = "%b %d %H:%M" if history_window >= 3 else "%H:%M"
            cov_line = (f"DATA: {oldest_ts.strftime(cov_fmt)} → "
                        f"{newest_ts.strftime(cov_fmt)}  "
                        f"({span_str} of {short_labels[history_window]} window)")
            if row < cy + ch:
                self._add(row, 0, cov_line, cp(CP_MUTED))
            row += 1

        chart_h    = 5
        max_points = max(2, W - 12)
        metrics    = [
            ("CPU %",    "cpu_pct",  "cpu_pct"),
            ("RAM %",    "ram_pct",  "ram_pct"),
            ("TEMP °C", "cpu_temp", "cpu_temp"),
            ("DISK %",   "disk_pct", "ram_pct"),
        ]

        for label, key, thresh_key in metrics:
            pairs = [(r["ts"], r[key]) for r in filtered if r.get(key) is not None]
            if not pairs:
                continue
            timestamps = [p[0] for p in pairs]
            values     = [p[1] for p in pairs]

            # True data span, captured before any resampling reshapes the lists
            # so the time axis always reflects the real oldest/newest samples
            # regardless of how the trim/stretch below cuts the tail.
            true_oldest = timestamps[0]
            true_newest = timestamps[-1]

            # Downsample to fit terminal width *before* detecting gaps, so the
            # trim can't change which jumps look like outages. down_step records
            # the trim factor; the kept points end up down_step× farther apart
            # than the raw sample interval.
            down_step = 1
            if len(values) > max_points:
                down_step  = max(1, len(values) // max_points)
                values     = values[::down_step][-max_points:]
                timestamps = timestamps[::down_step][-max_points:]

            # Gap detection for logger outages: any jump larger than 5× the
            # estimated sample interval means the logger was not running. We
            # record each gap's fractional position within the data (0.0–1.0)
            # rather than injecting None — asciichartpy raises on None — and
            # overlay a dotted vertical marker after the chart is drawn. After
            # downsampling the kept points are down_step× farther apart, so
            # scale the threshold to match. Capped at 20 gaps so a
            # frequently-restarted logger can't shred the chart into slivers.
            GAP_THRESHOLD = 5 * sample_interval * down_step
            MAX_GAPS      = 20
            gap_cols      = []
            for i in range(1, len(values)):
                if len(gap_cols) >= MAX_GAPS:
                    break
                prev_ts, cur_ts = timestamps[i - 1], timestamps[i]
                if cur_ts.timestamp() - prev_ts.timestamp() > GAP_THRESHOLD:
                    # Fraction of the (post-downsample) width at this gap.
                    gap_cols.append(i / (len(values) - 1))

            # Stretch sparse data so the chart fills the available width. The
            # data is all real numbers, and because each entry is repeated
            # uniformly, the gap fractions recorded above stay valid (they are
            # fractions of the width, not absolute indices).
            if len(values) < max_points:
                step       = max_points // len(values)
                values     = [v for v in values for _ in range(step)][:max_points]
                timestamps = [t for t in timestamps for _ in range(step)][:max_points]

            if len(values) < 2:
                continue

            latest     = values[-1]
            chart_attr = threshold_cp(latest, thresh_key)

            if row >= cy + ch:
                break
            self._label(row, 0, f"{label}  {latest:.1f}")
            row += 1

            try:
                chart_str   = asciichartpy.plot(values, {"height": chart_h})
                chart_lines = chart_str.split("\n")
            except Exception:
                chart_lines = ["  (chart error)"]

            body_y0 = row
            for cline in chart_lines:
                if row >= cy + ch:
                    break
                self._add(row, 0, cline, chart_attr)
                row += 1
            body_y1 = row  # exclusive end of the drawn chart-body rows

            # Time-axis row: a dynamic number of evenly spaced ticks that adapts
            # to the available data width. The y-axis prefix is everything up to
            # and including the ┤/┼ tick plus one trailing space.
            first    = chart_lines[0] if chart_lines else ""
            axis_pos = -1
            for i, cchar in enumerate(first):
                if cchar in ("┤", "┼"):
                    axis_pos = i
                    break
            if axis_pos >= 0:
                prefix_w = axis_pos + 2
                longest  = max(len(cl) for cl in chart_lines)
                data_w   = longest - prefix_w
                # Overlay outage markers: a dotted vertical line down the chart
                # body at each recorded gap fraction. Every write is bounds-
                # checked so it can never draw outside the panel.
                if data_w > 0:
                    for frac in gap_cols:
                        gap_col = int(round(frac * (data_w - 1)))
                        gx      = prefix_w + gap_col
                        if 0 <= gap_col < data_w and 0 <= gx < W:
                            for gy in range(body_y0, body_y1):
                                if cy <= gy < cy + ch:
                                    self._add(gy, gx, "┊", cp(CP_WARN))
                if row < cy + ch and data_w > 0:
                    old_t   = true_oldest.timestamp()
                    new_t   = true_newest.timestamp()
                    label_w = 5 if history_window <= 2 else 6
                    # How many labels fit without crowding: at least 8 columns of
                    # breathing room between adjacent tick centres, capped at 10.
                    # Falls back to 2 (oldest + newest) on narrow terminals.
                    max_ticks = min(10, max(2, data_w // (label_w + 8)))
                    ticks     = []
                    for i in range(max_ticks):
                        frac = i / (max_ticks - 1)
                        col  = int(round(frac * (data_w - 1))) - label_w // 2
                        col  = max(0, min(data_w - label_w, col))
                        tdt  = _dt.fromtimestamp(old_t + (new_t - old_t) * frac)
                        ticks.append((col, _fmt_axis(tdt)))
                    # Resolve overlaps right-to-left, dropping the earlier label.
                    kept          = []
                    occupied_left = data_w
                    for col, text in reversed(ticks):
                        if col + len(text) <= occupied_left:
                            kept.append((col, text))
                            occupied_left = col
                    # Tick-mark row: a │ centred under each retained label. Drawn
                    # only when the label row below it still fits, so it can never
                    # push the time labels off the panel.
                    if row + 1 < cy + ch:
                        tick_chars = [" "] * data_w
                        for col, text in kept:
                            centre = col + label_w // 2
                            if 0 <= centre < data_w:
                                tick_chars[centre] = "│"
                        self._add(row, prefix_w, "".join(tick_chars), cp(CP_MUTED))
                        row += 1
                    axis_chars = [" "] * data_w
                    for col, text in kept:
                        for j, tchar in enumerate(text):
                            if 0 <= col + j < data_w:
                                axis_chars[col + j] = tchar
                    self._add(row, prefix_w, "".join(axis_chars), cp(CP_MUTED))
                row += 1

            row += 1  # spacer between charts

    # ── dispatch ──────────────────────────────────────────────────────────────

    def render(self, active_tab, state, log_filter, mode, filter_buf, history_window=0):
        H, W = self.win.getmaxyx()
        self.win.erase()
        if H < self.MIN_H or W < self.MIN_W:
            msg = f"Terminal too small ({W}×{H}), need ≥{self.MIN_W}×{self.MIN_H}"
            self._add(H // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_CRITICAL, bold=True))
            self.win.noutrefresh()
            curses.doupdate()
            return
        self._render_header()
        self._render_tab_bar(active_tab)
        self._render_footer(state)
        if   active_tab == 1: self._render_system(state)
        elif active_tab == 2: self._render_network(state)
        elif active_tab == 3: self._render_logs(state, log_filter)
        elif active_tab == 4: self._render_services(state)
        elif active_tab == 5: self._render_sdcard(state)
        elif active_tab == 6: self._render_backup(state)
        elif active_tab == 7: self._render_history(history_window)
        if mode == "filter_input":
            prompt = f" FILTER: {filter_buf}_ "
            self._add(H - 2, 2, prompt, cp(CP_HILIGHT, bold=True) | curses.A_REVERSE)
        self.win.noutrefresh()
        curses.doupdate()


# ── entry point ────────────────────────────────────────────────────────────────
def _curses_main(stdscr, args):
    init_colors()
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(100)
    stdscr.keypad(True)

    active_tab     = max(1, min(7, args.tab))
    mode           = "normal"
    log_filter     = ""
    filter_buf     = ""
    history_window = 0
    last_render    = 0.0
    alive          = [True]

    signal.signal(signal.SIGINT,  lambda *_: alive.__setitem__(0, False))
    signal.signal(signal.SIGTERM, lambda *_: alive.__setitem__(0, False))

    threads = [
        SystemThread(),
        ARPPassiveThread(),
        PingSweepThread(enabled=not args.no_scan),
        LogThread(),
        ServiceWatchdogThread(),
        SDCardThread(),
        BackupStatusThread(),
    ]
    for t in threads:
        t.start()

    renderer = FullRenderer(stdscr)

    while alive[0]:
        ch = stdscr.getch()

        if mode == "normal":
            if ch in (ord("q"), ord("Q"), 27):
                break
            elif ch == curses.KEY_RESIZE:
                curses.update_lines_cols()
                last_render = 0.0
            elif ord("1") <= ch <= ord("7"):
                active_tab = ch - ord("0")
                last_render = 0.0
            elif ch == ord("h") and active_tab == 7:
                history_window = (history_window + 1) % 5
                last_render = 0.0
            elif ch == ord("/") and active_tab == 3:
                mode       = "filter_input"
                filter_buf = log_filter
                curses.curs_set(1)
                last_render = 0.0
        elif mode == "filter_input":
            if ch == 27:
                mode, filter_buf = "normal", ""
                curses.curs_set(0)
                last_render = 0.0
            elif ch in (curses.KEY_ENTER, 10, 13):
                log_filter, mode, filter_buf = filter_buf, "normal", ""
                curses.curs_set(0)
                last_render = 0.0
            elif ch in (curses.KEY_BACKSPACE, 127):
                filter_buf = filter_buf[:-1]
                last_render = 0.0
            elif 32 <= ch <= 126:
                filter_buf += chr(ch)
                last_render = 0.0

        now = time.monotonic()
        if now - last_render >= REFRESH:
            state = get_state()
            renderer.render(active_tab, state, log_filter, mode, filter_buf, history_window)
            last_render = now

    for t in threads:
        t.stop()
    for t in threads:
        t.join(timeout=2.0)


def main():
    global REFRESH
    parser = argparse.ArgumentParser(
        description="syswatch — deep space terminal system monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--tab", type=int, default=1, choices=range(1, 8), metavar="N",
        help="start on tab N (1-7, default 1)",
    )
    parser.add_argument(
        "--refresh", type=float, default=1.0, metavar="N",
        help="refresh rate in seconds (default 1.0, min 0.5)",
    )
    parser.add_argument(
        "--no-scan", action="store_true",
        help="disable the active ping sweep (passive ARP only)",
    )
    parser.add_argument(
        "--version", action="version", version="syswatch 1.0.0",
    )
    args = parser.parse_args()
    if args.refresh < 0.5:
        args.refresh = 0.5
    REFRESH = args.refresh
    try:
        curses.wrapper(lambda stdscr: _curses_main(stdscr, args))
    except KeyboardInterrupt:
        pass
    print("\nSYSWATCH — DISCONNECTED\n")


if __name__ == "__main__":
    main()
