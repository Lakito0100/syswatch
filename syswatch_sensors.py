#!/usr/bin/env python3
"""syswatch_sensors — platform/sensor detection shared by syswatch and syswatch-logger"""

import collections
import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time
import traceback
from datetime import datetime as _dt

import psutil

VERSION = "1.3.0"

# ── debug logging ─────────────────────────────────────────────────────────────
# A shared, dependency-free error-tracking facility used by syswatch.py and
# syswatch-logger.py: every collector's bare `except Exception` calls
# note_error() instead of silently passing, so a broken sensor (raises) can be
# told apart from an absent one (returns None by design). Tracking is always
# on (cheap: one deque append under a lock) so has_recent_errors() can drive a
# "degraded" indicator even when nobody opted into --debug; writing the actual
# traceback to DEBUG_LOG_PATH only happens once set_debug(True) is called —
# with debug off, behaviour is unchanged from before this facility existed.

# Kept for compatibility with anything referring to the plain path; the actual
# writes go through debug_log_path(), which is sudo-aware (see user_data_path).
DEBUG_LOG_PATH = os.path.expanduser("~/.local/share/syswatch/debug.log")


def debug_log_path():
    return user_data_path("debug.log")

_debug_enabled = False
_error_lock    = threading.Lock()
_recent_errors = collections.deque(maxlen=200)  # (monotonic_ts, collector)
_last_logged   = {}  # collector -> monotonic ts of last debug.log write
_LOG_DEDUP_WINDOW = 60.0  # seconds — a collector that fails every cycle (e.g.
                          # a genuinely absent sensor probed once a second)
                          # gets one debug.log entry per window, not one per
                          # cycle, so a long --debug run stays readable.


def set_debug(enabled):
    global _debug_enabled
    _debug_enabled = bool(enabled)


def is_debug():
    return _debug_enabled


def note_error(collector, exc=None):
    now = time.monotonic()
    with _error_lock:
        _recent_errors.append((now, collector))
        if not _debug_enabled:
            return
        last = _last_logged.get(collector)
        if last is not None and now - last < _LOG_DEDUP_WINDOW:
            return
        _last_logged[collector] = now
    try:
        path = debug_log_path()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "a") as f:
            ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            f.write(f"[{ts}] {collector}\n")
            if exc is not None:
                f.write("".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)))
            f.write("\n")
        chown_to_invoking_user(d, path)
    except Exception:
        pass  # debug logging itself must never be a new source of crashes


def has_recent_errors(window=15.0):
    now = time.monotonic()
    with _error_lock:
        while _recent_errors and now - _recent_errors[0][0] > window:
            _recent_errors.popleft()
        return len(_recent_errors) > 0


def log_uncaught_thread_exception(args):
    """Install as threading.excepthook so a thread that dies from something
    escaping its own run() loop is recorded instead of just quietly ending."""
    name = args.thread.name if args.thread is not None else "unknown"
    note_error(f"thread:{name} (uncaught, thread exiting)", args.exc_value)


# ── invoking user (sudo-aware paths) ─────────────────────────────────────────

_invoking_home_cache = ()  # () = not yet resolved; (value,) once resolved


def invoking_user_home():
    """Home directory of the human behind `sudo`, or None when that doesn't
    apply (not root, no SUDO_USER, or the user can't be resolved).

    Under `sudo syswatch`, HOME/`~` point at root's home, so every piece of
    per-user state — config.toml, metrics.csv, known_devices.json, the alert
    logs — would silently be a *different* set of files from the ones an
    unprivileged run uses. Everything that resolves per-user state goes through
    this so they all agree on whose files they mean; resolved via the passwd
    database rather than assuming /home/<name>, which is wrong for users with a
    non-standard home.

    Cached: the answer can't change during the process, and note_error() calls
    into this often enough that repeating a passwd lookup would be wasteful.
    """
    global _invoking_home_cache
    if _invoking_home_cache:
        return _invoking_home_cache[0]
    result = None
    try:
        if os.geteuid() == 0:
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user and sudo_user != "root":
                import pwd
                result = pwd.getpwnam(sudo_user).pw_dir or None
    except Exception:
        result = None
    _invoking_home_cache = (result,)
    return result


def user_data_path(*parts):
    """Path under ~/.local/share/syswatch/, sudo-aware.

    Prefers this process's own path when that file already exists, then the
    invoking user's. When neither exists the invoking user's wins, so state
    *created* during a `sudo` run lands in the real user's home rather than
    root's — matching config_path_default(). Callers that write should follow
    up with chown_to_invoking_user() so the result isn't root-owned.
    """
    own = os.path.join(os.path.expanduser("~/.local/share/syswatch"), *parts)
    if os.path.exists(own):
        return own
    home = invoking_user_home()
    if home:
        return os.path.join(home, ".local", "share", "syswatch", *parts)
    return own


def chown_to_invoking_user(*paths):
    """Under `sudo`, hand files/directories written into the invoking user's
    home back to them, so a sudo run doesn't leave root-owned state the user
    can no longer update unprivileged. Paths outside that home are left alone.
    Best-effort throughout: failing to chown never invalidates the write."""
    home = invoking_user_home()
    if not home:
        return
    try:
        import pwd
        pw = pwd.getpwnam(os.environ["SUDO_USER"])
        root = os.path.realpath(home)
    except Exception:
        return
    for p in paths:
        if not p:
            continue
        try:
            real = os.path.realpath(p)
            if real != root and not real.startswith(root + os.sep):
                continue
            os.chown(p, pw.pw_uid, pw.pw_gid)
        except Exception:
            pass


# ── platform identity ────────────────────────────────────────────────────────

_is_pi_cache = None


def is_pi():
    global _is_pi_cache
    if _is_pi_cache is None:
        _is_pi_cache = "Raspberry Pi" in platform_model()
    return _is_pi_cache


def platform_model():
    try:
        with open("/proc/device-tree/model") as f:
            model = f.read().strip("\x00").strip()
            if model:
                return model
    except Exception:
        pass
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("Model"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    try:
        vendor  = open("/sys/class/dmi/id/sys_vendor").read().strip()
        product = open("/sys/class/dmi/id/product_name").read().strip()
        model = " ".join(p for p in (vendor, product) if p)
        if model:
            return model
    except Exception:
        pass
    try:
        import platform as _platform
        return _platform.machine() or "unknown"
    except Exception as e:
        note_error("platform_model (all sources failed)", e)
        return "unknown"


# ── CPU temperature ──────────────────────────────────────────────────────────

_CPU_PRIORITY_KEYS = ("cpu_thermal", "coretemp", "k10temp", "zenpower", "acpitz")
_CPU_LABEL_HINTS   = ("package id 0", "tctl", "cpu")
_NON_CPU_KEYS      = ("nvme", "iwlwifi", "i915", "amdgpu", "nouveau", "pch_", "drivetemp", "wifi")


def _plausible_temp(v):
    return v is not None and 0 < v < 150


def cpu_temp():
    try:
        temps = psutil.sensors_temperatures()
    except Exception as e:
        note_error("cpu_temp (psutil.sensors_temperatures)", e)
        temps = None
    if temps:
        for key in _CPU_PRIORITY_KEYS:
            entries = temps.get(key)
            if not entries:
                continue
            for e in entries:
                if e.label and e.label.strip().lower() in _CPU_LABEL_HINTS and _plausible_temp(e.current):
                    return round(e.current, 1)
            for e in entries:
                if _plausible_temp(e.current):
                    return round(e.current, 1)
        for key, entries in temps.items():
            if any(key.lower().startswith(bad) for bad in _NON_CPU_KEYS):
                continue
            for e in entries or []:
                if _plausible_temp(e.current):
                    return round(e.current, 1)
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return round(int(f.read().strip()) / 1000, 1)
    except Exception as e:
        note_error("cpu_temp (thermal_zone0 fallback)", e)
    return None


def cpu_temp_hint():
    return "no sensor — try: sudo apt install lm-sensors && sudo sensors-detect"


# ── GPU temperature ──────────────────────────────────────────────────────────

_gpu_vendor_cache = None  # "nvidia" | "amd" | "intel" | "none", detected once


def _detect_gpu_vendor():
    if shutil.which("nvidia-smi"):
        try:
            r = subprocess.run(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=1.0,
            )
            if r.returncode == 0 and r.stdout.strip():
                return "nvidia"
        except Exception as e:
            note_error("_detect_gpu_vendor (nvidia-smi)", e)
    for hwmon_name in glob.glob("/sys/class/drm/card*/device/hwmon/hwmon*/name"):
        try:
            with open(hwmon_name) as f:
                if f.read().strip() == "amdgpu":
                    return "amd"
        except Exception:
            pass
    try:
        temps = psutil.sensors_temperatures()
    except Exception as e:
        note_error("_detect_gpu_vendor (psutil.sensors_temperatures)", e)
        temps = None
    if temps and "i915" in temps:
        return "intel"
    return "none"


def _gpu_vendor():
    global _gpu_vendor_cache
    if _gpu_vendor_cache is None:
        _gpu_vendor_cache = _detect_gpu_vendor()
    return _gpu_vendor_cache


_gpu_temp_cache = None  # (monotonic_ts, result)
_GPU_TEMP_TTL   = 5.0


def _read_gpu_temp_nvidia():
    try:
        r = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,temperature.gpu", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=1.0,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return None
        # One CSV row per GPU. Splitting the whole output instead of just the
        # first line meant a second GPU turned the temperature field into
        # "55\nNVIDIA GeForce RTX 3090, 61", which float() rejected — so every
        # multi-GPU machine reported no GPU temperature at all and logged a
        # parse error every refresh. Read the first GPU, like the single-GPU
        # case always did.
        first = r.stdout.strip().splitlines()[0]
        name, _, temp_str = first.rpartition(",")
        temp = float(temp_str.strip())
        return {"vendor": "NVIDIA", "label": name.strip(), "temp": temp}
    except Exception as e:
        note_error("_read_gpu_temp_nvidia", e)
        return None


def _read_gpu_temp_amd():
    for temp_path in glob.glob("/sys/class/drm/card*/device/hwmon/hwmon*/temp1_input"):
        name_path = os.path.join(os.path.dirname(temp_path), "name")
        try:
            with open(name_path) as f:
                if f.read().strip() != "amdgpu":
                    continue
            with open(temp_path) as f:
                temp = int(f.read().strip()) / 1000
            return {"vendor": "AMD", "label": "amdgpu", "temp": temp}
        except Exception:
            continue
    return None


def _read_gpu_temp_intel():
    try:
        temps = psutil.sensors_temperatures()
    except Exception as e:
        note_error("_read_gpu_temp_intel", e)
        return None
    entries = (temps or {}).get("i915")
    if not entries:
        return None
    for e in entries:
        if _plausible_temp(e.current):
            return {"vendor": "Intel", "label": e.label or "i915", "temp": e.current}
    return None


def gpu_temp():
    global _gpu_temp_cache
    now = time.monotonic()
    if _gpu_temp_cache is not None and now - _gpu_temp_cache[0] < _GPU_TEMP_TTL:
        return _gpu_temp_cache[1]
    vendor = _gpu_vendor()
    result = None
    if vendor == "nvidia":
        result = _read_gpu_temp_nvidia()
    elif vendor == "amd":
        result = _read_gpu_temp_amd()
    elif vendor == "intel":
        result = _read_gpu_temp_intel()
    _gpu_temp_cache = (now, result)
    return result


# ── storage device / temperature ─────────────────────────────────────────────

_root_device_cache = None


def root_device():
    global _root_device_cache
    if _root_device_cache is not None:
        return _root_device_cache

    partition = None
    try:
        for p in psutil.disk_partitions():
            if p.mountpoint == "/":
                partition = p.device
                break
    except Exception as e:
        note_error("root_device (psutil.disk_partitions)", e)
    if partition is None:
        try:
            r = subprocess.run(["findmnt", "-no", "SOURCE", "/"],
                                capture_output=True, text=True, timeout=2)
            if r.returncode == 0 and r.stdout.strip():
                partition = r.stdout.strip()
        except Exception as e:
            note_error("root_device (findmnt)", e)

    base = None
    if partition:
        dev_name = os.path.basename(partition)
        try:
            r = subprocess.run(["lsblk", "-no", "PKNAME", partition],
                                capture_output=True, text=True, timeout=2)
            if r.returncode == 0 and r.stdout.strip():
                base = r.stdout.strip().splitlines()[0].strip()
        except Exception as e:
            note_error("root_device (lsblk)", e)
        if not base:
            m = re.match(r"^(mmcblk\d+|nvme\d+n\d+|sd[a-z]+|vd[a-z]+|xvd[a-z]+)", dev_name)
            base = m.group(1) if m else dev_name

    if base is None:
        kind = "unknown"
    elif base.startswith("mmcblk"):
        kind = "mmc"
    elif base.startswith("nvme"):
        kind = "nvme"
    elif base.startswith(("dm-", "loop")) or "mapper" in base:
        kind = "virtual"
    else:
        kind = "disk"

    _root_device_cache = {
        "partition": partition,
        "base":      base,
        "kind":      kind,
        "sysfs":     f"/sys/block/{base}" if base else None,
    }
    return _root_device_cache


def boot_mount():
    try:
        mounts = {p.mountpoint for p in psutil.disk_partitions()}
    except Exception as e:
        note_error("boot_mount (psutil.disk_partitions)", e)
        mounts = set()
    for candidate in ("/boot/firmware", "/boot", "/boot/efi"):
        if candidate in mounts:
            return candidate
    return None


_storage_temp_cache = None  # (monotonic_ts, result)
_STORAGE_TEMP_TTL   = 60.0


def _read_storage_temp_psutil():
    try:
        temps = psutil.sensors_temperatures()
    except Exception as e:
        note_error("_read_storage_temp_psutil", e)
        return None
    entries = (temps or {}).get("nvme")
    if not entries:
        return None
    for e in entries:
        if e.label and "composite" in e.label.strip().lower() and _plausible_temp(e.current):
            return round(e.current, 1)
    plausible = [e.current for e in entries if _plausible_temp(e.current)]
    return round(max(plausible), 1) if plausible else None


def _read_storage_temp_smartctl(base, kind):
    # smartmontools is a documented soft dependency. Letting the run() call
    # below raise FileNotFoundError instead would record a collector error on
    # every refresh, so a machine that simply doesn't have smartctl installed
    # sat with the header's degraded ⚠ lit permanently — an absent tool
    # reported as a failing one. Absent means "no reading", same as _vcg() and
    # PingSweepThread already treat their own missing binaries.
    if not shutil.which("smartctl"):
        return None
    dev = f"/dev/{base}"
    cmds = [["smartctl", "-A", dev, "--json"]]
    if kind == "mmc":
        cmds.append(["smartctl", "-A", dev, "--device=mmc", "--json"])
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            data = json.loads(r.stdout)
        except Exception as e:
            note_error("_read_storage_temp_smartctl", e)
            continue
        if not isinstance(data, dict):
            continue
        nvme_log = data.get("nvme_smart_health_information_log")
        if isinstance(nvme_log, dict) and "temperature" in nvme_log:
            try:
                return float(nvme_log["temperature"])
            except Exception:
                pass
        # smartctl can emit "ata_smart_attributes": null (e.g. on an NVMe
        # device queried without --device=nvme) rather than omitting the key,
        # so .get(..., {}) alone doesn't guard against a None here.
        ata_attrs = data.get("ata_smart_attributes")
        table = ata_attrs.get("table") if isinstance(ata_attrs, dict) else None
        for attr in table or []:
            if not isinstance(attr, dict):
                continue
            if attr.get("id") == 194 or "Temperature" in attr.get("name", ""):
                raw = attr.get("raw", {})
                raw = raw.get("value") if isinstance(raw, dict) else None
                try:
                    return float(str(raw).split()[0])
                except Exception:
                    pass
    return None


def storage_temp():
    global _storage_temp_cache
    now = time.monotonic()
    if _storage_temp_cache is not None and now - _storage_temp_cache[0] < _STORAGE_TEMP_TTL:
        return _storage_temp_cache[1]
    result = _read_storage_temp_psutil()
    if result is None:
        dev = root_device()
        if dev["base"]:
            result = _read_storage_temp_smartctl(dev["base"], dev["kind"])
    _storage_temp_cache = (now, result)
    return result


# ── network ───────────────────────────────────────────────────────────────────

_MAX_SWEEP_PREFIXLEN = 22  # skip anything larger than a /22 (>1024 hosts)


def local_networks():
    nets = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception as e:
        note_error("local_networks (psutil.net_if_addrs/stats)", e)
        return nets
    for iface, iface_addrs in addrs.items():
        if iface == "lo" or iface.startswith("lo"):
            continue
        st = stats.get(iface)
        if st is not None and not st.isup:
            continue
        for a in iface_addrs:
            if a.family != 2:  # socket.AF_INET, avoid importing socket just for this
                continue
            if not a.address or not a.netmask:
                continue
            if a.address.startswith("169.254."):
                continue
            try:
                net = ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False)
            except Exception:
                continue
            if net.prefixlen < _MAX_SWEEP_PREFIXLEN:
                continue
            if net.prefixlen == 32:
                continue
            if net not in nets:
                nets.append(net)
    return nets


# ── backup service ────────────────────────────────────────────────────────────

_BACKUP_STATUS_FILE = "/var/log/project-backup-status.json"


def backup_service_available():
    if os.path.exists(_BACKUP_STATUS_FILE):
        return True
    for unit in ("project-backup.service", "project-backup.timer"):
        try:
            r = subprocess.run(
                ["systemctl", "is-enabled", unit],
                capture_output=True, text=True, timeout=2,
            )
            if r.stdout.strip() in ("enabled", "static", "enabled-runtime"):
                return True
        except Exception:
            pass
    return False
