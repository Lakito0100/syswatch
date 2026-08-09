#!/usr/bin/env python3
"""syswatch_sensors — platform/sensor detection shared by syswatch and syswatch-logger"""

import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time

import psutil

VERSION = "1.2.0"

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
    except Exception:
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
    except Exception:
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
    except Exception:
        pass
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
        except Exception:
            pass
    for hwmon_name in glob.glob("/sys/class/drm/card*/device/hwmon/hwmon*/name"):
        try:
            with open(hwmon_name) as f:
                if f.read().strip() == "amdgpu":
                    return "amd"
        except Exception:
            pass
    try:
        temps = psutil.sensors_temperatures()
    except Exception:
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
        name, temp_str = [p.strip() for p in r.stdout.strip().split(",", 1)]
        temp = float(temp_str)
        return {"vendor": "NVIDIA", "label": name, "temp": temp}
    except Exception:
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
    except Exception:
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
    except Exception:
        pass
    if partition is None:
        try:
            r = subprocess.run(["findmnt", "-no", "SOURCE", "/"],
                                capture_output=True, text=True, timeout=2)
            if r.returncode == 0 and r.stdout.strip():
                partition = r.stdout.strip()
        except Exception:
            pass

    base = None
    if partition:
        dev_name = os.path.basename(partition)
        try:
            r = subprocess.run(["lsblk", "-no", "PKNAME", partition],
                                capture_output=True, text=True, timeout=2)
            if r.returncode == 0 and r.stdout.strip():
                base = r.stdout.strip().splitlines()[0].strip()
        except Exception:
            pass
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
    except Exception:
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
    except Exception:
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
    dev = f"/dev/{base}"
    cmds = [["smartctl", "-A", dev, "--json"]]
    if kind == "mmc":
        cmds.append(["smartctl", "-A", dev, "--device=mmc", "--json"])
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            data = json.loads(r.stdout)
        except Exception:
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
    except Exception:
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
