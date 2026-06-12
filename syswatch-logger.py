#!/usr/bin/env python3
"""syswatch-logger — background metrics sampler for syswatch"""

import sys
import os
import time
import subprocess
import argparse
from datetime import datetime as _dt


def _bootstrap():
    import importlib.util as ilu
    missing = [p for p in ("psutil",) if ilu.find_spec(p) is None]
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


def _cpu_temp():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return round(int(f.read().strip()) / 1000, 1)
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["vcgencmd", "measure_temp"],
            capture_output=True, text=True, timeout=0.5,
        )
        raw = r.stdout.strip()
        if raw and "temp=" in raw:
            return float(raw.split("=")[1].strip("'C "))
    except Exception:
        pass
    return None


def _trim(csv_path, days=30):
    try:
        cutoff = time.time() - days * 86400
        with open(csv_path) as f:
            lines = f.readlines()
        keep_from = len(lines)  # default: remove all if nothing is fresh
        for i, line in enumerate(lines):
            parts = line.strip().split(",")
            if not parts:
                continue
            try:
                if _dt.fromisoformat(parts[0]).timestamp() >= cutoff:
                    keep_from = i
                    break
            except Exception:
                pass
        if keep_from > 0:
            with open(csv_path, "w") as f:
                f.writelines(lines[keep_from:])
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="syswatch-logger — background metrics sampler for syswatch",
    )
    parser.add_argument(
        "--interval", type=int, default=120, metavar="N",
        help="sample interval in seconds (default 120)",
    )
    parser.add_argument(
        "--version", action="version", version="syswatch-logger 1.0.0",
    )
    args = parser.parse_args()

    log_dir  = os.path.expanduser("~/.local/share/syswatch")
    csv_path = os.path.join(log_dir, "metrics.csv")
    os.makedirs(log_dir, exist_ok=True)

    # Prime cpu_percent so the first non-blocking call has a valid baseline.
    psutil.cpu_percent(interval=None)

    while True:
        try:
            cpu  = psutil.cpu_percent(interval=None)
            mem  = psutil.virtual_memory().percent
            temp = _cpu_temp()
            disk = psutil.disk_usage("/").percent
            ts   = _dt.now().strftime("%Y-%m-%dT%H:%M:%S")
            temp_str = f"{temp:.1f}" if temp is not None else ""
            line = f"{ts},{cpu:.1f},{mem:.1f},{temp_str},{disk:.1f}\n"
            with open(csv_path, "a") as f:
                f.write(line)
            _trim(csv_path)
        except Exception:
            pass
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
