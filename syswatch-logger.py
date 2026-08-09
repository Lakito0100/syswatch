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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import syswatch_sensors as sensors


def _core_voltage():
    # Pi-only: vcgencmd doesn't exist elsewhere, and there's no portable
    # equivalent for core voltage on other hardware.
    if not sensors.is_pi():
        return None
    try:
        r = subprocess.run(
            ["vcgencmd", "measure_volts", "core"],
            capture_output=True, text=True, timeout=0.5,
        )
        raw = r.stdout.strip()
        if raw.startswith("volt="):
            return float(raw[5:].rstrip("V"))
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
        "--version", action="version", version=f"syswatch-logger {sensors.VERSION}",
    )
    args = parser.parse_args()

    log_dir  = os.path.expanduser("~/.local/share/syswatch")
    csv_path = os.path.join(log_dir, "metrics.csv")
    os.makedirs(log_dir, exist_ok=True)

    # Prime cpu_percent so the first non-blocking call has a valid baseline.
    psutil.cpu_percent(interval=None)

    while True:
        try:
            cpu   = psutil.cpu_percent(interval=None)
            mem   = psutil.virtual_memory().percent
            temp  = sensors.cpu_temp()
            disk  = psutil.disk_usage("/").percent
            volt  = _core_voltage()
            gtemp = sensors.gpu_temp()
            stemp = sensors.storage_temp()
            try:
                batt = psutil.sensors_battery()
            except Exception:
                batt = None
            ts    = _dt.now().strftime("%Y-%m-%dT%H:%M:%S")
            temp_str  = f"{temp:.1f}" if temp is not None else ""
            # 4 decimals: core voltage moves in ~0.0125V steps, .1f would
            # collapse the whole series to one flat value.
            volt_str  = f"{volt:.4f}" if volt is not None else ""
            gtemp_str = f"{gtemp['temp']:.1f}" if gtemp is not None else ""
            stemp_str = f"{stemp:.1f}" if stemp is not None else ""
            batt_str  = f"{batt.percent:.1f}" if batt is not None else ""
            line = (f"{ts},{cpu:.1f},{mem:.1f},{temp_str},{disk:.1f},"
                     f"{volt_str},{gtemp_str},{stemp_str},{batt_str}\n")
            with open(csv_path, "a") as f:
                f.write(line)
            _trim(csv_path)
        except Exception:
            pass
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
