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
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import syswatch_sensors as sensors
import syswatch_config

# Same safety net as syswatch.py: this is a long-running daemon with no
# threads of its own today, but installing this is free and means a future
# change that does add one won't silently lose crash visibility.
threading.excepthook = sensors.log_uncaught_thread_exception


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
    except Exception as e:
        sensors.note_error("_core_voltage", e)
    return None


def _append_alert(log_dir, filename, msg):
    try:
        path = os.path.join(log_dir, filename)
        ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "a") as f:
            f.write(f"{ts} {msg}\n")
        # No-op unless running under sudo, where a newly created alert log
        # would otherwise be root-owned inside the user's home.
        sensors.chown_to_invoking_user(path)
    except Exception as e:
        sensors.note_error("_append_alert", e)


def _check_temp_alert(log_dir, temp, thresh_pair, prev_level):
    if temp is None or not thresh_pair:
        return prev_level
    warn, crit = thresh_pair
    level = 2 if temp >= crit else 1 if temp >= warn else 0
    if level > prev_level:
        label     = "CRITICAL" if level == 2 else "WARNING"
        threshold = crit if level == 2 else warn
        _append_alert(log_dir, "temp_alerts.log",
                      f"{label} cpu_temp={temp:.1f}C (threshold={threshold}C)")
    return level


def _check_disk_alert(log_dir, pct, thresh_pair, prev_level):
    if pct is None or not thresh_pair:
        return prev_level
    warn, crit = thresh_pair
    level = 2 if pct >= crit else 1 if pct >= warn else 0
    if level > prev_level:
        label     = "CRITICAL" if level == 2 else "WARNING"
        threshold = crit if level == 2 else warn
        _append_alert(log_dir, "disk_alerts.log",
                      f"{label} disk=/ {pct:.1f}% (threshold={threshold}%)")
    return level


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
    except Exception as e:
        sensors.note_error("_trim", e)


def main():
    parser = argparse.ArgumentParser(
        description="syswatch-logger — background metrics sampler for syswatch",
    )
    parser.add_argument(
        "--interval", type=int, default=None, metavar="N",
        help="sample interval in seconds (overrides config; default 120)",
    )
    parser.add_argument(
        "--config", type=str, default=None, metavar="PATH",
        help="use this config file instead of the default "
             "($XDG_CONFIG_HOME/syswatch/config.toml)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="log every collector failure (which one, exception, full "
             "traceback) to ~/.local/share/syswatch/debug.log",
    )
    parser.add_argument(
        "--version", action="version", version=f"syswatch-logger {sensors.VERSION}",
    )
    args = parser.parse_args()
    sensors.set_debug(args.debug)

    config, cfg_errors = syswatch_config.load_config(args.config)
    for e in cfg_errors:
        print(f"config: {e}", file=sys.stderr)

    interval       = args.interval if args.interval is not None else config["logger"]["interval"]
    retention_days = config["logger"]["retention_days"]
    thresh         = config["thresholds"]

    # Sudo-aware (see sensors.user_data_path). The service normally runs as the
    # real user, where this is just ~/.local/share/syswatch; it matters when
    # someone runs the logger by hand under sudo, which would otherwise start a
    # second metrics.csv under /root that the HISTORY tab never shows.
    csv_path = sensors.user_data_path("metrics.csv")
    log_dir  = os.path.dirname(csv_path)
    os.makedirs(log_dir, exist_ok=True)
    # Once at startup rather than per-sample: this is a long-running daemon and
    # ownership only needs correcting for files it had to create.
    sensors.chown_to_invoking_user(log_dir, csv_path)

    # Prime cpu_percent so the first non-blocking call has a valid baseline.
    psutil.cpu_percent(interval=None)

    temp_alert_level = 0
    disk_alert_level = 0

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
            except Exception as e:
                sensors.note_error("main (psutil.sensors_battery)", e)
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
            _trim(csv_path, days=retention_days)
            temp_alert_level = _check_temp_alert(log_dir, temp, thresh.get("cpu_temp"), temp_alert_level)
            disk_alert_level = _check_disk_alert(log_dir, disk, thresh.get("disk_pct"), disk_alert_level)
        except Exception as e:
            sensors.note_error("main (sample loop)", e)
        time.sleep(interval)


if __name__ == "__main__":
    main()
