#!/usr/bin/env python3
"""syswatch_inventory — human-readable summaries of an existing syswatch
config and data files, for install-syswatch.sh.

The installer asks whether to keep each existing file on an upgrade or
uninstall. This module does the reading — TOML, CSV, JSON — so the shell
script never has to parse any of it. It only reads; it never changes a file.

Command-line use (from the installer):
    syswatch_inventory.py config PATH   multi-line summary of a config.toml
    syswatch_inventory.py file PATH     one-line summary of a data/log file
    syswatch_inventory.py files DIR     the data files in DIR, one per line
"""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import syswatch_config  # noqa: E402

# Shown first, in this order; anything else in the directory follows.
KNOWN_DATA_FILES = (
    "metrics.csv",
    "temp_alerts.log",
    "disk_alerts.log",
    "known_devices.json",
    "trusted_networks.json",
    "debug.log",
)
# Internal bookkeeping, not user data — never worth a question.
INTERNAL_FILES = ("alerts.lock",)

# Keys that older versions used and this one ignores.
DEPRECATED_KEYS = {
    ("network", "subnet"): "no longer used — scanning only covers subnets "
                           "you confirm when trusting a network",
}


def _size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _mtime(path):
    try:
        return datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
    except OSError:
        return "?"


def _fmt(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_fmt(x) for x in v) + "]"
    if isinstance(v, str):
        return f'"{v}"'
    return str(v)


# ── config ────────────────────────────────────────────────────────────────────

def config_summary(path):
    """Lines describing `path`: when it was last changed, every setting that
    differs from the built-in defaults, and anything this version would
    reject, downgrade or ignore."""
    lines = [f"{path} (last changed {_mtime(path)})"]
    try:
        with open(path, encoding="utf-8") as f:
            raw = syswatch_config._parse_toml(f.read())
    except Exception as e:
        lines.append(f"  ! can't be read or parsed: {e}")
        lines.append("    (syswatch would ignore it and use built-in defaults)")
        return lines
    if not isinstance(raw, dict):
        lines.append("  ! not a valid config (top level isn't a table)")
        return lines

    defaults = syswatch_config.defaults()
    config, errors = syswatch_config.load_config(path)
    changed, deprecated = [], []
    for section in sorted(raw):
        values = raw[section]
        if not isinstance(values, dict):
            continue
        for key in sorted(values):
            if (section, key) in DEPRECATED_KEYS:
                deprecated.append(f"  - {section}.{key} = {_fmt(values[key])}: "
                                  f"{DEPRECATED_KEYS[(section, key)]}")
                continue
            if section not in defaults or key not in defaults[section]:
                continue  # reported via `errors`
            value, default = config[section][key], defaults[section][key]
            if value != default:
                changed.append(f"  {section}.{key} = {_fmt(value)}   (default {_fmt(default)})")
    if changed:
        lines.append("  Settings that differ from the defaults:")
        lines.extend("  " + c for c in changed)
    else:
        lines.append("  All settings are the built-in defaults.")
    if errors or deprecated:
        lines.append("  Notes for this version:")
        lines.extend(f"  - {e}" for e in errors)
        lines.extend(deprecated)
    return lines


# ── data files ────────────────────────────────────────────────────────────────

def _summary_metrics(path):
    rows, first, last = 0, None, None
    with open(path, errors="replace") as f:
        for line in f:
            ts = line.split(",", 1)[0].strip()
            try:
                when = datetime.fromisoformat(ts)
            except ValueError:
                continue
            rows += 1
            first = when if first is None or when < first else first
            last = when if last is None or when > last else last
    if not rows:
        return "metrics history: no samples"
    return (f"metrics history: {rows} samples, {first:%Y-%m-%d} → {last:%Y-%m-%d}")


def _summary_alerts(path, what):
    last, count = None, 0
    with open(path, errors="replace") as f:
        for line in f:
            if line.strip():
                count += 1
                last = line.strip()
    if not count:
        return f"{what} alert log: empty"
    entries = "1 entry" if count == 1 else f"{count} entries"
    return f"{what} alert log: {entries}, last: {last[:70]}"


def _summary_known_devices(path):
    import syswatch_known_devices as kd
    data = kd.load(path)
    devices = sum(len(v) for v in data.values())
    return f"known devices: {devices} device(s) on {len(data)} network(s)"


def _summary_trusted(path):
    import syswatch_trusted_networks as tn
    data = tn.load(path)
    if not data:
        return "networks trusted for scanning: none"
    names = "; ".join((info.get("label") or net_id) for net_id, info in data.items())
    return f"networks trusted for scanning: {len(data)} ({names[:80]})"


def file_summary(path):
    """One line describing a syswatch data/log file. Never raises."""
    name = os.path.basename(path)
    try:
        size = _size(os.path.getsize(path))
        if name == "metrics.csv":
            detail = _summary_metrics(path)
        elif name == "temp_alerts.log":
            detail = _summary_alerts(path, "temperature")
        elif name == "disk_alerts.log":
            detail = _summary_alerts(path, "disk")
        elif name == "known_devices.json":
            detail = _summary_known_devices(path)
        elif name == "trusted_networks.json":
            detail = _summary_trusted(path)
        elif name == "debug.log":
            detail = "debug log"
        elif name.startswith("config.toml"):
            detail = "config backup"
        else:
            detail = "other file"
        return f"{name}: {detail} ({size}, last changed {_mtime(path)})"
    except Exception as e:
        return f"{name}: can't be read ({e})"


def data_files(directory):
    """Data files in `directory` (non-recursive), known ones first."""
    try:
        names = [n for n in os.listdir(directory)
                 if os.path.isfile(os.path.join(directory, n)) and n not in INTERNAL_FILES]
    except OSError:
        return []
    order = {n: i for i, n in enumerate(KNOWN_DATA_FILES)}
    names.sort(key=lambda n: (order.get(n, len(order)), n))
    return [os.path.join(directory, n) for n in names]


def main(argv):
    if len(argv) != 3 or argv[1] not in ("config", "file", "files"):
        sys.stderr.write(__doc__)
        return 2
    cmd, arg = argv[1], argv[2]
    if cmd == "config":
        print("\n".join(config_summary(arg)))
    elif cmd == "file":
        print(file_summary(arg))
    else:
        for p in data_files(arg):
            print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
