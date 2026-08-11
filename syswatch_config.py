#!/usr/bin/env python3
"""syswatch_config — loads, validates and merges syswatch's TOML config file.

Precedence is CLI flags > config file > built-in defaults; this module only
handles the "config file > built-in defaults" half — callers (syswatch.py,
syswatch-logger.py) apply CLI overrides on top of what load_config() returns.

Validation is total: a malformed file, an unknown key, a wrong type or an
out-of-range value can never raise past this module. Bad values are reported
in the returned error list and the built-in default is used instead.
"""

import ipaddress
import os
import re
import subprocess

import syswatch_sensors as sensors


# ── locating the config file ─────────────────────────────────────────────────

def config_path_default():
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(xdg, "syswatch", "config.toml")


# ── platform-aware service defaults ──────────────────────────────────────────

def _service_exists(unit):
    try:
        r = subprocess.run(
            ["systemctl", "show", unit, "--property=LoadState",
             "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=2,
        )
        return r.returncode == 0 and "LoadState=not-found" not in r.stdout
    except Exception:
        return False


def _default_watched_services():
    if sensors.is_pi():
        return ["ssh", "networking", "cron", "bluetooth", "avahi-daemon", "triggerhappy"]
    # Non-Pi: only default to services that actually exist on this machine —
    # a hardcoded Pi-flavored list shows every unit as "not-found" elsewhere.
    candidate_groups = [
        ("ssh", "sshd"),
        ("cron",),
        ("NetworkManager", "networking"),
        ("bluetooth",),
    ]
    result = []
    for group in candidate_groups:
        for unit in group:
            if _service_exists(unit):
                result.append(unit)
                break
    return result


# ── built-in defaults ─────────────────────────────────────────────────────────

_DEFAULT_THRESH = {
    "cpu_pct":      (80, 95),
    "ram_pct":      (75, 90),
    "cpu_temp":     (70, 80),
    "disk_pct":     (85, 95),
    "gpu_temp":     (85, 95),
    "storage_temp": (65, 75),
}

_DEFAULT_NETWORK = {
    "scan":                          True,
    "subnet":                        "192.168.1.0/24",
    "intruder_alerts":               True,
    "arp_refresh":                   2.0,
    "ping_cycle":                    420.0,
    "ping_batch":                    10,
    "intruder_ttl":                  600.0,
    "baseline_window":               60.0,
    "known_devices_retention_days":  90,
}

_DEFAULT_UI = {
    "refresh":          1.0,
    "default_tab":      1,
    "top_n":            5,
    "history":          60,
    "alert_ttl":        30.0,
    "watchdog_refresh": 10.0,
    "storage_refresh":  60.0,
}

_DEFAULT_LOGGER = {
    "interval":       120,
    "retention_days": 30,
}


def defaults():
    """A fresh copy of the built-in defaults (platform-aware service list computed now)."""
    return {
        "services":   {"watch": _default_watched_services()},
        "thresholds": {k: tuple(v) for k, v in _DEFAULT_THRESH.items()},
        "network":    dict(_DEFAULT_NETWORK),
        "ui":         dict(_DEFAULT_UI),
        "logger":     dict(_DEFAULT_LOGGER),
    }


# ── validators ────────────────────────────────────────────────────────────────

def _v_bool(path, v, errors):
    if not isinstance(v, bool):
        errors.append(f"{path}: expected true/false, got {v!r}")
        return None
    return v


def _v_str_list(path, v, errors):
    if not isinstance(v, list) or not all(isinstance(i, str) for i in v):
        errors.append(f"{path}: expected an array of strings")
        return None
    return list(v)


def _v_subnet(path, v, errors):
    if not isinstance(v, str):
        errors.append(f"{path}: expected a string")
        return None
    try:
        ipaddress.IPv4Network(v, strict=False)
    except Exception:
        errors.append(f"{path}: invalid subnet {v!r} (expected CIDR, e.g. 192.168.1.0/24)")
        return None
    return v


def _v_int(lo=None, hi=None):
    def validator(path, v, errors):
        if isinstance(v, bool) or not isinstance(v, int):
            errors.append(f"{path}: expected an integer, got {v!r}")
            return None
        if (lo is not None and v < lo) or (hi is not None and v > hi):
            errors.append(f"{path}: {v} out of range ({lo}-{hi})")
            return None
        return v
    return validator


def _v_num(lo=None, hi=None):
    def validator(path, v, errors):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            errors.append(f"{path}: expected a number, got {v!r}")
            return None
        fv = float(v)
        if (lo is not None and fv < lo) or (hi is not None and fv > hi):
            errors.append(f"{path}: {v} out of range ({lo}-{hi})")
            return None
        return fv
    return validator


def _v_thresh_pair(path, v, errors):
    if not isinstance(v, list) or len(v) != 2:
        errors.append(f"{path}: expected [warn, critical]")
        return None
    warn, crit = v
    if (isinstance(warn, bool) or isinstance(crit, bool)
            or not all(isinstance(n, (int, float)) for n in (warn, crit))):
        errors.append(f"{path}: warn/critical must be numbers")
        return None
    warn, crit = float(warn), float(crit)
    if not (0 <= warn <= 1000 and 0 <= crit <= 1000):
        errors.append(f"{path}: values must be within 0-1000")
        return None
    if warn > crit:
        errors.append(f"{path}: warn must be <= critical")
        return None
    return (warn, crit)


_SCHEMA = {
    "services": {
        "watch": _v_str_list,
    },
    "thresholds": {
        k: _v_thresh_pair for k in _DEFAULT_THRESH
    },
    "network": {
        "scan":                         _v_bool,
        "subnet":                       _v_subnet,
        "intruder_alerts":              _v_bool,
        "arp_refresh":                  _v_num(0.1, 3600),
        "ping_cycle":                   _v_num(1, 86400),
        "ping_batch":                   _v_int(1, 1000),
        "intruder_ttl":                 _v_num(0, 86400 * 30),
        "baseline_window":              _v_num(0, 3600),
        "known_devices_retention_days": _v_int(1, 3650),
    },
    "ui": {
        "refresh":          _v_num(0.1, 60),
        "default_tab":      _v_int(1, 20),
        "top_n":            _v_int(1, 50),
        "history":          _v_int(2, 10000),
        "alert_ttl":        _v_num(1, 3600),
        "watchdog_refresh": _v_num(1, 3600),
        "storage_refresh":  _v_num(1, 3600),
    },
    "logger": {
        "interval":       _v_int(1, 86400),
        "retention_days": _v_int(1, 3650),
    },
}


# ── minimal TOML fallback parser (Python < 3.11, no tomllib) ────────────────
#
# Covers only the documented subset: single-level tables ([section]), quoted
# strings, ints, floats, booleans, flat arrays and # comments. Not a general
# TOML implementation — multi-line strings, nested tables, dotted keys,
# inline tables and datetimes are all out of scope.

class _TomlFallbackError(ValueError):
    pass


def _strip_comment(line):
    in_str  = False
    quote   = ""
    escaped = False
    for i, c in enumerate(line):
        if in_str:
            if escaped:
                escaped = False
            elif c == "\\" and quote == '"':
                escaped = True
            elif c == quote:
                in_str = False
        else:
            if c in ("'", '"'):
                in_str = True
                quote = c
            elif c == "#":
                return line[:i]
    return line


def _split_top_level(s):
    parts = []
    cur = ""
    in_str = False
    quote = ""
    for c in s:
        if in_str:
            cur += c
            if c == quote:
                in_str = False
        else:
            if c in ("'", '"'):
                in_str = True
                quote = c
                cur += c
            elif c == ",":
                parts.append(cur)
                cur = ""
            else:
                cur += c
    if cur.strip():
        parts.append(cur)
    return parts


def _parse_scalar(s, lineno):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return s[1:-1].encode().decode("unicode_escape")
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1]
    if s == "true":
        return True
    if s == "false":
        return False
    if re.fullmatch(r"[+-]?\d+", s):
        return int(s)
    try:
        return float(s)
    except ValueError:
        raise _TomlFallbackError(f"line {lineno}: cannot parse value {s!r}")


def _parse_value(val, lineno):
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item.strip(), lineno) for item in _split_top_level(inner)]
    return _parse_scalar(val, lineno)


def _parse_toml_fallback(text):
    data = {}
    current = None
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if not section:
                raise _TomlFallbackError(f"line {lineno}: empty table name")
            current = data.setdefault(section, {})
            continue
        if "=" not in line:
            raise _TomlFallbackError(f"line {lineno}: expected 'key = value'")
        key, _, val = line.partition("=")
        key = key.strip()
        if not key:
            raise _TomlFallbackError(f"line {lineno}: missing key")
        parsed = _parse_value(val, lineno)
        if current is None:
            raise _TomlFallbackError(
                f"line {lineno}: key outside of any [section]")
        current[key] = parsed
    return data


def _parse_toml(text):
    try:
        import tomllib
    except ModuleNotFoundError:
        return _parse_toml_fallback(text)
    return tomllib.loads(text)


# ── loading + merging ─────────────────────────────────────────────────────────

def _merge_validated(cfg, raw, errors):
    for section, values in raw.items():
        if section not in _SCHEMA:
            errors.append(f"unknown section [{section}]")
            continue
        if not isinstance(values, dict):
            errors.append(f"[{section}]: expected a table")
            continue
        for key, val in values.items():
            validator = _SCHEMA[section].get(key)
            if validator is None:
                errors.append(f"{section}.{key}: unknown key")
                continue
            result = validator(f"{section}.{key}", val, errors)
            if result is not None:
                cfg[section][key] = result


def load_config(path=None):
    """Load and validate the config file, merged over built-in defaults.

    Returns (config, errors). config always has the full schema populated
    (missing/invalid keys fall back to defaults). errors is a list of human
    -readable problem descriptions; a missing config file is NOT an error —
    it produces an empty errors list.
    """
    errors = []
    cfg = defaults()
    used_path = path or config_path_default()

    if not os.path.exists(used_path):
        return cfg, errors

    try:
        with open(used_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        errors.append(f"could not read {used_path}: {e}")
        return cfg, errors

    try:
        raw = _parse_toml(text)
    except Exception as e:
        errors.append(f"could not parse {used_path}: {e}")
        return cfg, errors

    if not isinstance(raw, dict):
        errors.append(f"{used_path}: top level must be a table")
        return cfg, errors

    _merge_validated(cfg, raw, errors)
    return cfg, errors


# ── writing an example config ────────────────────────────────────────────────

def example_config_text():
    services = _default_watched_services()
    services_toml = ", ".join(f'"{s}"' for s in services)
    return f'''# syswatch configuration
#
# Location: $XDG_CONFIG_HOME/syswatch/config.toml (default ~/.config/syswatch/config.toml)
# Precedence: CLI flags > this file > built-in defaults.
#
# Any key you omit falls back to its built-in default. An invalid value
# (wrong type, out of range, unknown key) is ignored and reported as a
# startup warning rather than blocking syswatch from starting.

[services]
# Systemd units watched on the SERVICES tab and in --report.
watch = [{services_toml}]

[thresholds]
# Each threshold is [warning, critical].
cpu_pct      = [80, 95]
ram_pct      = [75, 90]
cpu_temp     = [70, 80]
disk_pct     = [85, 95]
gpu_temp     = [85, 95]
storage_temp = [65, 75]

[network]
scan             = true                 # active ping sweep in addition to passive ARP reading
subnet           = "192.168.1.0/24"     # fallback CIDR swept when no local network is auto-detected
intruder_alerts  = true                 # flag devices never seen on this network as INTRUDER
arp_refresh      = 2.0                  # seconds between ARP table reads
ping_cycle       = 420                  # seconds to sweep every host once
ping_batch       = 10                   # concurrent pings per batch
intruder_ttl     = 600                  # seconds before an INTRUDER downgrades to Idle
baseline_window  = 60                   # seconds to silently learn devices the first time a network is seen
known_devices_retention_days = 90       # prune allowlist entries not seen in N days

[ui]
refresh          = 1.0   # seconds between redraws (minimum enforced: 0.5)
default_tab      = 1     # 1-based tab to start on
top_n            = 5     # processes shown on the SYSTEM tab
history          = 60    # samples kept for in-memory sparklines
alert_ttl        = 30    # seconds a footer alert stays visible
watchdog_refresh = 10.0  # seconds between service-status checks
storage_refresh  = 60.0  # seconds between storage/SMART checks

[logger]
interval       = 120  # seconds between syswatch-logger samples
retention_days = 30   # days of metrics.csv history kept
'''


def write_default_config(path=None, force=False):
    """Write a fully commented example config. Raises FileExistsError if the
    file already exists and force is False. Returns the path written."""
    path = path or config_path_default()
    if os.path.exists(path) and not force:
        raise FileExistsError(path)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(example_config_text())
    os.replace(tmp, path)
    return path
