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
    """Where the config lives when no --config PATH was given.

    Mirrors how the HISTORY tab locates metrics.csv (see
    sensors.user_data_path): under `sudo syswatch`, `~` is root's home, so a
    config written by the real user would otherwise be invisible and syswatch
    would silently run on built-in thresholds. An explicit XDG_CONFIG_HOME
    always wins; otherwise prefer whichever file actually exists, falling back
    to the invoking user's location so a config *written* under sudo lands in
    their home rather than root's.
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "syswatch", "config.toml")
    own = os.path.join(os.path.expanduser("~/.config"), "syswatch", "config.toml")
    if os.path.exists(own):
        return own
    home = sensors.invoking_user_home()
    if home:
        return os.path.join(home, ".config", "syswatch", "config.toml")
    return own


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
    "scan":                          "known",
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


def _v_scan_mode(path, v, errors):
    # Normalizes to one of "known" / "always" / "never" — the same
    # vocabulary --scan uses. Accepts real TOML booleans (true/false) and
    # the strings "known", "true", "false" so an existing `scan = true` or
    # `scan = false` config keeps working exactly as before.
    if isinstance(v, bool):
        return "always" if v else "never"
    if isinstance(v, str):
        lv = v.strip().lower()
        if lv == "known":
            return "known"
        if lv == "true":
            return "always"
        if lv == "false":
            return "never"
    errors.append(f'{path}: expected "known", true, or false, got {v!r}')
    return None


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
        "scan":                         _v_scan_mode,
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


def validate_raw(section, key, raw_text):
    """Validate one hand-typed value for `section.key` using the exact same
    parser and validator load_config() uses on the config file — the single
    entry point interactive prompts (install-syswatch.sh) call so there's
    only one place that knows what's a valid value for a given key.

    raw_text is parsed the same way a config file's value would be (TOML
    scalars/arrays via the fallback parser above), with two allowances that
    make sense for a typed reply but not a config file: unquoted bareword
    strings (e.g. `known` instead of `"known"`), and a bare comma-separated
    pair for an array value (e.g. `70, 80` instead of `[70, 80]` — typing
    the enclosing brackets isn't obvious when the prompt already wraps the
    suggested default in brackets of its own). Returns (value, None) on
    success or (None, error_message) on failure.
    """
    if section not in _SCHEMA or key not in _SCHEMA[section]:
        return None, f"{section}.{key}: unknown key"
    text = raw_text.strip()
    try:
        parsed = _parse_value(text, 0)
    except _TomlFallbackError:
        if "," in text and not (text.startswith("[") and text.endswith("]")):
            try:
                parsed = _parse_value(f"[{text}]", 0)
            except _TomlFallbackError:
                parsed = text
        else:
            parsed = text
    errors = []
    value = _SCHEMA[section][key](f"{section}.{key}", parsed, errors)
    if value is None:
        return None, "; ".join(errors) if errors else f"{section}.{key}: invalid value"
    return value, None


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
        # A missing file at the *default* path is the normal case (no config
        # written yet) and stays silent. A file the caller explicitly asked
        # for is different: a typo, or a relative path resolved against the
        # wrong cwd, would otherwise run on built-in defaults with no hint
        # that the requested file was never read.
        if path is not None:
            errors.append(f"{used_path}: no such file — using built-in defaults")
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
#
# example_config_text() takes an optional `overrides` — a sparse dict shaped
# like {"thresholds": {"cpu_pct": (80.0, 95.0)}, "network": {...}, ...} —
# used by install-syswatch.sh to bake in a few interactively-answered values
# (already validated via validate_raw()) while leaving every other key's
# comment and formatting exactly as the fully-defaulted example reads. With
# no overrides (or overrides=None) the output is byte-identical to before.

def _fmt_num_bare(v):
    # 80.0 -> "80" (matches the bare-int style the hand-written defaults
    # below use), 85.5 -> "85.5".
    fv = float(v)
    return str(int(fv)) if fv.is_integer() else str(fv)


def _fmt_thresh(default_pair, override):
    warn, crit = override if override is not None else default_pair
    return f"[{_fmt_num_bare(warn)}, {_fmt_num_bare(crit)}]"


def _fmt_scan(override):
    # validate_raw()/_v_scan_mode normalize to "known"/"always"/"never",
    # but only "known" is itself valid *inside* a config file — "always"/
    # "never" round-trip as the true/false spelling load_config() accepts.
    mode = override if override is not None else "known"
    return {"known": '"known"', "always": "true", "never": "false"}[mode]


def _fmt_bool(v):
    return "true" if v else "false"


def example_config_text(overrides=None):
    overrides = overrides or {}
    th  = overrides.get("thresholds", {})
    net = overrides.get("network", {})
    ui  = overrides.get("ui", {})
    lg  = overrides.get("logger", {})

    services = _default_watched_services()
    services_toml = ", ".join(f'"{s}"' for s in services)

    cpu_pct      = _fmt_thresh(_DEFAULT_THRESH["cpu_pct"],      th.get("cpu_pct"))
    ram_pct      = _fmt_thresh(_DEFAULT_THRESH["ram_pct"],      th.get("ram_pct"))
    cpu_temp     = _fmt_thresh(_DEFAULT_THRESH["cpu_temp"],     th.get("cpu_temp"))
    disk_pct     = _fmt_thresh(_DEFAULT_THRESH["disk_pct"],     th.get("disk_pct"))
    gpu_temp     = _fmt_thresh(_DEFAULT_THRESH["gpu_temp"],     th.get("gpu_temp"))
    storage_temp = _fmt_thresh(_DEFAULT_THRESH["storage_temp"], th.get("storage_temp"))

    scan            = _fmt_scan(net.get("scan"))
    intruder_alerts = _fmt_bool(net.get("intruder_alerts", _DEFAULT_NETWORK["intruder_alerts"]))

    # str(float(...)) always keeps a decimal point (str(float(1)) == "1.0"),
    # matching the hand-written "1.0" default without truncating precision
    # on a value like 0.33 the way a fixed-decimal format would.
    refresh     = str(float(ui.get("refresh", _DEFAULT_UI["refresh"])))
    default_tab = int(ui.get("default_tab", _DEFAULT_UI["default_tab"]))

    log_interval  = int(lg.get("interval", _DEFAULT_LOGGER["interval"]))
    log_retention = int(lg.get("retention_days", _DEFAULT_LOGGER["retention_days"]))

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
cpu_pct      = {cpu_pct}
ram_pct      = {ram_pct}
cpu_temp     = {cpu_temp}
disk_pct     = {disk_pct}
gpu_temp     = {gpu_temp}
storage_temp = {storage_temp}

[network]
# scan controls the active ping sweep and takes three values:
#   "known" (default) — sweep only if the current network is already in
#                        known_devices.json; passive ARP reading everywhere
#                        else. Press [t] on the NETWORK tab (or run
#                        --trust-all-devices) to mark a network as known.
#   true               — always sweep, regardless of whether the network
#                        is known (the old unconditional behaviour)
#   false              — never sweep; passive ARP reading only
scan             = {scan}
subnet           = "192.168.1.0/24"     # fallback CIDR swept when no local network is auto-detected
intruder_alerts  = {intruder_alerts}                 # flag devices never seen on this network as INTRUDER
arp_refresh      = 2.0                  # seconds between ARP table reads
ping_cycle       = 420                  # seconds to sweep every host once
ping_batch       = 10                   # concurrent pings per batch
intruder_ttl     = 600                  # seconds before an INTRUDER downgrades to Idle
baseline_window  = 60                   # seconds to silently learn devices the first time a network is seen
known_devices_retention_days = 90       # prune allowlist entries not seen in N days

[ui]
refresh          = {refresh}   # seconds between redraws (minimum enforced: 0.5)
default_tab      = {default_tab}     # 1-based tab to start on
top_n            = 5     # processes shown on the SYSTEM tab
history          = 60    # samples kept for in-memory sparklines
alert_ttl        = 30    # seconds a footer alert stays visible
watchdog_refresh = 10.0  # seconds between service-status checks
storage_refresh  = 60.0  # seconds between storage/SMART checks

[logger]
interval       = {log_interval}  # seconds between syswatch-logger samples
retention_days = {log_retention}   # days of metrics.csv history kept
'''


def write_default_config(path=None, force=False, overrides=None):
    """Write a fully commented example config, with `overrides` (see
    example_config_text()) baked in where given. Raises FileExistsError if
    the file already exists and force is False. Returns the path written."""
    path = path or config_path_default()
    if os.path.exists(path) and not force:
        raise FileExistsError(path)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(example_config_text(overrides))
    os.replace(tmp, path)
    # config_path_default() resolves to the invoking user's home under sudo, so
    # without this `sudo syswatch --write-default-config` would leave a
    # root-owned config they can't edit unprivileged.
    sensors.chown_to_invoking_user(d, path)
    return path
