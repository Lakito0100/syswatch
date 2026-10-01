#!/bin/bash
set -euo pipefail

LIB_DIR="/usr/local/lib/syswatch"
BIN_FILE="/usr/local/bin/syswatch"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UNATTENDED=0
SKIP_CONFIG=0
TARGET_USER=""

# ── helpers ───────────────────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 1; }

check_root() {
    [[ "$EUID" -eq 0 ]] || die "This script must be run as root (use sudo)."
}

check_python3() {
    command -v python3 >/dev/null 2>&1 || die "python3 is not available. Please install Python 3."
}

# Resolves the user syswatch is installed for — --user NAME if given,
# otherwise the human behind `sudo` — and their home directory, used both for
# the syswatch-logger systemd service's User= and for where config.toml gets
# written. Deliberately not $HOME: sudo commonly resets HOME to root's when
# env_reset is on, so trusting $HOME here would write root's config instead
# of the invoking user's. Run as plain root (no SUDO_USER) without --user,
# there is no one to pick: refuse rather than guess a username that most
# likely doesn't exist on this machine.
resolve_install_target() {
    INSTALL_USER="${TARGET_USER:-${SUDO_USER:-}}"
    if [[ -z "$INSTALL_USER" ]]; then
        die "Cannot tell which user to install for. Run via 'sudo' from your own account, or pass --user NAME (use --user root to run the logger as root)."
    fi
    # The `|| true` keeps a lookup failure (nonexistent user) from tripping
    # `set -e`/pipefail right here, silently killing the script before the
    # explicit check below gets a chance to report it properly.
    INSTALL_HOME="$(getent passwd "$INSTALL_USER" | cut -d: -f6)" || true
    [[ -n "$INSTALL_HOME" ]] || die "Could not resolve a home directory for user '$INSTALL_USER'."
    INSTALL_GROUP="$(id -gn "$INSTALL_USER" 2>/dev/null || echo "$INSTALL_USER")"
    CONFIG_PATH="$INSTALL_HOME/.config/syswatch/config.toml"
}

# ── uninstall ─────────────────────────────────────────────────────────────────

do_uninstall() {
    check_root
    echo "Uninstalling syswatch..."

    # Stop and disable syswatch-logger service
    SERVICE_DST="/etc/systemd/system/syswatch-logger.service"
    systemctl stop    syswatch-logger.service 2>/dev/null || true
    systemctl disable syswatch-logger.service 2>/dev/null || true
    if [[ -f "$SERVICE_DST" ]]; then
        rm -f "$SERVICE_DST"
        systemctl daemon-reload
        echo "  Removed $SERVICE_DST"
    fi

    if [[ -f "$BIN_FILE" ]]; then
        rm -f "$BIN_FILE"
        echo "  Removed $BIN_FILE"
    else
        echo "  $BIN_FILE not found, skipping."
    fi
    if [[ -d "$LIB_DIR" ]]; then
        rm -rf "$LIB_DIR"
        echo "  Removed $LIB_DIR"
    else
        echo "  $LIB_DIR not found, skipping."
    fi
    DOC_DIR="/usr/share/doc/syswatch"
    if [[ -d "$DOC_DIR" ]]; then
        rm -rf "$DOC_DIR"
        echo "  Removed $DOC_DIR"
    fi
    echo "syswatch uninstalled."
    echo "Note: ~/.config/syswatch/, ~/.local/share/syswatch/ (metrics, alert logs,"
    echo "known devices) were left in place."
}

# ── config.toml generation ───────────────────────────────────────────────────
#
# Only install-syswatch.sh drives the interactive prompting (reading input,
# reprompting, deciding what to ask); syswatch_config.py stays the one place
# that knows the TOML format and validation rules — every value typed here
# is validated via its validate_raw(), and the file itself is rendered via
# its write_default_config(), never assembled as text in this script.

run_py() {
    PYTHONPATH="$LIB_DIR" python3 "$@"
}

# validate_value SECTION KEY RAW — prints "OK <json-value>" or "ERR <msg>".
validate_value() {
    run_py - "$1" "$2" "$3" <<'PYEOF'
import sys, json
import syswatch_config as cfg
section, key, raw = sys.argv[1], sys.argv[2], sys.argv[3]
value, err = cfg.validate_raw(section, key, raw)
if err:
    print("ERR " + err)
else:
    print("OK " + json.dumps(value))
PYEOF
}

# Populates DEF_* bash variables from syswatch_config.defaults() so the
# prompts always show the actual built-in defaults, never a hand-copied
# number that could drift out of sync with the Python source of truth.
load_config_defaults() {
    local out
    out="$(run_py - <<'PYEOF'
import shlex
import syswatch_config as cfg

def fmt(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple)):
        # No enclosing brackets: the prompt already wraps this in its own
        # "[recommended value]" brackets, and "[[70, 80]]" reads as a typo
        # rather than nested syntax — validate_raw() accepts a bare
        # "70, 80" pair just as readily as "[70, 80]".
        return ", ".join(fmt(x) for x in v)
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)

d = cfg.defaults()
pairs = [
    ("DEF_CPU_PCT",         d["thresholds"]["cpu_pct"]),
    ("DEF_RAM_PCT",         d["thresholds"]["ram_pct"]),
    ("DEF_CPU_TEMP",        d["thresholds"]["cpu_temp"]),
    ("DEF_DISK_PCT",        d["thresholds"]["disk_pct"]),
    ("DEF_GPU_TEMP",        d["thresholds"]["gpu_temp"]),
    ("DEF_STORAGE_TEMP",    d["thresholds"]["storage_temp"]),
    ("DEF_SCAN",            d["network"]["scan"]),
    ("DEF_INTRUDER_ALERTS", d["network"]["intruder_alerts"]),
    ("DEF_REFRESH",         d["ui"]["refresh"]),
    ("DEF_DEFAULT_TAB",     d["ui"]["default_tab"]),
    ("DEF_LOG_INTERVAL",    d["logger"]["interval"]),
    ("DEF_LOG_RETENTION",   d["logger"]["retention_days"]),
]
for name, val in pairs:
    print(f"{name}={shlex.quote(fmt(val))}")
PYEOF
)"
    eval "$out"
}

# ask SECTION KEY QUESTION DEFAULT_DISPLAY — prompts, blank accepts the
# default, reprompts (via the real validator, never a hand-rolled check) on
# anything invalid. Leaves the validated value as JSON in $REPLY_JSON.
ask() {
    local section="$1" key="$2" question="$3" default_display="$4"
    local raw result
    while true; do
        raw=""
        read -r -p "  ${section}.${key} — ${question} [${default_display}]: " raw || raw=""
        [[ -z "$raw" ]] && raw="$default_display"
        result="$(validate_value "$section" "$key" "$raw")"
        case "$result" in
            "OK "*)
                REPLY_JSON="${result#OK }"
                return 0
                ;;
            "ERR "*)
                echo "    ${result#ERR } — try again." >&2
                ;;
            *)
                echo "    Validation failed unexpectedly — try again." >&2
                ;;
        esac
    done
}

# Runs the questionnaire and leaves the collected, validated answers as a
# JSON object in $OVERRIDES_JSON, ready for syswatch_config.write_default_config().
prompt_for_config() {
    load_config_defaults

    echo ""
    echo "  Setting up config.toml — press Enter to accept the suggested value."
    echo ""

    ask thresholds cpu_pct \
        "CPU usage % [warning, critical] — colors the CPU bars on the SYSTEM tab" \
        "$DEF_CPU_PCT"
    local j_cpu_pct="$REPLY_JSON"

    ask thresholds ram_pct \
        "RAM usage % [warning, critical] — colors the RAM bar on the SYSTEM tab" \
        "$DEF_RAM_PCT"
    local j_ram_pct="$REPLY_JSON"

    ask thresholds cpu_temp \
        "CPU temperature °C [warning, critical] — colors the CPU temp bar, triggers the audible alert" \
        "$DEF_CPU_TEMP"
    local j_cpu_temp="$REPLY_JSON"

    ask thresholds disk_pct \
        "Disk usage % [warning, critical] — colors disk usage indicators" \
        "$DEF_DISK_PCT"
    local j_disk_pct="$REPLY_JSON"

    ask thresholds gpu_temp \
        "GPU temperature °C [warning, critical] — colors the GPU temp bar" \
        "$DEF_GPU_TEMP"
    local j_gpu_temp="$REPLY_JSON"

    ask thresholds storage_temp \
        "Storage (SSD/eMMC/SD) temperature °C [warning, critical]" \
        "$DEF_STORAGE_TEMP"
    local j_storage_temp="$REPLY_JSON"

    ask network scan \
        'Active ping sweep: "trusted" = only on networks you explicitly confirm for scanning (press [s] on the NETWORK tab), "never" = never' \
        "$DEF_SCAN"
    local j_scan="$REPLY_JSON"

    ask network intruder_alerts \
        "Flag devices never seen on the current network as INTRUDER" \
        "$DEF_INTRUDER_ALERTS"
    local j_intruder_alerts="$REPLY_JSON"

    ask ui refresh \
        "TUI redraw interval in seconds (lower = smoother, more CPU)" \
        "$DEF_REFRESH"
    local j_refresh="$REPLY_JSON"

    ask ui default_tab \
        "Tab number the TUI opens on by default" \
        "$DEF_DEFAULT_TAB"
    local j_default_tab="$REPLY_JSON"

    ask logger interval \
        "Seconds between syswatch-logger background samples (metrics.csv)" \
        "$DEF_LOG_INTERVAL"
    local j_log_interval="$REPLY_JSON"

    ask logger retention_days \
        "Days of metrics.csv history kept before pruning" \
        "$DEF_LOG_RETENTION"
    local j_log_retention="$REPLY_JSON"

    OVERRIDES_JSON=$(cat <<JSON
{
  "thresholds": {
    "cpu_pct": $j_cpu_pct,
    "ram_pct": $j_ram_pct,
    "cpu_temp": $j_cpu_temp,
    "disk_pct": $j_disk_pct,
    "gpu_temp": $j_gpu_temp,
    "storage_temp": $j_storage_temp
  },
  "network": {
    "scan": $j_scan,
    "intruder_alerts": $j_intruder_alerts
  },
  "ui": {
    "refresh": $j_refresh,
    "default_tab": $j_default_tab
  },
  "logger": {
    "interval": $j_log_interval,
    "retention_days": $j_log_retention
  }
}
JSON
)
}

# Writes $CONFIG_PATH (interactively or with pure defaults) and fixes
# ownership. Assumes the caller already confirmed the file doesn't exist yet.
generate_config() {
    local interactive=1
    if [[ "$UNATTENDED" == "1" ]]; then
        interactive=0
    elif [[ ! -t 0 ]]; then
        echo "  No interactive terminal on stdin — writing default config.toml (same as --unattended)."
        interactive=0
    fi

    OVERRIDES_JSON="{}"
    if [[ "$interactive" == "1" ]]; then
        prompt_for_config
    fi

    local config_dir xdg_dir need_xdg_chown=0
    config_dir="$(dirname "$CONFIG_PATH")"
    xdg_dir="$(dirname "$config_dir")"
    [[ -d "$xdg_dir" ]] || need_xdg_chown=1

    local render_err
    if ! render_err="$(run_py -c '
import sys, json
import syswatch_config as cfg
overrides = json.load(sys.stdin)
print(cfg.write_default_config(path=sys.argv[1], overrides=overrides))
' "$CONFIG_PATH" <<<"$OVERRIDES_JSON" 2>&1)"; then
        echo "  WARNING: could not write $CONFIG_PATH:" >&2
        echo "  $render_err" >&2
        return 1
    fi

    chown -R "$INSTALL_USER:$INSTALL_GROUP" "$config_dir"
    [[ "$need_xdg_chown" == "1" ]] && chown "$INSTALL_USER:$INSTALL_GROUP" "$xdg_dir"

    echo "  Wrote $CONFIG_PATH (owned by $INSTALL_USER)"
}

# ── install ───────────────────────────────────────────────────────────────────

do_install() {
    check_root
    check_python3
    resolve_install_target

    SRC="$SCRIPT_DIR/syswatch.py"
    [[ -f "$SRC" ]] || die "syswatch.py not found in $SCRIPT_DIR"

    echo "Installing syswatch..."

    # 1. Copy syswatch.py and its shared sensor module to lib directory
    install -d -m 755 "$LIB_DIR"
    install -m 755 "$SRC" "$LIB_DIR/syswatch.py"
    echo "  Installed $LIB_DIR/syswatch.py"

    SRC_SENSORS="$SCRIPT_DIR/syswatch_sensors.py"
    [[ -f "$SRC_SENSORS" ]] || die "syswatch_sensors.py not found in $SCRIPT_DIR"
    install -m 755 "$SRC_SENSORS" "$LIB_DIR/syswatch_sensors.py"
    echo "  Installed $LIB_DIR/syswatch_sensors.py"

    SRC_CONFIG="$SCRIPT_DIR/syswatch_config.py"
    [[ -f "$SRC_CONFIG" ]] || die "syswatch_config.py not found in $SCRIPT_DIR"
    install -m 755 "$SRC_CONFIG" "$LIB_DIR/syswatch_config.py"
    echo "  Installed $LIB_DIR/syswatch_config.py"

    SRC_DEVICES="$SCRIPT_DIR/syswatch_known_devices.py"
    [[ -f "$SRC_DEVICES" ]] || die "syswatch_known_devices.py not found in $SCRIPT_DIR"
    install -m 755 "$SRC_DEVICES" "$LIB_DIR/syswatch_known_devices.py"
    echo "  Installed $LIB_DIR/syswatch_known_devices.py"

    # 2. Create wrapper in /usr/local/bin
    cat > "$BIN_FILE" <<'EOF'
#!/bin/bash
exec python3 /usr/local/lib/syswatch/syswatch.py "$@"
EOF
    chmod 755 "$BIN_FILE"
    echo "  Installed $BIN_FILE"

    # 3. Copy syswatch-logger.py
    SRC_LOGGER="$SCRIPT_DIR/syswatch-logger.py"
    if [[ -f "$SRC_LOGGER" ]]; then
        install -m 755 "$SRC_LOGGER" "$LIB_DIR/syswatch-logger.py"
        echo "  Installed $LIB_DIR/syswatch-logger.py"
    fi

    # 4. Install systemd service for syswatch-logger
    SERVICE_SRC="$SCRIPT_DIR/syswatch-logger.service"
    SERVICE_DST="/etc/systemd/system/syswatch-logger.service"
    if [[ -f "$SERVICE_SRC" ]]; then
        install -m 644 "$SERVICE_SRC" "$SERVICE_DST"
        # The repo service file ships with a default User=; rewrite it on the
        # installed copy so the logger runs as the human installing it.
        sed -i "s/^User=.*/User=${INSTALL_USER}/" "$SERVICE_DST"
        echo "  Installed $SERVICE_DST (User=${INSTALL_USER})"
        systemctl daemon-reload
        systemctl enable syswatch-logger.service
        # restart (not start) so an updated syswatch-logger.py takes effect on reinstall
        systemctl restart syswatch-logger.service
        if systemctl is-active --quiet syswatch-logger.service; then
            echo "  syswatch-logger service is running."
        else
            echo "  WARNING: syswatch-logger did not start — check: journalctl -u syswatch-logger"
        fi
    fi

    # 5. Install a commented example config to the doc dir. Never touches a
    # user's real config at ~/.config/syswatch/ — this is documentation only.
    DOC_DIR="/usr/share/doc/syswatch"
    install -d -m 755 "$DOC_DIR"
    EXAMPLE_TMP="$(mktemp)"
    if PYTHONPATH="$LIB_DIR" python3 -c \
        "import syswatch_config, sys; sys.stdout.write(syswatch_config.example_config_text())" \
        > "$EXAMPLE_TMP" 2>/dev/null; then
        install -m 644 "$EXAMPLE_TMP" "$DOC_DIR/config.example.toml"
        echo "  Installed $DOC_DIR/config.example.toml"
    else
        echo "  WARNING: could not generate config.example.toml"
    fi
    rm -f "$EXAMPLE_TMP"

    # 6. Generate (or preserve) the invoking user's real config.toml. Only
    # ever writes when nothing is there yet — an existing config on a
    # reinstall/upgrade is left completely untouched, no questionnaire.
    CONFIG_STATUS=""
    if [[ "$SKIP_CONFIG" == "1" ]]; then
        echo "  Skipping config.toml generation (--skip-config)."
        CONFIG_STATUS="not written (--skip-config) — run 'syswatch --write-default-config' any time"
    elif [[ -f "$CONFIG_PATH" ]]; then
        echo "  Config already exists at $CONFIG_PATH — leaving it untouched."
        CONFIG_STATUS="already existed at $CONFIG_PATH — left untouched"
    else
        if generate_config; then
            CONFIG_STATUS="written to $CONFIG_PATH"
        else
            CONFIG_STATUS="NOT written — see warning above; run 'syswatch --write-default-config' as $INSTALL_USER"
        fi
    fi

    # 7. Verify install
    echo "  Verifying install..."
    if "$BIN_FILE" --version; then
        echo ""
        echo "syswatch installed. Run it from anywhere with: syswatch"
        echo "Config: $CONFIG_STATUS"
        echo "See $DOC_DIR/config.example.toml for every available option."
    else
        die "Verification failed — syswatch --version did not succeed."
    fi
}

# ── usage ─────────────────────────────────────────────────────────────────────

usage() {
    cat <<USAGE
Usage: $0 [OPTIONS]

  (no options)     Install syswatch. Interactively asks for a handful of
                    config.toml settings (thresholds, scan mode, refresh
                    rate, ...) with the built-in default suggested in
                    [brackets] — press Enter to accept it. Skipped, and
                    pure defaults written instead, when stdin isn't a
                    terminal (e.g. curl ... | bash).
  --unattended      Skip all prompts; write config.toml with built-in
                    defaults. Implied automatically for non-interactive runs.
  --skip-config     Do not write a config.toml at all (today's behaviour —
                    generate one later with 'syswatch --write-default-config').
  --user NAME       Install for this user (logger service User=, config
                    location) instead of the one behind sudo. Required
                    when running as plain root without sudo.
  --uninstall       Remove syswatch. Leaves ~/.config/syswatch/ and
                    ~/.local/share/syswatch/ (config, metrics, known devices)
                    in place.
  -h, --help        Show this help.
USAGE
}

# ── dispatch ──────────────────────────────────────────────────────────────────

ACTION="install"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall)   ACTION="uninstall" ;;
        --unattended)  UNATTENDED=1 ;;
        --skip-config) SKIP_CONFIG=1 ;;
        --user)
            [[ $# -ge 2 && -n "$2" ]] || die "--user needs a username"
            TARGET_USER="$2"
            shift
            ;;
        --user=*)      TARGET_USER="${1#--user=}" ;;
        -h|--help)     ACTION="help" ;;
        *) die "Unknown argument: $1  Usage: $0 [--unattended] [--skip-config] [--user NAME] [--uninstall]" ;;
    esac
    shift
done

case "$ACTION" in
    uninstall) do_uninstall ;;
    help)      usage        ;;
    install)   do_install   ;;
esac
