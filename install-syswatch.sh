#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Install locations. The SYSWATCH_* overrides exist only so the test suite can
# install into a scratch directory — leave them unset for a real install.
LIB_DIR="${SYSWATCH_LIB_DIR:-/usr/local/lib/syswatch}"
BIN_FILE="${SYSWATCH_BIN:-/usr/local/bin/syswatch}"
UNIT_DIR="${SYSWATCH_UNIT_DIR:-/etc/systemd/system}"
DOC_DIR="${SYSWATCH_DOC_DIR:-/usr/share/doc/syswatch}"
ROOT_HOME="${SYSWATCH_ROOT_HOME:-$(getent passwd root | cut -d: -f6 || true)}"
ROOT_HOME="${ROOT_HOME:-/root}"
# Where find_stray_launchers looks besides the target user's ~/.local/bin and
# ~/bin. Overridable so the tests don't see the real install's launcher.
if [[ -v SYSWATCH_LAUNCHER_DIRS ]]; then
    LAUNCHER_DIRS="$SYSWATCH_LAUNCHER_DIRS"
else
    LAUNCHER_DIRS="${PATH:-}:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin"
fi
SERVICE_DST="$UNIT_DIR/syswatch-logger.service"

UNATTENDED=0
SKIP_CONFIG=0
PURGE=0
TARGET_USER=""
INTERACTIVE=0   # set in dispatch: 1 only with a terminal and no --unattended

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
# likely doesn't exist on this machine. With "soft" as $1 (uninstall), an
# unknown user isn't fatal: INSTALL_USER is left empty instead.
resolve_install_target() {
    INSTALL_USER="${TARGET_USER:-${SUDO_USER:-}}"
    if [[ -z "$INSTALL_USER" ]]; then
        [[ "${1:-}" == "soft" ]] && return 0
        die "Cannot tell which user to install for. Run via 'sudo' from your own account, or pass --user NAME (use --user root to run the logger as root)."
    fi
    # The `|| true` keeps a lookup failure (nonexistent user) from tripping
    # `set -e`/pipefail right here, silently killing the script before the
    # explicit check below gets a chance to report it properly.
    INSTALL_HOME="$(getent passwd "$INSTALL_USER" | cut -d: -f6)" || true
    [[ -n "$INSTALL_HOME" ]] || die "Could not resolve a home directory for user '$INSTALL_USER'."
    INSTALL_GROUP="$(id -gn "$INSTALL_USER" 2>/dev/null || echo "$INSTALL_USER")"
    CONFIG_PATH="$INSTALL_HOME/.config/syswatch/config.toml"
    DATA_DIR="$INSTALL_HOME/.local/share/syswatch"
}

# ask_yes_no QUESTION DEFAULT — DEFAULT is y or n, used for an empty answer
# and, without a terminal (or with --unattended), as the answer itself.
# Returns 0 for yes.
ask_yes_no() {
    local question="$1" default="$2" hint reply
    if [[ "$default" == "y" ]]; then hint="[Y/n]"; else hint="[y/N]"; fi
    if [[ "$INTERACTIVE" != "1" ]]; then
        [[ "$default" == "y" ]]
        return
    fi
    while true; do
        reply=""
        read -r -p "      $question $hint " reply || reply=""
        case "${reply,,}" in
            "")     [[ "$default" == "y" ]]; return ;;
            y|yes)  return 0 ;;
            n|no)   return 1 ;;
            *)      echo "      Please answer y or n." ;;
        esac
    done
}

# Summaries of existing config/data files come from syswatch_inventory.py in
# the source tree being installed, so the shell never parses TOML/CSV/JSON.
inventory() {
    run_py "$SCRIPT_DIR/syswatch_inventory.py" "$@"
}

version_in() {
    # VERSION as recorded in the .py files of directory $1, or empty for
    # versions too old to record one. Read with grep rather than by running
    # the old code: pre-1.4 versions pip-installed missing modules on start.
    grep -hoE '^VERSION = "[0-9][0-9.]*"' "$1"/*.py 2>/dev/null | head -n 1 \
        | grep -oE '[0-9][0-9.]*' || true
}

safe_rm_dir() {
    # rm -rf, but only on a path that is plainly one of syswatch's own
    # directories — never an empty or unexpected value.
    local dir="$1"
    [[ -n "$dir" && "$dir" != "/" && "$(basename "$dir")" == "syswatch" ]] \
        || die "refusing to remove unexpected directory '$dir'"
    rm -rf -- "$dir"
}

# ── existing program files ───────────────────────────────────────────────────

remove_program_files() {
    systemctl stop    syswatch-logger.service 2>/dev/null || true
    systemctl disable syswatch-logger.service 2>/dev/null || true
    if [[ -f "$SERVICE_DST" ]]; then
        rm -f -- "$SERVICE_DST"
        systemctl daemon-reload 2>/dev/null || true
        echo "    Removed $SERVICE_DST"
    fi
    if [[ -e "$BIN_FILE" ]]; then
        rm -f -- "$BIN_FILE"
        echo "    Removed $BIN_FILE"
    fi
    if [[ -e "$LIB_DIR" ]]; then
        safe_rm_dir "$LIB_DIR"
        echo "    Removed $LIB_DIR"
    fi
    if [[ -e "$DOC_DIR" ]]; then
        safe_rm_dir "$DOC_DIR"
        echo "    Removed $DOC_DIR"
    fi
}

# Every version so far installed to the same four places. Whatever is there
# is removed wholesale before the new files go in, so no module, cache or
# unit from an older layout can linger next to the new version.
detect_and_remove_old_install() {
    local found=() p old_ver
    for p in "$LIB_DIR" "$BIN_FILE" "$SERVICE_DST" "$DOC_DIR"; do
        [[ -e "$p" ]] && found+=("$p")
    done
    if (( ${#found[@]} == 0 )); then
        echo "  No previous installation found."
        return
    fi
    old_ver="$(version_in "$LIB_DIR")"
    if [[ "$old_ver" == "$NEW_VERSION" ]]; then
        echo "  Found syswatch $old_ver (same version) — reinstalling it:"
    else
        echo "  Found an older syswatch (${old_ver:-version not recorded, older than 1.1}) — replacing it with $NEW_VERSION:"
    fi
    remove_program_files
}

# Copies of the `syswatch` launcher somewhere other than $BIN_FILE (an old
# manual install, ~/.local/bin, ...) would shadow or outlive this install.
find_stray_launchers() {
    local dirs=() d f key seen=" " real_bin
    real_bin="$(realpath -m "$BIN_FILE")"
    IFS=: read -r -a dirs <<< "$LAUNCHER_DIRS"
    [[ -n "${INSTALL_HOME:-}" ]] && dirs+=("$INSTALL_HOME/.local/bin" "$INSTALL_HOME/bin")
    for d in "${dirs[@]}"; do
        [[ -n "$d" ]] || continue
        f="$d/syswatch"
        [[ -e "$f" || -L "$f" ]] || continue
        # Resolved only to recognise duplicates and $BIN_FILE itself — what
        # gets removed is always "$d/syswatch": for a symlink that's the
        # link, never the file it points to (which may be in a source tree).
        key="$(realpath -m "$(dirname "$f")")/syswatch"
        [[ "$seen" == *" $key "* ]] && continue
        seen+="$key "
        [[ "$key" == "$real_bin" || "$(realpath -m "$f")" == "$real_bin" ]] && continue
        if grep -qs "syswatch" "$f"; then
            echo "  Found another syswatch launcher: $f"
            if ask_yes_no "Remove it?" n; then
                rm -f -- "$f"
                echo "      Removed."
            else
                echo "      Kept — it may run a different version than $BIN_FILE."
            fi
        fi
    done
}

# Pre-1.4 versions pip-installed asciichartpy on first run; it's bundled now.
# Only reported: something else on the system might use it.
report_pip_leftovers() {
    local origin
    origin="$(python3 -c 'import importlib.util as u; s = u.find_spec("asciichartpy"); print(s.origin if s else "")' 2>/dev/null || true)"
    if [[ -n "$origin" ]]; then
        echo "  Note: asciichartpy is installed at $(dirname "$origin") (pip-installed by older"
        echo "        syswatch versions). syswatch bundles it now, so it isn't needed any more;"
        echo "        if nothing else uses it: sudo python3 -m pip uninstall --break-system-packages asciichartpy"
    fi
}

ensure_psutil() {
    if python3 -c 'import psutil' 2>/dev/null; then
        return
    fi
    if command -v apt-get >/dev/null 2>&1; then
        echo "  Installing python3-psutil (apt)..."
        apt-get install -y python3-psutil >/dev/null \
            || die "Could not install python3-psutil — run 'sudo apt install python3-psutil' and re-run."
    else
        die "psutil is missing. Install your distribution's python3-psutil package and re-run."
    fi
}

# ── existing config and data ─────────────────────────────────────────────────

# review_data_dir DIR TITLE — one-line summary of every file in DIR and a
# keep (default) / delete question each.
review_data_dir() {
    local dir="$1" title="$2" skip="${3:-}" files=() f
    [[ -d "$dir" ]] || return 0
    while IFS= read -r f; do
        [[ -n "$skip" && "$(basename -- "$f")" == "$skip" ]] || files+=("$f")
    done < <(inventory files "$dir")
    (( ${#files[@]} )) || return 0
    echo "  $title ($dir):"
    for f in "${files[@]}"; do
        echo "    - $(inventory file "$f")"
        if ! ask_yes_no "Keep it?" y; then
            rm -f -- "$f"
            echo "      Deleted."
        fi
    done
    rmdir --ignore-fail-on-non-empty "$dir" 2>/dev/null || true
}

# review_config_dir DIR — config.toml, then every other file in DIR: the
# config.toml.bak-* copies a "replace" saves were otherwise never offered for
# deletion, so they outlived an uninstall unless --purge was used.
review_config_dir() {
    local dir="$1"
    if [[ -f "$dir/config.toml" ]]; then
        review_config_for_removal "$dir/config.toml" || true
    fi
    review_data_dir "$dir" "Other config files" config.toml
}

# review_config_for_removal PATH — summary + keep (default) / delete.
# Returns 0 if the file is still there afterwards.
review_config_for_removal() {
    local path="$1"
    [[ -f "$path" ]] || return 1
    echo "  Config:"
    inventory config "$path" | sed 's/^/    /'
    if ask_yes_no "Keep it?" y; then
        return 0
    fi
    rm -f -- "$path"
    rmdir --ignore-fail-on-non-empty "$(dirname "$path")" 2>/dev/null || true
    echo "      Deleted."
    return 1
}

handle_config() {
    if [[ "$SKIP_CONFIG" == "1" ]]; then
        echo "  Skipping config.toml (--skip-config)."
        CONFIG_STATUS="not written (--skip-config) — run 'syswatch --write-default-config' any time"
        return
    fi
    if [[ -f "$CONFIG_PATH" ]]; then
        echo "  Existing config found:"
        inventory config "$CONFIG_PATH" | sed 's/^/    /'
        if ask_yes_no "Keep this config? (no = save it as a backup and set up a new one)" y; then
            CONFIG_STATUS="kept existing $CONFIG_PATH"
            return
        fi
        local backup
        backup="$CONFIG_PATH.bak-$(date +%Y%m%d-%H%M%S)"
        mv -- "$CONFIG_PATH" "$backup"
        echo "      Saved the old config as $backup"
        if generate_config; then
            CONFIG_STATUS="new config written to $CONFIG_PATH (old one saved as $backup)"
        else
            CONFIG_STATUS="NOT written — see warning above; old one saved as $backup"
        fi
        return
    fi
    if generate_config; then
        CONFIG_STATUS="written to $CONFIG_PATH"
    else
        CONFIG_STATUS="NOT written — see warning above; run 'syswatch --write-default-config' as $INSTALL_USER"
    fi
}

# Older versions run with `sudo` wrote config and data into root's home
# rather than the user's. Offer to clean those up when installing for a
# regular user; never touch them when root *is* the install user.
review_root_leftovers() {
    [[ "$INSTALL_USER" == "root" ]] && return 0
    [[ "$(realpath -m "$ROOT_HOME")" == "$(realpath -m "$INSTALL_HOME")" ]] && return 0
    local cfg_dir="$ROOT_HOME/.config/syswatch"
    local data="$ROOT_HOME/.local/share/syswatch"
    [[ -d "$cfg_dir" || -d "$data" ]] || return 0
    echo ""
    echo "  Found syswatch files in root's home — most likely left by running an older"
    echo "  version with sudo. syswatch $NEW_VERSION uses $INSTALL_USER's files even under sudo."
    review_config_dir "$cfg_dir"
    review_data_dir "$data" "Data"
}

# Files in the user's syswatch directories owned by someone else (root, from
# an older version run with sudo) can't be updated by syswatch afterwards.
fix_ownership() {
    [[ "$INSTALL_USER" == "root" ]] && return 0
    local d wrong
    for d in "$INSTALL_HOME/.config/syswatch" "$DATA_DIR"; do
        [[ -d "$d" ]] || continue
        wrong="$(find "$d" ! -user "$INSTALL_USER" -print 2>/dev/null | wc -l)"
        if (( wrong > 0 )); then
            chown -R "$INSTALL_USER:$INSTALL_GROUP" "$d"
            echo "  Gave $wrong file(s) in $d back to $INSTALL_USER (were owned by another user)."
        fi
    done
}

# ── config.toml generation ───────────────────────────────────────────────────
#
# Only install-syswatch.sh drives the interactive prompting (reading input,
# reprompting, deciding what to ask); syswatch_config.py stays the one place
# that knows the TOML format and validation rules — every value typed here
# is validated via its validate_raw(), and the file itself is rendered via
# its write_default_config(), never assembled as text in this script.

# Runs Python against the source tree being installed (not whatever is in
# $LIB_DIR, which may be an old version or already removed). No bytecode
# caches: this runs as root inside the user's checkout.
run_py() {
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 "$@"
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
    local interactive="$INTERACTIVE"

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

install_program_files() {
    [[ -f "$SCRIPT_DIR/syswatch.py" ]] || die "syswatch.py not found in $SCRIPT_DIR"
    install -d -m 755 "$LIB_DIR"
    local f mode
    for f in "$SCRIPT_DIR"/syswatch*.py; do
        case "$(basename "$f")" in
            syswatch.py|syswatch-logger.py) mode=755 ;;
            *)                              mode=644 ;;
        esac
        install -m "$mode" "$f" "$LIB_DIR/$(basename "$f")"
    done
    echo "  Installed $(find "$LIB_DIR" -maxdepth 1 -name '*.py' | wc -l) files to $LIB_DIR"

    install -d -m 755 "$(dirname "$BIN_FILE")"
    printf '#!/bin/bash\nexec python3 %q "$@"\n' "$LIB_DIR/syswatch.py" > "$BIN_FILE"
    chmod 755 "$BIN_FILE"
    echo "  Installed $BIN_FILE"

    local service_src="$SCRIPT_DIR/syswatch-logger.service"
    if [[ -f "$service_src" ]]; then
        install -d -m 755 "$UNIT_DIR"
        install -m 644 "$service_src" "$SERVICE_DST"
        # The repo unit ships with a placeholder User=; run the logger as the
        # user installing it, from wherever the files actually went.
        sed -i -e "s|^User=.*|User=${INSTALL_USER}|" \
               -e "s|/usr/local/lib/syswatch/|${LIB_DIR}/|" "$SERVICE_DST"
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

    # A commented example config, for reference only — the user's real
    # config is handled by handle_config().
    install -d -m 755 "$DOC_DIR"
    local example_tmp
    example_tmp="$(mktemp)"
    if run_py -c "import syswatch_config, sys; sys.stdout.write(syswatch_config.example_config_text())" \
        > "$example_tmp" 2>/dev/null; then
        install -m 644 "$example_tmp" "$DOC_DIR/config.example.toml"
        echo "  Installed $DOC_DIR/config.example.toml"
    else
        echo "  WARNING: could not generate config.example.toml"
    fi
    rm -f "$example_tmp"
}

do_install() {
    check_root
    check_python3
    resolve_install_target
    NEW_VERSION="$(version_in "$SCRIPT_DIR")"
    [[ -n "$NEW_VERSION" ]] || die "Could not read the version of the syswatch in $SCRIPT_DIR"

    echo "Installing syswatch $NEW_VERSION for $INSTALL_USER..."
    [[ "$INTERACTIVE" == "1" ]] || echo "  (non-interactive: existing config and data files will be kept)"

    echo ""
    echo "Checking for an existing installation..."
    detect_and_remove_old_install
    find_stray_launchers
    report_pip_leftovers

    echo ""
    echo "Installing..."
    ensure_psutil
    install_program_files

    echo ""
    echo "Config and data for $INSTALL_USER..."
    CONFIG_STATUS=""
    handle_config
    review_data_dir "$DATA_DIR" "Existing data files"
    review_root_leftovers
    fix_ownership

    echo ""
    echo "Verifying install..."
    if "$BIN_FILE" --version; then
        echo ""
        echo "syswatch installed. Run it from anywhere with: syswatch"
        echo "Config: $CONFIG_STATUS"
        echo "See $DOC_DIR/config.example.toml for every available option."
        echo "Active network scanning is off until you trust a network: [s] on the NETWORK tab."
    else
        die "Verification failed — syswatch --version did not succeed."
    fi
}

# ── uninstall ─────────────────────────────────────────────────────────────────

purge_user_files() {
    local home="$1" d
    for d in "$home/.config/syswatch" "$home/.local/share/syswatch"; do
        if [[ -d "$d" ]]; then
            safe_rm_dir "$d"
            echo "    Deleted $d"
        fi
    done
}

review_user_files() {
    local home="$1" title="$2"
    local cfg_dir="$home/.config/syswatch"
    [[ -d "$cfg_dir" || -d "$home/.local/share/syswatch" ]] || return 0
    echo ""
    echo "$title"
    review_config_dir "$cfg_dir"
    review_data_dir "$home/.local/share/syswatch" "Data"
}

do_uninstall() {
    check_root
    resolve_install_target soft
    echo "Uninstalling syswatch..."
    remove_program_files
    echo "  Program files removed."

    local homes=()
    [[ -n "${INSTALL_HOME:-}" ]] && homes+=("$INSTALL_HOME")
    if [[ -z "${INSTALL_HOME:-}" || "$(realpath -m "$ROOT_HOME")" != "$(realpath -m "${INSTALL_HOME:-}")" ]]; then
        homes+=("$ROOT_HOME")
    fi

    local home
    if [[ "$PURGE" == "1" ]]; then
        echo ""
        echo "Deleting config and data (--purge)..."
        for home in "${homes[@]}"; do
            purge_user_files "$home"
        done
    elif [[ "$INTERACTIVE" == "1" ]]; then
        for home in "${homes[@]}"; do
            review_user_files "$home" "Config and data in $home:"
        done
    else
        echo "  Config and data were kept (~/.config/syswatch, ~/.local/share/syswatch);"
        echo "  re-run interactively to review them, or with --purge to delete them."
    fi
    echo ""
    echo "syswatch uninstalled."
}

# ── usage ─────────────────────────────────────────────────────────────────────

usage() {
    cat <<USAGE
Usage: $0 [OPTIONS]

  (no options)     Install or upgrade syswatch. An existing installation
                    (any older version) is detected and replaced. An
                    existing config.toml is summarised (settings that differ
                    from the defaults, anything this version changes) and
                    you choose to keep it or replace it; each existing data
                    file (metrics history, alert logs, known devices, ...)
                    is summarised and you choose to keep or delete it.
                    Keeping is always the default. With no config yet, asks
                    a handful of config.toml settings with the built-in
                    default in [brackets] — press Enter to accept it.
  --unattended      No questions: replace the program, keep every existing
                    config and data file, write a default config.toml if
                    there is none. Implied when stdin isn't a terminal.
  --skip-config     Do not write or review config.toml (generate one later
                    with 'syswatch --write-default-config').
  --user NAME       Install for this user (logger service User=, config
                    location) instead of the one behind sudo. Required
                    when running as plain root without sudo.
  --uninstall       Remove syswatch, then offer to delete its config and
                    data files one by one (default: keep). Without a
                    terminal everything is kept.
  --purge           With --uninstall: delete all config and data files
                    without asking.
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
        --purge)       PURGE=1 ;;
        --user)
            [[ $# -ge 2 && -n "$2" ]] || die "--user needs a username"
            TARGET_USER="$2"
            shift
            ;;
        --user=*)      TARGET_USER="${1#--user=}" ;;
        -h|--help)     ACTION="help" ;;
        *) die "Unknown argument: $1  Usage: $0 [--unattended] [--skip-config] [--user NAME] [--uninstall [--purge]]" ;;
    esac
    shift
done

[[ "$PURGE" == "1" && "$ACTION" != "uninstall" ]] && die "--purge only applies to --uninstall"
if [[ "$UNATTENDED" != "1" && -t 0 ]]; then
    INTERACTIVE=1
fi

case "$ACTION" in
    uninstall) do_uninstall ;;
    help)      usage        ;;
    install)   do_install   ;;
esac
