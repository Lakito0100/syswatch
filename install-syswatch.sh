#!/bin/bash
set -euo pipefail

LIB_DIR="/usr/local/lib/syswatch"
BIN_FILE="/usr/local/bin/syswatch"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── helpers ───────────────────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 1; }

check_root() {
    [[ "$EUID" -eq 0 ]] || die "This script must be run as root (use sudo)."
}

check_python3() {
    command -v python3 >/dev/null 2>&1 || die "python3 is not available. Please install Python 3."
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
    echo "syswatch uninstalled."
}

# ── install ───────────────────────────────────────────────────────────────────

do_install() {
    check_root
    check_python3

    SRC="$SCRIPT_DIR/syswatch.py"
    [[ -f "$SRC" ]] || die "syswatch.py not found in $SCRIPT_DIR"

    echo "Installing syswatch..."

    # 1. Copy syswatch.py to lib directory
    install -d -m 755 "$LIB_DIR"
    install -m 755 "$SRC" "$LIB_DIR/syswatch.py"
    echo "  Installed $LIB_DIR/syswatch.py"

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
        # installed copy so the logger runs as the human installing it (the user
        # behind sudo), falling back to 'lukas' if SUDO_USER is unset.
        INSTALL_USER="${SUDO_USER:-lukas}"
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

    # 5. Verify install
    echo "  Verifying install..."
    if "$BIN_FILE" --version; then
        echo ""
        echo "syswatch installed. Run it from anywhere with: syswatch"
    else
        die "Verification failed — syswatch --version did not succeed."
    fi
}

# ── dispatch ──────────────────────────────────────────────────────────────────

case "${1:-}" in
    --uninstall) do_uninstall ;;
    "")          do_install   ;;
    *)           die "Unknown argument: $1  Usage: $0 [--uninstall]" ;;
esac
