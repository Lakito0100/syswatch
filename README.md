# syswatch

A terminal system monitor for Raspberry Pi. syswatch displays CPU usage, memory, temperature, throttle state, network activity, connected devices, live journal logs, systemd service health, SD card health, and backup status — all in a single curses TUI that refreshes every second.

---

## Requirements

- Raspberry Pi OS (or any Linux with systemd)
- Python 3 (pre-installed on Raspberry Pi OS)
- [psutil](https://github.com/giampaolo/psutil) — installed automatically on first run if missing
- [asciichartpy](https://github.com/kroitor/asciichart) — installed automatically on first run if missing

---

## Install

```bash
sudo bash install-syswatch.sh
```

This copies `syswatch.py` to `/usr/local/lib/syswatch/` and creates a wrapper at `/usr/local/bin/syswatch` so the command is available system-wide. It also copies `syswatch-logger.py`, installs `syswatch-logger.service`, and starts the service so metrics collection begins immediately.

---

## Run

```bash
syswatch [options]
```

| Flag | Description |
|------|-------------|
| `--tab N` | Start on tab N (1-7, default 1) |
| `--refresh N` | Refresh interval in seconds (default 1.0, minimum 0.5) |
| `--no-scan` | Disable active ping sweep; use passive ARP table only |
| `--report` | Print a one-shot system report to stdout and exit (no TUI) |
| `--json` | With `--report`, output JSON instead of text |
| `--version` | Print version and exit |

Press `q`, `Q`, or `Esc` to quit. Press `1`–`7` to switch tabs directly.

---

## Tabs

### 1 · SYSTEM
Real-time CPU usage for each core plus an average bar with sparkline history. RAM and swap usage with bars. CPU and GPU temperature with a visual bar scaled to 90 °C, plus current clock frequency and core voltage. Throttle indicator showing under-voltage, frequency cap, throttle, and soft-temp-limit flags (● = active now, ○ = never). Network RX/TX rates and disk read/write rates with per-channel sparklines. Top 5 processes by CPU with PID, name, CPU%, memory%, and status.

### 2 · NETWORK
Scans the local network using passive ARP table reading and an active ping sweep across the Pi's own /24, auto-detected from its primary IPv4 address (falling back to the `SCAN_SUBNET` constant — `192.168.0.x`–`192.168.1.x` — if detection fails). Lists every discovered device with IP address, MAC address, resolved hostname, time since last seen, and status (Active / Recent / Idle). Devices that appear more than 30 seconds after startup are flagged as **INTRUDER** and trigger a footer alert.

### 3 · LOGS
Streams the systemd journal in real time via `journalctl -f`. Shows service name, timestamp, and message for each entry. An error-rate sparkline and count in the header show errors per 60-second window. Press `/` to open the filter prompt (see below).

### 4 · SERVICES
Watches the services listed in `WATCHED_SERVICES` at the top of `syswatch.py` (default: ssh, networking, cron, bluetooth, avahi-daemon, triggerhappy). Displays active state, sub-state, main PID, restart count, time active since, and last result. A failed service is highlighted in red; a restart count above 5 triggers a critical colour.

### 5 · SD CARD
Reports the health of `/dev/mmcblk0` (SD card or eMMC). Tries `smartctl` first, then falls back to kernel sysfs registers (`pre_eol_info`, `life_time`) and dmesg error counts. Shows SMART health status, SoC temperature, power-on hours, bytes written this boot, filesystem usage for `/` and `/boot`, and raw I/O counters since boot.

### 6 · BACKUP
> Requires the [project-backup](https://github.com/Lakito0100/backup-system) tool.

Reads `/var/log/project-backup-status.json` written by the `project-backup` tool. Displays the status, timestamp, duration, and file counts of the last backup run; lists configured source paths with existence checks; and shows a scrollable run history with a files-transferred sparkline.

### 7 · HISTORY
Reads the metrics CSV recorded by syswatch-logger and renders line charts for CPU %, RAM %, CPU temperature, disk %, and core voltage over the selected time window. Press `h` while on this tab to cycle between the last 1 hour, 8 hours, 24 hours, 7 days, and 30 days. If the terminal is too short to fit all charts, press `↓`/`↑` to scroll one chart at a time — the header shows the current position while scrolled. Each chart is coloured using the same warning/critical thresholds as the live display. If no data is available yet, a message prompts you to start syswatch-logger. When syswatch is launched with `sudo` (so `~` resolves to `/root`), it falls back to reading the invoking user's CSV at `/home/$SUDO_USER/.local/share/syswatch/metrics.csv`.

---

## syswatch-logger

syswatch-logger is a lightweight background process that wakes up every 2 minutes (120 seconds, the default `--interval`), samples CPU %, RAM %, CPU temperature, root-disk usage, and core voltage, and appends one CSV line to `~/.local/share/syswatch/metrics.csv`. Lines older than 30 days are trimmed automatically after each write.

`install-syswatch.sh` installs and starts syswatch-logger as a systemd service (`syswatch-logger.service`) running as the installed user. The service starts automatically on boot and restarts on failure.

**CSV location:** `~/.local/share/syswatch/metrics.csv`

Example rows (2-minute spacing; columns are timestamp, CPU %, RAM %, CPU temp, disk %, core voltage):
```
2026-06-11T14:35:00,32.1,45.2,56.3,12.4,1.3125
2026-06-11T14:37:00,34.0,46.1,57.0,12.4,1.3125
```

Rows written by versions before 1.1.0 have five columns (no voltage). They stay fully compatible — the HISTORY tab reads both formats, so there is no need to delete or migrate an existing `metrics.csv`; old rows simply have no voltage value.

To run the logger directly (e.g. for testing): `python3 syswatch-logger.py [--interval N] [--version]`

To change the sample interval permanently, add `--interval N` (seconds) to the `ExecStart=` line in `/etc/systemd/system/syswatch-logger.service`, then run `sudo systemctl daemon-reload && sudo systemctl restart syswatch-logger`. The HISTORY tab estimates the interval from the data, so its gap detection adapts automatically.

---

## Report mode

`syswatch --report` prints a one-shot snapshot to stdout and exits — no TUI, no background threads. It includes uptime, CPU/GPU temperature, core voltage, throttle flags (current and since boot), the state of every watched service (failed units are called out), and disk usage for `/` and `/boot`. Add `--json` for machine-readable output.

This is designed for cron and email digests, e.g. a daily report at 07:00:

```
0 7 * * * /usr/local/bin/syswatch --report | mail -s "Pi status" you@example.com
```

Values that cannot be read on the current hardware (e.g. `vcgencmd` temperatures on a non-Pi machine) are reported as `N/A` in text mode and `null` in JSON.

> Note: on Raspberry Pi OS Bookworm and later the boot partition is mounted at `/boot/firmware`; the `/boot` line then reflects the root filesystem. This matches the SD CARD tab's existing behaviour.

---

## Disk space alert

Like the temperature alert, syswatch monitors filesystem usage of `/` and `/boot` (checked every 60 seconds by the SD-card watcher). When usage crosses a threshold for the first time, it rings the terminal bell (`\a`) and appends a timestamped line to:

```
~/.local/share/syswatch/disk_alerts.log
```

The alert fires once per upward crossing per mount — it will not repeat every cycle while usage stays high, but will fire again if usage drops below the threshold and rises back above it.

Thresholds (configurable in `THRESH["disk_pct"]` at the top of `syswatch.py`):
- **WARNING** — 85 % used
- **CRITICAL** — 95 % used

These thresholds also colour the disk-usage bars on the SYSTEM, SD CARD, and HISTORY tabs.

Example log entries:

```
2026-07-02 09:14:03 WARNING disk=/ 86.2% (threshold=85%)
2026-07-02 11:41:56 CRITICAL disk=/boot 95.4% (threshold=95%)
```

---

## Log filter (Logs tab)

While on the **LOGS** tab, press `/` to open the filter prompt at the bottom of the screen. Type any substring to filter entries by service name or message text. Press **Enter** to apply the filter (only matching lines are shown). Press **Esc** to clear the filter and return to the full log view. The active filter is shown in the header bar.

---

## Temperature alert log

When the CPU temperature crosses a threshold for the first time, syswatch rings the terminal bell (`\a`) and appends a timestamped line to:

```
~/.local/share/syswatch/temp_alerts.log
```

The directory is created automatically if it does not exist. The alert fires once per upward crossing — it will not repeat every second while the temperature stays high, but will fire again if the temperature drops below the threshold and rises back above it.

Thresholds (configurable in `THRESH["cpu_temp"]` at the top of `syswatch.py`):
- **WARNING** — 70 °C
- **CRITICAL** — 80 °C

Example log entries:

```
2026-06-11 14:32:17 WARNING cpu_temp=72.5C (threshold=70C)
2026-06-11 14:35:02 CRITICAL cpu_temp=81.3C (threshold=80C)
```

---

## Uninstall

```bash
sudo bash install-syswatch.sh --uninstall
```

This stops and disables `syswatch-logger.service`, removes its service file, and removes `/usr/local/bin/syswatch` and `/usr/local/lib/syswatch/`. It does not remove `~/.local/share/syswatch/` (the metrics CSV and alert log).
