# syswatch

A terminal system monitor for Linux — Raspberry Pi, desktops, and laptops alike. syswatch displays CPU usage, memory, temperature (CPU, GPU, and storage, whatever sensors the machine actually has), network activity, connected devices, live journal logs, systemd service health, storage health, and (on machines with it installed) backup status — all in a single curses TUI that refreshes every second.

syswatch detects the hardware it's running on and adapts: Raspberry Pi throttle flags and core voltage only appear on a Pi; GPU temperature is read from whichever of NVIDIA/AMD/Intel is actually present; the STORAGE tab reads SMART data from whatever the root filesystem sits on (NVMe, SATA, SD/eMMC); rows with no available sensor are hidden rather than shown as `N/A`.

---

## Requirements

- Any Linux with systemd
- Python 3
- [psutil](https://github.com/giampaolo/psutil) — installed automatically on first run if missing
- [asciichartpy](https://github.com/kroitor/asciichart) — installed automatically on first run if missing

Soft dependencies (each feature degrades gracefully — hiding the relevant row — if the tool isn't installed):
- `lm-sensors` (`sensors-detect`) for CPU/motherboard temperature sensors on non-Pi hardware
- `smartmontools` (`smartctl`) for storage health/temperature when not exposed via `psutil.sensors_temperatures()`
- `nvidia-smi` for NVIDIA GPU temperature (ships with the NVIDIA driver)

---

## Install

```bash
sudo bash install-syswatch.sh
```

This copies `syswatch.py` and `syswatch_sensors.py` (the shared sensor-detection module) to `/usr/local/lib/syswatch/` and creates a wrapper at `/usr/local/bin/syswatch` so the command is available system-wide. It also copies `syswatch-logger.py`, installs `syswatch-logger.service`, and starts the service so metrics collection begins immediately.

---

## Run

```bash
syswatch [options]
```

| Flag | Description |
|------|-------------|
| `--tab N` | Start on tab N (1-based; the number of tabs depends on detected hardware — BACKUP only appears if `project-backup` is installed, so the count is 6 or 7) |
| `--refresh N` | Refresh interval in seconds (default 1.0, minimum 0.5) |
| `--no-scan` | Disable active ping sweep; use passive ARP table only |
| `--report` | Print a one-shot system report to stdout and exit (no TUI) |
| `--json` | With `--report`, output JSON instead of text |
| `--version` | Print version and exit |

Press `q`, `Q`, or `Esc` to quit. Press a number key to switch tabs directly — the tab bar shows each tab's number.

---

## Tabs

The tab bar always starts with SYSTEM, NETWORK, LOGS, SERVICES, STORAGE and ends with HISTORY. BACKUP is inserted between STORAGE and HISTORY only when `project-backup` is detected as installed — otherwise it's omitted and the remaining tabs (and their number keys) shift down by one. This means `--tab N` addresses a different tab depending on whether BACKUP is present; run with no arguments and check the tab bar if unsure.

### 1 · SYSTEM
Real-time CPU usage for each core plus an average bar with sparkline history. RAM and swap usage with bars, plus battery charge (percentage only) if the machine reports one — hidden entirely on desktops/servers/most Pi setups with no battery. CPU temperature, GPU temperature (vendor auto-detected: NVIDIA via `nvidia-smi`, AMD via sysfs `hwmon`, Intel via `psutil`'s `i915` sensor), and storage temperature — each with a visual bar, and each row hidden entirely if no working sensor is found. Current CPU clock frequency. On Raspberry Pi only: core voltage and a throttle indicator showing under-voltage, frequency cap, throttle, and soft-temp-limit flags (● = active now, ○ = never) — these are Pi-specific concepts (`vcgencmd`) with no portable equivalent, so they're simply absent on other hardware. Network RX/TX rates and disk read/write rates with per-channel sparklines. Top 5 processes by CPU with PID, name, CPU%, memory%, and status.

### 2 · NETWORK
Scans the local network using passive ARP table reading and an active ping sweep. Scan targets are derived from the machine's own network interfaces (`psutil.net_if_addrs()`) — every up, non-loopback IPv4 interface with a subnet of /22 or smaller is swept (larger subnets are skipped so a stray /16 can't queue tens of thousands of pings; link-local and /32 addresses, e.g. a Tailscale interface, are also skipped). If no usable interface is found, it falls back to auto-detecting a single /24 from the machine's primary IPv4 address, and finally to the `SCAN_SUBNET` constant (`192.168.0.x`–`192.168.1.x`) as a last resort. Lists every discovered device with IP address, MAC address, resolved hostname, time since last seen, and status (Active / Recent / Idle). Devices that appear more than 30 seconds after startup are flagged as **INTRUDER** and trigger a footer alert.

### 3 · LOGS
Streams the systemd journal in real time via `journalctl -f`. Shows service name, timestamp, and message for each entry. An error-rate sparkline and count in the header show errors per 60-second window. Press `/` to open the filter prompt (see below).

### 4 · SERVICES
Watches the services listed in `WATCHED_SERVICES` at the top of `syswatch.py` (default: ssh, networking, cron, bluetooth, avahi-daemon, triggerhappy). Displays active state, sub-state, main PID, restart count, time active since, and last result. A failed service is highlighted in red; a restart count above 5 triggers a critical colour.

### 5 · STORAGE
Reports the health of whatever device the root filesystem actually lives on — SD card, eMMC, NVMe, or SATA/USB disk — auto-detected via `psutil.disk_partitions()` and `lsblk`. NVMe and SATA disks are read via `smartctl`; SD/eMMC cards fall back to kernel sysfs registers (`pre_eol_info`, `life_time`) and dmesg error counts, same as before. Shows the detected device and type, SMART health status, storage temperature, power-on hours, bytes written this boot, filesystem usage for `/` and (if it's a separate mount) the boot partition — detected as whichever of `/boot/firmware`, `/boot`, `/boot/efi` actually has its own mount, so it isn't shown at all on a system with no separate boot partition — and raw I/O counters since boot.

### 6 · BACKUP *(only shown if `project-backup` is installed)*
> Requires the [project-backup](https://github.com/Lakito0100/backup-system) tool.

Reads `/var/log/project-backup-status.json` written by the `project-backup` tool. Displays the status, timestamp, duration, and file counts of the last backup run; lists configured source paths with existence checks; and shows a scrollable run history with a files-transferred sparkline. syswatch checks at startup whether `project-backup` is installed and enabled (systemd unit/timer, or the status file already exists); if not, this tab is omitted entirely rather than shown empty.

### 7 · HISTORY
Reads the metrics CSV recorded by syswatch-logger and renders line charts for CPU %, RAM %, CPU temperature, disk %, core voltage, GPU temperature, storage temperature, and battery charge over the selected time window — a chart is only drawn for a metric that has data in the current window, so e.g. the voltage chart won't appear on non-Pi hardware and the battery chart won't appear on a machine with no battery. Press `h` while on this tab to cycle between the last 1 hour, 8 hours, 24 hours, 7 days, and 30 days. If the terminal is too short to fit all charts, press `↓`/`↑` to scroll one chart at a time — the header shows the current position while scrolled. Each chart is coloured using the same warning/critical thresholds as the live display. If no data is available yet, a message prompts you to start syswatch-logger. When syswatch is launched with `sudo` (so `~` resolves to `/root`), it falls back to reading the invoking user's CSV at `/home/$SUDO_USER/.local/share/syswatch/metrics.csv`.

Data is plotted on a uniform time grid rather than one column per sample, so a gap in logging (the machine was off or asleep) occupies its true width on the chart — a dotted band — instead of collapsing to a single column with misleading axis labels.

---

## syswatch-logger

syswatch-logger is a lightweight background process that wakes up every 2 minutes (120 seconds, the default `--interval`), samples CPU %, RAM %, CPU temperature, root-disk usage, core voltage (Pi only), GPU temperature, storage temperature, and battery charge, and appends one CSV line to `~/.local/share/syswatch/metrics.csv`. Lines older than 30 days are trimmed automatically after each write.

`install-syswatch.sh` installs and starts syswatch-logger as a systemd service (`syswatch-logger.service`) running as the installed user. The service starts automatically on boot and restarts on failure.

**CSV location:** `~/.local/share/syswatch/metrics.csv`

Example rows (2-minute spacing; columns are timestamp, CPU %, RAM %, CPU temp, disk %, core voltage, GPU temp, storage temp, battery %):
```
2026-06-11T14:35:00,32.1,45.2,56.3,12.4,1.3125,48.0,41.9,89.5
2026-06-11T14:37:00,34.0,46.1,57.0,12.4,1.3125,47.0,41.9,89.5
```

A sensor that isn't available on the running machine logs as an empty field rather than `0`, so the HISTORY tab's charts can tell "no sensor" from "0 degrees" — e.g. on non-Pi hardware the voltage column is always blank, and its chart doesn't appear at all; a desktop or server with no battery leaves the last column blank the same way. Rows written by older versions have fewer columns: pre-1.1.0 rows have five (no voltage), 1.1.x rows have six (+voltage), 1.2.0 rows have eight (+GPU temp, +storage temp). All four widths remain fully compatible — the HISTORY tab reads them uniformly, so there is no need to delete or migrate an existing `metrics.csv`; older rows simply have no value in the columns that didn't exist yet.

To run the logger directly (e.g. for testing): `python3 syswatch-logger.py [--interval N] [--version]`

To change the sample interval permanently, add `--interval N` (seconds) to the `ExecStart=` line in `/etc/systemd/system/syswatch-logger.service`, then run `sudo systemctl daemon-reload && sudo systemctl restart syswatch-logger`. The HISTORY tab estimates the interval from the data, so its gap detection adapts automatically.

---

## Report mode

`syswatch --report` prints a one-shot snapshot to stdout and exits — no TUI, no background threads. It includes the detected hardware model, uptime, CPU/GPU/storage temperature, and (Raspberry Pi only) core voltage and throttle flags (current and since boot), the state of every watched service (failed units are called out), and disk usage for `/` and the boot partition (if it's a separate mount). Add `--json` for machine-readable output.

This is designed for cron and email digests, e.g. a daily report at 07:00:

```
0 7 * * * /usr/local/bin/syswatch --report | mail -s "System status" you@example.com
```

Values that cannot be read on the current hardware (e.g. no GPU sensor found, or core voltage/throttle flags on non-Pi hardware) are reported as `N/A` in text mode and `null` (or omitted, for the boot-partition disk entry when there is none) in JSON.

---

## Disk space alert

Like the temperature alert, syswatch monitors filesystem usage of `/` and, if present, the boot partition (checked every 60 seconds by the storage watcher). When usage crosses a threshold for the first time, it rings the terminal bell (`\a`) and appends a timestamped line to:

```
~/.local/share/syswatch/disk_alerts.log
```

The alert fires once per upward crossing per mount — it will not repeat every cycle while usage stays high, but will fire again if usage drops below the threshold and rises back above it.

Thresholds (configurable in `THRESH["disk_pct"]` at the top of `syswatch.py`):
- **WARNING** — 85 % used
- **CRITICAL** — 95 % used

These thresholds also colour the disk-usage bars on the SYSTEM, STORAGE, and HISTORY tabs.

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
