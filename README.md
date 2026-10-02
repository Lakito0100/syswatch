# syswatch

A terminal system monitor for Linux (Debian, Ubuntu, Pop!_OS, Raspberry Pi OS, and most other systemd-based distros). syswatch displays CPU usage, memory, temperature (CPU, GPU, and storage, whatever sensors the machine actually has), battery charge, network activity, connected devices, live journal logs, systemd service health, storage health, and (on machines with it installed) backup status — all in a single curses TUI that refreshes every second.

syswatch detects the hardware it's running on and adapts: Raspberry Pi throttle flags and core voltage only appear on a Pi; GPU temperature is read from whichever of NVIDIA (`nvidia-smi`), AMD (sysfs `hwmon`), or Intel (`psutil`'s `i915` sensor) is actually present; the STORAGE tab reads SMART data from whatever the root filesystem actually sits on (NVMe, SATA, SD/eMMC); rows with no available sensor are hidden rather than shown as `N/A`.

---

## Requirements

- Any Linux with systemd
- Python 3.9 – 3.13
- [psutil](https://github.com/giampaolo/psutil) — `sudo apt install python3-psutil`. The installer does this for you. syswatch no longer pip-installs anything at runtime: if psutil is missing, it says how to install it and exits.

[asciichartpy](https://github.com/kroitor/asciichart) (MIT), used for the HISTORY charts, is bundled as `syswatch_asciichart.py`, so there are no other third-party dependencies. Config parsing uses the standard library's `tomllib` on Python 3.11+, and a small built-in fallback parser on 3.9/3.10.

Soft dependencies (each feature degrades gracefully — hiding the relevant row — if the tool isn't installed):
- `lm-sensors` (`sensors-detect`) for CPU/motherboard temperature sensors on non-Pi hardware
- `smartmontools` (`smartctl`) for storage health/temperature when not exposed via `psutil.sensors_temperatures()`
- `nvidia-smi` for NVIDIA GPU temperature (ships with the NVIDIA driver)

---

## Install

```bash
sudo bash install-syswatch.sh
```

The same command installs a fresh copy or upgrades an existing one.

**What it installs**
- All `syswatch*.py` modules go to `/usr/local/lib/syswatch/`, with a wrapper at `/usr/local/bin/syswatch`.
- `syswatch-logger.service` is installed and started, running as you, so metrics collection begins immediately.
- A fully commented example config goes to `/usr/share/doc/syswatch/config.example.toml`.
- If `python3-psutil` is missing, it's installed with apt.

**Upgrading an older version.** Any earlier syswatch is detected — its version is shown, or "older than 1.1" for versions that didn't record one — and its program files are removed completely before the new ones go in. That covers `/usr/local/lib/syswatch/`, the wrapper, the logger service and the doc directory, so no stale module or cache from an older layout survives. Two more checks run at the same time:
- Another `syswatch` launcher elsewhere (e.g. `~/.local/bin/syswatch` from a manual install) is listed and you're asked whether to remove it (default: keep). For a symlink, only the link is removed, never the file it points to.
- A copy of `asciichartpy` that older versions pip-installed is reported with the command to remove it, but not removed, since something else might use it.

**Existing config.** If `~/.config/syswatch/config.toml` exists, you get a summary of it:
- when it was last changed
- every setting that differs from the built-in defaults, with the default shown next to it
- anything this version treats differently (for example `scan = true`, which no longer exists, or an unknown key)

Then you choose to keep it (the default) or replace it. Replacing renames the old file to `config.toml.bak-<date>` and asks the setup questions below.

**Existing data files.** Each file in `~/.local/share/syswatch/` gets a one-line summary and a keep (default) / delete question:
- metrics history: number of samples and date range
- alert logs: number of entries and the last one
- known devices: number of devices and networks
- trusted-for-scanning networks
- debug log

Files there owned by another user (left by running an old version with `sudo`) are given back to you.

**Leftovers in root's home.** Older versions run with `sudo` kept their config and data in root's home instead of yours. If any are found, they're shown the same way, each with a keep (default) / delete question.

**New config.** With no config yet, it asks a short set of questions worth answering per machine:
- the alert thresholds (CPU/RAM/disk/GPU/storage-temp warning and critical levels)
- `[network] scan` mode and INTRUDER alerting
- the TUI refresh rate and starting tab
- the logger's sample interval and retention

Each question shows the built-in default in `[brackets]`; press Enter to accept it. Everything else is written from the built-in defaults, so the result is always a complete, valid config. Answers are validated with the same rules `syswatch` itself uses at startup, and an invalid answer asks again.

Options:
- `--unattended` asks nothing. It replaces the program, keeps every existing config and data file, and writes a default config only if there's none. This also happens automatically whenever stdin isn't a terminal (e.g. `curl ... | sudo bash`), so the installer never waits for input it can't get.
- `--user NAME` installs for that account (the logger service's `User=` and where `config.toml` is written) instead of the one behind `sudo`. It's required when running the installer as plain `root` with no `$SUDO_USER`. There is no fallback username; the installer refuses rather than guessing.
- `--skip-config` neither writes nor reviews `config.toml`. Run `syswatch --write-default-config` later, or just run with built-in defaults.

---

## Run

```bash
syswatch [options]
```

| Flag | Description |
|------|-------------|
| `--tab N` | Start on tab N (1-based). The tab bar is built dynamically — BACKUP only appears if `project-backup` is detected, so the tab count and numbering shift depending on the machine. Run with no arguments and check the tab bar if unsure. Overrides `[ui] default_tab` in the config. |
| `--refresh N` | Refresh interval in seconds (minimum 0.5). Overrides `[ui] refresh`. |
| `--scan MODE` | Override `[network] scan` for this run: `trusted` (sweep only networks you explicitly trusted for scanning — the default; `known` is accepted as the old name) or `never` (passive ARP only). There is no `always` mode. |
| `--no-scan` | Disable active ping sweep; use passive ARP table only. Same as `--scan never`. Overrides `[network] scan`. |
| `--report` | Print a one-shot system report to stdout and exit (no TUI) |
| `--json` | With `--report`, output JSON instead of text |
| `--config PATH` | Use this config file instead of the default (`$XDG_CONFIG_HOME/syswatch/config.toml`) |
| `--write-default-config` | Write a fully commented example config to the default location (or `--config PATH`) and exit. Refuses to overwrite an existing file unless `--force` is also given. |
| `--force` | With `--write-default-config`, overwrite an existing file |
| `--trust-all-devices` | Mark every device currently in the ARP table as known on the current network (same as the NETWORK tab's `[t]` binding), then exit. Only stops INTRUDER flags — it never enables scanning. |
| `--trust-network` | Trust the current network for active scanning (same as `[s]` on the NETWORK tab): shows the network and the subnets that would be swept, warns, and asks `[y/N]`. Refuses without an interactive terminal — scan permission can't be granted from a script. |
| `--untrust-network` | Stop scanning the current network and forget its scan trust (asks `[y/N]`). |
| `--debug` | Log every collector failure (which one, the exception, a full traceback) to `~/.local/share/syswatch/debug.log`, deduplicated to at most one entry per collector per minute so a chronically-failing one doesn't flood the file |
| `--version` | Print version and exit |

A **⚠** next to the clock in the header means some collector has thrown an exception in the last 15 seconds — visible whether or not `--debug` is on, so a degraded run doesn't require already knowing to turn on debug logging. A missing optional tool (no `smartctl`, no GPU sensor) is *not* an error and won't light it. **⚠ DEAD** instead means a collector thread has died outright: whatever panel it fed is frozen for the rest of the session, so unlike the transient ⚠ this one never clears, and a footer alert names the thread once when it happens. Either way, turn on `--debug` and check `debug.log` to see what and why.

Press `q` or `Q` to quit. (`Esc` deliberately does *not* quit: curses reports a bare `27` both for a real Esc and for a split escape sequence from an arrow key or a laggy terminal, so treating it as quit made exits fire on routine terminal noise.) Press a number key to switch tabs directly — the tab bar shows each tab's number, and since the tab list is dynamic that mapping can differ between machines.

---

## Configuration

syswatch reads `$XDG_CONFIG_HOME/syswatch/config.toml` (default `~/.config/syswatch/config.toml`). Precedence is **CLI flags > config file > built-in defaults** — a missing config file is not a warning, it just means every key falls back to its default.

<a name="files-and-sudo"></a>
**Per-user files under `sudo`.** Running `sudo syswatch` makes `~` point at root's home, which would otherwise give you a completely different set of state files from an unprivileged run. Every per-user file therefore resolves the same sudo-aware way — it uses the current user's path if that file already exists, otherwise the invoking user's (`$SUDO_USER`, looked up in the passwd database rather than assumed to be `/home/<name>`, so it's correct for a non-standard home):

| File | Purpose |
|------|---------|
| `~/.config/syswatch/config.toml` | thresholds and settings |
| `~/.local/share/syswatch/metrics.csv` | HISTORY tab data |
| `~/.local/share/syswatch/known_devices.json` | INTRUDER allowlist |
| `~/.local/share/syswatch/trusted_networks.json` | networks you confirmed for active scanning |
| `~/.local/share/syswatch/temp_alerts.log`, `disk_alerts.log` | alert history |
| `~/.local/share/syswatch/debug.log` | `--debug` output |

So `sudo syswatch` reads your thresholds, your history and your device allowlist — rather than running on built-in defaults and flagging every device on your own LAN as an INTRUDER because root's allowlist is empty. Anything it has to *create* is written into the invoking user's home and chowned to them, so a `sudo` run never leaves behind root-owned state you can't update afterwards. An explicit `XDG_CONFIG_HOME` still wins for the config.

`sudo bash install-syswatch.sh` [generates this file interactively](#install) at install time, so it usually already exists. If you skipped that (`--skip-config`), deleted it, or are just editing it by hand, regenerate a starting point with:

```bash
syswatch --write-default-config
```

Any key you omit falls back to its default. An invalid value — wrong type, out of range, unknown key, or an unparseable file — is never fatal: syswatch falls back to the default for that key, and the problems are surfaced as a footer alert in the TUI (and printed to stderr in `--report` mode). A `--config PATH` that doesn't exist is reported the same way, so a typo or a relative path resolved against the wrong directory doesn't quietly run on built-in defaults; a missing file at the *default* path stays silent, since that's the normal no-config-yet case.

`syswatch-logger` reads the same file's `[logger]` and `[thresholds]` sections.

Full example (the same content `--write-default-config` generates, except `[services] watch` there reflects what's actually installed on your machine — see below):

```toml
# syswatch configuration
#
# Location: $XDG_CONFIG_HOME/syswatch/config.toml (default ~/.config/syswatch/config.toml)
# Precedence: CLI flags > this file > built-in defaults.
#
# Any key you omit falls back to its built-in default. An invalid value
# (wrong type, out of range, unknown key) is ignored and reported as a
# startup warning rather than blocking syswatch from starting.

[services]
# Systemd units watched on the SERVICES tab and in --report.
watch = ["ssh", "cron", "NetworkManager", "bluetooth"]

[thresholds]
# Each threshold is [warning, critical].
cpu_pct      = [80, 95]
ram_pct      = [75, 90]
cpu_temp     = [70, 80]
disk_pct     = [85, 95]
gpu_temp     = [85, 95]
storage_temp = [65, 75]

[network]
# scan controls the active ping sweep:
#   "trusted" (default) — sweep only networks you explicitly trusted for
#                         scanning: press [s] on the NETWORK tab and confirm
#                         with [y] (or run --trust-network). Everywhere else
#                         syswatch only reads the ARP table passively.
#                         Trusting *devices* ([t]) never enables scanning.
#   "never"             — never sweep; passive reading only, on every network
# There is deliberately no "always" mode: an active sweep of a network that
# isn't yours can trigger its security alerts.
scan             = "trusted"
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
```

The default `[services] watch` list is platform-aware, not baked into the example above: on a Raspberry Pi it's `ssh, networking, cron, bluetooth, avahi-daemon, triggerhappy`; on other machines syswatch checks with `systemctl` which of `ssh`/`sshd`, `cron`, `NetworkManager`/`networking`, `bluetooth` actually exist and only defaults to those — no more units guaranteed to show up as "not found".

> **Behaviour change in 1.4 — scanning needs explicit, confirmed trust.** Earlier versions started actively ping-sweeping a network as soon as it had *any* device in `known_devices.json` — which happened after pressing `[t]`, and even after just one passive session there (baseline learning) — and `scan = true` / `--scan always` swept every network unconditionally. Now:
> - Trusting **devices** (`[t]`, `--trust-all-devices`) only stops them being flagged INTRUDER. It never enables scanning.
> - Trusting a **network for scanning** is a separate action (`[s]` then `[y]`, or `--trust-network`) that is stored separately, in `trusted_networks.json`.
> - Networks trusted under the old rules are **not** carried over: after upgrading, nothing is swept until you confirm a network once with `[s]`.
> - `scan = true` / `"always"` are no longer valid. They're reported as a config warning and treated as `"trusted"`; `--scan always` is rejected. `scan = false` still means never. `[network] subnet` is no longer used (it was a fallback sweep target) and is ignored if present.

---

## Tabs

The tab bar always starts with SYSTEM, NETWORK, LOGS, SERVICES, STORAGE and ends with HISTORY. BACKUP is inserted between STORAGE and HISTORY only when `project-backup` is detected as installed — otherwise it's omitted and the remaining tabs (and their number keys) shift down by one. `build_tabs()` computes this list at startup, so it genuinely varies by machine; don't assume a fixed tab count or a fixed number-key mapping.

### 1 · SYSTEM
Real-time CPU usage for each core plus an average bar with sparkline history. RAM and swap usage with bars, plus battery charge (percentage only) if the machine reports one — hidden entirely on desktops/servers/most Pi setups with no battery. CPU temperature, GPU temperature (vendor auto-detected: NVIDIA via `nvidia-smi`, AMD via sysfs `hwmon`, Intel via `psutil`'s `i915` sensor — on a multi-GPU machine the first GPU reported is shown), and storage temperature — each with a visual bar, and each row hidden entirely if no working sensor is found. Current CPU clock frequency. On Raspberry Pi only: core voltage and a throttle indicator showing under-voltage, frequency cap, throttle, and soft-temp-limit flags (● = active now, ○ = never) — these are Pi-specific concepts (`vcgencmd`) with no portable equivalent, so they're simply absent on other hardware. Network RX/TX rates and disk read/write rates with per-channel sparklines. Top processes by CPU (`[ui] top_n`, default 5) with PID, name, CPU%, memory%, and status.

### 2 · NETWORK
Lists the devices on the local network — IP address, MAC address, resolved hostname, time since last seen, and status (Active / Recent / Idle / INTRUDER) — by reading the kernel's neighbour (ARP) table passively. That passive reading is all syswatch does on a network unless you explicitly allow more.

"Last seen" comes from the kernel's neighbour state (`ip -j neigh`). Only an entry the kernel has recently confirmed (REACHABLE/DELAY/PROBE) counts as seeing the device; a STALE entry doesn't. Linux keeps STALE entries indefinitely on small networks, so a switched-off device would otherwise stay "Active" for days. Without iproute2's JSON output, syswatch falls back to `/proc/net/arp`, which has no state, so presence in the table is all it can use.

**Two separate keys, two separate kinds of trust:**

- **`[t]` — trust all devices.** Every currently listed device is written into the [known-devices allowlist](#known-devices-allowlist) and any INTRUDER flags are cleared. That's all: it does **not** make syswatch scan the network. `syswatch --trust-all-devices` does the same without the TUI.
- **`[s]` — trust this network and enable active scanning.** Opens a confirmation box showing:
  - the network's identity (its gateway's MAC address)
  - the subnet(s) that would be swept and how many hosts that is
  - a warning that an active sweep is visible to the network and can trigger its security alerts

  **Only `[y]` confirms; any other key cancels**, and nothing changes. Once confirmed, the network is stored in `~/.local/share/syswatch/trusted_networks.json` and syswatch pings every host in those subnets about once per `[network] ping_cycle` (default 7 minutes) whenever it runs on that network. Pressing `[s]` on a network that's already trusted offers to stop scanning and untrust it, with the same `[y]`-only confirmation. `syswatch --trust-network` / `--untrust-network` are the command-line equivalents; they ask `[y/N]` and refuse to run without a terminal.

Safeguards around the active sweep (`[network] scan = "trusted"`, the default):

- **Network identity is the gateway's MAC address.** A network that can only be identified by its subnet (e.g. `192.168.1.0/24`, which thousands of routers share) can't be trusted at all, so a café using the same addressing as your home never matches your home's trust. The tab says so when this applies.
- **Permission is re-checked before every batch of pings**, from a fresh reading of the network identity — not just when the sweep starts. Leaving the trusted network (or untrusting it) stops the sweep within one batch.
- **Only confirmed subnets are swept**: the ones that contained the gateway when you pressed `[y]`, and only while they're still local. There is no fallback target. Subnets larger than /22 are never offered, so a stray /16 can't queue tens of thousands of pings.
- **Confirmation is tied to what you saw.** If the network changes while the box is open, or between opening it and pressing `[y]`, the confirmation is void. If the terminal is too small to show the whole warning, `[y]` doesn't count.
- **Nothing else turns scanning on.** Baseline learning, `[t]`, and config values can't enable it. `scan = "never"` (or `--no-scan`) turns it off everywhere, even on trusted networks.

The status line at the top of the tab shows the scan state:
- `PASSIVE-ONLY — [s] trust this network & enable scanning (asks first)`
- `ACTIVE SCANNING — trusted network · [s] stop & untrust`
- `SCANNING DISABLED (scan = never)`
- `PASSIVE-ONLY — network can't be identified` (no gateway MAC)

While a trusted network is being scanned, a second line shows when and how often the pings go out, for example `SWEEP 120/254 hosts · next batch of 10 in 7s · full sweep ≈ every 8m · last done 09:12 (6 replied)`: progress through the current sweep, the countdown to the next batch, how long a full sweep really takes (measured, so a little longer than `ping_cycle`), and when the last one finished and how many hosts answered. Right after `[s]` + `[y]` it reads `SWEEP waiting to start…` for a few seconds.

The `[t]` hint sits next to it and turns red while an INTRUDER is flagged. Both are drawn inside the tab itself, not the footer, so they stay visible on narrow terminals and whatever footer alert is showing.

When you switch networks, the device list is cleared, so `[t]` can never trust the previous network's devices onto the new one.

**INTRUDER detection is per-network**, not just "seen after startup": a persistent allowlist (see [Known devices](#known-devices-allowlist)) tracks which MACs have been seen on which network. A device is flagged INTRUDER only if its MAC has never been seen on the network syswatch is *currently* on — so a laptop that already knows every device on its home LAN won't false-positive there, but will still flag genuinely new devices on a café Wi-Fi. The first time syswatch runs on a given network, everything discovered in the first `[network] baseline_window` seconds (default 60) is learned silently rather than alerted on. Set `[network] intruder_alerts = false` to disable the flagging (and its footer alert) entirely. Baseline learning only affects INTRUDER flagging; it never enables scanning.


### 3 · LOGS
Streams the systemd journal in real time via `journalctl -f`. Shows service name, timestamp, and message for each entry. An error-rate sparkline and count in the header show errors per 60-second window. Press `/` to open the filter prompt (see below).

### 4 · SERVICES
Watches the systemd units listed under `[services] watch` in your config (platform-aware default — see [Configuration](#configuration)). Displays active state, sub-state, main PID, restart count, time active since, and last result. A failed service is highlighted in red; a restart count above 5 triggers a critical colour.

### 5 · STORAGE
Reports the health of whatever device the root filesystem actually lives on — SD card, eMMC, NVMe, or SATA/USB disk — auto-detected via `psutil.disk_partitions()` and `lsblk`. NVMe and SATA disks are read via `smartctl`; SD/eMMC cards fall back to kernel sysfs registers (`pre_eol_info`, `life_time`) and dmesg error counts. Shows the detected device and type, SMART health status, storage temperature, power-on hours, bytes written this boot, filesystem usage for `/` and (if it's a separate mount) the boot partition — detected as whichever of `/boot/firmware`, `/boot`, `/boot/efi` actually has its own mount, so it isn't shown at all on a system with no separate boot partition — and raw I/O counters since boot.

The device/filesystem error counts come from the kernel ring buffer, which most distributions (Debian, Ubuntu, Pop!\_OS) restrict to root by default via `kernel.dmesg_restrict=1`. When it can't be read those counts show **`N/A`** rather than `0` — an unreadable log is not the same as a clean one, and on an SD/eMMC card whose health is derived from those counts the health field reads `N/A` too instead of guessing. Run syswatch with `sudo` (or set `kernel.dmesg_restrict=0`) to get real counts. Likewise, most SMART fields need `smartctl` to be able to open the device, which normally means running as root; without that they read `N/A`.

### 6 · BACKUP *(only shown if `project-backup` is installed)*
> Requires the [project-backup](https://github.com/Lakito0100/backup-system) tool.

Reads `/var/log/project-backup-status.json` written by the `project-backup` tool. Displays the status, timestamp, duration, and file counts of the last backup run; lists configured source paths with existence checks; and shows a scrollable run history with a files-transferred sparkline. syswatch checks at startup whether `project-backup` is installed and enabled (systemd unit/timer, or the status file already exists); if not, this tab is omitted entirely rather than shown empty.

### 7 · HISTORY
Reads the metrics CSV recorded by syswatch-logger and renders line charts for CPU %, RAM %, CPU temperature, disk %, core voltage, GPU temperature, storage temperature, and battery charge over the selected time window — a chart is only drawn for a metric that has data in the current window, so e.g. the voltage chart won't appear on non-Pi hardware and the battery chart won't appear on a machine with no battery. Press `h` while on this tab to cycle between the last 1 hour, 8 hours, 24 hours, 7 days, and 30 days. If the terminal is too short to fit all charts, **press `↓`/`↑` to scroll one chart at a time** — the header shows the current position (e.g. `(2/6)`) while scrolled. Each chart is coloured using the same warning/critical thresholds as the live display. If no data is available yet, a message prompts you to start syswatch-logger. When syswatch is launched with `sudo` (so `~` resolves to `/root`), it reads the invoking user's CSV instead — see [Per-user files under `sudo`](#files-and-sudo), which applies identically to the config, the device allowlist and the alert logs.

Data is plotted on a uniform time grid rather than one column per sample, so a gap in logging (the machine was off or asleep) occupies its true width on the chart — a dotted band — instead of collapsing to a single column with misleading axis labels.

---

## syswatch-logger

syswatch-logger is a lightweight background process that wakes up every `[logger] interval` seconds (default 120), samples CPU %, RAM %, CPU temperature, root-disk usage, core voltage (Pi only), GPU temperature, storage temperature, and battery charge, and appends one CSV line to `~/.local/share/syswatch/metrics.csv`. Lines older than `[logger] retention_days` (default 30) are trimmed automatically after each write. It also reads `[thresholds]` and appends to the same alert log files syswatch itself uses (see below), so temperature/disk alerting keeps working even when the TUI isn't running.

`install-syswatch.sh` installs and starts syswatch-logger as a systemd service (`syswatch-logger.service`) running as the installed user. The service starts automatically on boot and restarts on failure.

**CSV location:** `~/.local/share/syswatch/metrics.csv`

Example rows (2-minute spacing; columns are timestamp, CPU %, RAM %, CPU temp, disk %, core voltage, GPU temp, storage temp, battery %):
```
2026-06-11T14:35:00,32.1,45.2,56.3,12.4,1.3125,48.0,41.9,89.5
2026-06-11T14:37:00,34.0,46.1,57.0,12.4,1.3125,47.0,41.9,89.5
```

A sensor that isn't available on the running machine logs as an empty field rather than `0`, so the HISTORY tab's charts can tell "no sensor" from "0 degrees" — e.g. on non-Pi hardware the voltage column is always blank, and its chart doesn't appear at all; a desktop or server with no battery leaves the last column blank the same way. Rows written by older versions have fewer columns: pre-1.1.0 rows have five (no voltage), 1.1.x rows have six (+voltage), 1.2.0 rows have eight (+GPU temp, +storage temp), current rows have nine (+battery). All widths remain fully compatible — the HISTORY tab reads them uniformly, so there is no need to delete or migrate an existing `metrics.csv`; older rows simply have no value in the columns that didn't exist yet.

To run the logger directly (e.g. for testing): `python3 syswatch-logger.py [--interval N] [--config PATH] [--version]`

`--interval` overrides `[logger] interval` from the config for that run. To change the sample interval permanently, either set `[logger] interval` in your config, or add `--interval N` to the `ExecStart=` line in `/etc/systemd/system/syswatch-logger.service` and run `sudo systemctl daemon-reload && sudo systemctl restart syswatch-logger`. The HISTORY tab estimates the interval from the data, so its gap detection adapts automatically.

---

## Report mode

`syswatch --report` prints a one-shot snapshot to stdout and exits — no TUI, no background threads. It includes the detected hardware model, uptime, CPU/GPU/storage temperature, the active `[network] scan` mode (and, when it's `"trusted"`, whether the current network is trusted for scanning — i.e. whether this run would actually sweep), and (Raspberry Pi only) core voltage and throttle flags (current and since boot), the state of every watched service (failed units are called out), and disk usage for `/` and the boot partition (if it's a separate mount). Add `--json` for machine-readable output (`scan_mode` and `scan_network_trusted` fields; `scan_network_recognised` is kept as an alias for older scripts). Config problems, if any, are printed to stderr before the report itself.

This is designed for cron and email digests, e.g. a daily report at 07:00:

```
0 7 * * * /usr/local/bin/syswatch --report | mail -s "System status" you@example.com
```

Values that cannot be read on the current hardware (e.g. no GPU sensor found, or core voltage/throttle flags on non-Pi hardware) are reported as `N/A` in text mode and `null` (or omitted, for the boot-partition disk entry when there is none) in JSON.

---

## Disk space alert

Like the temperature alert, syswatch monitors filesystem usage of `/` and, if present, the boot partition (checked every `[ui] storage_refresh` seconds, default 60). When usage crosses a threshold for the first time, it rings the terminal bell (`\a`) and appends a timestamped line to:

```
~/.local/share/syswatch/disk_alerts.log
```

syswatch-logger checks `/` against the same thresholds independently, so the alert keeps working while only the logger service is running. When both are running, only one of them writes each alert line (whichever holds `~/.local/share/syswatch/alerts.lock`), so alerts aren't logged twice.

The alert fires once per upward crossing per mount — it will not repeat every cycle while usage stays high, but will fire again if usage drops below the threshold and rises back above it.

Thresholds (configurable via `[thresholds] disk_pct` in your config):
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

The directory is created automatically if it does not exist. syswatch-logger checks CPU temperature against the same thresholds independently, so the alert keeps working while only the logger service is running. When both are running, only one of them writes each alert line (whichever holds `~/.local/share/syswatch/alerts.lock`), so alerts aren't logged twice. The alert fires once per upward crossing — it will not repeat every second while the temperature stays high, but will fire again if the temperature drops below the threshold and rises back above it.

Thresholds (configurable via `[thresholds] cpu_temp` in your config):
- **WARNING** — 70 °C
- **CRITICAL** — 80 °C

Example log entries:

```
2026-06-11 14:32:17 WARNING cpu_temp=72.5C (threshold=70C)
2026-06-11 14:35:02 CRITICAL cpu_temp=81.3C (threshold=80C)
```

---

## Known devices allowlist

syswatch keeps a persistent, per-network allowlist of devices at:

```
~/.local/share/syswatch/known_devices.json
```

(Under `sudo` this resolves to the invoking user's copy, not root's — see [Per-user files under `sudo`](#files-and-sudo) — so an elevated run doesn't start from an empty allowlist and flag your whole LAN.)

It's keyed by network identity — the default gateway's MAC address where obtainable, otherwise the local subnet's CIDR — so a device known on your home LAN doesn't count as "known" the moment you connect to a different network. Each entry records when a MAC was first and last seen on that network, and its resolved hostname at the time:

```json
{
  "gw:aa:bb:cc:dd:ee:ff": {
    "10:20:30:40:50:60": {
      "first_seen": 1770000000.0,
      "last_seen":  1770003600.0,
      "hostname":   "laptop.home"
    }
  }
}
```

Writes are atomic (written to a temp file, then renamed into place), so a crash or power loss mid-write can't corrupt it. A newly learned or trusted device is saved straight away; mere `last_seen` refreshes of devices already in the file are batched and written at most every 5 minutes (and on exit), so a long-running syswatch doesn't rewrite the file every couple of seconds — which matters on a Pi's SD card. A missing, empty, truncated, or otherwise malformed file is treated as an empty allowlist rather than a crash. Entries not seen for `[network] known_devices_retention_days` (default 90) are pruned automatically. If the file genuinely can't be written (read-only home, full disk, wrong permissions) that's reported as a collector error — it lights the header ⚠ and is logged with `--debug` — rather than passing silently, which would otherwise look like `t` had worked while nothing was ever remembered between runs.

Add devices to the allowlist either by pressing `t` on the NETWORK tab, or by running `syswatch --trust-all-devices` (useful for a first-time setup, e.g. right after install). Neither enables scanning — see [`[s]`](#2--network) for that; trusted-for-scanning networks live in a separate file, `trusted_networks.json`. Delete the file to reset it, or edit `known_devices_retention_days` to control how long devices are remembered on networks you don't visit often.

---

## Tests

The test suite uses only the standard library's `unittest` (plus `psutil`/`asciichartpy`, which syswatch itself needs) and runs on any Linux machine without root, sensors, systemd or a network — hardware-specific paths are exercised with mocked inputs. From the repository root:

```bash
python3 -m unittest discover -s tests -t tests
```

`tests/test_installer.py` runs `install-syswatch.sh` end to end: install, upgrade over a fake old version, keep/replace/delete answers, and uninstall/purge. It needs root, because it creates a throwaway user, and is skipped otherwise. Run it with `sudo python3 -m unittest discover -s tests -t tests -p test_installer.py`. It installs into a scratch directory with a stub `systemctl`, so it doesn't touch the real system. GitHub Actions runs the whole suite on Python 3.9–3.13, plus the installer tests and `shellcheck`, on every push.

It covers config parsing/validation (both the `tomllib` and the Python 3.9/3.10 fallback parser), the scan-safety rules (`tests/test_trust.py`: `[t]` never enables scanning, only `[y]` confirms `[s]`, no ping ever leaves an untrusted, changed or unconfirmed network), the known-devices allowlist, sensor parsing (`smartctl`/`nvidia-smi` output, device-mapper root disks), syswatch-logger's trimming and alerts, the collector threads, rendering of every tab at several terminal sizes with both normal and malformed data, and end-to-end runs of `--report`, `--write-default-config`, `--trust-all-devices` and the TUI itself in a pseudo-terminal.

---

## Uninstall

```bash
sudo bash install-syswatch.sh --uninstall
```

This stops and removes `syswatch-logger.service` and removes `/usr/local/bin/syswatch`, `/usr/local/lib/syswatch/` and `/usr/share/doc/syswatch/`. It then shows your config and each data file with the same summaries as the installer, and asks whether to keep each one (the default is keep). Leftovers in root's home are offered the same way. Without a terminal, everything is kept.

`sudo bash install-syswatch.sh --uninstall --purge` deletes `~/.config/syswatch/` and `~/.local/share/syswatch/` (and root's copies, if any) without asking.
