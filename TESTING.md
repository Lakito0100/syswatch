# syswatch 1.4.0 — local test plan

This file is for a Claude Code session that has **no prior context**. It explains what changed, what's risky, and how to test it on real hardware: first a Pop!_OS laptop, then a Raspberry Pi, both on the owner's home network. Read it all before running anything.

`TESTING.md` and `CLAUDE.md` are temporary. They are removed in the last step, once the owner says testing is finished.

---

## 1. Context: what changed and where the risk is

Everything below is on the `development` branch. Until now it has only been tested in a cloud container with no sensors, no Wi-Fi, no systemd, no `ping` and no real LAN. It has never run on real hardware.

### Bug fixes (first pass)
- **STORAGE tab, `--report` and disk alerts showed the wrong disk-usage %.** Reserved blocks were counted as used, e.g. 88% where `df` said 22%. They now match `df` and the SYSTEM tab.
- **The header's ⚠ stayed lit on machines without a temperature sensor, cpufreq or Wi-Fi.** A missing sensor was treated as a broken one.
- **The UI froze while sensors were read.** The system collector held the shared lock during slow tools (`smartctl`, `nvidia-smi`, `vcgencmd`).
- **Hostname lookups had no real timeout,** so a network without reverse DNS could stall device discovery.
- **Network-tab fixes:**
  - a race between `[t]` and the device-discovery thread
  - devices that left the network stayed "Active" forever
  - `known_devices.json` was rewritten every 2 s (SD-card wear)
  - a failed reverse lookup overwrote stored hostnames with the bare IP
  - the ping sweep kept scanning the old subnet after a network change
- **Storage fixes:**
  - SMART parsing crashed on `null` JSON fields
  - **the root disk on encrypted/LVM installs was detected as a partition** (Pop!_OS's default layout), so SMART data and I/O counters were missing
- **Other fixes:**
  - SERVICES columns went out of alignment for long unit/state names
  - non-ASCII text in the config was mangled on Python 3.9/3.10
  - the logger rewrote `metrics.csv` in place, so the HISTORY tab could read a half-written file
  - the installer fell back to a hardcoded username `lukas`

### New trust model (highest risk; this is the safety feature)
Active scanning means pinging every address in the local subnet. It's visible to the network and can trigger its intrusion detection, so it must never happen by accident.
- **`[t]` (NETWORK tab) / `--trust-all-devices`** trusts the listed **devices** only. It stops INTRUDER flags and **never** enables scanning.
- **`[s]` then `[y]` / `--trust-network`** trusts the **network** for scanning. `[s]` opens a confirmation box showing:
  - the network's identity (`gw:<gateway MAC>`)
  - the subnet(s) and host count
  - a warning about security alerts

  **Only `y` confirms; any other key cancels.** `[s]` on an already-trusted network offers to untrust it, also confirmed only with `y`.
- Trusted networks live in `~/.local/share/syswatch/trusted_networks.json`, separate from `known_devices.json`.
- **"always" mode was removed.**
  - Config `scan = true` / `"always"` produces a warning and is treated as `"trusted"`.
  - `--scan always` is rejected.
  - The remaining modes are `trusted` (default) and `never`.
- **When the sweep runs:**
  - It re-checks permission before every batch, from a fresh network identity.
  - It only pings subnets that were confirmed **and** are still local.
  - There is no fallback subnet.
  - Networks identified only by a subnet (no gateway MAC) can't be trusted.
- **Networks trusted by older versions are not carried over.** After upgrading, nothing is scanned until `[s]` + `[y]` is done once.

### Installer (`install-syswatch.sh`)
- **Old versions:** detects an existing install (shows its version, or "older than 1.1") and removes the old program files completely before installing.
- **Stray launchers:** finds other `syswatch` launchers, e.g. `~/.local/bin/syswatch`, and asks before removing them. For a symlink, only the link is removed.
- **Existing config:** shows a summary (settings that differ from the defaults, plus notes such as the removed always mode) and asks **keep (default) / replace**. Replace saves a `.bak-<date>` copy and runs the setup questions.
- **Data files:** each file in `~/.local/share/syswatch/` gets a one-line summary and **keep (default) / delete**.
- **Leftovers:** syswatch files in root's home from older `sudo` runs are offered for deletion. Root-owned files in the user's own syswatch directories are chowned back.
- **Flags:**
  - `--unattended` (or no terminal): no prompts, everything is kept.
  - `--user NAME`: install for that user; required when running as plain root without sudo.
- **Dependencies:** installs `python3-psutil` with apt if missing.

### Uninstall
- `--uninstall` removes the program, then asks keep/delete per config and data file (default keep). Without a terminal, everything is kept.
- `--uninstall --purge` deletes `~/.config/syswatch/` and `~/.local/share/syswatch/` (and root's leftovers) without asking.

### Dependencies
- `asciichartpy` (the HISTORY charts) is now bundled as `syswatch_asciichart.py`.
- syswatch no longer pip-installs anything at runtime. A missing `psutil` prints `sudo apt install python3-psutil` and exits.

### Alert-log locking
The TUI and `syswatch-logger` used to both write every temperature/disk alert. Now whichever process holds an `flock` on `~/.local/share/syswatch/alerts.lock` is the only writer.

### Neighbour-state presence
NETWORK "last seen" now comes from `ip -4 -j neigh`. Only REACHABLE/DELAY/PROBE entries count as seen now; STALE entries don't. Without `ip`'s JSON output, syswatch falls back to `/proc/net/arp`.

### Module split
`syswatch.py` (~3,800 lines) was split into:
- `syswatch_state.py`: `settings` namespace and shared state
- `syswatch_collectors.py`: system/log/service/storage/backup threads
- `syswatch_network.py`: discovery, trust, ping sweep
- `syswatch_render.py`: all drawing

The behaviour is meant to be unchanged; this is a regression risk across every tab.

---

## 2. Safety rules for this session (mandatory)

1. **Never press `y` in the scan dialog, and never run `syswatch --trust-network`, unless the owner has explicitly confirmed in this conversation that the machine is on their own home network right now.**
   - Ask again whenever the network might have changed (laptop moved, Wi-Fi switched).
   - `[s]` followed by any *other* key is always safe; it's how the "cancel" path is tested.
2. **Ask before running the installer, the uninstaller, `sudo` commands, `systemctl`, or anything else that touches files outside the repository and `/tmp`.**
3. **Never delete the owner's config or data files** (`~/.config/syswatch/`, `~/.local/share/syswatch/`, or root's copies) without asking first. Answer installer keep/delete prompts only as the owner instructs.
4. The owner has to type the sudo password and answer interactive prompts. Claude Code's shell is not a terminal. For those steps:
   - give the exact command
   - the owner runs it in their own terminal
   - then check the result yourself (files, ownership, `systemctl status`, output they paste)
5. Bug fixes go on a separate branch (see §6), never straight onto `development`, and each fix must be explained.

---

## 3. Setup

```bash
git clone https://github.com/Lakito0100/syswatch.git
cd syswatch
git checkout development
git log --oneline -1          # note the commit for the report

sudo apt install python3-psutil                  # required
sudo apt install lm-sensors smartmontools tmux   # optional: CPU temps, SMART data, TUI driving
# lm-sensors on the laptop: run `sudo sensors-detect` once (accept defaults) if CPU temp shows "no sensor"
python3 --version             # Pop!_OS 22.04 → 3.10, 24.04 → 3.12; Raspberry Pi OS bookworm → 3.11
```

**Driving the TUI from the session (optional, needs `tmux`).** Claude Code's shell isn't a terminal, but tmux can host one:

```bash
tmux new-session -d -s sw -x 120 -y 40 'python3 syswatch.py --debug'
tmux send-keys -t sw 2            # switch to tab 2
tmux capture-pane -t sw -p        # print the screen
tmux send-keys -t sw q            # quit (q only works outside the scan dialog)
```

Rule 1 applies to `send-keys` too: never send `y` while the scan dialog is open without the owner's confirmation.

---

## 4. Ordered test steps

Record **PASS / FAIL** for each step and keep notes. If a step fails, collect the evidence (§7) before moving on.

### Step 1 — Unit test suite
Run it yourself:
```bash
python3 -m unittest discover -s tests -t tests        # as the normal user
```
- **PASS:** ends with `OK`. Skips are fine; say how many and why:
  - `test_installer.py` is skipped without root
  - one `tomllib` test is skipped on Python 3.10
  - two trust end-to-end tests are skipped if the network has no identifiable gateway
- **Safe to run anywhere:** the suite never pings the real network. The end-to-end trust tests use a throwaway `HOME` and a fake `ping`.

Then ask the owner to run the root-only installer tests in their terminal:
```bash
sudo python3 -m unittest discover -s tests -t tests -p test_installer.py
```
- **PASS:** `OK` (10 tests).
- These create and delete a temporary user `swtestNNNNN` and install into a scratch directory with a fake `systemctl`. They don't touch the real install.

### Step 2 — Installer over an existing older install
1. **Check what's installed:**
   ```bash
   ls /usr/local/lib/syswatch/ 2>/dev/null && grep -ho '^VERSION = "[0-9.]*"' /usr/local/lib/syswatch/*.py
   ```
   If nothing is installed, ask the owner whether to install the last pre-1.4 version (1.3.0) first, so there is something to upgrade:
   ```bash
   git worktree add /tmp/syswatch-1.3 b2fb6ee
   sudo bash /tmp/syswatch-1.3/install-syswatch.sh --unattended
   git worktree remove /tmp/syswatch-1.3
   ```
   Warn the owner first: 1.3.0 may pip-install `asciichartpy` system-wide on its first run (`--break-system-packages`). The new installer then reports it and prints how to remove it.
2. **Set up the cases to check** (ask first):
   - Make sure `~/.config/syswatch/config.toml` exists with at least one non-default value. Write one with `syswatch --write-default-config` if needed, then edit e.g. `cpu_temp`. Adding `scan = true` also tests the deprecation note.
   - Create one root-owned file in the data directory: `sudo touch ~/.local/share/syswatch/chown-test.log`.
3. **Owner runs** `sudo bash install-syswatch.sh` from the repo, answering as you instruct.
   - **PASS** if all of these hold:
     - It prints `Found an older syswatch (1.3.0 …)` (or `older than 1.1`).
     - It lists the removed paths.
     - `/usr/local/lib/syswatch/` afterwards contains exactly the repo's current `syswatch*.py` files (no stale modules) and `grep VERSION` shows `1.4.0`.
     - The config summary lists exactly the non-default settings with their defaults, plus a note for `scan = true` if set. Keep is the default (Enter).
     - Each data file has a sensible one-line summary (sample count/date range for `metrics.csv`, entry count/last line for alert logs, device/network counts).
     - Answering `n` to `chown-test.log` deletes it.
     - `Gave N file(s) … back to <user>` appears if any root-owned file was kept.
     - `syswatch --version` prints `1.4.0` and `systemctl status syswatch-logger` is `active`.
4. **Replace path:** owner runs it again and answers `n` to "Keep this config?".
   - **PASS:** a `config.toml.bak-YYYYmmdd-HHMMSS` exists, the setup questions are asked, and the new config is owned by the user.
5. **Unattended:** `sudo bash install-syswatch.sh --unattended`. You can run this yourself only if passwordless sudo works; otherwise the owner runs it.
   - **PASS:** no prompts; every config and data file is still there; `Found syswatch 1.4.0 (same version) — reinstalling it`.
6. **Stray launcher** (optional, ask first): create a symlink `ln -s "$PWD/syswatch.py" ~/.local/bin/syswatch`, run the installer and answer `y` to "Remove it?".
   - **PASS:** the link is gone and `syswatch.py` in the repo is untouched.

### Step 3 — TUI as a normal user and with sudo, every tab
Run `syswatch --debug`, visit every tab (number keys), then quit with `q`. Repeat with `sudo syswatch --debug`. Use tmux (§3) or ask the owner for screenshots.

| Tab | PASS criteria |
|---|---|
| 1 SYSTEM | Per-core bars and sparklines move; RAM/swap correct; temperature rows present where the hardware has sensors (see §5); top processes listed. Header has **no ⚠** after ~20 s (a missing `ping` lights it once at start; nothing else should). |
| 2 NETWORK | Device list fills from the neighbour table. Status line shows `PASSIVE-ONLY — [s] trust this network …` next to `[t] trust all devices …`. Devices that are off move to Recent/Idle within minutes rather than staying Active. |
| 3 LOGS | Journal lines stream; `/` opens the filter; Enter applies it; Esc clears it; Backspace and Ctrl-H both delete. |
| 4 SERVICES | Watched units listed; columns aligned (the RESTARTS number sits under its header). |
| 5 STORAGE | Device line names the **whole disk** (e.g. `/dev/nvme0n1 (nvme)`, `/dev/mmcblk0 (mmc)`), never a partition or `dm-*`. Filesystem % matches `df -h /` (±0.1). Normal user: SMART and dmesg counts may be `N/A`. With sudo: SMART health/power-on hours and DEV/FS error counts appear. |
| 6/7 HISTORY | Charts appear once `metrics.csv` has data (see step 6); `h` cycles windows; ↑/↓ scroll. |

With sudo, also check:
- No `/root/.local/share/syswatch` or `/root/.config/syswatch` is created: `sudo ls /root/.local/share/syswatch` should fail.
- Any file syswatch creates under the user's home is owned by the user.

Afterwards, check `debug.log` (§7) for anything that isn't an absent tool.

### Step 4 — NETWORK tab trust flow
Watch for pings in a second terminal throughout. A batch of up to 10 pings runs about every 16 s while scanning:
```bash
while true; do pgrep -af 'ping -c1 -W1' ; sleep 1; done
# or: sudo tcpdump -ni any icmp
```
1. **`[t]` never starts scanning.** Press `t`. **PASS:**
   - INTRUDER flags clear
   - the footer says "all listed devices trusted (scanning unchanged)"
   - the status line still says PASSIVE-ONLY
   - no ping processes for 60 s
   - `~/.local/share/syswatch/trusted_networks.json` doesn't exist or has no entry for this network
2. **`[s]` + any other key changes nothing.** Press `s`; the box appears with the network id, subnet, host count and the warning. Press `n` (repeat with Esc, Enter, `q`, `s`). **PASS:**
   - each one closes the box with "cancelled — scan trust unchanged"
   - still PASSIVE-ONLY
   - no pings
   - `trusted_networks.json` unchanged
   - `q` inside the box only cancels; it doesn't quit
3. **`[s]` + `y` starts scanning. Home network only — ask the owner to confirm first.** **PASS:**
   - the status line changes to `ACTIVE SCANNING — trusted network`
   - ping processes appear within ~5–20 s, all inside the subnet shown in the box
   - `trusted_networks.json` contains `gw:<router MAC>` with that subnet
   - devices that answer pings show Active
4. **Leaving or switching networks stops scanning** (laptop): switch Wi-Fi to another network, e.g. a phone hotspot. **PASS:**
   - the status line returns to PASSIVE-ONLY
   - the device list is cleared and refills with the new network's devices
   - **no pings at all** on the other network for at least 60 s
   - switching back home resumes scanning without asking again (trust persisted)

   On the Pi, if it can't easily change networks, skip this and note it.
5. **`[s]` again untrusts.** On the trusted network, press `s`; the box says "STOP SCANNING THIS NETWORK?". Press `n` first: nothing changes. Then `s`, `y`. **PASS:**
   - "network untrusted — active scanning stopped"
   - PASSIVE-ONLY
   - pings stop within one batch (~20 s)
   - the entry is removed from `trusted_networks.json`
   - known devices are kept
6. **Small terminal:** shrink the terminal until the box doesn't fit, press `s`, then `y`. **PASS:** cancelled with "enlarge the terminal…", not trusted.

### Step 5 — `--report`, `--report --json`, `--trust-network`, `--untrust-network`
- `syswatch --report` and `syswatch --report --json | python3 -m json.tool`. **PASS:**
  - valid JSON
  - disk `/` % matches `df`
  - `scan_mode` is `trusted`, and `scan_network_trusted` matches the trust file (`scan_network_recognised` carries the same value)
  - temperatures as in §5
- `syswatch --scan always --report` → **PASS:** rejected with "invalid choice" (exit 2).
- A config with `scan = true` → **PASS:** stderr warns that always mode was removed; the report says `trusted`.
- `syswatch --trust-network < /dev/null` → **PASS:** refuses ("needs an interactive terminal"), nothing written.
- Owner runs `syswatch --trust-network` in their terminal and answers `n` → **PASS:** "Cancelled — nothing changed".
- **Home network only, after confirmation:** answers `y` → trusted. Then `syswatch --untrust-network` + `y` → removed.

### Step 6 — `syswatch-logger` service, then HISTORY
- `systemctl status syswatch-logger` → active, `User=` is the owner.
- `journalctl -u syswatch-logger -n 50` → no tracebacks.
- `tail -3 ~/.local/share/syswatch/metrics.csv` → a new row every 120 s. **PASS:** the first row after a restart has a plausible CPU value (not `0.0`) and the expected columns:
  - timestamp, cpu, ram, cpu_temp, disk, voltage (Pi only), gpu_temp, storage_temp, battery
  - empty fields where there is no sensor
- **Alert locking:** temporarily set `[thresholds] cpu_temp = [20, 95]` and restart the logger. Within a few seconds it writes a WARNING line to `temp_alerts.log` and becomes the alert writer. Then start the TUI, which crosses the same threshold. **PASS:**
  - starting the TUI adds **no** second WARNING line (before 1.4, both processes logged it)
  - `~/.local/share/syswatch/alerts.lock` exists
  - put the threshold back afterwards
- **After a few hours:** HISTORY shows charts for every metric with data. The time axis matches the CSV timestamps. Gaps (machine asleep/off) show as dotted `┊` bands. A sparsely reported metric (e.g. storage temp) shows no gap markers between readings. `h` cycles 1h/8h/24h/7d/30d.

### Step 7 — Uninstall, with and without `--purge`
**Ask first.** Back up `~/.config/syswatch` and `~/.local/share/syswatch`, e.g. `cp -a` to `/tmp`, if the owner wants to keep their history.
- Owner runs `sudo bash install-syswatch.sh --uninstall`, keeps some files and deletes others. **PASS:**
  - program files, wrapper, unit and doc dir are gone
  - `systemctl status syswatch-logger` reports the unit isn't found
  - exactly the files answered `n` are deleted
- `sudo bash install-syswatch.sh --uninstall < /dev/null` → **PASS:** everything kept, with a note about `--purge`.
- Reinstall, then `sudo bash install-syswatch.sh --uninstall --purge` → **PASS:** `~/.config/syswatch` and `~/.local/share/syswatch` are gone, with no prompts.
- `sudo bash install-syswatch.sh --purge` (without `--uninstall`) → **PASS:** refused.
- Finally reinstall, restoring the owner's backup if they want it.

---

## 5. Hardware checklists

### Pop!_OS laptop
- [ ] **CPU temp:** shown on SYSTEM and in `--report`. If "no sensor", run `sensors-detect` and recheck. Compare with `sensors`.
- [ ] **GPU temp:** vendor in the label (NVIDIA via `nvidia-smi`, AMD, Intel `i915`). Compare with `nvidia-smi` or `sensors`. Hybrid graphics: note which GPU is shown.
- [ ] **NVMe temp:** STORAGE TEMP row and the STORAGE tab. Compare with `sensors` (nvme Composite) or `sudo smartctl -A /dev/nvme0n1`.
- [ ] **SMART with sudo:** STORAGE tab health `PASSED`/`GOOD` and power-on hours. Compare with `sudo smartctl -a /dev/nvme0n1`.
- [ ] **Battery:** BATT row on SYSTEM; the HISTORY battery chart after a few hours.
- [ ] **Encrypted/LVM root:** compare `lsblk -s "$(findmnt -no SOURCE /)"` with the STORAGE DEVICE line. It must be the bottom `disk` entry (e.g. `nvme0n1`); I/O counters must not say "unavailable".
- [ ] **Wi-Fi signal:** a `WLP…  -NNdBm` row in the SYSTEM tab's NETWORK panel if `/proc/net/wireless` exists (`cat /proc/net/wireless`). Its absence is OK when that file doesn't exist.
- [ ] **Suspend/resume** with the TUI open: no crash, and HISTORY shows the gap.

### Raspberry Pi
- [ ] **Core voltage:** SYSTEM `FREQ … 1.xxxxV`. Compare with `vcgencmd measure_volts core`.
- [ ] **Throttle flags:** UV/FREQ/THROT/TEMP dots. Compare with `vcgencmd get_throttled` (0x0 = all ○). Under-voltage on a weak supply should show ●.
- [ ] **SD/eMMC health:** STORAGE DEVICE `/dev/mmcblk0 (mmc)` with card type.
  - With sudo, health is derived from dmesg error counts (or eMMC `pre_eol_info`).
  - Without sudo, health may be `N/A`, which is OK.
- [ ] **Logger service on ARM:**
  - active
  - voltage column filled in `metrics.csv`
  - the HISTORY `VOLT V` chart appears
- [ ] **Performance on a slow CPU:**
  - `top -p $(pgrep -f syswatch.py | head -1)` shows modest CPU at the default 1 s refresh
  - tab switches and key presses respond within ~1 s
  - the HISTORY tab with a long `metrics.csv` doesn't stutter (it re-parses only when the file changes)
  - nothing freezes while the STORAGE tab refreshes SMART/dmesg
- [ ] **Default services:** the SERVICES tab lists the Pi defaults (`ssh`, `networking`, `cron`, `bluetooth`, `avahi-daemon`, `triggerhappy`) if no config overrides them.

---

## 6. Fixing bugs found during testing

- Create a branch off `development` (e.g. `test-fixes-1.4`), never commit fixes directly to `development`, and push that branch only.
- For each fix, explain:
  - what failed and on which machine
  - the root cause
  - the change
  - how it was verified (ideally a new or updated test that failed before the fix)
- Run the whole suite before every push.

## 7. What to report back

For each machine, a table of steps 1–7 (and each checklist item) with PASS / FAIL / SKIPPED, plus:
- the exact output of any failing test
- `~/.local/share/syswatch/debug.log` from runs with `--debug`, saying which entries are expected (absent tools) and which are real failures
- `syswatch --report --json`
- terminal dumps (`tmux capture-pane -p`) or the owner's screenshots of anything that looks wrong
- the commit tested (`git log --oneline -1`), the Python version, and the OS/hardware model
- links to any fix branch, with the explanations from §6

## 8. Cleanup (last step)

When the owner confirms testing is finished on both machines, remove this file and `CLAUDE.md` so the repository is clean again:
```bash
git checkout development && git pull
git rm TESTING.md CLAUDE.md
git commit -m "Remove temporary test guide"
git push origin development
```
Also remove anything the testing left behind: scratch worktrees under `/tmp`, test symlinks, config backups the owner doesn't want.
