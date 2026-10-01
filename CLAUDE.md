# syswatch

A curses terminal system monitor for systemd Linux (Debian, Ubuntu, Pop!_OS, Raspberry Pi OS). It shows:
- CPU, memory, temperatures, battery, network devices, journal logs, systemd services, storage health and (optionally) backup status, in tabs
- an optional background logger (`syswatch-logger.py`, a systemd service) that writes `~/.local/share/syswatch/metrics.csv` for the HISTORY tab

Python 3.9–3.13. The only third-party dependency is `psutil` (`sudo apt install python3-psutil`); syswatch never pip-installs anything.

**Testing in progress:** follow `TESTING.md` for the current hardware test plan. This file and `TESTING.md` are temporary and get removed when that test round is finished (see TESTING.md §8).

## Commands

```bash
python3 syswatch.py [--debug]                 # TUI (q quits)
python3 syswatch.py --report [--json]         # one-shot report
python3 -m unittest discover -s tests -t tests                               # full suite (stdlib unittest)
sudo python3 -m unittest discover -s tests -t tests -p test_installer.py     # installer tests, root only
ruff check --select E9,F,B --target-version py39 syswatch*.py tests/*.py      # lint, as in CI
shellcheck install-syswatch.sh
```

CI (`.github/workflows/tests.yml`) runs the suite on 3.9–3.13, plus ruff, shellcheck and the root installer tests.

## Layout

| File | Role |
|---|---|
| `syswatch.py` | Entry point: CLI, `--report`, `--trust-*`, curses main loop |
| `syswatch_state.py` | `settings` namespace (every tunable; filled once by `main()`), shared `_state` + `_state_lock`, alerts |
| `syswatch_collectors.py` | `Metrics` and the system/log/service/storage/backup threads |
| `syswatch_network.py` | Device discovery, hostname lookup, `NetworkTrust`, `ScanTrustDialog`, `PingSweepThread` |
| `syswatch_render.py` | Colours, sparklines, `FullRenderer` (one `_render_*` per tab) |
| `syswatch_sensors.py` | Platform/sensor detection, error tracking (`note_error`), sudo-aware paths, alert-log writer; shared with the logger |
| `syswatch_config.py` | TOML config loading/validation (`tomllib` or a built-in fallback parser on 3.9/3.10) |
| `syswatch_known_devices.py` / `syswatch_trusted_networks.py` | Device allowlist / networks trusted for scanning (separate on purpose) |
| `syswatch_inventory.py` | Config/data summaries for the installer |
| `syswatch_asciichart.py` | Vendored asciichartpy (MIT), unmodified |
| `syswatch-logger.py`, `syswatch-logger.service` | Background metrics logger |
| `install-syswatch.sh` | Install/upgrade/uninstall (`--unattended`, `--user`, `--skip-config`, `--uninstall [--purge]`) |
| `tests/` | One `test_*.py` per area; `helpers.py` sets `sys.path` and provides a fake curses window |

## Conventions

- **Active scanning needs explicit, confirmed trust.** `PingSweepThread` may only ping subnets of a network in `trusted_networks.json`, re-checked before every batch. Only `[s]`+`[y]` or `--trust-network` (y/N on a TTY) write that file. Device trust (`[t]`) must never imply scan trust. Don't add any path that enables scanning implicitly. Never trust or scan a real network while developing or testing without the owner's explicit confirmation that it's their own network.
- **Collectors never raise.** Failures go to `_note()` / `sensors.note_error()`, which lights the header ⚠. An *absent* tool or sensor (no `smartctl`, no thermal zone, `FileNotFoundError`) returns `None` silently, because absent isn't broken.
- **Shared state** is read via `get_state()` (deep-ish snapshot) and written under `_state_lock`. Never do slow work (subprocesses, DNS) while holding it.
- **Tunables** live in `syswatch_state.settings`. Read them as `settings.X` at call time; tests patch `st.settings`.
- **Per-user files** resolve through `sensors.user_data_path()` / `config_path_default()` (sudo-aware), and anything written under sudo is passed to `sensors.chown_to_invoking_user()`. Persistent JSON is written atomically (temp file + `os.replace`).
- **Config:** every key has a validator in `syswatch_config._SCHEMA`. Bad values are reported and fall back to defaults; they're never fatal.
- **Style:** match the surrounding code. Comments explain *why* (often the bug a line prevents), not what.
- **Tests:** add a test that fails before the fix. Tests must not touch the real home directory, network or system: use temp dirs, mocks, and the fake `ping` / `systemctl` patterns already in `tests/`.
- **Commits:** fixes found while testing go on a separate branch off `development`, each explained in its commit message.
