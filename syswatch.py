#!/usr/bin/env python3
"""syswatch — deep space terminal system monitor

Entry point: command line, --report / --trust-* modes, and the curses main
loop. The rest lives in:

    syswatch_state.py       settings + the state shared between threads
    syswatch_collectors.py  system/journal/service/storage/backup threads
    syswatch_network.py     device discovery, scan trust, ping sweep
    syswatch_render.py      colours, sparklines, FullRenderer (every tab)
    syswatch_sensors.py     platform/sensor detection (shared with the logger)
    syswatch_config.py      config file loading and validation
"""

import sys
import os
import time
import signal
import threading
import curses
import json
import argparse
import locale
from datetime import datetime as _dt


def _bootstrap():
    # psutil is the one third-party dependency. It used to be pip-installed
    # here on first run — under `sudo` that meant pip writing into the system
    # Python with --break-system-packages, which can break apt-managed
    # packages. Now it's installed by install-syswatch.sh (apt's
    # python3-psutil); if it's missing, say how to get it and stop.
    import importlib.util as ilu
    if ilu.find_spec("psutil") is None:
        sys.stderr.write(
            "syswatch needs the psutil Python module, which isn't installed.\n"
            "Install it with:  sudo apt install python3-psutil\n"
            "(or re-run install-syswatch.sh, which does this for you).\n")
        sys.exit(1)

_bootstrap()
import psutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import syswatch_sensors as sensors
import syswatch_config
import syswatch_known_devices as known_devices
import syswatch_trusted_networks as trusted_networks

# A thread whose run() loop somehow lets an exception escape its own
# try/except would otherwise just die silently — no crash, no signal, the
# numbers it was updating simply stop moving. This makes that visible the
# same way every other collector failure is: recorded via note_error(), so
# it shows up in the degraded indicator and (with --debug) debug.log.
threading.excepthook = sensors.log_uncaught_thread_exception


def _init_ctype_locale():
    """Give ncurses a locale that can actually encode the glyphs the TUI is
    drawn from. Must run before curses initialises.

    Python never calls setlocale() on its own, so the C-level locale stays "C"
    (ASCII) unless we set it. ncurses converts the wide characters Python hands
    it back to bytes using that locale, so under e.g. `LC_ALL=C ssh host
    syswatch` every box-drawing, block and sparkline glyph came out as raw
    invalid-UTF-8 bytes and the whole display was garbage. (LANG=C alone
    happened to survive only because PEP 538 coerces it to C.UTF-8; setting
    LC_ALL suppresses that coercion.)

    Only LC_CTYPE is touched, not LC_ALL — character encoding is the only part
    that matters here, and taking LC_TIME/LC_NUMERIC as well would quietly
    change strftime month abbreviations on the HISTORY axis and number
    formatting elsewhere. If the user's own locale can't represent the glyphs,
    fall back to a UTF-8 one; if none exists, leave things as they were.
    """
    try:
        locale.setlocale(locale.LC_CTYPE, "")
    except Exception:
        pass
    try:
        codeset = locale.nl_langinfo(locale.CODESET)
    except Exception:
        return
    if codeset.lower().replace("-", "").replace("_", "") == "utf8":
        return
    for candidate in ("C.UTF-8", "C.utf8", "en_US.UTF-8"):
        try:
            locale.setlocale(locale.LC_CTYPE, candidate)
            return
        except Exception:
            continue



from syswatch_state import _note, get_state, push_alert, scan_dead_threads, settings  # noqa: E402
from syswatch_collectors import (BackupStatusThread, LogThread, Metrics,  # noqa: E402
                                 ServiceWatchdogThread, StorageThread, SystemThread)
from syswatch_network import (ARPPassiveThread, NetworkTrust, PingSweepThread,  # noqa: E402
                              ScanTrustDialog, _name_or_none, _resolve_hostname,
                              current_network)
from syswatch_render import FullRenderer, fmtb, fmtup, init_colors  # noqa: E402


def build_tabs():
    tabs = [
        ("system",   "SYSTEM"),
        ("network",  "NETWORK"),
        ("logs",     "LOGS"),
        ("services", "SERVICES"),
        ("storage",  "STORAGE"),
    ]
    if sensors.backup_service_available():
        tabs.append(("backup", "BACKUP"))
    tabs.append(("history", "HISTORY"))
    return tabs

# ── entry point ────────────────────────────────────────────────────────────────
def _curses_main(stdscr, args, cfg_errors=None):
    init_colors()
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(100)
    stdscr.keypad(True)

    tabs           = build_tabs()
    active_tab     = max(1, min(len(tabs), args.tab))
    if active_tab != args.tab:
        # The tab list depends on the machine (BACKUP is optional), so a
        # configured tab number can be out of range on one host and fine on
        # another — say what happened rather than silently picking another.
        push_alert(f"tab {args.tab} doesn't exist here ({len(tabs)} tabs) — "
                   f"opened {tabs[active_tab - 1][1]} instead")
    mode           = "normal"
    log_filter     = ""
    filter_buf     = ""
    history_window = 0
    history_scroll = 0
    last_render    = 0.0
    alive          = [True]

    def _tab_id(n):
        return tabs[n - 1][0] if 1 <= n <= len(tabs) else None

    signal.signal(signal.SIGINT,  lambda *_: alive.__setitem__(0, False))
    signal.signal(signal.SIGTERM, lambda *_: alive.__setitem__(0, False))

    trust      = NetworkTrust()
    arp_thread = ARPPassiveThread(trust=trust)
    scan_dialog = ScanTrustDialog(trust, on_change=arp_thread.publish_network_meta)
    threads = [
        SystemThread(),
        arp_thread,
        PingSweepThread(scan_mode=settings.SCAN_MODE, trust=trust),
        LogThread(),
        ServiceWatchdogThread(),
        StorageThread(),
    ]
    if any(tid == "backup" for tid, _ in tabs):
        threads.append(BackupStatusThread())
    for t in threads:
        t.start()

    if cfg_errors:
        push_alert(f"config: {'; '.join(cfg_errors)}")

    renderer = FullRenderer(stdscr, tabs)

    while alive[0]:
        ch = stdscr.getch()

        if mode == "normal":
            # Deliberately NOT treating a bare ESC (27) as quit: curses
            # delivers a standalone 27 not just for an actual Esc keypress
            # but also whenever an escape sequence (arrow/function keys, or
            # a fragment from a laggy terminal/multiplexer) is split across
            # reads and the ESCDELAY timeout elapses before the rest
            # arrives — indistinguishable from Esc at this point. That made
            # quitting ambiguous with routine terminal noise; q/Q is now the
            # only way to quit.
            if ch in (ord("q"), ord("Q")):
                break
            elif ch == curses.KEY_RESIZE:
                curses.update_lines_cols()
                last_render = 0.0
            elif ord("1") <= ch <= ord("0") + len(tabs):
                active_tab = ch - ord("0")
                last_render = 0.0
            elif ch == ord("h") and _tab_id(active_tab) == "history":
                history_window = (history_window + 1) % 5
                last_render = 0.0
            elif ch == curses.KEY_DOWN and _tab_id(active_tab) == "history":
                history_scroll = min(history_scroll + 1, renderer.hist_scroll_max)
                last_render = 0.0
            elif ch == curses.KEY_UP and _tab_id(active_tab) == "history" and history_scroll > 0:
                history_scroll -= 1
                last_render = 0.0
            elif ch == ord("/") and _tab_id(active_tab) == "logs":
                mode       = "filter_input"
                filter_buf = log_filter
                curses.curs_set(1)
                last_render = 0.0
            elif ch in (ord("t"), ord("T")) and _tab_id(active_tab) == "network":
                # Devices only — never scan permission (that's [s]).
                try:
                    arp_thread.trust_all()
                    push_alert("all listed devices trusted (scanning unchanged)")
                except Exception as e:
                    _note("trust_all (keybinding)", e)
                last_render = 0.0
            elif ch in (ord("s"), ord("S")) and _tab_id(active_tab) == "network":
                try:
                    if scan_dialog.open():
                        mode = "confirm_scan"
                except Exception as e:
                    _note("scan trust dialog (open)", e)
                last_render = 0.0
        elif mode == "confirm_scan":
            if ch == curses.KEY_RESIZE:
                curses.update_lines_cols()
                last_render = 0.0
            try:
                closed = scan_dialog.handle_key(ch, renderer.dialog_complete)
            except Exception as e:
                _note("scan trust dialog (key)", e)
                scan_dialog.pending, closed = None, True
            if closed:
                mode = "normal"
                last_render = 0.0
        elif mode == "filter_input":
            if ch == 27:
                mode, filter_buf = "normal", ""
                curses.curs_set(0)
                last_render = 0.0
            elif ch in (curses.KEY_ENTER, 10, 13):
                log_filter, mode, filter_buf = filter_buf, "normal", ""
                curses.curs_set(0)
                last_render = 0.0
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                filter_buf = filter_buf[:-1]
                last_render = 0.0
            elif 32 <= ch <= 126:
                filter_buf += chr(ch)
                last_render = 0.0

        now = time.monotonic()
        if now - last_render >= settings.REFRESH:
            if mode == "confirm_scan":
                scan_dialog.check_network()
                if scan_dialog.pending is None:
                    mode = "normal"
            scan_dead_threads(threads)
            state = get_state()
            try:
                # Nothing between here and curses.wrapper() catches a render
                # bug — before this, any unhandled exception anywhere in the
                # ~20 _render_* / _draw_* methods (a bad coordinate, an
                # unexpected None, a negative sparkline index, ...) would
                # propagate all the way out of curses.wrapper() and kill the
                # whole TUI with a traceback instead of just this one frame.
                renderer.render(active_tab, state, log_filter, mode, filter_buf,
                                history_window, history_scroll, scan_dialog.pending)
            except Exception as e:
                _note("render", e)
            last_render = now

    for t in threads:
        t.stop()
    for t in threads:
        t.join(timeout=2.0)


def _print_report(as_json):
    # One-shot snapshot for cron/email digests: no curses, no threads.
    # Metrics.__init__ primes psutil cpu_percent across every process, which
    # a report doesn't need — the probes used here are all stateless.
    m = Metrics.__new__(Metrics)
    now   = _dt.now()
    is_pi = sensors.is_pi()

    uptime_secs  = time.time() - psutil.boot_time()
    model        = sensors.platform_model()
    cpu_temp     = m._soc_temp()
    gpu_temp     = m._gpu_temp()
    gpu_info     = None if is_pi else sensors.gpu_temp()
    storage_temp = sensors.storage_temp()
    voltage      = m._voltage()   if is_pi else None
    throttled    = m._throttled() if is_pi else None

    watchdog = ServiceWatchdogThread()
    services = []
    for unit in settings.WATCHED_SERVICES:
        props = watchdog._query(unit)
        if props is None:            # systemctl not available
            services = None
            break
        services.append({
            "unit":   unit,
            "state":  props.get("ActiveState", "unknown"),
            "sub":    props.get("SubState", ""),
        })
    failed = [s["unit"] for s in services or [] if s["state"] == "failed"]

    boot = sensors.boot_mount()
    disks = {"/": StorageThread._fs_stats("/")}
    if boot:
        disks[boot] = StorageThread._fs_stats(boot)

    # Whether *this run* would actually sweep: only on a network the user
    # explicitly trusted for scanning (NetworkTrust), checked the same way
    # PingSweepThread does it.
    network_trusted = None
    if settings.SCAN_MODE == "trusted":
        try:
            net_id, _cidrs = current_network()
            network_trusted = NetworkTrust().is_trusted(net_id)
        except Exception as e:
            _note("_print_report (scan trust probe)", e)

    if as_json:
        report = {
            "generated":     now.strftime("%Y-%m-%dT%H:%M:%S"),
            "is_pi":         is_pi,
            "model":         model,
            "uptime_secs":   round(uptime_secs, 1),
            "cpu_temp_c":    cpu_temp,
            "gpu_temp_c":    gpu_temp,
            "gpu_vendor":    gpu_info["vendor"] if gpu_info else None,
            "storage_temp_c": storage_temp,
            "core_volts":    voltage,
            "throttled":     throttled,
            "scan_mode":     settings.SCAN_MODE,
            "scan_network_trusted":    network_trusted,
            # Pre-1.4 name for the same field, kept for existing consumers.
            "scan_network_recognised": network_trusted,
            "services":      services,
            "failed_services": failed,
            "disks": {
                mount: (
                    {"used": fs["used"], "total": fs["total"],
                     "pct": round(fs["pct"], 1)}
                    if fs else None
                )
                for mount, fs in disks.items()
            },
        }
        print(json.dumps(report, indent=2))
        return

    def fmt(val, suffix=""):
        return f"{val}{suffix}" if val is not None else "N/A"

    print(f"SYSWATCH REPORT — {now.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Model:        {model}")
    print(f"Uptime:       {fmtup(uptime_secs)}")
    print(f"CPU temp:     {fmt(cpu_temp, ' °C')}")
    gpu_suffix = f" ({gpu_info['vendor']})" if gpu_info else ""
    print(f"GPU temp:     {fmt(gpu_temp, ' °C')}{gpu_suffix}")
    print(f"Storage temp: {fmt(storage_temp, ' °C')}")
    if settings.SCAN_MODE == "trusted":
        if network_trusted:
            scan_line = "trusted — this network is trusted for scanning (sweep active)"
        else:
            scan_line = ("trusted — this network is NOT trusted for scanning "
                         "(passive-only; [s] on the NETWORK tab or --trust-network)")
    else:
        scan_line = "never (passive ARP only)"
    print(f"Scan mode:    {scan_line}")
    if is_pi:
        print(f"Core voltage: {f'{voltage:.4f} V' if voltage is not None else 'N/A'}")
        if throttled is not None:
            flags = [("under-voltage", "uv"), ("freq-capped", "freq"),
                     ("throttled", "throt"), ("soft-temp-limit", "temp")]
            active = [n for n, k in flags if throttled.get(f"{k}_now")]
            ever   = [n for n, k in flags if throttled.get(f"{k}_ever")]
            print(f"Throttle now: {', '.join(active) if active else 'none'}")
            print(f"Throttle ever:{' ' + ', '.join(ever) if ever else ' none'}")
        else:
            print("Throttle:     N/A")
    if services is None:
        print("Services:     N/A (systemctl not available)")
    elif not services:
        print("Services:     none configured ([services] watch is empty)")
    elif failed:
        print(f"Services:     {len(failed)} FAILED — {', '.join(failed)}")
    elif all(s["state"] == "unknown" for s in services):
        print("Services:     state unknown (systemctl query failed)")
    else:
        print(f"Services:     all {len(services)} watched units OK")
    for mount, fs in disks.items():
        if fs is None:
            print(f"Disk {mount:<7} N/A")
        else:
            print(f"Disk {mount:<7} {fmtb(fs['used'])}/{fmtb(fs['total'])}"
                  f"  ({fs['pct']:.1f}% used)")


def _cli_trust_all_devices():
    # One-shot, non-interactive equivalent of the NETWORK tab's [t] binding:
    # snapshot the current ARP table, learn every MAC on the current network,
    # and clear anything that would otherwise show as INTRUDER.
    arp    = ARPPassiveThread()
    now    = time.time()
    net_id = arp._refresh_network_identity(now)
    parsed = arp._parse_arp_table()
    for mac, info in parsed.items():
        hostname = _resolve_hostname(info["ip"])
        known_devices.remember(arp._known, net_id, mac,
                               _name_or_none(hostname, info["ip"]), now)
    arp._save(now)
    print(f"Trusted {len(parsed)} device(s) on network '{net_id}'. "
          f"Saved to {settings.KNOWN_DEVICES_PATH}")
    print("This does not enable active scanning — use --trust-network for that.")


def _cli_scan_trust(untrust=False):
    """--trust-network / --untrust-network: the non-TUI equivalent of [s],
    with the same warning and an explicit y/N. Refuses without a terminal:
    there is deliberately no way to grant scan permission unattended."""
    trust = NetworkTrust()
    net_id, cidrs = current_network()
    if untrust:
        if not trust.is_trusted(net_id):
            print(f"Network '{net_id}' is not trusted for scanning — nothing to do.")
            return 0
        prompt = (f"Stop scanning and untrust network '{net_id}' "
                  f"({', '.join(trust.cidrs(net_id))})? [y/N] ")
    else:
        if settings.SCAN_MODE == "never":
            print("Note: scan = never in your config, so no scanning will happen "
                  "until that is changed.", file=sys.stderr)
        if trust.is_trusted(net_id):
            print(f"Network '{net_id}' is already trusted for scanning "
                  f"({', '.join(trust.cidrs(net_id))}).")
            return 0
        reason = trusted_networks.untrustable_reason(net_id)
        if reason is None and not cidrs:
            reason = ("no scannable local subnet contains this network's gateway "
                      "(subnets larger than /22 are never swept)")
        if reason:
            print(f"Can't trust this network for scanning: {reason}", file=sys.stderr)
            return 1
        hosts = trusted_networks.host_count(cidrs)
        print(f"Network:   {net_id}\n"
              f"Will ping: {', '.join(cidrs)} ({hosts} hosts), about every "
              f"{int(settings.PING_CYCLE)}s while syswatch runs on this network.\n\n"
              "WARNING: an active sweep is visible to the network and can trigger\n"
              "intrusion-detection / security alerts. Only do this on a network\n"
              "you own or are allowed to scan.\n")
        prompt = "Trust this network and enable active scanning? [y/N] "
    if not sys.stdin.isatty():
        print("Refusing: confirmation needs an interactive terminal.", file=sys.stderr)
        return 1
    try:
        answer = input(prompt)
    except EOFError:
        answer = ""
    if answer.strip().lower() not in ("y", "yes"):
        print("Cancelled — nothing changed.")
        return 1
    # Re-check: the answer only covers the network that was shown.
    now_id, now_cidrs = current_network()
    if now_id != net_id or (not untrust and now_cidrs != cidrs):
        print("The network changed while waiting — cancelled, nothing changed.",
              file=sys.stderr)
        return 1
    if untrust:
        trust.untrust(net_id)
        print("Network untrusted — syswatch will no longer scan it.")
        return 0
    reason = trust.trust(net_id, cidrs)
    if reason:
        print(f"Can't trust this network for scanning: {reason}", file=sys.stderr)
        return 1
    print(f"Network trusted — syswatch will actively scan {', '.join(cidrs)} here.")
    return 0


def main():

    parser = argparse.ArgumentParser(
        description="syswatch — deep space terminal system monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--tab", type=int, default=None, metavar="N",
        help="start on tab N (1-based; tab count depends on detected hardware "
             "— run with no args and check the tab bar; overrides config)",
    )
    parser.add_argument(
        "--refresh", type=float, default=None, metavar="N",
        help="refresh rate in seconds (min 0.5; overrides config)",
    )
    parser.add_argument(
        "--no-scan", action="store_true",
        help="disable the active ping sweep (passive ARP only); same as "
             "--scan never; overrides config",
    )
    parser.add_argument(
        "--scan", type=str, default=None, choices=["trusted", "known", "never"],
        metavar="MODE",
        help="override [network] scan for this run: trusted = sweep only "
             "networks you explicitly trusted for scanning (default; 'known' "
             "is an old alias), never = passive ARP only. There is no "
             "'always' mode.",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="print a one-shot system report to stdout and exit (no TUI)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="with --report, output JSON instead of text",
    )
    parser.add_argument(
        "--config", type=str, default=None, metavar="PATH",
        help="use this config file instead of the default "
             "($XDG_CONFIG_HOME/syswatch/config.toml)",
    )
    parser.add_argument(
        "--write-default-config", action="store_true",
        help="write a fully commented example config to the default location "
             "(or --config PATH) and exit",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="with --write-default-config, overwrite an existing file",
    )
    parser.add_argument(
        "--trust-all-devices", action="store_true",
        help="mark every device currently in the ARP table as known on this "
             "network (same as the NETWORK tab's [t] binding), then exit",
    )
    parser.add_argument(
        "--trust-network", action="store_true",
        help="trust the current network for active scanning (shows what would "
             "be scanned and asks y/N; needs a terminal), then exit",
    )
    parser.add_argument(
        "--untrust-network", action="store_true",
        help="stop scanning the current network and forget its scan trust "
             "(asks y/N), then exit",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="log every collector failure (which one, exception, full "
             "traceback) to ~/.local/share/syswatch/debug.log",
    )
    parser.add_argument(
        "--version", action="version", version=f"syswatch {sensors.VERSION}",
    )
    args = parser.parse_args()
    sensors.set_debug(args.debug)

    if args.write_default_config:
        path = args.config or syswatch_config.config_path_default()
        try:
            written = syswatch_config.write_default_config(path, force=args.force)
        except FileExistsError:
            print(f"Config already exists at {path} — use --force to overwrite.",
                  file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            print(f"Could not write config: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Wrote example config to {written}")
        return

    config, cfg_errors = syswatch_config.load_config(args.config)

    # CLI flags override the config file. --scan takes precedence over
    # --no-scan when both are given (an explicit --scan is the more
    # specific ask), but either alone overrides the config's [network] scan.
    if args.no_scan:
        config["network"]["scan"] = "never"
    if args.scan is not None:
        config["network"]["scan"] = "trusted" if args.scan == "known" else args.scan
    if args.refresh is not None:
        config["ui"]["refresh"] = args.refresh
    if args.tab is not None:
        config["ui"]["default_tab"] = args.tab

    settings.WATCHED_SERVICES = config["services"]["watch"]
    settings.THRESH           = config["thresholds"]
    settings.SCAN_MODE         = config["network"]["scan"]
    settings.INTRUDER_ALERTS   = config["network"]["intruder_alerts"]
    settings.ARP_REFRESH       = config["network"]["arp_refresh"]
    settings.PING_CYCLE        = config["network"]["ping_cycle"]
    settings.PING_BATCH        = config["network"]["ping_batch"]
    settings.INTRUDER_TTL      = config["network"]["intruder_ttl"]
    settings.BASELINE_WINDOW   = config["network"]["baseline_window"]
    settings.KNOWN_DEVICES_RETENTION_DAYS = config["network"]["known_devices_retention_days"]
    settings.HISTORY           = config["ui"]["history"]
    settings.TOP_N             = config["ui"]["top_n"]
    settings.ALERT_TTL         = config["ui"]["alert_ttl"]
    settings.WATCHDOG_REFRESH  = config["ui"]["watchdog_refresh"]
    settings.SDCARD_REFRESH    = config["ui"]["storage_refresh"]
    settings.REFRESH           = max(0.5, config["ui"]["refresh"])

    if args.trust_all_devices:
        for e in cfg_errors:
            print(f"config: {e}", file=sys.stderr)
        _cli_trust_all_devices()
        return

    if args.trust_network or args.untrust_network:
        for e in cfg_errors:
            print(f"config: {e}", file=sys.stderr)
        sys.exit(_cli_scan_trust(untrust=args.untrust_network))

    if args.report:
        for e in cfg_errors:
            print(f"config: {e}", file=sys.stderr)
        _print_report(args.json)
        return

    args.tab = config["ui"]["default_tab"]
    _init_ctype_locale()  # must precede curses init — see the function's docstring
    try:
        curses.wrapper(lambda stdscr: _curses_main(stdscr, args, cfg_errors))
    except KeyboardInterrupt:
        pass
    print("\nSYSWATCH — DISCONNECTED\n")


if __name__ == "__main__":
    main()
