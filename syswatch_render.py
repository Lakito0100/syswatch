#!/usr/bin/env python3
"""syswatch_render — everything that draws: colours, formatting helpers,
sparklines and FullRenderer (one _render_* method per tab)."""

import collections
import curses
import math
import os
import socket
import time
from datetime import datetime as _dt

import syswatch_asciichart as asciichartpy  # vendored, see the file header
import syswatch_sensors as sensors
import syswatch_trusted_networks as trusted_networks
from syswatch_state import NUM_CORES, _alerts, _dead_threads, _note, settings


# ── color pair IDs ─────────────────────────────────────────────────────────────
CP_PRIMARY   = 1   # bright cyan-blue — main data color
CP_SECONDARY = 2   # medium grey — secondary labels
CP_ACCENT    = 3   # deep amber — warnings and highlights
CP_DIM       = 4   # very dark grey — inactive/background elements
CP_CRITICAL  = 5   # hard red — critical alerts only
CP_WARN      = 6   # amber-orange — warning state
CP_GOOD      = 7   # cold green — healthy/nominal state
CP_HDR       = 8   # black text on cyan-blue — header/footer bars
CP_MUTED     = 9   # dim grey — sparklines, inactive separators
CP_HILIGHT   = 10  # bright ice blue — active tab, selected items

SPARK_CHARS = " ▁▂▃▄▅▆▇█"


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    try:
        if curses.COLORS >= 256:
            curses.init_pair(CP_PRIMARY,   39,  -1)
            curses.init_pair(CP_SECONDARY, 244, -1)
            curses.init_pair(CP_ACCENT,    202, -1)
            curses.init_pair(CP_DIM,       237, -1)
            curses.init_pair(CP_CRITICAL,  196, -1)
            curses.init_pair(CP_WARN,      214, -1)
            curses.init_pair(CP_GOOD,      48,  -1)
            curses.init_pair(CP_HDR,       232, 39)
            curses.init_pair(CP_MUTED,     240, -1)
            curses.init_pair(CP_HILIGHT,   51,  -1)
        else:
            raise ValueError("8-color fallback")
    except Exception:
        curses.init_pair(CP_PRIMARY,   curses.COLOR_CYAN,    -1)
        curses.init_pair(CP_SECONDARY, curses.COLOR_WHITE,   -1)
        curses.init_pair(CP_ACCENT,    curses.COLOR_YELLOW,  -1)
        curses.init_pair(CP_DIM,       curses.COLOR_WHITE,   -1)
        curses.init_pair(CP_CRITICAL,  curses.COLOR_RED,     -1)
        curses.init_pair(CP_WARN,      curses.COLOR_YELLOW,  -1)
        curses.init_pair(CP_GOOD,      curses.COLOR_GREEN,   -1)
        curses.init_pair(CP_HDR,       curses.COLOR_BLACK,   curses.COLOR_CYAN)
        curses.init_pair(CP_MUTED,     curses.COLOR_WHITE,   -1)
        curses.init_pair(CP_HILIGHT,   curses.COLOR_CYAN,    -1)


def cp(pair_id, bold=False):
    attr = curses.color_pair(pair_id)
    return attr | curses.A_BOLD if bold else attr


def threshold_cp(val, key):
    t = settings.THRESH.get(key)
    if t is None or val is None:
        return cp(CP_PRIMARY)
    if val >= t[1]: return cp(CP_CRITICAL, bold=True)
    if val >= t[0]: return cp(CP_WARN)
    return cp(CP_GOOD)


def fmtb(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


def fmtup(s):
    d = int(s // 86400); s %= 86400
    h = int(s // 3600);  s %= 3600
    m = int(s // 60);    s = int(s % 60)
    return (f"{d}d " if d else "") + f"{h:02}:{m:02}:{s:02}"


def sparkline(history, width):
    data = list(history)
    if not data or width <= 0:
        return " " * width
    # max(data) can be <= 0 (e.g. a counter reset briefly drives every value
    # negative), which would otherwise turn `hi` negative and make
    # int(v / hi * 8) produce a negative index — SPARK_CHARS[-50] either wraps
    # to an unrelated glyph or raises IndexError outright, crashing the
    # render. Floor hi at a small positive value and clamp each value's
    # domain to [0, hi] so the index math can never leave [0, 8].
    hi = max(data)
    hi = hi if hi > 0 else 1
    data = data[-width:]
    chars = []
    for v in data:
        idx = int(max(0.0, v) / hi * 8)
        chars.append(SPARK_CHARS[max(0, min(8, idx))])
    return "".join(chars).ljust(width)


# ── FullRenderer ───────────────────────────────────────────────────────────────
class FullRenderer:
    MIN_W = 40
    MIN_H = 12

    def __init__(self, win, tabs):
        self.win  = win
        self.tabs = tabs  # [(id, label), ...] — see build_tabs()
        curses.curs_set(0)
        win.timeout(100)
        win.keypad(True)
        self._hist_cache = None  # (checked_at: float, rows: list, file_sig)
        self.dialog_complete = False  # last confirm dialog was drawn in full
        self.hist_scroll_max = 0  # highest valid Tab 7 scroll offset (charts)

    # ── primitives ────────────────────────────────────────────────────────────

    def _add(self, y, x, text, attr=0):
        H, W = self.win.getmaxyx()
        if y < 0 or y >= H or x < 0 or x >= W:
            return
        text = str(text)[:max(0, W - x)]
        if not text:
            return
        try:
            self.win.addstr(y, x, text, attr)
        except curses.error:
            pass

    def _hline(self, y, x, char, n, attr=0):
        H, W = self.win.getmaxyx()
        n = min(n, W - x)
        if n <= 0 or y < 0 or y >= H:
            return
        try:
            self.win.addstr(y, x, char * n, attr)
        except curses.error:
            pass

    def _bar(self, y, x, pct, width, key=None):
        if width < 3:
            return
        # threshold_cp() right below already treats a None value as "no
        # data" and falls back gracefully; _bar() itself didn't, so any
        # caller passing through an unavailable metric (battery/GPU/storage
        # temp) unguarded would crash here on `pct / 100`. Every current call
        # site already guards its own None case before calling in, but that
        # makes it easy for a *future* call site to reintroduce the crash —
        # guarding here too costs nothing and matches threshold_cp's contract.
        if pct is None:
            pct = 0
        inner  = width - 2
        filled = max(0, min(inner, int(pct / 100 * inner)))
        c      = threshold_cp(pct, key) if key else cp(CP_PRIMARY)
        self._add(y, x,                "[",                     cp(CP_SECONDARY))
        # █/░ (Block Elements, U+2588/U+2591) rather than the parallelogram
        # glyphs (U+25B0/U+25B1, Geometric Shapes) — the latter are missing
        # from enough monospace fonts that a terminal falls back to a
        # substitute glyph with different advance width, and since a bar is
        # dozens of these in a row, even a small per-glyph width error
        # compounds into the whole row (and everything after it) drifting
        # far past its intended column, visually swallowing the next panel.
        # Block Elements are part of code page 437 and universally supported.
        self._add(y, x + 1,            "█" * filled,            c)
        self._add(y, x + 1 + filled,   "░" * (inner - filled),  cp(CP_DIM))
        self._add(y, x + 1 + inner,    "]",                     cp(CP_SECONDARY))

    def _label(self, y, x, text, width=None):
        H, W = self.win.getmaxyx()
        w = width if width is not None else (W - x)
        self._hline(y, x, "─", w, cp(CP_DIM))
        label = f"┤ {text} ├"
        lx = x + 2
        if len(label) + 2 <= w:
            self._add(y, lx, label, cp(CP_PRIMARY, bold=True))

    def _spark_attr(self, history, key=None):
        data = list(history)
        if not data:
            return cp(CP_MUTED)
        latest = data[-1]
        if key:
            t = settings.THRESH.get(key)
            if t:
                if latest >= t[1]: return cp(CP_CRITICAL, bold=True)
                if latest >= t[0]: return cp(CP_WARN)
        return cp(CP_GOOD)

    # ── structural elements ───────────────────────────────────────────────────

    def _render_header(self):
        H, W = self.win.getmaxyx()
        host  = socket.gethostname()
        now   = _dt.now()
        ts    = now.strftime("%H:%M:%S")
        date  = now.strftime("%Y-%m-%d")
        left  = "▸ SYSWATCH"
        # A degraded indicator that's visible regardless of tab or whatever
        # the footer happens to be showing (a user alert, the network-tab
        # hint, ...) — placed in the header instead of competing with those
        # for the footer's limited space. Shown whenever any collector has
        # thrown recently, independent of whether --debug is on, so a
        # degraded run is visible without having to already know to enable
        # debug logging.
        # A dead collector thread outranks a transient collector error: it never
        # recovers, so unlike has_recent_errors() this marker never clears.
        if _dead_threads:
            degraded = "⚠ DEAD "
        elif sensors.has_recent_errors():
            degraded = "⚠ "
        else:
            degraded = ""
        right = f"{degraded}{ts}  {date} "
        self._hline(0, 0, " ", W, cp(CP_HDR))
        self._add(0, 1, left, cp(CP_HDR, bold=True))
        cx = max(len(left) + 2, (W - len(host)) // 2)
        self._add(0, cx, host, cp(CP_HDR))
        rpos = max(cx + len(host) + 1, W - len(right))
        # Bold (not a different color pair) when degraded: CP_WARN's
        # foreground/background combination isn't guaranteed to match the
        # header bar's, and swapping it in here would leave a
        # differently-colored patch breaking up the otherwise continuous bar.
        self._add(0, rpos, right, cp(CP_HDR, bold=bool(degraded)))

    def _render_tab_bar(self, active_tab):
        H, W = self.win.getmaxyx()
        self._hline(1, 0, " ", W, cp(CP_DIM))
        x = 1
        for i, (_id, label) in enumerate(self.tabs):
            padded = f"[ {i + 1}:{label} ]"
            if x + len(padded) >= W:
                break
            if (i + 1) == active_tab:
                attr = cp(CP_HILIGHT, bold=True) | curses.A_UNDERLINE
            else:
                attr = cp(CP_SECONDARY)
            self._add(1, x, padded, attr)
            x += len(padded) + 1

    def _render_footer(self, state):
        H, W = self.win.getmaxyx()
        self._hline(H - 1, 0, " ", W, cp(CP_HDR))
        snap = (state or {}).get("system")
        left_end = 0
        if snap:
            la   = snap.get("load_avg", (0, 0, 0))
            up   = fmtup(snap.get("uptime", 0))
            text = f" UP {up}  LOAD {la[0]:.2f}/{la[1]:.2f}/{la[2]:.2f}"
            left_end = min(len(text), W * 60 // 100)
            self._add(H - 1, 0, text[:left_end], cp(CP_HDR))
        try:
            alert_str = None
            if _alerts:
                ts_pushed, candidate = _alerts[-1]
                if time.monotonic() - ts_pushed <= settings.ALERT_TTL:
                    alert_str = candidate
            if alert_str is not None:
                alert_text = f"  \u26a0 {alert_str}"
                start = W * 60 // 100
                self._add(H - 1, start, alert_text[:W - start - 1],
                          cp(CP_CRITICAL, bold=True))
            else:
                # The NETWORK tab's [t] binding used to be hinted here, but
                # this branch sits after the alert branch above and was
                # silently overwritten whenever a footer alert was showing \u2014
                # including the INTRUDER alert, exactly when the hint matters
                # most. It's now rendered inside the NETWORK tab body itself
                # (_render_network), which stays visible regardless of alert
                # state, so this footer no longer needs a per-tab case.
                mdl   = ((state or {}).get("model") or "unknown")[:32]
                right = f"  {mdl} "
                rpos  = max(left_end + 1, W - len(right))
                self._add(H - 1, rpos, right[:W - rpos], cp(CP_HDR))
        except Exception as e:
            _note("_render_footer", e)

    # ── Tab 1: SYSTEM ─────────────────────────────────────────────────────────

    def _draw_cpu(self, y, x, h, w, snap, hist):
        self._label(y, x, "CPU", w)
        if not snap or h < 2:
            return
        cores = snap.get("cores", [])
        n     = min(len(cores), NUM_CORES, h - 3)
        lbl_w = 4
        pct_w = 7
        bw    = max(4, w - lbl_w - pct_w)
        for i in range(n):
            row = y + 1 + i
            if row >= y + h:
                break
            p = cores[i] if i < len(cores) else 0.0
            c = threshold_cp(p, "cpu_pct")
            self._add(row, x,               f"C{i:<2} ", cp(CP_SECONDARY))
            self._bar(row, x + lbl_w,       p, bw, "cpu_pct")
            self._add(row, x + lbl_w + bw,  f" {p:5.1f}%", c)
        avg_row = y + 1 + n
        if avg_row < y + h:
            avg = snap.get("cpu_avg", 0.0)
            c   = threshold_cp(avg, "cpu_pct")
            self._add(avg_row, x,              "AVG ", cp(CP_SECONDARY, bold=True))
            self._bar(avg_row, x + lbl_w,      avg, bw, "cpu_pct")
            self._add(avg_row, x + lbl_w + bw, f" {avg:5.1f}%", c)
        spark_row = y + 2 + n
        cpu_hist  = (hist or {}).get("cpu", [])
        if spark_row < y + h and len(cpu_hist) >= 2:
            spark_color = self._spark_attr(cpu_hist, "cpu_pct")
            self._add(spark_row, x, "    " + sparkline(cpu_hist, bw), spark_color)

    def _draw_memory(self, y, x, h, w, snap, hist):
        self._label(y, x, "MEMORY", w)
        if not snap or h < 2:
            return
        row = y + 1
        for lbl, uk, tk, pk in [
            ("RAM ", "ram_used",  "ram_total",  "ram_pct"),
            ("SWAP", "swap_used", "swap_total", "swap_pct"),
        ]:
            if row + 1 >= y + h:
                break
            pct  = snap.get(pk, 0)
            used = snap.get(uk, 0)
            tot  = snap.get(tk, 0)
            c    = threshold_cp(pct, "ram_pct")
            info = f"{fmtb(used):>8}/{fmtb(tot):<8}"
            self._add(row, x,         lbl,             cp(CP_SECONDARY, bold=True))
            self._add(row, x + 5,     info,            cp(CP_PRIMARY))
            self._add(row, x + w - 7, f"{pct:5.1f}%", c)
            row += 1
            self._bar(row, x, pct, w, "ram_pct")
            row += 1
        batt_pct = snap.get("battery_pct")
        if batt_pct is not None and row + 1 < y + h:
            self._add(row, x,         "BATT",          cp(CP_SECONDARY, bold=True))
            self._add(row, x + w - 7, f"{batt_pct:5.1f}%", cp(CP_PRIMARY))
            row += 1
            self._bar(row, x, batt_pct, w)
            row += 1
        ram_hist = (hist or {}).get("ram", [])
        if row < y + h and len(ram_hist) >= 2:
            spark_color = self._spark_attr(ram_hist, "ram_pct")
            self._add(row, x, sparkline(ram_hist, w), spark_color)

    @staticmethod
    def _temp_rows(snap):
        """Which rows _draw_temp will actually draw, for sizing and rendering."""
        is_pi = snap.get("is_pi", False)
        rows  = ["cpu_temp"]
        if snap.get("gpu_temp") is not None:
            rows.append("gpu_temp")
        if snap.get("storage_temp") is not None:
            rows.append("storage_temp")
        rows.append("freq")
        if is_pi:
            rows.append("throt")
        return rows

    def _draw_temp(self, y, x, h, w, snap):
        title = "TEMP & THROTTLE" if (snap or {}).get("is_pi") else "TEMPERATURES"
        self._label(y, x, title, w)
        if not snap or h < 2:
            return
        row  = y + 1
        gpu_label = "GPU TEMP"
        if not snap.get("is_pi") and snap.get("gpu_vendor"):
            gpu_label = f"GPU TEMP ({snap['gpu_vendor']})"
        temp_labels = {
            "cpu_temp":     "CPU TEMP",
            "gpu_temp":     gpu_label,
            "storage_temp": "STORAGE TEMP",
        }
        temp_thresh_key = {
            "cpu_temp":     "cpu_temp",
            "gpu_temp":     "gpu_temp",
            "storage_temp": "storage_temp",
        }
        temp_row_keys = [k for k in self._temp_rows(snap) if k in temp_labels]
        # Size the label column to the longest label actually shown this frame
        # (e.g. "GPU TEMP (NVIDIA)") instead of a fixed 13 — a fixed width let
        # the bar start before the label text ended, overwriting it. Capped so
        # a narrow panel still leaves room for the bar and value.
        lw = 13
        if temp_row_keys:
            lw = max(lw, max(len(temp_labels[k]) for k in temp_row_keys) + 1)
        lw = min(lw, max(13, w - 12))
        for key in self._temp_rows(snap):
            if row >= y + h:
                break
            if key == "freq":
                freq  = snap.get("cpu_freq")
                volt  = snap.get("voltage")
                f_str = f"{freq} MHz" if freq else "N/A    "
                v_str = f"  {volt:.4f}V" if volt else ""
                self._add(row, x, f"FREQ {f_str}{v_str}", cp(CP_PRIMARY))
                row += 1
                continue
            if key == "throt":
                th    = snap.get("throttled") or {}
                flags = [
                    ("UV",    th.get("uv_now",    False), th.get("uv_ever",    False)),
                    ("FREQ",  th.get("freq_now",  False), th.get("freq_ever",  False)),
                    ("THROT", th.get("throt_now", False), th.get("throt_ever", False)),
                    ("TEMP",  th.get("temp_now",  False), th.get("temp_ever",  False)),
                ]
                self._add(row, x, "THROT: ", cp(CP_SECONDARY))
                col = x + 7
                for lbl, now_f, ever in flags:
                    if now_f:
                        dot, c = "●", cp(CP_CRITICAL, bold=True)
                    elif ever:
                        dot, c = "●", cp(CP_WARN)
                    else:
                        dot, c = "○", cp(CP_DIM)
                    self._add(row, col, f"{dot}{lbl} ", c)
                    col += len(lbl) + 2
                row += 1
                continue
            # temperature row
            label = temp_labels[key][:lw]
            v     = snap.get(key)
            c     = threshold_cp(v, temp_thresh_key[key])
            self._add(row, x, f"{label:<{lw}}", cp(CP_SECONDARY))
            bw2   = max(4, w - lw - 8)
            if v is not None:
                self._bar(row, x + lw, min(100.0, v / 90.0 * 100), bw2)
                self._add(row, x + lw + bw2, f" {v:.1f}°C", c)
            elif key == "cpu_temp":
                self._add(row, x + lw, sensors.cpu_temp_hint(), cp(CP_MUTED))
            else:
                self._add(row, x + lw, "░" * bw2 + " N/A", cp(CP_DIM))
            row += 1

    def _draw_network_sys(self, y, x, h, w, snap, hist):
        self._label(y, x, "NETWORK", w)
        if not snap or h < 2:
            return
        row = y + 1
        rx  = snap.get("net_rx", 0)
        tx  = snap.get("net_tx", 0)
        if row < y + h:
            self._add(row, x, f"↓ RX  {rx:8.1f} KB/s", cp(CP_PRIMARY, bold=True))
            row += 1
        if row < y + h:
            self._add(row, x, f"↑ TX  {tx:8.1f} KB/s", cp(CP_ACCENT))
            row += 1
        wifi = snap.get("wifi")
        if wifi and row < y + h:
            sig   = wifi["signal"]
            wc    = CP_GOOD if sig > -60 else (CP_WARN if sig > -75 else CP_CRITICAL)
            wpct  = max(0.0, min(100.0, (sig + 90) / 60 * 100))
            iface = wifi.get("iface", "WiFi").upper()[:8]
            bw    = max(4, w - 15)
            self._add(row, x, f"{iface} {sig:.0f}dBm ", cp(wc))
            self._bar(row, x + 14, wpct, bw)
            row += 1
        rx_hist = (hist or {}).get("net_rx", [])
        tx_hist = (hist or {}).get("net_tx", [])
        if row < y + h and len(rx_hist) >= 2:
            mid      = w // 2
            rx_color = self._spark_attr(rx_hist)
            tx_color = self._spark_attr(tx_hist)
            self._add(row, x,       sparkline(rx_hist, mid),     rx_color)
            self._add(row, x + mid, sparkline(tx_hist, w - mid), tx_color)

    def _draw_disk(self, y, x, h, w, snap, hist):
        self._label(y, x, "DISK /", w)
        if not snap or h < 2:
            return
        row  = y + 1
        pct  = snap.get("disk_pct", 0)
        used = snap.get("disk_used", 0)
        tot  = snap.get("disk_total", 0)
        c    = threshold_cp(pct, "disk_pct")
        dr   = snap.get("disk_read", 0)
        dw_  = snap.get("disk_write", 0)
        if row < y + h:
            info = f"{fmtb(used):>8}/{fmtb(tot):<8}"
            self._add(row, x,         info,          cp(CP_PRIMARY))
            self._add(row, x + w - 7, f"{pct:5.1f}%", c)
            row += 1
        if row < y + h:
            self._bar(row, x, pct, w, "disk_pct")
            row += 1
        if row < y + h:
            self._add(row, x,        f"↓ {dr:6.1f} KB/s",  cp(CP_PRIMARY))
            self._add(row, x + w//2, f"↑ {dw_:6.1f} KB/s", cp(CP_SECONDARY))
            row += 1
        dr_hist = (hist or {}).get("disk_read",  [])
        dw_hist = (hist or {}).get("disk_write", [])
        if row < y + h and len(dr_hist) >= 2:
            mid      = w // 2
            dr_color = self._spark_attr(dr_hist)
            dw_color = self._spark_attr(dw_hist)
            self._add(row, x,       sparkline(dr_hist, mid),     dr_color)
            self._add(row, x + mid, sparkline(dw_hist, w - mid), dw_color)

    def _draw_procs(self, y, x, h, w, snap):
        self._label(y, x, "PROCESSES", w)
        if not snap or h < 2:
            return
        procs = snap.get("top_procs", [])
        row   = y + 1
        if row < y + h:
            hdr = f"{'PID':>6}  {'NAME':<14}  {'CPU%':>5}  {'MEM%':>5}  STAT"
            self._add(row, x, hdr[:w], cp(CP_ACCENT, bold=True))
            row += 1
        show_n = max(settings.TOP_N, h - 2)
        for p in procs[:show_n]:
            if row >= y + h:
                break
            cpu  = p.get("cpu_percent") or 0.0
            mem  = p.get("memory_percent") or 0.0
            name = (p.get("name") or "")[:14]
            stat = (p.get("status") or "")[:4].upper()
            c    = threshold_cp(cpu, "cpu_pct")
            line = f"{p['pid']:>6}  {name:<14}  {cpu:5.1f}  {mem:5.1f}  {stat}"
            self._add(row, x, line[:w], c)
            row += 1

    def _render_system(self, state):
        H, W = self.win.getmaxyx()
        snap = state.get("system")
        hist = state.get("system_hist")
        cy   = 2
        ch   = H - 3
        if not snap:
            msg = "COLLECTING DATA…"
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2),
                      msg, cp(CP_PRIMARY, bold=True))
            return
        div_x = W * 52 // 100
        lw    = div_x - 1
        rx    = div_x + 1
        rw    = W - rx
        for row in range(cy, cy + ch):
            try:
                self.win.addch(row, div_x, curses.ACS_VLINE, cp(CP_DIM))
            except curses.error:
                pass
        cpu_h = min(NUM_CORES + 4, ch * 55 // 100)
        mem_h = ch - cpu_h
        cpu_y = cy
        mem_y = cy + cpu_h
        temp_rows_needed = 1 + len(self._temp_rows(snap))  # +1 for the panel header
        temp_h = min(temp_rows_needed, max(3, ch * 27 // 100))
        net_h  = min(5, ch * 23 // 100)
        disk_h = min(5, ch * 23 // 100)
        proc_h = ch - temp_h - net_h - disk_h
        temp_y = cy
        net_y  = cy + temp_h
        disk_y = net_y + net_h
        proc_y = disk_y + disk_h
        self._draw_cpu(         cpu_y,  0,  cpu_h,  lw, snap, hist)
        self._draw_memory(      mem_y,  0,  mem_h,  lw, snap, hist)
        self._draw_temp(        temp_y, rx, temp_h, rw, snap)
        self._draw_network_sys( net_y,  rx, net_h,  rw, snap, hist)
        self._draw_disk(        disk_y, rx, disk_h, rw, snap, hist)
        self._draw_procs(       proc_y, rx, proc_h, rw, snap)

    # ── Tab 2: NETWORK SCANNER ────────────────────────────────────────────────

    @staticmethod
    def _scan_status_variants(scan_mode, trusted, trustable):
        """(variants longest-first, attr) for the scan half of the NETWORK
        tab's status line."""
        if scan_mode == "never":
            return (["SCANNING DISABLED (scan = never) — passive only",
                     "SCANNING DISABLED · passive only",
                     "PASSIVE ONLY"], cp(CP_MUTED))
        if trusted:
            return (["ACTIVE SCANNING — trusted network · [s] stop & untrust",
                     "SCANNING · [s] stop & untrust",
                     "SCANNING · [s] stop",
                     "[s] stop"], cp(CP_GOOD, bold=True))
        if not trustable:
            return (["PASSIVE-ONLY — network can't be identified (no gateway MAC), scanning unavailable",
                     "PASSIVE-ONLY — unidentified network, can't scan",
                     "PASSIVE-ONLY",
                     "PASSIVE"], cp(CP_WARN, bold=True))
        return (["PASSIVE-ONLY — [s] trust this network & enable scanning (asks first)",
                 "PASSIVE-ONLY — [s] trust network & scan (asks first)",
                 "PASSIVE-ONLY · [s] trust & scan",
                 "PASSIVE · [s] scan",
                 "[s] scan"], cp(CP_WARN, bold=True))

    @staticmethod
    def _scan_progress_variants(status, now):
        """(variants longest-first, attr) for the line under the status line
        while the network is trusted for scanning: the status line alone said
        nothing about when or how often pings go out."""
        if not status or not status.get("active"):
            return (["SWEEP waiting to start…", "SWEEP waiting…", "waiting…"],
                    cp(CP_MUTED))

        def dur(secs):
            secs = max(0, secs)
            return f"{int(secs)}s" if secs < 120 else f"{round(secs / 60)}m"

        progress = f"{status.get('hosts_done', 0)}/{status.get('hosts_total', 0)}"
        left = (status.get("next_batch_at") or now) - now
        if left < 1:
            batch = short_next = "pinging now"
            tiny = "now"
        else:
            batch = f"next batch of {status.get('batch_size', 0)} in {dur(left)}"
            short_next = f"next in {dur(left)}"
            tiny = dur(left)
        cycle = dur(status.get("cycle_s") or 0)
        done_at = status.get("last_done_at")
        if done_at:
            hhmm = _dt.fromtimestamp(done_at).strftime("%H:%M")
            last_long = f"last done {hhmm} ({status.get('last_replied', 0)} replied)"
            last_short = f"last {hhmm}"
        else:
            last_long = last_short = "first sweep in progress"
        return ([f"SWEEP {progress} hosts · {batch} · full sweep ≈ every {cycle} · {last_long}",
                 f"SWEEP {progress} · {short_next} · every ≈{cycle} · {last_short}",
                 f"SWEEP {progress} · {short_next}",
                 f"{progress} · {tiny}"],
                cp(CP_SECONDARY))

    @staticmethod
    def _device_status_variants(has_intruder):
        if has_intruder:
            return (["INTRUDER(S) FLAGGED — [t] trust all devices to clear (does not enable scanning)",
                     "INTRUDER(S) — [t] trust all devices",
                     "INTRUDER · [t] trust devices",
                     "[t] trust devices",
                     "[t] trust"], cp(CP_CRITICAL, bold=True))
        return (["[t] trust all devices (stops INTRUDER flags; does not scan)",
                 "[t] trust all devices",
                 "[t] trust devices",
                 "[t] trust"], cp(CP_MUTED))

    def _render_network_status(self, y, w, meta, has_intruder):
        # Two independent actions, shown side by side so neither can be
        # mistaken for the other: [t] trusts *devices* (INTRUDER flags only)
        # and [s] trusts the *network* for active scanning, after a
        # confirmation. The device hint is never dropped while an INTRUDER is
        # flagged, so on a narrow terminal the scan half shrinks first.
        scan_v, scan_attr = self._scan_status_variants(
            meta.get("scan_mode", settings.SCAN_MODE), meta.get("trusted", False),
            meta.get("trustable", False))
        dev_v, dev_attr = self._device_status_variants(has_intruder)
        max_w = max(0, w - 1)
        sep = "   "
        for sv in scan_v:
            for dv in dev_v:
                if len(sv) + len(sep) + len(dv) <= max_w:
                    self._add(y, 0, sv, scan_attr)
                    self._add(y, len(sv) + len(sep), dv, dev_attr)
                    return
        first, attr = (dev_v, dev_attr) if has_intruder else (scan_v, scan_attr)
        text = next((v for v in first if len(v) <= max_w), first[-1][:max_w])
        if text:
            self._add(y, 0, text, attr)

    def _render_confirm_dialog(self, pending):
        """Modal "are you sure?" box for trusting/untrusting the current
        network for active scanning. Only [y] confirms (handled in
        _curses_main); every other key cancels."""
        H, W = self.win.getmaxyx()
        cidrs = pending.get("cidrs") or []
        if pending.get("action") == "untrust":
            title = " STOP SCANNING THIS NETWORK? "
            body = [
                f"Network: {pending.get('net_id')}",
                f"Subnets: {', '.join(cidrs) or '-'}",
                "",
                "syswatch will stop the active ping sweep here and forget",
                "that this network is trusted for scanning. Known devices",
                "are kept.",
                "",
                "[y] Yes, untrust      any other key: cancel",
            ]
            attr = cp(CP_WARN, bold=True)
        else:
            hosts = trusted_networks.host_count(cidrs)
            title = " ENABLE ACTIVE SCANNING ON THIS NETWORK? "
            body = [
                f"Network: {pending.get('net_id')}",
                f"Will ping every address in: {', '.join(cidrs)} ({hosts} hosts),",
                f"repeated about every {int(settings.PING_CYCLE)}s for as long as syswatch runs here.",
                "",
                "WARNING: an active sweep is visible to the network and can",
                "trigger intrusion-detection / security alerts. Only do this",
                "on a network you own or are allowed to scan.",
                "",
                "[y] Yes, trust & scan      any other key: cancel (default)",
            ]
            attr = cp(CP_CRITICAL, bold=True)
        inner = max(len(title), *(len(b) for b in body))
        box_w = min(W - 2, inner + 4)
        box_h = min(H - 2, len(body) + 2)
        # [y] is only honoured once the *whole* warning has been on screen —
        # a terminal too small to show it must not let a keypress confirm
        # something the user couldn't read.
        self.dialog_complete = box_w >= inner + 4 and box_h >= len(body) + 2
        x0 = max(0, (W - box_w) // 2)
        y0 = max(0, (H - box_h) // 2)
        self._add(y0, x0, "┌" + "─" * (box_w - 2) + "┐", attr)
        self._add(y0, x0 + max(1, (box_w - len(title)) // 2), title[:box_w - 2], attr)
        for i in range(box_h - 2):
            line = body[i] if i < len(body) else ""
            text = (" " + line).ljust(box_w - 2)[:box_w - 2]
            self._add(y0 + 1 + i, x0, "│", attr)
            self._add(y0 + 1 + i, x0 + 1, text,
                      attr if line.startswith(("WARNING", "[y]")) else cp(CP_PRIMARY))
            self._add(y0 + 1 + i, x0 + box_w - 1, "│", attr)
        self._add(y0 + box_h - 1, x0, "└" + "─" * (box_w - 2) + "┘", attr)

    def _render_network(self, state):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3
        self._label(cy, 0, "NETWORK SCANNER")
        devices      = state.get("devices") or {}
        net_meta     = state.get("network_meta") or {}
        has_intruder = any(d.status == "INTRUDER" for d in devices.values())
        status_row = cy + 1
        self._render_network_status(status_row, W, net_meta, has_intruder)
        hdr_row = status_row + 1
        if (net_meta.get("trusted")
                and net_meta.get("scan_mode", settings.SCAN_MODE) == "trusted"):
            variants, attr = self._scan_progress_variants(state.get("scan_status"), time.time())
            text = next((v for v in variants if len(v) <= W - 1), variants[-1][:max(0, W - 1)])
            if text:
                self._add(hdr_row, 0, text, attr)
            hdr_row += 1
        if not devices:
            msg = "SCANNING…  (ARP TABLE EMPTY OR UNAVAILABLE)"
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_MUTED))
            return
        sorted_devs = sorted(devices.values(), key=lambda d: d.last_seen, reverse=True)
        count_str   = f"  {len(sorted_devs)} device(s)"
        self._add(cy, max(0, W - len(count_str) - 1), count_str, cp(CP_SECONDARY))
        # HOSTNAME is the one field with genuinely variable-length content, so it
        # absorbs any extra terminal width instead of leaving the rest of a wide
        # window blank after a fixed 20-column table.
        hn_w = max(20, W - (15 + 2 + 17 + 2 + 2 + 12 + 2 + 10))
        self._add(hdr_row, 0,
                  f"{'IP':<15}  {'MAC':<17}  {'HOSTNAME':<{hn_w}}  {'LAST SEEN':<12}  STATUS",
                  cp(CP_PRIMARY, bold=True))
        self._hline(hdr_row + 1, 0, "─", W, cp(CP_DIM))
        row = hdr_row + 2
        now = time.time()
        for dev in sorted_devs:
            if row >= cy + ch:
                break
            status = dev.status
            if status == "INTRUDER":
                c = cp(CP_CRITICAL, bold=True) | curses.A_BLINK
            elif status == "Active":
                c = cp(CP_GOOD)
            elif status == "Recent":
                c = cp(CP_PRIMARY)
            else:
                c = cp(CP_DIM)
            age = now - dev.last_seen
            if age < 60:
                age_str = f"{int(age)}s ago"
            elif age < 3600:
                age_str = f"{int(age // 60)}m ago"
            else:
                age_str = f"{int(age // 3600)}h ago"
            hn   = (dev.hostname if dev.hostname != dev.ip else "-")[:hn_w]
            line = (f"{dev.ip:<15}  {dev.mac:<17}  {hn:<{hn_w}}  "
                    f"{age_str:<12}  {status}")
            self._add(row, 0, line[:W], c)
            row += 1

    # ── Tab 3: LOGS ───────────────────────────────────────────────────────────

    @staticmethod
    def _prio_attr(priority):
        if priority <= 2:   return cp(CP_CRITICAL, bold=True)
        if priority == 3:   return cp(CP_CRITICAL)
        if priority == 4:   return cp(CP_WARN)
        if priority <= 6:   return cp(CP_PRIMARY)
        return cp(CP_MUTED)

    @staticmethod
    def _error_sparkline(log_errs, width=30):
        now     = time.time()
        buckets = [0] * 60
        for ts in list(log_errs):
            age = int(now - ts)
            if 0 <= age < 60:
                buckets[59 - age] += 1
        peak   = max(buckets) or 1
        normed = [b / peak for b in buckets[-width:]]
        return sparkline(normed, width)

    def _render_logs(self, state, log_filter=""):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3
        log_errs = state.get("log_errs") or collections.deque()
        err_60   = sum(1 for ts in list(log_errs) if (time.time() - ts) < 60)
        spark    = self._error_sparkline(log_errs, min(30, W // 3))
        self._label(cy, 0, "LOGS")
        label_end = 2 + len("┤ LOGS ├")
        err_info  = f"  ERR/60s: {err_60}  "
        self._add(cy, label_end, err_info, cp(CP_CRITICAL, bold=True))
        self._add(cy, label_end + len(err_info), spark, cp(CP_CRITICAL))
        if log_filter:
            flt_str = f"  FILTER:{log_filter} "
            self._add(cy, max(label_end + len(err_info) + len(spark) + 1,
                              W - len(flt_str) - 1),
                      flt_str, cp(CP_HILIGHT, bold=True))
        logs = list(state.get("logs") or [])
        if not logs:
            msg = "AWAITING JOURNAL DATA…"
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_MUTED))
            return
        hdr_row = cy + 1
        self._add(hdr_row, 0,
                  f"{'SERVICE':<16}  {'TIME':<8}  MESSAGE",
                  cp(CP_PRIMARY, bold=True))
        self._hline(hdr_row + 1, 0, "─", W, cp(CP_DIM))
        content_start = cy + 3
        content_rows  = ch - 3
        if content_rows <= 0:
            return
        if log_filter:
            flt     = log_filter.lower()
            visible = [e for e in logs
                       if flt in e.get("unit", "").lower()
                       or flt in e.get("message", "").lower()]
        else:
            visible = logs
        visible = visible[-content_rows:]
        for i, entry in enumerate(visible):
            row = content_start + i
            if row >= cy + ch:
                break
            attr    = self._prio_attr(entry.get("priority", 7))
            unit    = entry.get("unit", "")[:15]
            ts_str  = entry.get("ts_str", "")
            message = entry.get("message", "")
            line    = f"{unit:<16}  {ts_str:<8}  {message}"
            self._add(row, 0, line[:W], attr)

    # ── Tab 4: SERVICES ───────────────────────────────────────────────────────

    def _render_services(self, state):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3
        self._label(cy, 0, "SERVICE WATCHDOG")
        services = state.get("services")
        if services is None:
            msg = "SYSTEMCTL NOT AVAILABLE"
            sub = "(systemd not detected on this system)"
            mid = cy + ch // 2
            self._add(mid,     max(0, (W - len(msg)) // 2), msg, cp(CP_SECONDARY, bold=True))
            self._add(mid + 1, max(0, (W - len(sub)) // 2), sub, cp(CP_MUTED))
            return
        if not settings.WATCHED_SERVICES:
            msg = "No services configured. Set [services] watch = [...] in your config (--write-default-config)."
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_MUTED))
            return
        row = cy + 1
        hdr = (f"{'NAME':<16}  {'STATE':<10}  {'SUB':<10}  "
               f"{'PID':>7}  {'RESTARTS':>8}  {'ACTIVE SINCE':<16}  RESULT")
        if row < cy + ch:
            self._add(row, 0, hdr[:W], cp(CP_PRIMARY, bold=True))
            row += 1
        if row < cy + ch:
            self._hline(row, 0, "─", W, cp(CP_DIM))
            row += 1
        now = time.time()
        _REST_X = 51
        for svc in (services or []):
            if row >= cy + ch:
                break
            unit   = svc.get("unit", "")
            active = svc.get("ActiveState", "unknown")
            sub    = svc.get("SubState", "")
            pid    = svc.get("ExecMainPID", "0")
            nrest  = svc.get("NRestarts", "N/A")
            result = svc.get("Result", "")
            since  = svc.get("ActiveEnterTimestamp", "")
            if active == "active" and sub == "running":
                c = cp(CP_GOOD)
            elif active == "active":
                c = cp(CP_PRIMARY)
            elif active == "failed":
                c = cp(CP_CRITICAL, bold=True)
            else:
                c = cp(CP_DIM)
            since_str = "N/A"
            if since and since.lower() not in ("n/a", ""):
                try:
                    parts = since.split()
                    if len(parts) >= 3:
                        ts  = _dt.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
                        age = now - ts.timestamp()
                        if age >= 0:
                            since_str = fmtup(age)
                except Exception:
                    since_str = since[:16]
            try:
                nr = int(nrest)
                if nr > 5:
                    rest_str, rest_c = str(nr), cp(CP_CRITICAL, bold=True)
                elif nr > 0:
                    rest_str, rest_c = str(nr), cp(CP_WARN)
                else:
                    rest_str, rest_c = "0", cp(CP_DIM)
            except (ValueError, TypeError):
                rest_str, rest_c = "N/A", cp(CP_DIM)
            pid_str = pid if pid not in ("0", "") else "-"
            # Every field before RESTARTS is clipped to its column: the
            # restart count is re-drawn in its own colour at the fixed
            # _REST_X, so a longer unit ("systemd-networkd-wait-online") or
            # state ("deactivating", "auto-restart") shifted the row and that
            # overlay then landed on top of the PID/state text.
            line = (f"{unit[:16]:<16}  {active[:10]:<10}  {sub[:10]:<10}  "
                    f"{pid_str[:7]:>7}  {rest_str:>8}  {since_str:<16}  {result}")
            self._add(row, 0, line[:W], c)
            self._add(row, _REST_X, f"{rest_str:>8}", rest_c)
            row += 1

    # ── Tab 5: STORAGE ────────────────────────────────────────────────────────

    def _render_storage(self, state):
        H, W = self.win.getmaxyx()
        cy   = 2
        ch   = H - 3
        self._label(cy, 0, "STORAGE HEALTH")
        snap = state.get("storage")
        if snap is None:
            msg = "COLLECTING DATA…"
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2),
                      msg, cp(CP_PRIMARY, bold=True))
            return
        row    = cy + 1
        half   = W // 2
        is_mmc = snap.get("kind") == "mmc"
        device = snap.get("device")
        if device:
            notice = f"DEVICE: {device} ({snap.get('kind', 'unknown')})"
            self._add(row, max(0, (W - len(notice)) // 2), notice, cp(CP_PRIMARY, bold=True))
        else:
            notice = "NO STORAGE DEVICE DETECTED"
            self._add(row, max(0, (W - len(notice)) // 2), notice, cp(CP_WARN, bold=True))
        row += 1
        lw = half - 1
        if row < cy + ch:
            health    = snap.get("smart_health")
            card_type = snap.get("card_type") or ""
            suffix    = f" ({card_type})" if is_mmc and card_type else ""
            if health is None:
                h_str, h_c = "N/A",              cp(CP_MUTED)
            elif health in ("PASSED", "GOOD"):
                h_str, h_c = health + suffix,     cp(CP_GOOD, bold=True)
            elif health == "WARNING":
                h_str, h_c = "WARNING" + suffix,  cp(CP_WARN, bold=True)
            else:
                h_str, h_c = health + suffix,     cp(CP_CRITICAL, bold=True)
            self._add(row, 0,  "SMART HEALTH: ", cp(CP_SECONDARY))
            self._add(row, 14, h_str,             h_c)
            # None = the kernel log couldn't be read (dmesg_restrict), which is
            # not the same as zero — say so rather than implying a clean bill.
            dev_err = snap.get("dev_errors")
            dev_str = "N/A" if dev_err is None else str(dev_err)
            dev_c   = cp(CP_CRITICAL, bold=True) if dev_err else cp(CP_DIM)
            self._add(row, half,      "DEV ERRORS (this boot): ", cp(CP_SECONDARY))
            self._add(row, half + 24, dev_str,                    dev_c)
            row += 1
        if row < cy + ch:
            temp = snap.get("temp")
            self._add(row, 0, "TEMPERATURE:  ", cp(CP_SECONDARY))
            if temp is not None:
                bw = max(4, lw - 22)
                self._bar(row, 14, min(100.0, temp / 90.0 * 100), bw)
                self._add(row, 14 + bw, f" {temp:.1f}°C",
                          threshold_cp(temp, "storage_temp"))
            else:
                self._add(row, 14, "N/A", cp(CP_DIM))
            fs_err  = snap.get("fs_errors")
            fs_str  = "N/A" if fs_err is None else str(fs_err)
            fs_c    = cp(CP_CRITICAL, bold=True) if fs_err else cp(CP_DIM)
            self._add(row, half,      "FS ERRORS  (this boot): ", cp(CP_SECONDARY))
            self._add(row, half + 24, fs_str,                     fs_c)
            row += 1
        if row < cy + ch:
            poh = snap.get("power_on_hours")
            if poh is not None:
                self._add(row, 0,
                          f"POWER ON:     {poh}h ({poh // 24}d)", cp(CP_PRIMARY))
            else:
                self._add(row, 0, "POWER ON:     N/A", cp(CP_DIM))
            bw_val = snap.get("bytes_written")
            if bw_val is not None:
                self._add(row, half,
                          f"WRITTEN (this boot):    {fmtb(bw_val)}", cp(CP_PRIMARY))
            else:
                self._add(row, half, "WRITTEN (this boot):    N/A", cp(CP_DIM))
            row += 1
        if row < cy + ch:
            self._label(row, 0, "FILESYSTEM USAGE")
            row += 1
        boot_mount = snap.get("boot_mount")
        mounts = [("/", "fs_root")]
        if boot_mount:
            mounts.append((boot_mount, "fs_boot"))
        # Pad to the longest mount, not a fixed 7: "/boot/firmware" (Pi) and
        # "/boot/efi" overflowed it and pushed their numbers and bar out of
        # line with the "/" row.
        lbl_w = max(7, *(len(m) for m, _ in mounts))
        for mount, key in mounts:
            if row >= cy + ch:
                break
            fs = snap.get(key)
            if fs is None:
                self._add(row, 0, f"{mount:<{lbl_w}}  N/A", cp(CP_DIM))
                row += 1
                continue
            pct  = fs["pct"]
            lbl  = f"{mount:<{lbl_w}} "
            info = f" {fmtb(fs['used']):>8}/{fmtb(fs['total']):<8}  {pct:5.1f}%  "
            bar_x = len(lbl) + len(info)
            bw    = max(4, W - bar_x - 1)
            self._add(row, 0,        lbl,  cp(CP_SECONDARY, bold=True))
            self._add(row, len(lbl), info, cp(CP_PRIMARY))
            self._bar(row, bar_x, pct, bw, "disk_pct")
            row += 1
        if row < cy + ch:
            self._label(row, 0, "I/O COUNTERS (since boot)")
            row += 1
        io_reads = snap.get("io_reads")
        if io_reads is not None:
            if row < cy + ch:
                self._add(row, 0,
                          f"Reads:  {io_reads:>10} ops   "
                          f"Sectors: {snap.get('io_read_sectors', 0):>12}",
                          cp(CP_PRIMARY))
                row += 1
            if row < cy + ch:
                self._add(row, 0,
                          f"Writes: {snap.get('io_writes', 0):>10} ops   "
                          f"Sectors: {snap.get('io_write_sectors', 0):>12}",
                          cp(CP_SECONDARY))
                row += 1
        else:
            if row < cy + ch:
                self._add(row, 0,
                          "I/O stats unavailable (no /sys/block/<device>/stat)",
                          cp(CP_MUTED))

    # ── Tab 6: BACKUP ─────────────────────────────────────────────────────────

    def _render_backup(self, state):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3

        backup = state.get("backup")

        if backup is None:
            msg1 = "project-backup not installed or has not run yet"
            msg2 = "Run: sudo bash install-project-backup.sh"
            mid = cy + ch // 2
            self._add(mid,     max(0, (W - len(msg1)) // 2), msg1, cp(CP_DIM))
            self._add(mid + 1, max(0, (W - len(msg2)) // 2), msg2, cp(CP_DIM))
            return

        row = cy

        # ── Section 1: Last Run ───────────────────────────────────────────────
        self._label(row, 0, "LAST BACKUP")
        row += 1

        last_run = backup.get("last_run")
        if not isinstance(last_run, dict):
            last_run = None  # stale/malformed status file — treat like "no run yet"

        if last_run is None:
            if row < cy + ch:
                msg = "NO BACKUP HAS RUN YET"
                self._add(row, max(0, (W - len(msg)) // 2), msg, cp(CP_DIM))
            row += 4
        else:
            half = W // 2
            status          = last_run.get("status", "")
            timestamp       = last_run.get("timestamp", "N/A")
            duration_s      = last_run.get("duration_s")
            files_xfer      = last_run.get("files_transferred", 0)
            files_unch      = last_run.get("files_unchanged", 0)
            total_size_h    = last_run.get("total_size_human", "N/A")
            if not isinstance(duration_s, (int, float)):
                duration_s = None
            if not isinstance(files_xfer, (int, float)):
                files_xfer = 0
            if not isinstance(files_unch, (int, float)):
                files_unch = 0

            if status == "ok":
                s_str, s_c = "OK",    cp(CP_GOOD, bold=True)
            elif status == "error":
                s_str, s_c = "ERROR", cp(CP_CRITICAL, bold=True)
            else:
                s_str, s_c = status,  cp(CP_WARN)

            if duration_s is not None:
                if duration_s >= 60:
                    m, s = int(duration_s // 60), int(duration_s % 60)
                    dur_str = f"{m}m{s}s"
                else:
                    dur_str = f"{int(duration_s)}s"
            else:
                dur_str = "N/A"

            if row < cy + ch:
                self._add(row, 0,        "STATUS:    ",      cp(CP_SECONDARY))
                self._add(row, 11,       s_str,              s_c)
                self._add(row, half,     "FILES COPIED:    ", cp(CP_SECONDARY))
                self._add(row, half + 17, f"{files_xfer:,}", cp(CP_PRIMARY))
                row += 1

            if row < cy + ch:
                self._add(row, 0,        "TIMESTAMP: ",           cp(CP_SECONDARY))
                self._add(row, 11,       str(timestamp),           cp(CP_PRIMARY))
                self._add(row, half,     "FILES UNCHANGED: ",      cp(CP_SECONDARY))
                self._add(row, half + 17, f"{files_unch:,}",       cp(CP_MUTED))
                row += 1

            if row < cy + ch:
                self._add(row, 0,        "DURATION:  ",        cp(CP_SECONDARY))
                self._add(row, 11,       dur_str,               cp(CP_SECONDARY))
                self._add(row, half,     "TOTAL SIZE:    ",     cp(CP_SECONDARY))
                self._add(row, half + 15, str(total_size_h),   cp(CP_PRIMARY))
                row += 1

        # ── Section 2: Sources ────────────────────────────────────────────────
        if row < cy + ch:
            self._label(row, 0, "SOURCES")
            row += 1

        config = backup.get("config")
        if not isinstance(config, dict):
            config = {}
        sources = config.get("sources") or []
        if not isinstance(sources, list):
            sources = []
        for path in sources:
            if row >= cy + ch:
                break
            if not isinstance(path, str):
                continue
            exists = os.path.exists(path)
            if exists:
                self._add(row, 2, path,           cp(CP_GOOD))
                self._add(row, 2 + len(path), "  \u2713 EXISTS",  cp(CP_GOOD))
            else:
                self._add(row, 2, path,           cp(CP_WARN))
                self._add(row, 2 + len(path), "  \u2717 MISSING", cp(CP_WARN))
            row += 1

        # ── Section 3: Run History ────────────────────────────────────────────
        if row < cy + ch:
            self._label(row, 0, "RUN HISTORY")
            row += 1

        history = backup.get("history") or []
        if not isinstance(history, list):
            history = []

        if not history:
            if row < cy + ch:
                msg = "No history yet \u2014 run: sudo project-backup"
                self._add(row, max(0, (W - len(msg)) // 2), msg, cp(CP_DIM))
            return

        if row < cy + ch:
            hdr = (f"{'DATE':<12}{'TIME':<10}{'STATUS':<10}"
                   f"{'COPIED':>10}  {'SIZE':<12}DURATION")
            self._add(row, 0, hdr[:W], cp(CP_PRIMARY, bold=True))
            row += 1

        if row < cy + ch:
            self._hline(row, 0, "─", W, cp(CP_DIM))
            row += 1

        for entry in history:
            if row >= cy + ch:
                break
            if not isinstance(entry, dict):
                continue
            ts       = entry.get("timestamp", "")
            if not isinstance(ts, str):
                ts = ""
            date     = ts[:10] if len(ts) >= 10 else ts
            time_str = ts[11:19] if len(ts) >= 19 else ""
            estatus  = entry.get("status", "")
            if not isinstance(estatus, str):
                estatus = ""
            efiles   = entry.get("files_transferred", 0)
            if not isinstance(efiles, (int, float)):
                efiles = 0
            esize    = entry.get("total_size_human", "")
            edur_s   = entry.get("duration_s")
            if not isinstance(edur_s, (int, float)):
                edur_s = None

            if edur_s is not None:
                if edur_s >= 60:
                    m, s = int(edur_s // 60), int(edur_s % 60)
                    edur_str = f"{m}m{s}s"
                else:
                    edur_str = f"{int(edur_s)}s"
            else:
                edur_str = "N/A"

            if estatus == "ok":
                c = cp(CP_GOOD)
            elif estatus == "error":
                c = cp(CP_CRITICAL, bold=True)
            else:
                c = cp(CP_DIM)

            line = (f"{date:<12}{time_str:<10}{estatus.upper():<10}"
                    f"{efiles:>10,}  {esize:<12}{edur_str}")
            self._add(row, 0, line[:W], c)
            row += 1

        if len(history) >= 2 and row < cy + ch:
            label    = "TRANSFER HISTORY  "
            spark_w  = W - len(label)
            if spark_w > 0:
                spark_data = []
                for e in history:
                    v = e.get("files_transferred", 0) if isinstance(e, dict) else 0
                    spark_data.append(v if isinstance(v, (int, float)) else 0)
                self._add(row, 0,          label,                      cp(CP_MUTED))
                self._add(row, len(label), sparkline(spark_data, spark_w), cp(CP_PRIMARY))

    # ── Tab 7: HISTORY ───────────────────────────────────────────────────────

    _HIST_TTL = 10.0

    def _hist_csv_path(self):
        # Own path if it exists, else the invoking user's — under `sudo
        # syswatch`, ~ is root's home and the logger's data (written as the
        # real user) would be missed. Shared with config_path_default() so
        # metrics and config always resolve to the same user; the old inline
        # version assumed /home/<name>, which is wrong for a user whose home
        # isn't there.
        return sensors.user_data_path("metrics.csv")

    @staticmethod
    def _col(parts, i):
        """Column i as float, or None if missing/blank/out of range."""
        if i >= len(parts) or not parts[i]:
            return None
        try:
            return float(parts[i])
        except Exception:
            return None

    def _load_history(self):
        now = time.monotonic()
        if (self._hist_cache is not None
                and now - self._hist_cache[0] < self._HIST_TTL):
            return self._hist_cache[1]
        path = self._hist_csv_path()
        # Parsing a month of samples (~20k rows) takes long enough on a Pi to
        # stutter the UI, and this runs on the render thread — so only
        # re-parse when the file actually changed since the last load.
        try:
            st  = os.stat(path)
            sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            sig = None
        if (self._hist_cache is not None and sig is not None
                and self._hist_cache[2] == sig):
            self._hist_cache = (now, self._hist_cache[1], sig)
            return self._hist_cache[1]
        rows = []
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(",")
                    # 5 cols = pre-1.1.0 (no voltage); 6 = 1.1.x (+voltage);
                    # 8 = 1.2.0 (+gpu_temp, +storage_temp); 9 = current (+battery_pct).
                    if len(parts) < 5:
                        continue
                    try:
                        ts = _dt.fromisoformat(parts[0])
                    except Exception:
                        continue
                    rows.append({
                        "ts":            ts,
                        "cpu_pct":       self._col(parts, 1),
                        "ram_pct":       self._col(parts, 2),
                        "cpu_temp":      self._col(parts, 3),
                        "disk_pct":      self._col(parts, 4),
                        "voltage":       self._col(parts, 5),
                        "gpu_temp":      self._col(parts, 6),
                        "storage_temp":  self._col(parts, 7),
                        "battery_pct":   self._col(parts, 8),
                    })
        except FileNotFoundError:
            # No metrics.csv yet (logger not installed/started) — the tab
            # already says so. Recording it as an error re-lit the header's
            # degraded ⚠ on every reload, i.e. permanently while on this tab.
            pass
        except Exception as e:
            # e.g. a PermissionError on the file — worth a (deduplicated) record.
            _note("FullRenderer._load_history", e)
        # _render_history assumes chronological order (filtered[0]/[-1] as the
        # oldest/newest bound of the resample grid); an out-of-order CSV — clock
        # adjustments, concatenated files, manual edits — would otherwise send
        # the bin-index math negative and crash with an IndexError.
        rows.sort(key=lambda r: r["ts"])
        self._hist_cache = (now, rows, sig)
        return rows

    @staticmethod
    def _median_interval(timestamps):
        """Median spacing (seconds) between consecutive samples; 120s (the
        logger default) when there are too few to estimate. Needs ≥3."""
        if len(timestamps) < 3:
            return 120.0
        deltas = sorted(timestamps[i].timestamp() - timestamps[i - 1].timestamp()
                        for i in range(1, len(timestamps)))
        n = len(deltas)
        median = deltas[n // 2] if n % 2 else (deltas[n // 2 - 1] + deltas[n // 2]) / 2
        # A median of 0 (many duplicate/near-duplicate timestamps — bad clock
        # resolution, manually edited/concatenated CSVs) would otherwise
        # divide-by-zero in the resampling; it isn't a meaningful interval.
        return max(median, 1.0)

    def _render_history(self, history_window, history_scroll=0):
        H, W = self.win.getmaxyx()
        cy = 2
        ch = H - 3

        window_labels = ["1 HOUR", "8 HOURS", "24 HOURS", "7 DAYS", "30 DAYS"]
        window_secs   = [3600, 28800, 86400, 604800, 2592000]
        wlabel        = window_labels[history_window]

        self._label(cy, 0, f"HISTORY — {wlabel}  [h] next window  [↑↓] scroll")

        rows = self._load_history()
        if not rows:
            msg1 = "No history data yet."
            msg2 = "Start syswatch-logger to begin collecting metrics."
            mid  = cy + ch // 2
            self._add(mid,     max(0, (W - len(msg1)) // 2), msg1, cp(CP_SECONDARY, bold=True))
            self._add(mid + 1, max(0, (W - len(msg2)) // 2), msg2, cp(CP_MUTED))
            return

        now_ts   = _dt.now().timestamp()
        win_secs = window_secs[history_window]
        cutoff   = now_ts - win_secs
        filtered = [r for r in rows if r["ts"].timestamp() >= cutoff]
        if not filtered:
            msg = f"No data in the last {wlabel.lower()}."
            self._add(cy + ch // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_MUTED))
            return

        # Time-axis timestamps, shared across every chart in this window.
        oldest_ts = filtered[0]["ts"]
        newest_ts = filtered[-1]["ts"]

        # Estimate the logger's sample interval from the data (median of the
        # deltas between consecutive samples) so gap detection and the coverage
        # check adapt to a non-default --interval. Needs ≥3 rows to be
        # meaningful; otherwise assume the 120s default.
        sample_interval = self._median_interval([r["ts"] for r in filtered])

        def _fmt_axis(dt_obj):
            # 1h / 8h / 24h windows use clock time; 7d / 30d use calendar date.
            if history_window <= 2:
                return dt_obj.strftime("%H:%M")
            return dt_obj.strftime("%b %d")

        row = cy + 1

        # Data-coverage indicator: shown only while the window is not yet full.
        # Jitter tolerance is one estimated sample interval plus a 25% margin.
        window_start = now_ts - win_secs
        if oldest_ts.timestamp() - window_start > sample_interval * 1.25:
            span_secs = newest_ts.timestamp() - oldest_ts.timestamp()
            if span_secs < 7200:
                span_str = f"{int(round(span_secs / 60))}m"
            elif span_secs < 172800:
                span_str = f"{span_secs / 3600:.1f}h"
            else:
                span_str = f"{span_secs / 86400:.1f}d"
            short_labels = ["1h", "8h", "24h", "7d", "30d"]
            # Multi-day windows (7d / 30d) need the date too, not just the time.
            cov_fmt  = "%b %d %H:%M" if history_window >= 3 else "%H:%M"
            cov_line = (f"DATA: {oldest_ts.strftime(cov_fmt)} → "
                        f"{newest_ts.strftime(cov_fmt)}  "
                        f"({span_str} of {short_labels[history_window]} window)")
            if row < cy + ch:
                self._add(row, 0, cov_line, cp(CP_MUTED))
            row += 1

        chart_h    = 5
        max_points = max(2, W - 12)
        metrics    = [
            ("CPU %",     "cpu_pct",      "cpu_pct"),
            ("RAM %",     "ram_pct",      "ram_pct"),
            ("TEMP °C",   "cpu_temp",     "cpu_temp"),
            ("DISK %",    "disk_pct",     "disk_pct"),
            ("VOLT V",    "voltage",      "voltage"),
            ("GPU °C",    "gpu_temp",     "gpu_temp"),
            ("SSD °C",    "storage_temp", "storage_temp"),
            ("BATT %",    "battery_pct",  "battery_pct"),
        ]

        # Charts that actually have data in this window; scrolling steps
        # through this list one whole chart at a time.
        plotted = []
        for label, key, thresh_key in metrics:
            pairs = [(r["ts"], r[key]) for r in filtered if r.get(key) is not None]
            if pairs:
                plotted.append((label, key, thresh_key, pairs))
        self.hist_scroll_max = max(0, len(plotted) - 1)
        scroll = max(0, min(history_scroll, self.hist_scroll_max))
        if scroll:
            self._label(cy, 0, f"HISTORY — {wlabel}  [h] next window  "
                               f"[↑↓] scroll ({scroll + 1}/{len(plotted)})")

        for label, key, thresh_key, pairs in plotted[scroll:]:
            timestamps  = [p[0] for p in pairs]
            true_oldest = timestamps[0]
            true_newest = timestamps[-1]

            # Resample onto a uniform time grid instead of plotting one column
            # per sample. asciichartpy is index-based (evenly spaced columns,
            # no notion of time), so index-based plotting made the x-axis
            # labels — which interpolate linearly in wall-clock time — wrong
            # around any gap: an 8-hour outage collapsed to a single column
            # while the labels kept assuming uniform time flow across the
            # width. Bucketing by time makes column position linear in time
            # by construction, so the label math below is correct for free,
            # and an outage occupies its true width on screen. Samples that
            # land in the same bin are averaged, matching what the logger
            # itself already does (psutil.cpu_percent averages the interval).
            old_t = true_oldest.timestamp()
            new_t = true_newest.timestamp()
            span  = max(new_t - old_t, 1.0)
            # Never make bins narrower than this metric's own sample interval,
            # or a normally-running logger would leave most bins empty and
            # speckle the chart with false gaps. Per metric, not per row: a
            # sensor that only reports every few samples (or was added later)
            # would otherwise show a gap marker between every reading.
            metric_interval = max(sample_interval, self._median_interval(timestamps))
            n_bins = max(2, min(max_points, int(span / metric_interval) + 1))
            bin_w  = span / n_bins
            sums   = [0.0] * n_bins
            counts = [0]   * n_bins
            for ts, v in pairs:
                i = min(n_bins - 1, int((ts.timestamp() - old_t) / bin_w))
                sums[i]   += v
                counts[i] += 1
            values = [sums[i] / counts[i] if counts[i] else float("nan")
                      for i in range(n_bins)]

            if len(values) < 2:
                continue

            latest = next((v for v in reversed(values) if not math.isnan(v)), None)
            if latest is None:
                continue  # every bin in this window is a gap for this metric
            chart_attr = threshold_cp(latest, thresh_key)

            if row >= cy + ch:
                break
            # Core voltage sits in a ~0.05V band; one decimal would flatten it.
            latest_str = f"{latest:.4f}" if key == "voltage" else f"{latest:.1f}"
            self._label(row, 0, f"{label}  {latest_str}")
            row += 1

            try:
                chart_str   = asciichartpy.plot(values, {"height": chart_h})
                chart_lines = chart_str.split("\n") if chart_str else []
            except Exception:
                chart_lines = ["  (chart error)"]
            if not chart_lines:
                continue  # asciichartpy.plot() returns '' when every value is NaN

            body_y0 = row
            for cline in chart_lines:
                if row >= cy + ch:
                    break
                self._add(row, 0, cline, chart_attr)
                row += 1
            body_y1 = row  # exclusive end of the drawn chart-body rows

            # Time-axis row: a dynamic number of evenly spaced ticks that adapts
            # to the available data width. The y-axis prefix is everything up to
            # and including the ┤/┼ tick plus one trailing space.
            first    = chart_lines[0] if chart_lines else ""
            axis_pos = -1
            for i, cchar in enumerate(first):
                if cchar in ("┤", "┼"):
                    axis_pos = i
                    break
            if axis_pos >= 0:
                prefix_w = axis_pos + 2
                longest  = max(len(cl) for cl in chart_lines)
                data_w   = longest - prefix_w
                # Overlay outage markers over every NaN bin. asciichartpy's
                # rendered column count doesn't exactly equal len(values) (it
                # trims a column or two at each edge), so — same as the axis
                # ticks below — map bin index to column by fraction of width
                # rather than assuming a literal 1:1 index-to-column mapping.
                if data_w > 0:
                    for i, v in enumerate(values):
                        if not math.isnan(v):
                            continue
                        frac    = i / (n_bins - 1)
                        gap_col = int(round(frac * (data_w - 1)))
                        gx      = prefix_w + gap_col
                        if 0 <= gap_col < data_w and 0 <= gx < W:
                            for gy in range(body_y0, body_y1):
                                if cy <= gy < cy + ch:
                                    self._add(gy, gx, "┊", cp(CP_WARN))
                if row < cy + ch and data_w > 0:
                    label_w = 5 if history_window <= 2 else 6
                    # How many labels fit without crowding: at least 8 columns of
                    # breathing room between adjacent tick centres, capped at 10.
                    # Falls back to 2 (oldest + newest) on narrow terminals.
                    max_ticks = min(10, max(2, data_w // (label_w + 8)))
                    ticks     = []
                    for i in range(max_ticks):
                        frac = i / (max_ticks - 1)
                        col  = int(round(frac * (data_w - 1))) - label_w // 2
                        col  = max(0, min(data_w - label_w, col))
                        tdt  = _dt.fromtimestamp(old_t + (new_t - old_t) * frac)
                        ticks.append((col, _fmt_axis(tdt)))
                    # Resolve overlaps right-to-left, dropping the earlier label;
                    # also drop a label whose text repeats the one already kept
                    # (legitimate now that wide windows with sparse data can put
                    # two ticks within the same clock-time bucket).
                    kept          = []
                    occupied_left = data_w
                    for col, text in reversed(ticks):
                        if col + len(text) <= occupied_left and (
                                not kept or kept[-1][1] != text):
                            kept.append((col, text))
                            occupied_left = col
                    # Tick-mark row: a │ centred under each retained label. Drawn
                    # only when the label row below it still fits, so it can never
                    # push the time labels off the panel.
                    if row + 1 < cy + ch:
                        tick_chars = [" "] * data_w
                        for col, _text in kept:
                            centre = col + label_w // 2
                            if 0 <= centre < data_w:
                                tick_chars[centre] = "│"
                        self._add(row, prefix_w, "".join(tick_chars), cp(CP_MUTED))
                        row += 1
                    axis_chars = [" "] * data_w
                    for col, text in kept:
                        for j, tchar in enumerate(text):
                            if 0 <= col + j < data_w:
                                axis_chars[col + j] = tchar
                    self._add(row, prefix_w, "".join(axis_chars), cp(CP_MUTED))
                row += 1

            row += 1  # spacer between charts

    # ── dispatch ──────────────────────────────────────────────────────────────

    def render(self, active_tab, state, log_filter, mode, filter_buf,
               history_window=0, history_scroll=0, pending=None):
        H, W = self.win.getmaxyx()
        self.win.erase()
        self.dialog_complete = False
        if H < self.MIN_H or W < self.MIN_W:
            msg = f"Terminal too small ({W}×{H}), need ≥{self.MIN_W}×{self.MIN_H}"
            self._add(H // 2, max(0, (W - len(msg)) // 2), msg, cp(CP_CRITICAL, bold=True))
            self.win.noutrefresh()
            curses.doupdate()
            return
        active_tab_id = (self.tabs[active_tab - 1][0]
                         if 1 <= active_tab <= len(self.tabs) else None)
        self._render_header()
        self._render_tab_bar(active_tab)
        self._render_footer(state)
        tab_renderers = {
            "system":  lambda: self._render_system(state),
            "network": lambda: self._render_network(state),
            "logs":    lambda: self._render_logs(state, log_filter),
            "services": lambda: self._render_services(state),
            "storage": lambda: self._render_storage(state),
            "backup":  lambda: self._render_backup(state),
            "history": lambda: self._render_history(history_window, history_scroll),
        }
        if active_tab_id is not None:
            tab_renderers[active_tab_id]()
        if mode == "filter_input":
            prompt = f" FILTER: {filter_buf}_ "
            self._add(H - 2, 2, prompt, cp(CP_HILIGHT, bold=True) | curses.A_REVERSE)
        if mode == "confirm_scan" and pending:
            self._render_confirm_dialog(pending)
        self.win.noutrefresh()
        curses.doupdate()


