import collections
import curses
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from unittest import mock

import helpers
import syswatch as sw
import syswatch_collectors as col
import syswatch_network as net
import syswatch_render as rnd
import syswatch_state as st


def _curses_patches(test):
    """Let the renderers run without initscr(): color pairs and ACS glyphs
    only exist on a real terminal."""
    for target, kwargs in (
        ((curses, "color_pair"), {"new": lambda n: 0}),
        ((curses, "curs_set"), {"new": lambda n: None}),
        ((curses, "doupdate"), {"new": lambda: None}),
        ((curses, "ACS_VLINE"), {"new": "|", "create": True}),
    ):
        p = mock.patch.object(*target, **kwargs)
        p.start()
        test.addCleanup(p.stop)


class HelperFunctionTests(unittest.TestCase):
    def test_fmtb(self):
        self.assertEqual(rnd.fmtb(0), "0.0B")
        self.assertEqual(rnd.fmtb(1536), "1.5KB")
        self.assertEqual(rnd.fmtb(1024 ** 5 * 3), "3.0PB")

    def test_fmtup(self):
        self.assertEqual(rnd.fmtup(59), "00:00:59")
        self.assertEqual(rnd.fmtup(86400 + 3661), "1d 01:01:01")

    def test_sparkline_edge_cases(self):
        self.assertEqual(rnd.sparkline([], 4), "    ")
        self.assertEqual(rnd.sparkline([1, 2], 0), "")
        self.assertEqual(rnd.sparkline([-5, -1], 2), "  ")  # all-negative never indexes out of range
        self.assertEqual(rnd.sparkline([0, 50, 100], 3), " ▄█")
        self.assertEqual(len(rnd.sparkline(range(100), 10)), 10)

    def test_device_status(self):
        now = time.time()
        dev = st.DeviceInfo("1.2.3.4", "aa", "h", now, now, "Active")
        self.assertEqual(st._device_status(dev), "Active")
        dev.last_seen = now - 60
        self.assertEqual(st._device_status(dev), "Recent")
        dev.last_seen = now - 400
        self.assertEqual(st._device_status(dev), "Idle")
        dev.status, dev.last_seen = "INTRUDER", now - 10
        self.assertEqual(st._device_status(dev), "INTRUDER")
        dev.last_seen = now - st.settings.INTRUDER_TTL - 1
        self.assertEqual(st._device_status(dev), "Idle")


class FilterPromptTests(unittest.TestCase):
    def type_keys(self, keys, log_filter=""):
        editing, buf = True, log_filter  # "/" starts from the applied filter
        for ch in keys:
            editing, buf, log_filter = sw.filter_prompt_key(ch, buf, log_filter)
        return editing, buf, log_filter

    def test_enter_applies_and_backspace_or_ctrl_h_delete(self):
        keys = [ord(c) for c in "sysxx"] + [127, 8] + [ord(c) for c in "tem"] + [10]
        self.assertEqual(self.type_keys(keys), (False, "", "system"))

    def test_esc_clears_the_applied_filter(self):
        self.assertEqual(self.type_keys([27], log_filter="system"), (False, "", ""))


class FsStatsTests(unittest.TestCase):
    def test_matches_df_and_psutil(self):
        fs = col.StorageThread._fs_stats("/")
        du = sw.psutil.disk_usage("/")
        self.assertEqual(fs["total"], du.total)
        self.assertAlmostEqual(fs["pct"], du.percent, delta=0.2)

    def test_reserved_blocks_are_not_counted_as_used(self):
        St = collections.namedtuple("St", "f_blocks f_bfree f_bavail f_frsize")
        # 1000 blocks, 600 free of which only 550 available to non-root.
        with mock.patch.object(sw.os, "statvfs", return_value=St(1000, 600, 550, 4096)):
            fs = col.StorageThread._fs_stats("/")
        self.assertEqual(fs["used"], 400 * 4096)
        self.assertAlmostEqual(fs["pct"], 400 / 950 * 100)


class SmartTests(unittest.TestCase):
    def _smart(self, payload, kind="disk"):
        done = subprocess.CompletedProcess([], 0, stdout=json.dumps(payload), stderr="")
        with mock.patch.object(net.shutil, "which", return_value="/usr/sbin/smartctl"), \
                mock.patch.object(net.subprocess, "run", return_value=done), \
                mock.patch.object(col, "_note") as note:
            result = col.StorageThread._smart("sda", kind)
        return result, note

    def test_ata(self):
        result, note = self._smart({
            "smart_status": {"passed": True},
            "ata_smart_attributes": {"table": [
                {"name": "Power_On_Hours", "raw": {"value": 1234}},
                {"name": "Reallocated_Sector_Ct", "raw": {"value": 0}},
                {"name": "Wear_Leveling_Count", "raw": {"value": 3}},
            ]},
        })
        self.assertEqual(result["health"], "PASSED")
        self.assertEqual(result["power_on_hours"], 1234)
        self.assertEqual([a["name"] for a in result["attrs"]], ["Wear_Leveling_Count"])
        note.assert_not_called()

    def test_nvme_with_null_sections(self):
        result, note = self._smart({
            "smart_status": None,
            "ata_smart_attributes": None,
            "nvme_smart_health_information_log": {
                "percentage_used": 3, "power_on_hours": 99, "media_errors": 0},
        })
        self.assertEqual(result["health"], "GOOD")
        self.assertEqual(result["power_on_hours"], 99)
        note.assert_not_called()


class LogParseTests(unittest.TestCase):
    def test_parse_line_variants(self):
        lt = col.LogThread()
        entry = lt._parse_line(json.dumps({
            "PRIORITY": "3", "_SYSTEMD_UNIT": "ssh.service", "MESSAGE": "boom",
            "__REALTIME_TIMESTAMP": "1700000000000000"}).encode())
        self.assertEqual((entry["priority"], entry["unit"], entry["message"]), (3, "ssh", "boom"))
        binary = lt._parse_line(json.dumps({"MESSAGE": [104, 105], "SYSLOG_IDENTIFIER": "k"}).encode())
        self.assertEqual(binary["message"], "<binary>")
        with mock.patch.object(col, "_note"):
            self.assertIsNone(lt._parse_line(b"not json"))


class HostnameTests(unittest.TestCase):
    def setUp(self):
        net._hostname_cache.clear()
        self.addCleanup(net._hostname_cache.clear)

    def test_slow_resolver_is_bounded(self):
        release = threading.Event()

        def slow(*_a, **_k):
            release.wait(5)
            return ("late.example", "0")

        self.addCleanup(release.set)
        with mock.patch.object(net.socket, "getnameinfo", side_effect=slow), \
                mock.patch.object(net, "_HOSTNAME_TIMEOUT", 0.2):
            t0 = time.monotonic()
            self.assertEqual(net._resolve_hostname("10.9.9.9"), "10.9.9.9")
            self.assertLess(time.monotonic() - t0, 1.5)
        # Cached with the short retry TTL, not the hour-long one.
        self.assertEqual(net._hostname_cache["10.9.9.9"][2], net._HOSTNAME_RETRY_AFTER)

    def test_resolves_and_caches(self):
        with mock.patch.object(net.socket, "getnameinfo", return_value=("nas.lan", "0")) as gni:
            self.assertEqual(net._resolve_hostname("10.0.0.5"), "nas.lan")
            self.assertEqual(net._resolve_hostname("10.0.0.5"), "nas.lan")
        self.assertEqual(gni.call_count, 1)


class _ArpTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name, value in (("KNOWN_DEVICES_PATH", os.path.join(self.tmp.name, "known.json")),
                            ("TRUSTED_NETWORKS_PATH", os.path.join(self.tmp.name, "trusted.json")),
                            ("BASELINE_WINDOW", 0), ("INTRUDER_ALERTS", True)):
            p = mock.patch.object(st.settings, name, value)
            p.start()
            self.addCleanup(p.stop)
        with st._state_lock:
            st._state["devices"] = {}
        self.addCleanup(lambda: st._state.__setitem__("devices", {}))
        self.arp = net.ARPPassiveThread()
        p = mock.patch.object(sw.sensors, "local_networks", return_value=[])
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(sw.known_devices, "network_identity", return_value="net:test")
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(net, "_resolve_hostname", side_effect=lambda ip: ip)
        p.start()
        self.addCleanup(p.stop)

    def run_cycles(self, tables, interval=0.01):
        """Run the real run() loop over a sequence of fake ARP tables."""
        it = iter(tables)
        last = {}

        def parse():
            nonlocal last
            last = next(it, last)
            return dict(last)

        self.arp._parse_arp_table = parse
        with mock.patch.object(st.settings, "ARP_REFRESH", interval):
            self.arp.start()
            time.sleep(interval * (len(tables) + 5) + 0.3)
            self.arp.stop()
            self.arp.join(2)
        self.assertFalse(self.arp.is_alive())


class ArpThreadTests(_ArpTestBase):
    def test_new_device_on_known_network_is_intruder_and_trust_clears_it(self):
        sw.known_devices.save({"net:test": {"aa": {"first_seen": 1, "last_seen": time.time(),
                                                   "hostname": "a"}}}, st.settings.KNOWN_DEVICES_PATH)
        self.arp._known = sw.known_devices.load(st.settings.KNOWN_DEVICES_PATH)
        table = {"aa": {"ip": "10.0.0.2", "iface": "eth0"},
                 "bb": {"ip": "10.0.0.3", "iface": "eth0"}}
        self.run_cycles([table])
        devs = st.get_state()["devices"]
        self.assertEqual(devs["aa"].status, "Active")
        self.assertEqual(devs["bb"].status, "INTRUDER")
        self.arp.trust_all()
        self.assertEqual(st.get_state()["devices"]["bb"].status, "Active")
        saved = sw.known_devices.load(st.settings.KNOWN_DEVICES_PATH)
        self.assertIn("bb", saved["net:test"])
        self.assertEqual(saved["net:test"]["aa"]["hostname"], "a")  # not clobbered with the IP

    def test_departed_device_ages_out_of_active(self):
        table = {"aa": {"ip": "10.0.0.2", "iface": "eth0"}}
        with st._state_lock:
            st._state["devices"]["gone"] = st.DeviceInfo(
                "10.0.0.9", "gone", "x", 0, time.time() - 1000, "Active")
        self.run_cycles([table])
        self.assertEqual(st.get_state()["devices"]["gone"].status, "Idle")

    def test_unknown_network_with_no_baseline_flags_everything(self):
        self.run_cycles([{"aa": {"ip": "10.0.0.2", "iface": "eth0"}}])
        self.assertEqual(st.get_state()["devices"]["aa"].status, "INTRUDER")
        meta = st.get_state()["network_meta"]
        self.assertFalse(meta["trusted"])

    def test_last_seen_refreshes_are_not_written_every_cycle(self):
        table = {"aa": {"ip": "10.0.0.2", "iface": "eth0"}}
        with mock.patch.object(st.settings, "BASELINE_WINDOW", 60), \
                mock.patch.object(sw.known_devices, "save", wraps=sw.known_devices.save) as save:
            self.run_cycles([table] * 20)
        # One save for learning the new device, one final flush at shutdown —
        # not one per cycle.
        self.assertLessEqual(save.call_count, 3, save.call_count)
        self.assertIn("aa", sw.known_devices.load(st.settings.KNOWN_DEVICES_PATH)["net:test"])


class GetStateTests(unittest.TestCase):
    def test_snapshot_is_independent(self):
        with st._state_lock:
            st._state["devices"] = {"aa": st.DeviceInfo("1.1.1.1", "aa", "h", 0, 0, "Active")}
        self.addCleanup(lambda: st._state.__setitem__("devices", {}))
        snap = st.get_state()
        with st._state_lock:
            st._state["devices"]["aa"].status = "Idle"
            st._state["devices"]["bb"] = None
        self.assertEqual(snap["devices"]["aa"].status, "Active")
        self.assertNotIn("bb", snap["devices"])


class SystemThreadTests(unittest.TestCase):
    def test_collection_does_not_hold_the_state_lock(self):
        m = col.Metrics()
        real_top = m._top_procs
        held = []

        def probe():
            # If collect() ran under _state_lock this acquire would fail.
            ok = st._state_lock.acquire(blocking=False)
            if ok:
                st._state_lock.release()
            held.append(not ok)
            return real_top()

        m._top_procs = probe
        t = col.SystemThread()
        t._metrics = m
        # Thresholds out of reach: this runs the real collector, and a warm
        # test machine must not append to the user's real temp_alerts.log.
        with mock.patch.object(st.settings, "THRESH", {"cpu_temp": (1000, 1000)}):
            t.start()
            time.sleep(0.5)
            t.stop()
            t.join(3)
        self.assertTrue(held)
        self.assertFalse(any(held))
        state = st.get_state()
        self.assertIsNotNone(state["system"])
        self.assertGreaterEqual(len(state["system_hist"]["cpu"]), 1)


def _fake_system_snap(is_pi=False):
    now_procs = [{"pid": i, "name": f"proc{i}" * 3, "cpu_percent": 99.0 - i,
                  "memory_percent": None, "status": "running"} for i in range(60)]
    return {
        "cores": [5.0, 99.0, 50.0, 0.0], "cpu_avg": 38.5,
        "ram_used": 1 << 30, "ram_total": 4 << 30, "ram_pct": 25.0,
        "swap_used": 0, "swap_total": 0, "swap_pct": 0.0,
        "battery_pct": 81.2, "is_pi": is_pi, "model": "Test Box" * 10,
        "gpu_vendor": None if is_pi else "NVIDIA",
        "cpu_temp": 83.0, "gpu_temp": 61.0, "storage_temp": 44.0,
        "voltage": 1.2625 if is_pi else None, "cpu_freq": 1800,
        "throttled": ({"uv_now": True, "freq_now": False, "throt_now": False, "temp_now": False,
                       "uv_ever": True, "freq_ever": True, "throt_ever": False, "temp_ever": False,
                       "raw": 0x30001} if is_pi else None),
        "disk_used": 9 << 30, "disk_total": 10 << 30, "disk_pct": 90.0,
        "disk_read": 12.5, "disk_write": 3.0, "net_rx": 100.0, "net_tx": 1.0,
        "load_avg": (0.1, 0.2, 0.3),
        "wifi": {"iface": "wlan0", "signal": -67.0, "quality": 43.0},
        "uptime": 100000, "top_procs": now_procs,
    }


class RenderTests(unittest.TestCase):
    """Every tab, at several terminal sizes, with both well-formed and
    hostile state — a render must never raise or draw out of bounds."""

    SIZES = [(12, 40), (24, 80), (50, 200), (11, 39), (13, 41)]

    def setUp(self):
        _curses_patches(self)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.csv = os.path.join(self.tmp.name, "metrics.csv")
        p = mock.patch.object(sw.sensors, "user_data_path",
                              side_effect=lambda *parts: os.path.join(self.tmp.name, *parts))
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(st.settings, "THRESH", {k: v for k, v in (
            ("cpu_pct", (80, 95)), ("ram_pct", (75, 90)), ("cpu_temp", (70, 80)),
            ("disk_pct", (85, 95)), ("gpu_temp", (85, 95)), ("storage_temp", (65, 75)))})
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(st.settings, "WATCHED_SERVICES", ["ssh", "systemd-networkd-wait-online"])
        p.start()
        self.addCleanup(p.stop)
        self.tabs = [("system", "SYSTEM"), ("network", "NETWORK"), ("logs", "LOGS"),
                     ("services", "SERVICES"), ("storage", "STORAGE"),
                     ("backup", "BACKUP"), ("history", "HISTORY")]

    def _write_history(self):
        now = datetime.now()
        with open(self.csv, "w") as f:
            t = now - timedelta(days=8)
            while t < now:
                if not (now - timedelta(hours=10) < t < now - timedelta(hours=6)):
                    f.write(f"{t:%Y-%m-%dT%H:%M:%S},12.5,40.0,55.5,61.0,1.2625,48.0,41.0,90.0\n")
                t += timedelta(minutes=30)
            f.write("garbage line\n")
            f.write(f"{now:%Y-%m-%dT%H:%M:%S},1,2,,4\n")       # 5-column legacy row
            f.write(f"{now - timedelta(days=1):%Y-%m-%dT%H:%M:%S},1,2,3,4,5\n")  # out of order

    def _states(self):
        now = time.time()
        devices = {
            "aa:aa:aa:aa:aa:aa": st.DeviceInfo("192.168.100.200", "aa:aa:aa:aa:aa:aa",
                                               "very-long-hostname." * 5, now, now, "INTRUDER"),
            "bb:bb:bb:bb:bb:bb": st.DeviceInfo("10.0.0.2", "bb:bb:bb:bb:bb:bb",
                                               "10.0.0.2", now - 9000, now - 9000, "Idle"),
        }
        good = {
            "system": _fake_system_snap(), "system_hist": {
                k: [float(i % 7) for i in range(80)]
                for k in ("cpu", "ram", "cpu_temp", "gpu_temp", "storage_temp",
                          "net_rx", "net_tx", "cpu_freq", "disk_read", "disk_write")},
            "model": "Test Box", "devices": devices,
            "logs": [{"priority": p % 8, "unit": "u" * 30, "message": "m" * 500,
                      "ts": now, "ts_str": "12:00:00"} for p in range(300)],
            "log_errs": [now - i for i in range(100)],
            "services": [
                {"unit": "ssh", "ActiveState": "active", "SubState": "running",
                 "ExecMainPID": "123", "NRestarts": "0",
                 "ActiveEnterTimestamp": "Wed 2026-01-07 10:00:00 UTC", "Result": "success"},
                {"unit": "systemd-networkd-wait-online", "ActiveState": "deactivating",
                 "SubState": "auto-restart", "ExecMainPID": "0", "NRestarts": "9",
                 "ActiveEnterTimestamp": "garbage", "Result": "exit-code"},
            ],
            "storage": {"device": "/dev/nvme0n1", "kind": "nvme", "card_type": None,
                        "smart_health": "FAILED", "power_on_hours": 12345, "smart_attrs": [],
                        "temp": 77.0, "fs_root": {"total": 100, "used": 99, "free": 1, "pct": 99.0},
                        "boot_mount": "/boot/efi", "fs_boot": None, "dev_errors": None,
                        "fs_errors": 3, "io_reads": 1, "io_writes": 2, "io_read_sectors": 3,
                        "io_write_sectors": 4, "bytes_written": 2048},
            "backup": {"last_run": {"status": "ok", "timestamp": "2026-01-01T00:00:00",
                                    "duration_s": 75.5, "files_transferred": 12345,
                                    "files_unchanged": 9, "total_size_human": "1.2 GB"},
                       "config": {"sources": ["/", "/definitely/missing", 5]},
                       "history": [{"timestamp": "2026-01-01T00:00:00", "status": "ok",
                                    "files_transferred": 3, "total_size_human": "1 GB",
                                    "duration_s": 5}, "junk", {"status": None}]},
            "network_meta": {"net_id": "gw:x", "trusted": False, "trustable": True,
                             "cidrs": ["10.0.0.0/24"], "scan_mode": "trusted"},
        }
        hostile = {
            "system": None, "system_hist": None, "model": None, "devices": {},
            "logs": [], "log_errs": [], "services": None, "storage": None,
            "backup": {"last_run": "bogus", "config": None, "history": None},
            "network_meta": None,
        }
        pi = dict(good, system=_fake_system_snap(is_pi=True),
                  network_meta={"net_id": "gw:x", "trusted": True, "trustable": True,
                                "cidrs": ["10.0.0.0/24"], "scan_mode": "trusted"})
        never = dict(good, network_meta={"net_id": "net:10.0.0.0/24", "trusted": False,
                                         "trustable": False, "cidrs": [], "scan_mode": "never"})
        half_hostile = dict(good, backup={"last_run": None}, services=[],
                            storage=dict(good["storage"], device=None, kind="mmc",
                                         card_type="SD", smart_health=None, io_reads=None))
        return [good, hostile, pi, half_hostile, never]

    def test_every_tab_every_size(self):
        self._write_history()
        for h, w in self.SIZES:
            win = helpers.FakeWin(h, w)
            renderer = rnd.FullRenderer(win, self.tabs)
            for state in self._states():
                for tab in range(1, len(self.tabs) + 1):
                    for window in range(5):
                        for scroll in (0, 3, 99):
                            renderer.render(tab, state, "m", "filter_input", "abc",
                                            window, scroll)
                            renderer.render(tab, state, "", "confirm_scan", "",
                                            window, scroll,
                                            {"action": "trust", "net_id": "gw:aa:bb",
                                             "cidrs": ["192.168.178.0/24"]})
                            # Cache keyed on file signature, so force reloads to
                            # exercise both paths.
                            renderer._hist_cache = None
                    self.assertIn("SYSWATCH" if w >= 40 and h >= 12 else "too small", win.text())

    def test_history_renders_charts_and_gap_markers(self):
        self._write_history()
        win = helpers.FakeWin(60, 160)
        renderer = rnd.FullRenderer(win, self.tabs)
        renderer.render(7, self._states()[0], "", "normal", "", 2, 0)
        text = win.text()
        self.assertIn("CPU %", text)
        self.assertIn("┊", text)  # the 4-hour outage is drawn as a gap

    def test_services_columns_stay_aligned(self):
        win = helpers.FakeWin(24, 120)
        renderer = rnd.FullRenderer(win, self.tabs)
        renderer.render(4, self._states()[0], "", "normal", "", 0, 0)
        lines = win.text().splitlines()
        row = next(ln for ln in lines if ln.startswith("systemd-network"))
        self.assertEqual(row[18:30].strip(), "deactivati")
        self.assertEqual(row[51:59].strip(), "9")

    def test_storage_filesystem_rows_stay_aligned_with_a_long_mount(self):
        state = self._states()[0]
        state = dict(state, storage=dict(
            state["storage"], boot_mount="/boot/firmware",
            fs_boot={"total": 528592896, "used": 82614272, "free": 0, "pct": 15.6}))
        win = helpers.FakeWin(30, 120)
        renderer = rnd.FullRenderer(win, self.tabs)
        renderer.render(5, state, "", "normal", "", 0, 0)
        lines = win.text().splitlines()
        root = next(ln for ln in lines if ln.startswith("/ "))
        boot = next(ln for ln in lines if ln.startswith("/boot/firmware"))
        self.assertEqual(root.index("%"), boot.index("%"))
        self.assertEqual(root.index("["), boot.index("["))

    def test_history_cache_reloads_only_on_change(self):
        self._write_history()
        renderer = rnd.FullRenderer(helpers.FakeWin(24, 80), self.tabs)
        first = renderer._load_history()
        renderer._hist_cache = (0.0,) + renderer._hist_cache[1:]  # expire the TTL
        with mock.patch("builtins.open", side_effect=AssertionError("re-parsed")):
            self.assertIs(renderer._load_history(), first)
        with open(self.csv, "a") as f:
            f.write(f"{datetime.now():%Y-%m-%dT%H:%M:%S},1,2,3,4\n")
        renderer._hist_cache = (0.0,) + renderer._hist_cache[1:]
        self.assertEqual(len(renderer._load_history()), len(first) + 1)


class CliTests(unittest.TestCase):
    """End-to-end: the real entry point, as a subprocess, in a throwaway HOME."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = dict(os.environ, HOME=self.tmp.name, XDG_CONFIG_HOME=os.path.join(self.tmp.name, "cfg"))
        self.env.pop("SUDO_USER", None)
        self.script = os.path.join(helpers.ROOT, "syswatch.py")

    def _run(self, *args):
        return subprocess.run([sys.executable, self.script, *args], env=self.env,
                              capture_output=True, text=True, timeout=60)

    def test_report_json(self):
        r = self._run("--report", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        report = json.loads(r.stdout)
        self.assertIn("/", report["disks"])
        self.assertIn(report["scan_mode"], ("trusted", "never"))
        self.assertIn("scan_network_trusted", report)

    def test_report_text_and_config_errors_on_stderr(self):
        cfg_path = os.path.join(self.tmp.name, "bad.toml")
        with open(cfg_path, "w") as f:
            f.write("[ui]\nrefresh = -1\n")
        r = self._run("--report", "--config", cfg_path, "--scan", "never")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SYSWATCH REPORT", r.stdout)
        self.assertIn("never", r.stdout)
        self.assertIn("ui.refresh", r.stderr)

    def test_write_default_config(self):
        r = self._run("--write-default-config")
        self.assertEqual(r.returncode, 0, r.stderr)
        path = os.path.join(self.tmp.name, "cfg", "syswatch", "config.toml")
        self.assertTrue(os.path.exists(path))
        self.assertEqual(self._run("--write-default-config").returncode, 1)
        self.assertEqual(self._run("--write-default-config", "--force").returncode, 0)

    def test_trust_all_devices(self):
        r = self._run("--trust-all-devices")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Trusted", r.stdout)

    def test_tui_starts_switches_tabs_and_quits(self):
        import pty
        import select
        pid, fd = pty.fork()
        if pid == 0:  # pragma: no cover - child
            env = dict(self.env, TERM="xterm-256color")
            os.execve(sys.executable, [sys.executable, self.script], env)
        out = b""
        try:
            def pump(seconds):
                nonlocal out
                end = time.time() + seconds
                while time.time() < end:
                    r, _, _ = select.select([fd], [], [], 0.1)
                    if r:
                        try:
                            out += os.read(fd, 65536)
                        except OSError:
                            return
            pump(2.5)
            for key in "234567/x\x1bh":
                os.write(fd, key.encode())
                pump(0.4)
            os.write(fd, b"q")
            pump(2.5)
        finally:
            _, status = os.waitpid(pid, 0)
            os.close(fd)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, out[-2000:])
        self.assertIn(b"DISCONNECTED", out)
        self.assertNotIn(b"Traceback", out)


if __name__ == "__main__":
    unittest.main()


class NeighbourStateTests(unittest.TestCase):
    SAMPLE = json.dumps([
        {"dst": "192.168.1.1", "dev": "eth0", "lladdr": "AA:AA:AA:AA:AA:01", "state": ["REACHABLE"]},
        {"dst": "192.168.1.2", "dev": "eth0", "lladdr": "aa:aa:aa:aa:aa:02", "state": ["STALE"]},
        {"dst": "192.168.1.3", "dev": "eth0", "state": ["FAILED"]},
        {"dst": "192.168.1.4", "dev": "eth0", "lladdr": "aa:aa:aa:aa:aa:04", "state": ["INCOMPLETE"]},
        {"dst": "192.168.1.5", "dev": "eth0", "lladdr": "aa:aa:aa:aa:aa:05", "state": ["DELAY"]},
        {"dst": "192.168.1.6", "dev": "eth0", "lladdr": "00:00:00:00:00:00", "state": ["NOARP"]},
        "junk",
    ])

    def test_states(self):
        arp = net.ARPPassiveThread.__new__(net.ARPPassiveThread)
        parsed = arp._parse_neigh_json(self.SAMPLE)
        self.assertEqual(set(parsed), {"aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02", "aa:aa:aa:aa:aa:05"})
        self.assertTrue(parsed["aa:aa:aa:aa:aa:01"]["fresh"])
        self.assertFalse(parsed["aa:aa:aa:aa:aa:02"]["fresh"])
        self.assertTrue(parsed["aa:aa:aa:aa:aa:05"]["fresh"])

    def test_falls_back_to_proc_when_ip_is_missing_or_too_old(self):
        arp = net.ARPPassiveThread.__new__(net.ARPPassiveThread)
        arp._ip_json = None
        old_ip = subprocess.CompletedProcess([], 255, stdout="", stderr='Option "-j" is unknown')
        with mock.patch.object(net.shutil, "which", return_value="/sbin/ip"), \
                mock.patch.object(net.subprocess, "run", return_value=old_ip), \
                mock.patch.object(arp, "_parse_proc_arp", return_value={"x": 1}) as proc:
            self.assertEqual(arp._parse_arp_table(), {"x": 1})
            self.assertIs(arp._ip_json, False)
            arp._parse_arp_table()
        self.assertEqual(proc.call_count, 2)

    def test_stale_entry_does_not_refresh_last_seen(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with mock.patch.object(st.settings, "KNOWN_DEVICES_PATH", os.path.join(tmp.name, "k.json")), \
                mock.patch.object(st.settings, "TRUSTED_NETWORKS_PATH", os.path.join(tmp.name, "t.json")), \
                mock.patch.object(net, "current_network", return_value=("gw:aa", [])), \
                mock.patch.object(net, "_resolve_hostname", side_effect=lambda ip: ip), \
                mock.patch.object(st.settings, "ARP_REFRESH", 0.02):
            with st._state_lock:
                st._state["devices"] = {"m": st.DeviceInfo("10.0.0.2", "m", "h", 0, time.time() - 3000, "Active")}
            self.addCleanup(lambda: st._state.__setitem__("devices", {}))
            arp = net.ARPPassiveThread()
            arp._parse_arp_table = lambda: {"m": {"ip": "10.0.0.2", "iface": "eth0", "fresh": False}}
            arp._net_id = "gw:aa"  # same network: don't clear the list
            arp.start()
            time.sleep(0.2)
            arp.stop()
            arp.join(2)
        dev = st.get_state()["devices"]["m"]
        self.assertLess(dev.last_seen, time.time() - 2000)
        self.assertEqual(dev.status, "Idle")


class AlertWriterTests(unittest.TestCase):
    def test_only_one_process_writes(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        code = ("import sys, time; sys.path.insert(0, sys.argv[1]); import syswatch_sensors as s;"
                "print(s.append_alert('temp_alerts.log', sys.argv[3], directory=sys.argv[2]), flush=True);"
                "time.sleep(float(sys.argv[4]))")
        first = subprocess.Popen([sys.executable, "-c", code, helpers.ROOT, tmp.name, "A", "2"],
                                 stdout=subprocess.PIPE, text=True)
        self.assertEqual(first.stdout.readline().strip(), "True")
        second = subprocess.run([sys.executable, "-c", code, helpers.ROOT, tmp.name, "B", "0"],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(second.stdout.strip(), "False")
        first.wait(10)
        first.stdout.close()
        # The writer exited, so the lock is free again.
        third = subprocess.run([sys.executable, "-c", code, helpers.ROOT, tmp.name, "C", "0"],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(third.stdout.strip(), "True")
        with open(os.path.join(tmp.name, "temp_alerts.log")) as f:
            self.assertEqual([ln.split()[-1] for ln in f], ["A", "C"])


class HistoryIntervalTests(unittest.TestCase):
    def test_median_interval(self):
        t0 = datetime(2026, 1, 1)
        ts = [t0 + timedelta(seconds=s) for s in (0, 120, 240, 360, 2000)]
        self.assertEqual(rnd.FullRenderer._median_interval(ts), 120)
        self.assertEqual(rnd.FullRenderer._median_interval(ts[:2]), 120.0)
        self.assertEqual(rnd.FullRenderer._median_interval([t0, t0, t0]), 1.0)

    def test_sparse_metric_has_no_false_gaps(self):
        _curses_patches(self)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        now = datetime.now()
        with open(os.path.join(tmp.name, "metrics.csv"), "w") as f:
            for i in range(180):  # 6h of 2-minute samples, temp on every 5th row only
                t = now - timedelta(minutes=2 * (180 - i))
                temp = "50.0" if i % 5 == 0 else ""
                f.write(f"{t:%Y-%m-%dT%H:%M:%S},10,20,{temp},30\n")
        with mock.patch.object(sw.sensors, "user_data_path",
                               side_effect=lambda *p: os.path.join(tmp.name, *p)), \
                mock.patch.object(st.settings, "THRESH", {}):
            win = helpers.FakeWin(80, 120)
            rnd.FullRenderer(win, [("history", "HISTORY")]).render(1, {}, "", "normal", "", 1, 2)
        text = win.text()
        self.assertIn("TEMP °C", text)
        self.assertNotIn("┊", text)
