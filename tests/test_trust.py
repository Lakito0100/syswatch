"""Safety tests: syswatch must never actively scan a network unless the user
explicitly trusted *that* network for scanning and confirmed it."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import helpers
import syswatch as sw
import syswatch_network as net
import syswatch_state as st
import syswatch_trusted_networks as tn

GW = "gw:aa:bb:cc:dd:ee:ff"
OTHER_GW = "gw:11:22:33:44:55:66"
CIDR = "192.168.178.0/24"


class TrustedNetworksStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "trusted.json")

    def test_only_gateway_identities_are_trustable(self):
        self.assertTrue(tn.trustable(GW))
        for bad in ("net:192.168.1.0/24", "net:unknown", "gw:", "", None, 5):
            self.assertFalse(tn.trustable(bad), bad)
            with self.assertRaises(ValueError):
                tn.trust({}, bad, [CIDR])

    def test_trust_requires_a_subnet(self):
        with self.assertRaises(ValueError):
            tn.trust({}, GW, [])

    def test_malformed_files_mean_no_trust(self):
        for text in ("", "{", "[]", "null",
                     json.dumps({"net:192.168.1.0/24": {"cidrs": [CIDR]}}),
                     json.dumps({GW: {"cidrs": []}}),
                     json.dumps({GW: {"cidrs": ["not-a-cidr"]}}),
                     json.dumps({GW: "yes"})):
            with open(self.path, "w") as f:
                f.write(text)
            self.assertEqual(tn.load(self.path), {}, text)

    def test_round_trip(self):
        data = {}
        tn.trust(data, GW, [CIDR], now=5, label="home")
        self.assertTrue(tn.save(data, self.path))
        loaded = tn.load(self.path)
        self.assertTrue(tn.is_trusted(loaded, GW))
        self.assertEqual(tn.trusted_cidrs(loaded, GW), [CIDR])
        self.assertFalse(tn.is_trusted(loaded, OTHER_GW))
        self.assertTrue(tn.untrust(loaded, GW))
        self.assertFalse(tn.is_trusted(loaded, GW))

    def test_host_count(self):
        self.assertEqual(tn.host_count([CIDR]), 254)
        self.assertEqual(tn.host_count(["10.0.0.0/30", "bogus"]), 2)


class _TrustBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.trust_path = os.path.join(self.tmp.name, "trusted.json")
        for name, value in (("KNOWN_DEVICES_PATH", os.path.join(self.tmp.name, "known.json")),
                            ("TRUSTED_NETWORKS_PATH", self.trust_path),
                            ("SCAN_MODE", "trusted"), ("BASELINE_WINDOW", 60)):
            p = mock.patch.object(st.settings, name, value)
            p.start()
            self.addCleanup(p.stop)
        st._alerts.clear()
        self.addCleanup(st._alerts.clear)
        self.network = (GW, [CIDR])
        self.trust = net.NetworkTrust()

    def net(self):
        return self.network

    def alerts(self):
        return [a[1] for a in st._alerts]


class ScanTrustDialogTests(_TrustBase):
    def dialog(self, on_change=None):
        return net.ScanTrustDialog(self.trust, network_fn=self.net, on_change=on_change)

    def test_only_y_confirms(self):
        for key in ("n", "N", "\x1b", "\n", " ", "q", "t", "s"):
            d = self.dialog()
            self.assertTrue(d.open())
            self.assertTrue(d.handle_key(ord(key)), key)
            self.assertFalse(self.trust.is_trusted(GW), key)
            self.assertIsNone(d.pending)
        self.assertFalse(os.path.exists(self.trust_path))

    def test_no_key_and_resize_keep_the_dialog_open(self):
        d = self.dialog()
        d.open()
        self.assertFalse(d.handle_key(-1))
        self.assertFalse(d.handle_key(sw.curses.KEY_RESIZE))
        self.assertIsNotNone(d.pending)

    def test_y_trusts_and_persists(self):
        changed = []
        d = self.dialog(on_change=lambda: changed.append(1))
        d.open()
        self.assertEqual(d.pending, {"action": "trust", "net_id": GW, "cidrs": [CIDR]})
        d.handle_key(ord("y"))
        self.assertTrue(self.trust.is_trusted(GW))
        self.assertEqual(tn.trusted_cidrs(tn.load(self.trust_path), GW), [CIDR])
        self.assertEqual(changed, [1])

    def test_network_change_voids_the_confirmation(self):
        d = self.dialog()
        d.open()
        self.network = (OTHER_GW, [CIDR])
        d.handle_key(ord("y"))
        self.assertFalse(self.trust.is_trusted(GW))
        self.assertFalse(self.trust.is_trusted(OTHER_GW))
        self.assertTrue(any("network changed" in a for a in self.alerts()))

    def test_subnet_change_voids_the_confirmation(self):
        d = self.dialog()
        d.open()
        self.network = (GW, ["192.168.0.0/24"])
        d.handle_key(ord("y"))
        self.assertFalse(self.trust.is_trusted(GW))

    def test_check_network_cancels_an_open_dialog(self):
        d = self.dialog()
        d.open()
        d.check_network()
        self.assertIsNotNone(d.pending)
        self.network = (OTHER_GW, [CIDR])
        d.check_network()
        self.assertIsNone(d.pending)

    def test_incompletely_drawn_warning_cannot_be_confirmed(self):
        d = self.dialog()
        d.open()
        d.handle_key(ord("y"), dialog_complete=False)
        self.assertFalse(self.trust.is_trusted(GW))

    def test_unidentifiable_network_never_opens(self):
        for network in (("net:192.168.178.0/24", [CIDR]), ("net:unknown", []), (GW, [])):
            self.network = network
            d = self.dialog()
            self.assertFalse(d.open(), network)
            self.assertIsNone(d.pending)

    def test_scan_never_refuses(self):
        with mock.patch.object(st.settings, "SCAN_MODE", "never"):
            self.assertFalse(self.dialog().open())

    def test_untrust_flow(self):
        self.trust.trust(GW, [CIDR])
        d = self.dialog()
        d.open()
        self.assertEqual(d.pending["action"], "untrust")
        d.handle_key(ord("n"))
        self.assertTrue(self.trust.is_trusted(GW))
        d.open()
        d.handle_key(ord("y"))
        self.assertFalse(self.trust.is_trusted(GW))
        self.assertFalse(net.NetworkTrust().is_trusted(GW))


class PingSweepGateTests(_TrustBase):
    """Run the real sweep loop with Popen mocked and record every address it
    would have pinged."""

    def setUp(self):
        super().setUp()
        self.pinged = []

        class FakeProc:
            returncode = 1

            def wait(_self, timeout=None):
                return 1

            def kill(_self):
                pass

        def popen(cmd, **_kw):
            self.pinged.append(cmd[-1])
            return FakeProc()

        p1 = mock.patch.object(net.subprocess, "Popen", side_effect=popen)
        p2 = mock.patch.object(st.settings, "PING_CYCLE", 0.2)
        p3 = mock.patch.object(st.settings, "PING_BATCH", 64)
        p4 = mock.patch.object(net.shutil, "which", side_effect=lambda b: f"/usr/bin/{b}")
        p5 = mock.patch.dict(st._state, {"sweep_period": None})
        for p in (p1, p2, p3, p4, p5):
            p.start()
            self.addCleanup(p.stop)

    def sweep(self, seconds=0.6, scan_mode="trusted", network_fn=None):
        t = net.PingSweepThread(scan_mode=scan_mode, trust=self.trust,
                               network_fn=network_fn or self.net)
        t._GATED_POLL = 0.05
        t.start()
        time.sleep(seconds)
        t.stop()
        t.join(3)
        self.assertFalse(t.is_alive())

    def test_untrusted_network_is_never_pinged(self):
        self.sweep()
        self.assertEqual(self.pinged, [])

    def test_trusted_network_is_swept_within_its_subnet_only(self):
        self.trust.trust(GW, [CIDR])
        self.sweep()
        self.assertTrue(self.pinged)
        self.assertTrue(all(ip.startswith("192.168.178.") for ip in self.pinged))

    def test_never_mode_overrides_trust(self):
        self.trust.trust(GW, [CIDR])
        self.sweep(scan_mode="never")
        self.assertEqual(self.pinged, [])

    def test_different_network_with_same_subnet_is_not_pinged(self):
        self.trust.trust(GW, [CIDR])
        self.network = (OTHER_GW, [CIDR])  # café using the same addressing
        self.sweep()
        self.assertEqual(self.pinged, [])

    def test_trusted_subnet_that_is_no_longer_local_is_not_pinged(self):
        self.trust.trust(GW, [CIDR])
        self.network = (GW, ["10.0.0.0/24"])
        self.sweep()
        self.assertEqual(self.pinged, [])

    def test_leaving_the_network_mid_sweep_stops_within_a_batch(self):
        self.trust.trust(GW, [CIDR])
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            return (GW, [CIDR]) if calls["n"] <= 2 else (OTHER_GW, [CIDR])

        with mock.patch.object(st.settings, "PING_BATCH", 10):
            self.sweep(network_fn=flaky)
        # Gate + first batch allowed, then the identity changed: at most one batch.
        self.assertLessEqual(len(self.pinged), 10)

    def test_sweep_period_is_published_only_while_sweeping(self):
        # Device status stretches its "Recent" window by this; a stale value
        # after the sweep stopped would keep gone devices Recent for too long.
        self.trust.trust(GW, [CIDR])
        t = net.PingSweepThread(trust=self.trust, network_fn=self.net)
        t._GATED_POLL = 0.05
        t.start()
        deadline = time.time() + 2
        while st._state["sweep_period"] is None and time.time() < deadline:
            time.sleep(0.01)
        # 254 hosts in batches of 64 → 4 batches on top of PING_CYCLE.
        self.assertEqual(st._state["sweep_period"],
                         0.2 + 4 * net.PingSweepThread._BATCH_OVERHEAD)
        self.trust.untrust(GW)
        deadline = time.time() + 2
        while st._state["sweep_period"] is not None and time.time() < deadline:
            time.sleep(0.01)
        self.assertIsNone(st._state["sweep_period"])
        self.trust.trust(GW, [CIDR])
        time.sleep(0.2)
        t.stop()
        t.join(3)
        self.assertFalse(t.is_alive())
        self.assertIsNone(st._state["sweep_period"])

    def test_untrusted_network_publishes_no_sweep_period(self):
        self.sweep()
        self.assertIsNone(st._state["sweep_period"])

    def test_no_fallback_target_without_a_local_subnet(self):
        self.trust.trust(GW, [CIDR])
        self.network = (GW, [])
        self.sweep()
        self.assertEqual(self.pinged, [])


class DeviceTrustNeverEnablesScanningTests(_TrustBase):
    def setUp(self):
        super().setUp()
        with st._state_lock:
            st._state["devices"] = {}
        self.addCleanup(lambda: st._state.__setitem__("devices", {}))
        p = mock.patch.object(net, "current_network", side_effect=lambda: self.network)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(net, "_resolve_hostname", side_effect=lambda ip: ip)
        p.start()
        self.addCleanup(p.stop)

    def test_t_and_baseline_learning_do_not_trust_the_network(self):
        arp = net.ARPPassiveThread(trust=self.trust)
        arp._parse_arp_table = lambda: {"aa": {"ip": "192.168.178.2", "iface": "eth0"}}
        with mock.patch.object(st.settings, "ARP_REFRESH", 0.02):
            arp.start()
            time.sleep(0.3)
            arp.trust_all()
            time.sleep(0.1)
            arp.stop()
            arp.join(2)
        self.assertIn("aa", sw.known_devices.load(st.settings.KNOWN_DEVICES_PATH)[GW])
        self.assertFalse(self.trust.is_trusted(GW))
        self.assertFalse(os.path.exists(self.trust_path))
        self.assertFalse(st.get_state()["network_meta"]["trusted"])
        # Next run on the same network: devices known, still not scannable.
        self.assertFalse(net.NetworkTrust().is_trusted(GW))

    def test_network_change_clears_the_device_list(self):
        arp = net.ARPPassiveThread(trust=self.trust)
        arp._refresh_network_identity(time.time())
        with st._state_lock:
            st._state["devices"]["old"] = st.DeviceInfo("1.1.1.1", "old", "x", 0, 0, "Active")
        arp._refresh_network_identity(time.time())
        self.assertIn("old", st.get_state()["devices"])
        self.network = (OTHER_GW, [CIDR])
        arp._refresh_network_identity(time.time())
        self.assertEqual(st.get_state()["devices"], {})


class CliTrustTests(unittest.TestCase):
    """Runs the real CLI/TUI against this machine's real network identity,
    but in a throwaway HOME and with a fake `ping` first on PATH: these
    tests confirm trust (in that throwaway HOME), and a TUI left running for
    a few seconds afterwards must never be able to sweep whatever network
    the test machine is on. The fake only records its arguments."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        fake_bin = os.path.join(self.tmp.name, "fakebin")
        os.makedirs(fake_bin)
        self.ping_log = os.path.join(self.tmp.name, "ping.log")
        with open(os.path.join(fake_bin, "ping"), "w") as f:
            f.write(f'#!/bin/sh\necho "$@" >> "{self.ping_log}"\nexit 1\n')
        os.chmod(os.path.join(fake_bin, "ping"), 0o755)
        self.env = dict(os.environ, HOME=self.tmp.name,
                        XDG_CONFIG_HOME=os.path.join(self.tmp.name, "cfg"),
                        PATH=fake_bin + os.pathsep + os.environ.get("PATH", ""))
        self.env.pop("SUDO_USER", None)
        self.script = os.path.join(helpers.ROOT, "syswatch.py")
        self.trust_file = os.path.join(self.tmp.name, ".local", "share", "syswatch",
                                       "trusted_networks.json")

    def test_refuses_without_a_terminal(self):
        r = subprocess.run([sys.executable, self.script, "--trust-network"], env=self.env,
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.trust_file))

    def test_scan_always_flag_no_longer_exists(self):
        r = subprocess.run([sys.executable, self.script, "--scan", "always", "--report"],
                           env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("invalid choice", r.stderr)

    def _pty(self, args, keys, wait=2.5):
        import pty
        import select
        pid, fd = pty.fork()
        if pid == 0:  # pragma: no cover - child
            os.execve(sys.executable, [sys.executable, self.script, *args],
                      dict(self.env, TERM="xterm-256color"))
        out = b""

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
        try:
            pump(wait)
            for k in keys:
                os.write(fd, k.encode())
                pump(0.6)
            pump(1.5)
        finally:
            _, status = os.waitpid(pid, 0)
            os.close(fd)
        return os.waitstatus_to_exitcode(status), out.decode(errors="replace")

    def _require_trustable_network(self):
        net_id, cidrs = net.current_network()
        if not (tn.trustable(net_id) and cidrs):
            self.skipTest("this machine's network has no identifiable gateway/subnet")
        return net_id

    def test_cli_answer_no_then_yes(self):
        net_id = self._require_trustable_network()
        code, out = self._pty(["--trust-network"], ["n\n"])
        self.assertEqual(code, 1, out)
        self.assertIn("WARNING", out)
        self.assertFalse(os.path.exists(self.trust_file))
        code, out = self._pty(["--trust-network"], ["y\n"])
        self.assertEqual(code, 0, out)
        self.assertIn(net_id, tn.load(self.trust_file))
        code, out = self._pty(["--untrust-network"], ["y\n"])
        self.assertEqual(code, 0, out)
        self.assertEqual(tn.load(self.trust_file), {})

    def test_tui_t_never_trusts_and_s_needs_y(self):
        net_id = self._require_trustable_network()
        code, out = self._pty([], ["2", "t", "s", "n", "s", "x", "q"])
        self.assertEqual(code, 0, out[-2000:])
        self.assertIn("ENABLE ACTIVE SCANNING", out)
        self.assertNotIn("Traceback", out)
        self.assertFalse(os.path.exists(self.trust_file) and tn.load(self.trust_file))
        code, out = self._pty([], ["2", "s", "y", "q"])
        self.assertEqual(code, 0, out[-2000:])
        self.assertIn(net_id, tn.load(self.trust_file))


if __name__ == "__main__":
    unittest.main()
