import json
import os
import tempfile
import unittest
from unittest import mock

import helpers  # noqa: F401
import syswatch_config
import syswatch_inventory as inv


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.object(syswatch_config, "_default_watched_services", return_value=["ssh"])
        p.start()
        self.addCleanup(p.stop)

    def write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_config_summary_lists_only_changed_settings_and_notes(self):
        path = self.write("config.toml",
                          "[thresholds]\ncpu_temp = [75, 85]\ncpu_pct = [80, 95]\n"
                          "[network]\nscan = true\nsubnet = \"10.0.0.0/24\"\n"
                          "[ui]\nbogus = 1\n")
        text = "\n".join(inv.config_summary(path))
        self.assertIn("thresholds.cpu_temp = [75, 85]   (default [70, 80])", text)
        self.assertNotIn("cpu_pct", text)            # same as the default
        self.assertIn("always-scan mode was removed", text)
        self.assertIn("network.subnet", text)
        self.assertIn("ui.bogus: unknown key", text)

    def test_config_summary_defaults_and_broken_files(self):
        self.assertIn("All settings are the built-in defaults.",
                      "\n".join(inv.config_summary(self.write("a.toml", "[ui]\nrefresh = 1.0\n"))))
        self.assertIn("can't be read or parsed",
                      "\n".join(inv.config_summary(self.write("b.toml", "[ui\n"))))
        self.assertIn("can't be read or parsed",
                      "\n".join(inv.config_summary(os.path.join(self.tmp.name, "missing.toml"))))

    def test_file_summaries(self):
        csv = self.write("metrics.csv", "2026-01-01T00:00:00,1,2,,3\njunk\n2026-02-03T00:00:00,1,2,,3\n")
        self.assertIn("2 samples, 2026-01-01 → 2026-02-03", inv.file_summary(csv))
        log = self.write("temp_alerts.log", "a WARNING x\n\nb CRITICAL y\n")
        self.assertIn("2 entries, last: b CRITICAL y", inv.file_summary(log))
        self.assertIn("1 entry", inv.file_summary(self.write("disk_alerts.log", "z\n")))
        known = self.write("known_devices.json", json.dumps({"gw:a": {"m1": {}, "m2": {}}, "gw:b": {"m3": {}}}))
        self.assertIn("3 device(s) on 2 network(s)", inv.file_summary(known))
        trusted = self.write("trusted_networks.json", json.dumps(
            {"gw:aa:bb": {"cidrs": ["10.0.0.0/24"], "label": "home"}}))
        self.assertIn("networks trusted for scanning: 1 (home)", inv.file_summary(trusted))
        self.assertIn("none", inv.file_summary(self.write("trusted_networks.json", "{")))
        self.assertIn("no samples", inv.file_summary(self.write("metrics.csv", "")))
        self.assertIn("can't be read", inv.file_summary(os.path.join(self.tmp.name, "gone.log")))

    def test_data_files_order_and_internal_files(self):
        for name in ("zzz.txt", "known_devices.json", "alerts.lock", "metrics.csv"):
            self.write(name, "")
        os.mkdir(os.path.join(self.tmp.name, "subdir"))
        names = [os.path.basename(p) for p in inv.data_files(self.tmp.name)]
        self.assertEqual(names, ["metrics.csv", "known_devices.json", "zzz.txt"])
        self.assertEqual(inv.data_files(os.path.join(self.tmp.name, "nope")), [])


if __name__ == "__main__":
    unittest.main()
