import json
import os
import tempfile
import unittest

import helpers  # noqa: F401
import syswatch_known_devices as kd


class KnownDevicesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "known.json")

    def _write_raw(self, text):
        with open(self.path, "w") as f:
            f.write(text)

    def test_malformed_files_load_as_empty(self):
        for text in ("", "{", "[]", "null", '{"net": []}', "not json"):
            self._write_raw(text)
            self.assertEqual(kd.load(self.path), {}, text)
        self.assertEqual(kd.load(os.path.join(self.tmp.name, "missing.json")), {})

    def test_wrong_shaped_entries_are_dropped_or_cleaned(self):
        self._write_raw(json.dumps({
            "gw:aa": {"m1": {"first_seen": "x", "last_seen": 5, "hostname": 3},
                      "m2": "bogus"},
            "gw:bb": "bogus",
        }))
        data = kd.load(self.path)
        self.assertEqual(data, {"gw:aa": {"m1": {"first_seen": None, "last_seen": 5, "hostname": None}}})

    def test_round_trip_and_queries(self):
        data = {}
        kd.remember(data, "net1", "aa:bb", "host", now=100)
        kd.remember(data, "net1", "aa:bb", None, now=200)  # keeps hostname
        self.assertTrue(kd.save(data, self.path))
        loaded = kd.load(self.path)
        self.assertEqual(loaded["net1"]["aa:bb"],
                         {"first_seen": 100, "last_seen": 200, "hostname": "host"})
        self.assertTrue(kd.is_known(loaded, "net1", "aa:bb"))
        self.assertFalse(kd.is_known(loaded, "net2", "aa:bb"))
        self.assertTrue(kd.has_network(loaded, "net1"))
        self.assertFalse(kd.has_network(loaded, "net2"))

    def test_save_failure_is_reported(self):
        blocker = os.path.join(self.tmp.name, "file")
        open(blocker, "w").close()
        self.assertFalse(kd.save({}, os.path.join(blocker, "known.json")))

    def test_prune(self):
        day = 86400
        data = {"n1": {"old": {"last_seen": 0}, "new": {"last_seen": 100 * day}},
                "n2": {"old": {"last_seen": None}}}
        pruned = kd.prune(data, retention_days=90, now=100 * day)
        self.assertEqual(list(pruned), ["n1"])
        self.assertEqual(list(pruned["n1"]), ["new"])


if __name__ == "__main__":
    unittest.main()
