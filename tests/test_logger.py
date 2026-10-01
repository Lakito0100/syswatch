import os
import tempfile
import unittest
from datetime import datetime, timedelta

import helpers

logger = helpers.load_logger_module()


class TrimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.csv = os.path.join(self.tmp.name, "metrics.csv")

    def _rows(self, ages_days):
        now = datetime.now()
        return [f"{(now - timedelta(days=d)).strftime('%Y-%m-%dT%H:%M:%S')},1.0,2.0,,3.0\n"
                for d in ages_days]

    def test_drops_only_expired_rows(self):
        rows = self._rows([40, 35, 10, 1, 0])
        with open(self.csv, "w") as f:
            f.writelines(rows)
        logger._trim(self.csv, days=30)
        with open(self.csv) as f:
            self.assertEqual(f.readlines(), rows[2:])
        self.assertEqual([n for n in os.listdir(self.tmp.name) if ".tmp" in n], [])

    def test_untouched_when_nothing_expired(self):
        rows = self._rows([2, 1])
        with open(self.csv, "w") as f:
            f.writelines(rows)
        before = os.stat(self.csv).st_ino
        logger._trim(self.csv, days=30)
        self.assertEqual(os.stat(self.csv).st_ino, before)


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _log(self, name):
        path = os.path.join(self.tmp.name, name)
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return f.read().splitlines()

    def test_temp_alert_fires_once_per_upward_crossing(self):
        level = 0
        for temp in (60, 72, 75, 81, 82, 60, 71):
            level = logger._check_temp_alert(self.tmp.name, temp, (70, 80), level)
        lines = self._log("temp_alerts.log")
        self.assertEqual([ln.split()[2] for ln in lines], ["WARNING", "CRITICAL", "WARNING"])

    def test_disk_alert_and_missing_values(self):
        self.assertEqual(logger._check_disk_alert(self.tmp.name, None, (85, 95), 1), 1)
        self.assertEqual(logger._check_disk_alert(self.tmp.name, 96.0, (85, 95), 0), 2)
        self.assertIn("CRITICAL disk=/ 96.0%", self._log("disk_alerts.log")[0])


if __name__ == "__main__":
    unittest.main()
