import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

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


class _StopLoop(BaseException):
    """Raised from the patched sleep to leave main()'s endless loop; a
    BaseException so the loop's `except Exception` doesn't swallow it."""


class SampleRowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _one_row_on_a_pi(self):
        def fake_run(cmd, **_kw):
            out = {("vcgencmd", "measure_volts", "core"): "volt=0.8688V\n",
                   ("vcgencmd", "measure_temp", "pmic"): "temp=62.8'C\n"}.get(tuple(cmd), "")
            return subprocess.CompletedProcess(cmd, 0 if out else 1, out, "")

        sleeps = []

        def fake_sleep(secs):
            sleeps.append(secs)
            if len(sleeps) > 1:  # the first is main()'s cpu_percent priming
                raise _StopLoop

        s = logger.sensors
        with mock.patch.object(s, "user_data_path",
                               side_effect=lambda *p: os.path.join(self.tmp.name, *p)), \
             mock.patch.object(s, "chown_to_invoking_user"), \
             mock.patch.object(s, "is_pi", return_value=True), \
             mock.patch.object(s, "gpu_temp", return_value=None), \
             mock.patch.object(s, "cpu_temp", return_value=55.0), \
             mock.patch.object(s, "storage_temp", return_value=None), \
             mock.patch.object(s.shutil, "which", return_value="/usr/bin/vcgencmd"), \
             mock.patch("subprocess.run", side_effect=fake_run), \
             mock.patch.object(logger.time, "sleep", side_effect=fake_sleep), \
             mock.patch("sys.argv", ["syswatch-logger",
                                     "--config", os.path.join(self.tmp.name, "none.toml")]):
            with self.assertRaises(_StopLoop):
                logger.main()
        with open(os.path.join(self.tmp.name, "metrics.csv")) as f:
            return f.read().strip().split(",")

    def test_pi_row_has_voltage_and_gpu_temp(self):
        # The TUI showed the Pi's GPU TEMP (vcgencmd measure_temp pmic) but the
        # logger only asked sensors.gpu_temp(), which knows NVIDIA/AMD/Intel,
        # so the gpu_temp column stayed empty on every Pi and HISTORY never
        # drew a GPU chart there.
        row = self._one_row_on_a_pi()
        self.assertEqual(len(row), 9)
        self.assertEqual(row[5], "0.8688")
        self.assertEqual(row[6], "62.8")


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
