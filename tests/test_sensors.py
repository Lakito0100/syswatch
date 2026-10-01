import collections
import json
import subprocess
import unittest
from unittest import mock

import helpers  # noqa: F401
import syswatch_sensors as sensors

Temp = collections.namedtuple("Temp", "label current high critical")


def _t(label, current):
    return Temp(label, current, None, None)


class CpuTempTests(unittest.TestCase):
    def test_prefers_package_label_on_priority_key(self):
        temps = {"nvme": [_t("Composite", 40.0)],
                 "coretemp": [_t("Core 0", 50.0), _t("Package id 0", 55.0)]}
        with mock.patch.object(sensors.psutil, "sensors_temperatures", return_value=temps):
            self.assertEqual(sensors.cpu_temp(), 55.0)

    def test_skips_non_cpu_sensors(self):
        temps = {"nvme": [_t("Composite", 40.0)], "acpi_fan": [_t("", 33.0)]}
        with mock.patch.object(sensors.psutil, "sensors_temperatures", return_value=temps):
            self.assertEqual(sensors.cpu_temp(), 33.0)

    def test_missing_sensor_is_not_recorded_as_an_error(self):
        with mock.patch.object(sensors.psutil, "sensors_temperatures", return_value={}), \
                mock.patch("builtins.open", side_effect=FileNotFoundError), \
                mock.patch.object(sensors, "note_error") as note:
            self.assertIsNone(sensors.cpu_temp())
        note.assert_not_called()


class GpuTempTests(unittest.TestCase):
    def test_nvidia_multi_gpu_reads_first(self):
        out = "NVIDIA GeForce RTX 3090, 55\nNVIDIA GeForce RTX 3090, 61\n"
        done = subprocess.CompletedProcess([], 0, stdout=out, stderr="")
        with mock.patch.object(sensors.subprocess, "run", return_value=done):
            self.assertEqual(sensors._read_gpu_temp_nvidia(),
                             {"vendor": "NVIDIA", "label": "NVIDIA GeForce RTX 3090", "temp": 55.0})


class StorageTempTests(unittest.TestCase):
    def _run(self, payload):
        done = subprocess.CompletedProcess([], 0, stdout=json.dumps(payload), stderr="")
        with mock.patch.object(sensors.shutil, "which", return_value="/usr/sbin/smartctl"), \
                mock.patch.object(sensors.subprocess, "run", return_value=done):
            return sensors._read_storage_temp_smartctl("sda", "disk")

    def test_nvme_log(self):
        self.assertEqual(self._run({"nvme_smart_health_information_log": {"temperature": 38}}), 38.0)

    def test_ata_attribute_194(self):
        payload = {"ata_smart_attributes": {"table": [
            {"id": 9, "name": "Power_On_Hours", "raw": {"value": 100}},
            {"id": 194, "name": "Temperature_Celsius", "raw": {"value": "41 (Min/Max 20/50)"}},
        ]}}
        self.assertEqual(self._run(payload), 41.0)

    def test_null_sections_do_not_crash(self):
        self.assertIsNone(self._run({"ata_smart_attributes": None,
                                     "nvme_smart_health_information_log": None}))

    def test_absent_smartctl(self):
        with mock.patch.object(sensors.shutil, "which", return_value=None):
            self.assertIsNone(sensors._read_storage_temp_smartctl("sda", "disk"))


class RootDeviceTests(unittest.TestCase):
    def setUp(self):
        sensors._root_device_cache = None
        self.addCleanup(setattr, sensors, "_root_device_cache", None)

    def _fake_lsblk(self, outputs):
        def run(cmd, **_kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=outputs.get(tuple(cmd[:2]), ""), stderr="")
        return run

    def test_resolves_through_lvm_and_luks_to_the_disk(self):
        Part = collections.namedtuple("Part", "device mountpoint")
        outputs = {("lsblk", "-nrso"): "vg-root lvm\nnvme0n1p3_crypt crypt\nnvme0n1p3 part\nnvme0n1 disk\n"}
        with mock.patch.object(sensors.psutil, "disk_partitions",
                               return_value=[Part("/dev/mapper/vg-root", "/")]), \
                mock.patch.object(sensors.shutil, "which", return_value="/usr/bin/lsblk"), \
                mock.patch.object(sensors.subprocess, "run", side_effect=self._fake_lsblk(outputs)):
            dev = sensors.root_device()
        self.assertEqual(dev["base"], "nvme0n1")
        self.assertEqual(dev["kind"], "nvme")
        self.assertEqual(dev["sysfs"], "/sys/block/nvme0n1")

    def test_falls_back_to_name_pattern_without_lsblk(self):
        Part = collections.namedtuple("Part", "device mountpoint")
        with mock.patch.object(sensors.psutil, "disk_partitions",
                               return_value=[Part("/dev/mmcblk0p2", "/")]), \
                mock.patch.object(sensors.shutil, "which", return_value=None):
            dev = sensors.root_device()
        self.assertEqual((dev["base"], dev["kind"]), ("mmcblk0", "mmc"))


class LocalNetworksTests(unittest.TestCase):
    def test_filters(self):
        Addr = collections.namedtuple("Addr", "family address netmask")
        Stat = collections.namedtuple("Stat", "isup")
        addrs = {
            "lo":        [Addr(2, "127.0.0.1", "255.0.0.0")],
            "eth0":      [Addr(2, "192.168.1.10", "255.255.255.0")],
            "eth1":      [Addr(2, "10.1.2.3", "255.255.0.0")],        # /16: too big
            "tailscale": [Addr(2, "100.64.0.1", "255.255.255.255")],  # /32
            "down0":     [Addr(2, "172.16.0.1", "255.255.255.0")],
            "ll":        [Addr(2, "169.254.3.3", "255.255.0.0")],
        }
        stats = {k: Stat(k != "down0") for k in addrs}
        with mock.patch.object(sensors.psutil, "net_if_addrs", return_value=addrs), \
                mock.patch.object(sensors.psutil, "net_if_stats", return_value=stats):
            nets = sensors.local_networks()
        self.assertEqual([str(n) for n in nets], ["192.168.1.0/24"])


class ErrorTrackingTests(unittest.TestCase):
    def test_recent_errors_window(self):
        sensors._recent_errors.clear()
        self.assertFalse(sensors.has_recent_errors())
        sensors.note_error("test-collector")
        self.assertTrue(sensors.has_recent_errors())
        with mock.patch.object(sensors.time, "monotonic", return_value=sensors.time.monotonic() + 60):
            self.assertFalse(sensors.has_recent_errors())


if __name__ == "__main__":
    unittest.main()
