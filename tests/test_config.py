import os
import tempfile
import unittest
from unittest import mock

import helpers  # noqa: F401  (sets up sys.path)
import syswatch_config as cfg


class FallbackParserTests(unittest.TestCase):
    def test_basic_tables_values_and_comments(self):
        data = cfg._parse_toml_fallback(
            '# top comment\n'
            '[ui]\n'
            'refresh = 1.5   # trailing comment\n'
            'default_tab = 3\n'
            '[network]\n'
            'scan = "known"\n'
            'intruder_alerts = false\n'
            'subnet = "10.0.0.0/24"  # with # inside comment\n'
            '[services]\n'
            'watch = ["ssh", "cron#not-a-comment"]\n'
        )
        self.assertEqual(data["ui"], {"refresh": 1.5, "default_tab": 3})
        self.assertEqual(data["network"]["scan"], "known")
        self.assertIs(data["network"]["intruder_alerts"], False)
        self.assertEqual(data["services"]["watch"], ["ssh", "cron#not-a-comment"])

    def test_non_ascii_strings_survive(self):
        data = cfg._parse_toml_fallback('[services]\nwatch = ["münchen", "日本"]\n')
        self.assertEqual(data["services"]["watch"], ["münchen", "日本"])

    def test_escaped_quote_inside_array_string(self):
        data = cfg._parse_toml_fallback('[services]\nwatch = ["a\\"b,c", "d"]\n')
        self.assertEqual(data["services"]["watch"], ['a"b,c', "d"])

    def test_key_outside_section_is_an_error(self):
        with self.assertRaises(cfg._TomlFallbackError):
            cfg._parse_toml_fallback("refresh = 1\n")

    def test_unparseable_value_is_an_error(self):
        with self.assertRaises(cfg._TomlFallbackError):
            cfg._parse_toml_fallback("[ui]\nrefresh = one\n")

    def test_example_config_parses_identically_with_both_parsers(self):
        text = cfg.example_config_text()
        fallback = cfg._parse_toml_fallback(text)
        try:
            import tomllib
        except ModuleNotFoundError:
            self.skipTest("tomllib needs Python 3.11+")
        self.assertEqual(fallback, tomllib.loads(text))


class ValidationTests(unittest.TestCase):
    def test_scan_mode_vocabulary(self):
        cases = {
            "known": "known", "true": "always", "false": "never",
            "always": "always", "never": "never", "KNOWN": "known",
        }
        for raw, expected in cases.items():
            value, err = cfg.validate_raw("network", "scan", raw)
            self.assertIsNone(err, raw)
            self.assertEqual(value, expected, raw)
        value, err = cfg.validate_raw("network", "scan", "sometimes")
        self.assertIsNone(value)
        self.assertIn("network.scan", err)

    def test_threshold_pair_bare_and_bracketed(self):
        self.assertEqual(cfg.validate_raw("thresholds", "cpu_pct", "70, 80"), ((70.0, 80.0), None))
        self.assertEqual(cfg.validate_raw("thresholds", "cpu_pct", "[70, 80]"), ((70.0, 80.0), None))
        value, err = cfg.validate_raw("thresholds", "cpu_pct", "90, 80")
        self.assertIsNone(value)
        self.assertIn("warn must be <= critical", err)

    def test_ranges_and_types(self):
        self.assertIsNone(cfg.validate_raw("ui", "refresh", "0")[0])
        self.assertEqual(cfg.validate_raw("ui", "refresh", "2")[0], 2.0)
        self.assertIsNone(cfg.validate_raw("ui", "default_tab", "true")[0])
        self.assertIsNone(cfg.validate_raw("network", "subnet", '"not-a-cidr"')[0])
        self.assertEqual(cfg.validate_raw("network", "subnet", '"10.0.0.0/8"')[0], "10.0.0.0/8")

    def test_unknown_key(self):
        value, err = cfg.validate_raw("ui", "nope", "1")
        self.assertIsNone(value)
        self.assertIn("unknown key", err)


class LoadConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Keep defaults() from shelling out to systemctl for every test.
        p = mock.patch.object(cfg, "_default_watched_services", return_value=["ssh"])
        p.start()
        self.addCleanup(p.stop)

    def _write(self, text):
        path = os.path.join(self.tmp.name, "config.toml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_missing_explicit_path_is_reported(self):
        conf, errors = cfg.load_config(os.path.join(self.tmp.name, "nope.toml"))
        self.assertEqual(conf["ui"]["refresh"], 1.0)
        self.assertEqual(len(errors), 1)

    def test_invalid_values_fall_back_to_defaults(self):
        path = self._write(
            "[ui]\nrefresh = -3\ntop_n = 7\n"
            "[thresholds]\ncpu_temp = [90, 60]\n"
            "[bogus]\nx = 1\n"
            "[network]\nscan = false\nwhat = 1\n"
        )
        conf, errors = cfg.load_config(path)
        self.assertEqual(conf["ui"]["refresh"], 1.0)
        self.assertEqual(conf["ui"]["top_n"], 7)
        self.assertEqual(conf["thresholds"]["cpu_temp"], (70, 80))
        self.assertEqual(conf["network"]["scan"], "never")
        self.assertEqual(len(errors), 4, errors)

    def test_unparseable_file_never_raises(self):
        path = self._write("[ui\nrefresh = = =\n")
        conf, errors = cfg.load_config(path)
        self.assertEqual(conf["ui"]["refresh"], 1.0)
        self.assertTrue(errors)

    def test_write_default_config_refuses_overwrite_and_round_trips(self):
        path = os.path.join(self.tmp.name, "sub", "config.toml")
        overrides = {"thresholds": {"cpu_pct": (60.0, 85.5)},
                     "network": {"scan": "always", "intruder_alerts": False},
                     "ui": {"refresh": 0.75, "default_tab": 2},
                     "logger": {"interval": 30, "retention_days": 7}}
        cfg.write_default_config(path, overrides=overrides)
        with self.assertRaises(FileExistsError):
            cfg.write_default_config(path)
        conf, errors = cfg.load_config(path)
        self.assertEqual(errors, [])
        self.assertEqual(conf["thresholds"]["cpu_pct"], (60.0, 85.5))
        self.assertEqual(conf["network"]["scan"], "always")
        self.assertIs(conf["network"]["intruder_alerts"], False)
        self.assertEqual(conf["ui"]["refresh"], 0.75)
        self.assertEqual(conf["ui"]["default_tab"], 2)
        self.assertEqual(conf["logger"], {"interval": 30, "retention_days": 7})
        self.assertEqual(conf["services"]["watch"], ["ssh"])


if __name__ == "__main__":
    unittest.main()
