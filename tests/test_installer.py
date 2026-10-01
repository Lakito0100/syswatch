"""install-syswatch.sh end to end. Needs root (it creates a throwaway user)
and is skipped otherwise; CI runs it with sudo. Everything is installed into
a scratch directory via the SYSWATCH_* path overrides, with a stub systemctl,
so it never touches the real system."""

import os
import pty
import re
import select
import shutil
import subprocess
import tempfile
import time
import unittest

import helpers

INSTALLER = os.path.join(helpers.ROOT, "install-syswatch.sh")
PROMPT = re.compile(rb"(\[Y/n\] |\[y/N\] |\]: )$")


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("useradd"),
                     "installer tests need root")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="swinst-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.user = f"swtest{os.getpid() % 100000}"
        self.home = os.path.join(self.tmp, "home")
        subprocess.run(["useradd", "-M", "-d", self.home, "-s", "/bin/sh", self.user], check=True)
        self.addCleanup(subprocess.run, ["userdel", self.user], capture_output=True)
        os.makedirs(self.home)
        shutil.chown(self.home, self.user, self.user)
        stub = os.path.join(self.tmp, "stubbin")
        os.makedirs(stub)
        with open(os.path.join(stub, "systemctl"), "w") as f:
            f.write("#!/bin/sh\n[ \"$1\" = show ] && echo LoadState=not-found\nexit 0\n")
        os.chmod(os.path.join(stub, "systemctl"), 0o755)
        self.lib = os.path.join(self.tmp, "lib", "syswatch")
        self.bin = os.path.join(self.tmp, "bin", "syswatch")
        self.units = os.path.join(self.tmp, "units")
        self.doc = os.path.join(self.tmp, "doc", "syswatch")
        self.roothome = os.path.join(self.tmp, "roothome")
        self.env = dict(os.environ, PATH=stub + ":" + os.environ.get("PATH", ""),
                        SYSWATCH_LIB_DIR=self.lib, SYSWATCH_BIN=self.bin,
                        SYSWATCH_UNIT_DIR=self.units, SYSWATCH_DOC_DIR=self.doc,
                        SYSWATCH_ROOT_HOME=self.roothome)
        self.env.pop("SUDO_USER", None)
        self.config = os.path.join(self.home, ".config", "syswatch", "config.toml")
        self.data = os.path.join(self.home, ".local", "share", "syswatch")

    # ── helpers ──────────────────────────────────────────────────────────────
    def run_unattended(self, *args):
        r = subprocess.run(["bash", INSTALLER, "--user", self.user, *args], env=self.env,
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr

    def run_interactive(self, args, answers):
        """Answer each prompt in order; any prompt beyond `answers` gets Enter."""
        pid, fd = pty.fork()
        if pid == 0:  # pragma: no cover - child
            os.execve("/bin/bash", ["bash", INSTALLER, "--user", self.user, *args], self.env)
        out, used, last = b"", 0, time.time()
        try:
            while time.time() - last < 60:
                r, _, _ = select.select([fd], [], [], 0.2)
                if not r:
                    continue
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                out, last = out + chunk, time.time()
                if PROMPT.search(out):
                    ans = answers[used] if used < len(answers) else ""
                    used += 1
                    os.write(fd, (ans + "\n").encode())
        finally:
            _, status = os.waitpid(pid, 0)
            os.close(fd)
        return os.waitstatus_to_exitcode(status), out.decode(errors="replace")

    def put(self, path, text, owner=None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        if owner:
            for p in (os.path.dirname(path), path):
                shutil.chown(p, owner, owner)

    def owner(self, path):
        import pwd
        return pwd.getpwuid(os.stat(path).st_uid).pw_name

    # ── tests ────────────────────────────────────────────────────────────────
    def test_fresh_unattended_install(self):
        code, out = self.run_unattended()
        self.assertEqual(code, 0, out)
        self.assertIn("No previous installation found", out)
        self.assertTrue(os.path.exists(os.path.join(self.lib, "syswatch_trusted_networks.py")))
        self.assertEqual(self.owner(self.config), self.user)
        r = subprocess.run([self.bin, "--version"], capture_output=True, text=True)
        self.assertIn("syswatch 1.", r.stdout)
        with open(os.path.join(self.units, "syswatch-logger.service")) as f:
            unit = f.read()
        self.assertIn(f"User={self.user}", unit)
        self.assertIn(os.path.join(self.lib, "syswatch-logger.py"), unit)
        self.assertNotIn("CHANGE_ME", unit)

    def test_old_version_is_detected_and_replaced_completely(self):
        self.put(os.path.join(self.lib, "syswatch.py"), "# an old syswatch without VERSION\n")
        self.put(os.path.join(self.lib, "syswatch_stale_module.py"), "")
        self.put(self.bin, "#!/bin/bash\nexec python3 /old/syswatch.py\n")
        self.put(os.path.join(self.units, "syswatch-logger.service"), "[Service]\nUser=lukas\n")
        code, out = self.run_unattended()
        self.assertEqual(code, 0, out)
        self.assertIn("older than 1.1", out)
        self.assertFalse(os.path.exists(os.path.join(self.lib, "syswatch_stale_module.py")))
        with open(self.bin) as f:
            self.assertIn(self.lib, f.read())

    def test_existing_config_summary_and_keep(self):
        self.put(self.config, "[thresholds]\ncpu_temp = [75, 85]\n[network]\nscan = true\n", self.user)
        code, out = self.run_interactive(["--skip-config"], [])
        self.assertEqual(code, 0, out)
        self.assertNotIn("Existing config found", out)  # --skip-config: not reviewed
        code, out = self.run_interactive([], [""])
        self.assertEqual(code, 0, out)
        self.assertIn("thresholds.cpu_temp = [75, 85]   (default [70, 80])", out)
        self.assertIn("always-scan mode was removed", out)
        with open(self.config) as f:
            self.assertIn("[75, 85]", f.read())

    def test_replace_config_keeps_a_backup_and_asks_the_questions(self):
        self.put(self.config, "[thresholds]\ncpu_temp = [75, 85]\n", self.user)
        code, out = self.run_interactive([], ["n"])
        self.assertEqual(code, 0, out)
        self.assertIn("thresholds.cpu_pct — CPU usage", out)
        backups = [n for n in os.listdir(os.path.dirname(self.config)) if ".bak-" in n]
        self.assertEqual(len(backups), 1)
        with open(self.config) as f:
            self.assertIn("cpu_temp     = [70, 80]", f.read())
        self.assertEqual(self.owner(self.config), self.user)

    def test_each_data_file_keep_or_delete(self):
        self.put(os.path.join(self.data, "metrics.csv"), "2026-01-01T00:00:00,1,2,,3\n", self.user)
        self.put(os.path.join(self.data, "temp_alerts.log"), "x WARNING y\n", self.user)
        code, out = self.run_interactive(["--skip-config"], ["", "n"])
        self.assertEqual(code, 0, out)
        self.assertIn("metrics history: 1 samples", out)
        self.assertTrue(os.path.exists(os.path.join(self.data, "metrics.csv")))
        self.assertFalse(os.path.exists(os.path.join(self.data, "temp_alerts.log")))

    def test_unattended_keeps_everything_and_fixes_ownership(self):
        self.put(self.config, "[ui]\nrefresh = 2\n", self.user)
        self.put(os.path.join(self.data, "metrics.csv"), "", self.user)
        self.put(os.path.join(self.data, "temp_alerts.log"), "root-owned\n")  # owned by root
        code, out = self.run_unattended()
        self.assertEqual(code, 0, out)
        for p in (self.config, os.path.join(self.data, "metrics.csv"),
                  os.path.join(self.data, "temp_alerts.log")):
            self.assertTrue(os.path.exists(p), p)
        self.assertEqual(self.owner(os.path.join(self.data, "temp_alerts.log")), self.user)

    def test_root_leftovers_are_offered_for_deletion(self):
        self.put(os.path.join(self.roothome, ".config", "syswatch", "config.toml"), "[ui]\nrefresh = 2\n")
        self.put(os.path.join(self.roothome, ".local", "share", "syswatch", "debug.log"), "x\n")
        code, out = self.run_interactive(["--skip-config"], ["n", "n"])
        self.assertEqual(code, 0, out)
        self.assertIn("root's home", out)
        self.assertFalse(os.path.exists(os.path.join(self.roothome, ".config", "syswatch")))
        self.assertFalse(os.path.exists(os.path.join(self.roothome, ".local", "share", "syswatch")))

    def test_stray_symlinked_launcher_removes_only_the_link(self):
        target = os.path.join(self.tmp, "checkout", "syswatch.py")
        self.put(target, "# syswatch source\n")
        link = os.path.join(self.home, ".local", "bin", "syswatch")
        os.makedirs(os.path.dirname(link))
        os.symlink(target, link)
        code, out = self.run_interactive(["--skip-config"], ["y"])
        self.assertEqual(code, 0, out)
        self.assertIn(f"Found another syswatch launcher: {link}", out)
        self.assertFalse(os.path.lexists(link))
        self.assertTrue(os.path.exists(target))

    def test_uninstall_asks_and_purge_deletes(self):
        self.assertEqual(self.run_unattended()[0], 0)
        self.put(os.path.join(self.data, "metrics.csv"), "", self.user)
        self.put(os.path.join(self.data, "debug.log"), "", self.user)
        code, out = self.run_interactive(["--uninstall"], ["", "", "n"])
        self.assertEqual(code, 0, out)
        self.assertFalse(os.path.exists(self.lib))
        self.assertFalse(os.path.exists(self.bin))
        self.assertTrue(os.path.exists(self.config))
        self.assertTrue(os.path.exists(os.path.join(self.data, "metrics.csv")))
        self.assertFalse(os.path.exists(os.path.join(self.data, "debug.log")))
        code, out = self.run_unattended("--uninstall")
        self.assertEqual(code, 0, out)
        self.assertTrue(os.path.exists(self.config))  # unattended keeps
        code, out = self.run_unattended("--uninstall", "--purge")
        self.assertEqual(code, 0, out)
        self.assertFalse(os.path.exists(os.path.dirname(self.config)))
        self.assertFalse(os.path.exists(self.data))

    def test_purge_without_uninstall_is_rejected(self):
        code, out = self.run_unattended("--purge")
        self.assertNotEqual(code, 0)
        self.assertIn("--purge only applies to --uninstall", out)


if __name__ == "__main__":
    unittest.main()
