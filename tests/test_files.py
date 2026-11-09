"""syswatch_files: no write ever follows a planted symlink, and under sudo
every write into the invoking user's home is done as that user."""

import errno
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import helpers  # noqa: F401  (puts the repo root on sys.path)
import syswatch_files as files


class LocalWriteTests(unittest.TestCase):
    """The in-process path, also when the suite itself runs under sudo."""

    def setUp(self):
        p = mock.patch.object(files, "_invoking_cache", (None,))
        p.start()
        self.addCleanup(p.stop)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.victim = os.path.join(self.tmp, "victim")
        with open(self.victim, "w") as f:
            f.write("precious\n")

    def victim_text(self):
        with open(self.victim) as f:
            return f.read()

    def test_write_atomic_replaces_a_symlink_instead_of_writing_through_it(self):
        path = os.path.join(self.tmp, "sub", "config.toml")
        os.makedirs(os.path.dirname(path))
        os.symlink(self.victim, path)
        # The old fixed temp name, pre-planted: must not be used either.
        os.symlink(self.victim, path + ".tmp")
        files.write_atomic(path, b"new\n")
        self.assertFalse(os.path.islink(path))
        with open(path) as f:
            self.assertEqual(f.read(), "new\n")
        self.assertEqual(self.victim_text(), "precious\n")

    def test_write_atomic_keeps_the_existing_mode(self):
        path = os.path.join(self.tmp, "known.json")
        with open(path, "w") as f:
            f.write("{}")
        os.chmod(path, 0o600)
        files.write_atomic(path, b"[]")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_exclusive_refuses_existing_files_and_dangling_symlinks(self):
        path = os.path.join(self.tmp, "config.toml")
        files.write_atomic(path, b"one", exclusive=True)
        with self.assertRaises(FileExistsError):
            files.write_atomic(path, b"two", exclusive=True)
        dangling = os.path.join(self.tmp, "other.toml")
        os.symlink(os.path.join(self.tmp, "would-be-created"), dangling)
        with self.assertRaises(FileExistsError):
            files.write_atomic(dangling, b"x", exclusive=True)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "would-be-created")))

    def test_append_refuses_symlinks_and_fifos(self):
        link = os.path.join(self.tmp, "debug.log")
        os.symlink(self.victim, link)
        with self.assertRaises(OSError) as cm:
            files.append(link, b"x\n")
        self.assertEqual(cm.exception.errno, errno.ELOOP)
        fifo = os.path.join(self.tmp, "temp_alerts.log")
        os.mkfifo(fifo)
        with self.assertRaises(OSError):
            files.append(fifo, b"x\n")  # must fail, not block
        self.assertEqual(self.victim_text(), "precious\n")

    def test_append_creates_directory_and_file(self):
        path = os.path.join(self.tmp, "a", "b", "metrics.csv")
        files.append(path, b"1\n")
        files.append(path, b"2\n")
        with open(path) as f:
            self.assertEqual(f.read(), "1\n2\n")

    def test_open_lock_refuses_a_symlink(self):
        link = os.path.join(self.tmp, "alerts.lock")
        os.symlink(self.victim, link)
        with self.assertRaises(OSError):
            files.open_lock(link)
        fd = files.open_lock(os.path.join(self.tmp, "real.lock"))
        os.close(fd)

    def test_writes_as_the_user_need_nothing_readable_but_the_target(self):
        # The child gets its program inline; it never imports from disk.
        self.assertIn("_child_main(sys.argv[1], sys.argv[2])", files._child_program())
        self.assertIn("def _write_local", files._child_program())

    def test_not_root_means_no_invoking_user(self):
        with mock.patch.object(files, "_invoking_cache", ()), \
             mock.patch.object(files.os, "geteuid", return_value=1000), \
             mock.patch.dict(os.environ, {"SUDO_USER": "someone"}):
            self.assertIsNone(files.invoking_user())

    def test_signature_changes_when_the_file_does(self):
        path = os.path.join(self.tmp, "trusted.json")
        self.assertIsNone(files.signature(path))
        files.write_atomic(path, b"{}")
        first = files.signature(path)
        files.write_atomic(path, b'{"a": 1}')
        self.assertNotEqual(files.signature(path), first)


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("useradd"),
                     "needs root (creates a throwaway user)")
class SudoWriteTests(unittest.TestCase):
    """What `sudo syswatch` does in the invoking user's home, attacked the
    way the user could attack it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="swfiles-")
        os.chmod(self.tmp, 0o755)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.user = f"swfiles{os.getpid() % 100000}"
        self.home = os.path.join(self.tmp, "home")
        subprocess.run(["useradd", "-M", "-d", self.home, "-s", "/bin/sh", self.user], check=True)
        self.addCleanup(subprocess.run, ["userdel", self.user], capture_output=True)
        os.makedirs(self.home)
        shutil.chown(self.home, self.user, self.user)
        self.pw = pwd.getpwnam(self.user)
        self.roothome = os.path.join(self.tmp, "roothome")
        os.makedirs(self.roothome)
        # A root-owned file standing in for /etc/shadow.
        self.victim = os.path.join(self.tmp, "victim")
        with open(self.victim, "w") as f:
            f.write("precious\n")
        os.chmod(self.victim, 0o600)

    def as_user(self, *cmd):
        subprocess.run(["setpriv", f"--reuid={self.pw.pw_uid}", f"--regid={self.pw.pw_gid}",
                        "--init-groups", "--", *cmd], check=True)

    def private_checkout(self):
        """A copy of the code in a directory the user can't read — like a
        checkout under /root (or CI's runner home), run with sudo."""
        d = os.path.join(self.tmp, "private")
        if not os.path.isdir(d):
            os.makedirs(d, mode=0o700)
            for name in os.listdir(helpers.ROOT):
                if name.startswith("syswatch") and name.endswith(".py"):
                    shutil.copy(os.path.join(helpers.ROOT, name), d)
        return d

    def run_sudo_syswatch(self, *args):
        env = dict(os.environ, SUDO_USER=self.user, HOME=self.roothome)
        env.pop("XDG_CONFIG_HOME", None)
        return subprocess.run([sys.executable, os.path.join(self.private_checkout(), "syswatch.py"), *args],
                              env=env, capture_output=True, text=True, timeout=60)

    def run_sudo_python(self, code, *args):
        env = dict(os.environ, SUDO_USER=self.user, HOME=self.roothome)
        return subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, sys.argv[1]);" + code,
                               self.private_checkout(), *args],
                              env=env, capture_output=True, text=True, timeout=60)

    def owner(self, path):
        return pwd.getpwuid(os.lstat(path).st_uid).pw_name

    def victim_unchanged(self):
        st = os.stat(self.victim)
        with open(self.victim) as f:
            self.assertEqual(f.read(), "precious\n")
        self.assertEqual(st.st_uid, 0)

    def test_write_default_config_is_written_as_the_user(self):
        r = self.run_sudo_syswatch("--write-default-config")
        self.assertEqual(r.returncode, 0, r.stderr)
        cfg = os.path.join(self.home, ".config", "syswatch", "config.toml")
        for p in (cfg, os.path.dirname(cfg), os.path.dirname(os.path.dirname(cfg))):
            self.assertEqual(self.owner(p), self.user, p)

    def test_planted_temp_symlink_is_not_followed(self):
        # The original attack: config.toml.tmp -> victim, then
        # `sudo syswatch --write-default-config` overwrote the victim.
        d = os.path.join(self.home, ".config", "syswatch")
        self.as_user("mkdir", "-p", d)
        self.as_user("ln", "-s", self.victim, os.path.join(d, "config.toml.tmp"))
        r = self.run_sudo_syswatch("--write-default-config")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.victim_unchanged()

    def test_symlinked_directory_cannot_redirect_a_write(self):
        # ~/.local/share/syswatch -> a root-only directory: the write is the
        # user's, so it fails instead of landing there as root.
        target = os.path.join(self.tmp, "rootonly")
        os.makedirs(target, mode=0o700)
        self.as_user("mkdir", "-p", os.path.join(self.home, ".local", "share"))
        self.as_user("ln", "-s", target, os.path.join(self.home, ".local", "share", "syswatch"))
        r = self.run_sudo_python(
            "import syswatch_sensors as s; s.set_debug(True); s.note_error('x');"
            "print(s.append_alert('temp_alerts.log', 'WARNING'))")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "False")
        self.assertEqual(os.listdir(target), [])

    def test_config_outside_the_users_reach_is_refused(self):
        dest = os.path.join(self.tmp, "etc-like", "syswatch.toml")
        os.makedirs(os.path.dirname(dest), mode=0o755)
        r = self.run_sudo_syswatch("--write-default-config", "--config", dest)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ermission denied", r.stderr)
        self.assertFalse(os.path.exists(dest))
        os.symlink(self.victim, dest)
        r = self.run_sudo_syswatch("--write-default-config", "--config", dest, "--force")
        self.assertNotEqual(r.returncode, 0)
        self.victim_unchanged()

    def test_state_files_and_lock_are_created_as_the_user(self):
        r = self.run_sudo_python(
            "import syswatch_sensors as s, syswatch_known_devices as kd, os;"
            "home = os.path.expanduser('~' + sys.argv[2]);"
            "d = os.path.join(home, '.local', 'share', 'syswatch');"
            "print(s.append_alert('temp_alerts.log', 'WARNING'));"
            "print(kd.save({'gw:aa': {}}, os.path.join(d, 'known_devices.json')))",
            self.user)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), ["True", "True"])
        d = os.path.join(self.home, ".local", "share", "syswatch")
        for name in ("", "temp_alerts.log", "alerts.lock", "known_devices.json"):
            self.assertEqual(self.owner(os.path.join(d, name)), self.user, name)

    def test_give_back_skips_symlinks_and_hard_links(self):
        d = os.path.join(self.home, ".local", "share", "syswatch")
        os.makedirs(d)  # .local and .local/share root-owned, as an old sudo run left them
        leftover = os.path.join(d, "temp_alerts.log")
        with open(leftover, "w") as f:
            f.write("x\n")
        os.symlink(self.victim, os.path.join(d, "evil-link"))
        try:
            os.link(self.victim, os.path.join(d, "evil-hardlink"))
        except OSError:
            pass  # different filesystem: nothing to test for hard links
        changed = files.give_back(self.home, ".local/share/syswatch", self.pw.pw_uid, self.pw.pw_gid)
        self.assertEqual(self.owner(leftover), self.user)
        self.assertEqual(self.owner(d), self.user)
        self.assertEqual(self.owner(os.path.join(self.home, ".local")), self.user)
        self.assertGreaterEqual(changed, 3)
        self.victim_unchanged()

    def test_give_back_does_not_follow_a_symlinked_directory(self):
        program = os.path.join(self.tmp, "lib", "syswatch")
        os.makedirs(program)
        with open(os.path.join(program, "syswatch.py"), "w") as f:
            f.write("# code root runs\n")
        self.as_user("ln", "-s", os.path.join(self.tmp, "lib"), os.path.join(self.home, ".config"))
        files.give_back(self.home, ".config/syswatch", self.pw.pw_uid, self.pw.pw_gid)
        self.assertEqual(self.owner(program), "root")
        self.assertEqual(self.owner(os.path.join(program, "syswatch.py")), "root")


if __name__ == "__main__":
    unittest.main()
