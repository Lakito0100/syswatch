#!/usr/bin/env python3
"""syswatch_files — every write syswatch makes to its own files.

Under `sudo syswatch`, syswatch runs as root but keeps its config and state
in the invoking user's home (see syswatch_sensors.user_data_path). Root must
not write there itself: the user controls every directory in that tree and
can swap any entry for a symlink at any moment, so a planted
`config.toml.tmp -> /etc/shadow` turned root's write into an overwrite of an
arbitrary file, and chowning the result "back" by path could be raced into
handing the user ownership of one.

So under sudo, a write into the user's files is done by a short-lived child
process running *as that user*: it can do exactly what the user could do
themselves, nothing more, and what it creates is theirs without any chown.
Everything else (no sudo, or root's own home) is written in-process, still
without ever following a symlink at the file being written: temporary files
come from mkstemp() (O_EXCL), and appends and exclusive creates use
O_NOFOLLOW.

Standard library only: the logger, the installer's helpers and the child
process all import this.
"""

import errno
import os
import pwd
import stat
import subprocess
import sys
import tempfile

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC  = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_NOCTTY   = getattr(os, "O_NOCTTY", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)

_CHILD_TIMEOUT = 30  # seconds; a write is a few KB at most


# ── who writes ───────────────────────────────────────────────────────────────

_invoking_cache = ()  # () = not yet resolved; (value,) once resolved


def invoking_user():
    """passwd entry of the human behind `sudo`, or None when that doesn't
    apply (not root, no SUDO_USER, SUDO_USER is root, or unknown user).
    Cached: it can't change during the process."""
    global _invoking_cache
    if _invoking_cache:
        return _invoking_cache[0]
    pw = None
    try:
        if os.geteuid() == 0:
            name = os.environ.get("SUDO_USER")
            if name and name != "root":
                pw = pwd.getpwnam(name)
    except Exception:
        pw = None
    _invoking_cache = (pw,)
    return pw


def _inside(path, directory):
    path = os.path.abspath(path)
    directory = os.path.abspath(directory).rstrip(os.sep) or os.sep
    return path == directory or path.startswith(directory + os.sep)


def _write_as(path):
    """The passwd entry to perform a write to `path` as, or None to write
    in-process. Under sudo that's the invoking user for everything except
    root's own home: syswatch never needs root to write a file on the user's
    behalf, so a path outside their reach (e.g. `--config /etc/...`) simply
    fails with "permission denied", as it would for them."""
    pw = invoking_user()
    if pw is None:
        return None
    try:
        root_home = pwd.getpwuid(os.geteuid()).pw_dir
    except KeyError:
        root_home = ""
    # Decided on the path as given (lexically), never on where symlinks in
    # it lead: a link the user planted can't move a write into root's home.
    if root_home not in ("", os.sep) and _inside(path, root_home):
        return None
    return pw


# ── public API ───────────────────────────────────────────────────────────────

def write_atomic(path, data, exclusive=False):
    """Replace `path` with the bytes `data`, atomically (temporary file +
    rename). With exclusive=True, create it instead and raise
    FileExistsError if anything — even a dangling symlink — is there."""
    pw = _write_as(path)
    if pw is not None:
        _run_as(pw, "create" if exclusive else "replace", path, data)
    else:
        _write_local(path, data, exclusive)


def append(path, data):
    """Append the bytes `data` to `path`, creating it (and its directory)
    if needed. Refuses a symlink or anything but a regular file."""
    pw = _write_as(path)
    if pw is not None:
        _run_as(pw, "append", path, data)
    else:
        _append_local(path, data)


def ensure_dir(path):
    """os.makedirs(path, exist_ok=True), done as whoever writes there."""
    pw = _write_as(path)
    if pw is not None:
        _run_as(pw, "mkdir", path, b"")
    else:
        os.makedirs(path, exist_ok=True)


def open_lock(path):
    """A file descriptor on `path` for flock(), creating the file if needed.
    Under sudo the file is created by the invoking user and root only opens
    it — read-only, never through a symlink, and only if it's a regular
    file. The caller closes the descriptor."""
    pw = _write_as(path)
    if pw is not None:
        _run_as(pw, "append", path, b"")  # creates it, as the user
        flags = os.O_RDONLY
    else:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        flags = os.O_RDONLY | os.O_CREAT
    fd = os.open(path, flags | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, 0o644)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
    except BaseException:
        os.close(fd)
        raise
    return fd


def signature(path):
    """(mtime_ns, size, inode) of `path`, or None if it can't be stat'ed —
    cheap change detection for files another process may rewrite."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


# ── in-process writes ────────────────────────────────────────────────────────

def _umask():
    # Read rather than set-and-restore: os.umask() is process-wide, and
    # briefly zeroing it would affect files other threads create meanwhile.
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("Umask:"):
                    return int(line.split()[1], 8)
    except Exception:
        pass
    return 0o022


def _write_local(path, data, exclusive):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
                     0o666)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return
    try:
        st = os.lstat(path)
        mode = stat.S_IMODE(st.st_mode) if stat.S_ISREG(st.st_mode) else None
    except FileNotFoundError:
        mode = None
    if mode is None:
        mode = 0o666 & ~_umask()
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            os.fchmod(f.fileno(), mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _append_local(path, data):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    # O_NONBLOCK: opening a FIFO planted under this name must fail, not hang.
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _O_NOFOLLOW
                 | _O_NONBLOCK | _O_CLOEXEC, 0o666)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    finally:
        os.close(fd)


# ── writes as the invoking user ──────────────────────────────────────────────

_child_source = None


def _child_program():
    """The child's program: this module's own source plus a call to
    _child_main(), passed with `-c`. The child must not have to read
    anything as the user but the file it writes — syswatch may be running
    from a checkout they can't read (e.g. under /root), and importing this
    module from there failed every write."""
    global _child_source
    if _child_source is None:
        with open(os.path.splitext(os.path.abspath(__file__))[0] + ".py", encoding="utf-8") as f:
            _child_source = f.read()
    return _child_source + "\n_child_main(sys.argv[1], sys.argv[2])\n"


def _run_as(pw, op, path, data):
    """Perform `op` on `path` in a child process running as `pw`. Raises
    the child's OSError (same errno, so FileExistsError, PermissionError,
    ... come out as themselves)."""
    try:
        groups = os.getgrouplist(pw.pw_name, pw.pw_gid)
    except OSError:
        groups = [pw.pw_gid]
    r = subprocess.run(
        # -I: no PYTHON* variables, no user site-packages, no cwd on sys.path.
        [sys.executable, "-I", "-c", _child_program(), op, os.path.abspath(path)],
        input=data, capture_output=True, timeout=_CHILD_TIMEOUT, cwd="/",
        user=pw.pw_uid, group=pw.pw_gid, extra_groups=groups, umask=0o022,
        env={"PATH": "/usr/bin:/bin", "HOME": pw.pw_dir or "/", "LANG": "C.UTF-8"},
    )
    if r.returncode == 0:
        return
    err = r.stderr.decode("utf-8", "replace").strip().splitlines()
    last = err[-1] if err else f"exit status {r.returncode}"
    code, _, msg = last.partition(" ")
    if code.isdigit():
        raise OSError(int(code), msg, path)
    raise OSError(errno.EIO, last, path)


def _child_main(op, path):
    """Entry point of the child process started by _run_as()."""
    try:
        data = sys.stdin.buffer.read()
        if op == "replace":
            _write_local(path, data, exclusive=False)
        elif op == "create":
            _write_local(path, data, exclusive=True)
        elif op == "append":
            _append_local(path, data)
        elif op == "mkdir":
            os.makedirs(path, exist_ok=True)
        else:
            raise OSError(errno.EINVAL, f"unknown operation {op!r}")
    except OSError as e:
        sys.stderr.write(f"{e.errno or errno.EIO} {e.strerror or e}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"{errno.EIO} {e}\n")
        sys.exit(1)


# ── installer: hand root-owned leftovers back ────────────────────────────────

_GIVE_BACK_MAX_DEPTH = 8


def give_back(home, rel, uid, gid):
    """Installer helper, run as root: chown every root-owned file and
    directory under `home`/`rel` (e.g. ".config/syswatch") to uid:gid —
    leftovers from older versions run with sudo. Directories on the way
    (~/.config, ~/.local/share) are given back too if root owns them.

    Never follows a symlink: each directory is opened with O_NOFOLLOW
    relative to the one before, and each file is chowned through its own
    open descriptor after checking what it is, so swapping an entry for a
    symlink mid-walk can't redirect a chown outside the tree. Hard-linked
    files (which could be another name for a system file) are skipped.
    Returns how many entries were changed."""
    count = 0
    try:
        fd = os.open(home, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    except OSError:
        return 0
    try:
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if ".." in parts:
            raise ValueError("rel must stay inside home")
        for i, part in enumerate(parts):
            try:
                nfd = os.open(part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                              dir_fd=fd)
            except OSError:
                return count  # missing, a symlink, or not a directory
            os.close(fd)
            fd = nfd
            if i < len(parts) - 1 and os.fstat(fd).st_uid == 0 and uid != 0:
                os.fchown(fd, uid, gid)
                count += 1
        count += _give_back_tree(fd, uid, gid, 0)
    finally:
        os.close(fd)
    return count


def _give_back_tree(dfd, uid, gid, depth):
    count = 0
    if os.fstat(dfd).st_uid == 0 and uid != 0:
        os.fchown(dfd, uid, gid)
        count += 1
    if depth >= _GIVE_BACK_MAX_DEPTH:
        return count
    for name in os.listdir(dfd):
        try:
            fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_NOCTTY | _O_CLOEXEC,
                         dir_fd=dfd)
        except OSError:
            continue  # a symlink (ELOOP), a socket, already gone, ...
        try:
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                count += _give_back_tree(fd, uid, gid, depth + 1)
            elif (stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                    and st.st_uid == 0 and uid != 0):
                os.fchown(fd, uid, gid)
                count += 1
        finally:
            os.close(fd)
    return count
