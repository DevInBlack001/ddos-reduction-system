"""
storage.py: Generic JSON file persistence helpers.

Deliberately dependency-free (no imports from other stage2 modules) so
every other module can use it without risking an import cycle: it just
takes a path and does file I/O, it doesn't know or care what's stored.
"""

import os
import json
import logging
import stat


def _atomic_write(path, write_fn):
    """Write via a temp file in the same directory, chmod, then rename over
    the target. The rename is what makes this atomic: a reader never sees a
    partially written file, and a crash mid-write leaves the previous
    complete file in place rather than a truncated one. The temp file also
    closes the create-time TOCTOU load_json_file used to have between
    checking a path was missing and opening it: os.open with O_CREAT|O_EXCL
    fails outright if something already exists at the temp name instead of
    silently following it."""
    tmp = f"{path}.tmp{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            write_fn(f)
        os.replace(tmp, path)
    finally:
        # Only present if the write above raised before the rename.
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_json_file(path, default):
    # O_NOFOLLOW: refuse to read through a symlink placed at this path by
    # another local account, consistent with these files living in a
    # directory only this service is meant to write to.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        _atomic_write(path, lambda f: json.dump(default, f))
        return default
    except OSError:
        return default
    try:
        with os.fdopen(fd, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json_file(path, data):
    try:
        _atomic_write(path, lambda f: json.dump(data, f, indent=2))
    except Exception as e:
        logging.error(f"[-] Failed to save configuration to {path}: {e}")


def _check_model_owner_and_mode(st, what):
    """Refuse a model file or its directory that another account could have
    written. Stage 2 runs as root in a production install, so a root run
    service accepts only root owned paths with no group or other write bit.
    Run by hand as an operator (a development checkout), the operator's own
    files are accepted, and only a world writable one is refused, since a
    default umask of 002 gives an operator's own files a group write bit."""
    euid = os.geteuid()
    if euid == 0:
        allowed, forbidden = (0,), stat.S_IWGRP | stat.S_IWOTH
    else:
        allowed, forbidden = (0, euid), stat.S_IWOTH
    if st.st_uid not in allowed:
        raise PermissionError(f"{what} is owned by uid {st.st_uid}, which is not trusted to supply a model")
    if st.st_mode & forbidden:
        raise PermissionError(f"{what} is writable by another account (mode {stat.S_IMODE(st.st_mode):o})")


def load_trusted_model(path):
    """joblib.load for a model file, after checking who could have written it.

    joblib unpickles, and unpickling runs code, so a model file that anyone
    else could replace is code execution in this service. The file is opened
    without following a symlink, and both it and its directory must pass the
    ownership and mode check above. The check runs on the open descriptor, so
    the file cannot be swapped between the check and the load.
    """
    import joblib

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"{path} is not a regular file")
        _check_model_owner_and_mode(st, path)
        directory = os.path.dirname(os.path.abspath(path))
        _check_model_owner_and_mode(os.stat(directory), directory)
        return joblib.load(handle)
