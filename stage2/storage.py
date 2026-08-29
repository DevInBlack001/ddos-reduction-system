"""
storage.py: Generic JSON file persistence helpers.

Deliberately dependency-free (no imports from other stage2 modules) so
every other module can use it without risking an import cycle: it just
takes a path and does file I/O, it doesn't know or care what's stored.
"""

import os
import json
import logging


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
