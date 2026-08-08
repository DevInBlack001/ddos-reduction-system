"""
storage.py: Generic JSON file persistence helpers.

Deliberately dependency-free (no imports from other stage2 modules) so
every other module can use it without risking an import cycle: it just
takes a path and does file I/O, it doesn't know or care what's stored.
"""

import os
import json
import logging


def load_json_file(path, default):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f)
        os.chmod(path, 0o600)
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json_file(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(path, 0o600)
    except Exception as e:
        logging.error(f"[-] Failed to save configuration to {path}: {e}")
