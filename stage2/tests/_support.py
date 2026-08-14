"""
Shared helpers for the Stage 2 test suite.

Stage 2 modules read their paths from module-level attributes on `config`
and keep runtime state on `state`, so tests have to redirect both. Every
helper here is undone in tearDown so tests stay order independent.

Addresses throughout the suite come from the ranges reserved for
documentation, so nothing here names a real host:

    192.0.2.x       protected hosts
    198.51.100.x    traffic sources
    203.0.113.x     dashboard clients
    2001:db8::/32   IPv6

Interfaces are eth0, eth1, and br0 for the same reason.
"""

import os
import sys
import sqlite3
import tempfile

# Make the stage2 package importable when tests are run from anywhere.
STAGE2_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if STAGE2_DIR not in sys.path:
    sys.path.insert(0, STAGE2_DIR)


def temp_path(suffix=".json"):
    """A path in a fresh temp file that the caller owns and must clean up."""
    handle = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    handle.close()
    return handle.name


def make_logs_db():
    """A throwaway SQLite file built from the real schema.

    This used to carry its own copy of the CREATE TABLE statements, which is
    how a constraint mismatch between setup_admin.py and stage2.py reached
    production without a test failing. Tests now get whatever the running
    system would get.
    """
    import schema

    path = temp_path(".db")
    conn = sqlite3.connect(path)
    schema.apply(conn)
    conn.close()
    return path


def unlink(*paths):
    for p in paths:
        # WAL leaves a -wal and a -shm file beside the database.
        for target in (p, f"{p}-wal", f"{p}-shm") if p else ():
            try:
                if os.path.exists(target):
                    os.unlink(target)
            except OSError:
                pass


def reset_db_module():
    """Drop db.py's cached connection and purge timer.

    db.py holds one connection and remembers when it last trimmed
    metrics_history. Both outlive a single test, so every test that
    redirects config.DB_PATH has to clear them.
    """
    import db

    db.close()
    db._last_purge = None


class FakeUrl:
    def __init__(self, path):
        self.path = path


class FakeClient:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    """Enough of a Starlette Request for the auth routes and middleware.

    httpx is not installed, so fastapi.testclient is unavailable. The route
    handlers are plain functions, so they are called directly with this
    instead.
    """

    def __init__(self, path="/static/index.html", cookies=None, headers=None, host="203.0.113.2"):
        self.url = FakeUrl(path)
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.client = FakeClient(host) if host else None


class _PassedThroughResponse(str):
    """A pass-through sentinel that also tolerates response.set_cookie().

    A string stand-in for the downstream response lets a test tell "the
    request was allowed through" from "the middleware answered it itself"
    via a plain equality check. The middleware refreshes the session cookie
    on every valid request, which calls set_cookie() on whatever call_next
    returned, so the sentinel needs to accept that call too.
    """

    def set_cookie(self, **kwargs):
        pass


def run_middleware(middleware, request, response=None):
    """Drive the async auth middleware and return whatever came back."""
    import asyncio

    if response is None:
        response = _PassedThroughResponse("passed through")

    async def call_next(_request):
        return response

    return asyncio.run(middleware(request, call_next))


class FakeCompleted:
    """Stand-in for subprocess.CompletedProcess."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class RecordingRun:
    """Replacement for subprocess.run that records argv instead of executing.

    Enforcement shells out to ipset and iptables. Running those for real in
    a test would edit the host firewall, so every enforcement test installs
    this and asserts on what would have been executed.
    """

    def __init__(self, returncode=0, stdout=""):
        self.calls = []
        self.returncode = returncode
        self.stdout = stdout

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        return FakeCompleted(self.returncode, self.stdout)

    def argv_containing(self, needle):
        return [c for c in self.calls if needle in " ".join(c)]

    def ran(self, needle):
        return any(needle in " ".join(c) for c in self.calls)
