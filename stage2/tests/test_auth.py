"""Tests for auth.py: login, sessions, the request gate, and lockout."""

import sqlite3
import time
import unittest

import _support
from _support import FakeRequest, make_logs_db, run_middleware, temp_path, unlink

import bcrypt
from fastapi import HTTPException

import auth
import config
import state


PASSWORD = "correct horse"
# Minimum work factor. Production hashes use the library default; a test only
# needs a real bcrypt hash, and the default cost makes the suite crawl.
HASH = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()


def add_user(db_path, username, password_hash=HASH):
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, salt TEXT)")
    conn.execute("INSERT OR REPLACE INTO users VALUES (?, ?, ?)", (username, password_hash, ""))
    conn.commit()
    conn.close()


class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self._db = config.DB_PATH
        self._cert, self._key = config.TLS_CERT_PATH, config.TLS_KEY_PATH
        self.db_path = make_logs_db()
        config.DB_PATH = self.db_path
        # Force plain HTTP unless a test says otherwise.
        config.TLS_CERT_PATH = temp_path(".pem") + ".missing"
        config.TLS_KEY_PATH = temp_path(".pem") + ".missing"
        add_user(self.db_path, "admin")

        state.active_sessions.clear()
        state.failed_login_attempts.clear()

    def tearDown(self):
        config.DB_PATH = self._db
        config.TLS_CERT_PATH, config.TLS_KEY_PATH = self._cert, self._key
        state.active_sessions.clear()
        state.failed_login_attempts.clear()
        unlink(self.db_path)

    def login(self, username="admin", password=PASSWORD, host="203.0.113.2"):
        return auth.login(FakeRequest(host=host), username=username, password=password)

    def open_session(self, username="admin"):
        token = f"token-for-{username}"
        state.active_sessions[token] = {"username": username, "last_active": time.time()}
        return token


class LoginTests(AuthTestCase):
    def test_correct_credentials_create_a_session(self):
        self.login()
        self.assertEqual(len(state.active_sessions), 1)

    def test_correct_credentials_redirect_to_the_dashboard(self):
        self.assertEqual(self.login().headers["location"], "/static/index.html")

    def test_the_session_records_the_username(self):
        self.login()
        self.assertEqual(next(iter(state.active_sessions.values()))["username"], "admin")

    def test_the_cookie_is_httponly(self):
        self.assertIn("httponly", self.login().headers["set-cookie"].lower())

    def test_the_cookie_is_not_secure_without_a_certificate(self):
        # A secure cookie is never sent over plain HTTP, so setting it
        # unconditionally locks out a deployment with no certificate.
        self.assertNotIn("secure", self.login().headers["set-cookie"].lower())

    def test_the_cookie_is_secure_once_tls_is_configured(self):
        cert, key = temp_path(".pem"), temp_path(".pem")
        config.TLS_CERT_PATH, config.TLS_KEY_PATH = cert, key
        try:
            self.assertIn("secure", self.login().headers["set-cookie"].lower())
        finally:
            unlink(cert, key)

    def test_a_wrong_password_is_rejected(self):
        with self.assertRaises(HTTPException) as caught:
            self.login(password="wrong")
        self.assertEqual(caught.exception.status_code, 401)

    def test_an_unknown_user_is_rejected(self):
        with self.assertRaises(HTTPException) as caught:
            self.login(username="nobody")
        self.assertEqual(caught.exception.status_code, 401)

    def test_an_unknown_user_creates_no_session(self):
        with self.assertRaises(HTTPException):
            self.login(username="nobody")
        self.assertEqual(state.active_sessions, {})

    def test_a_non_bcrypt_stored_hash_is_rejected(self):
        # A row left over from the SHA-256 era must fail closed, not crash.
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE users SET password_hash = ? WHERE username = 'admin'", ("deadbeef",))
        conn.commit()
        conn.close()
        with self.assertRaises(HTTPException) as caught:
            self.login()
        self.assertEqual(caught.exception.status_code, 401)

    def test_each_login_gets_a_distinct_token(self):
        self.login()
        self.login()
        self.assertEqual(len(state.active_sessions), 2)


class LockoutTests(AuthTestCase):
    def fail_once(self, host="203.0.113.2"):
        with self.assertRaises(HTTPException):
            self.login(password="wrong", host=host)

    def test_failures_are_recorded_per_client(self):
        self.fail_once()
        self.assertEqual(len(state.failed_login_attempts["203.0.113.2"]), 1)

    def test_lockout_engages_after_the_attempt_limit(self):
        for _ in range(state.LOGIN_MAX_ATTEMPTS):
            self.fail_once()
        with self.assertRaises(HTTPException) as caught:
            self.login()
        self.assertEqual(caught.exception.status_code, 429)

    def test_lockout_blocks_even_the_correct_password(self):
        for _ in range(state.LOGIN_MAX_ATTEMPTS):
            self.fail_once()
        with self.assertRaises(HTTPException):
            self.login()
        self.assertEqual(state.active_sessions, {})

    def test_lockout_is_scoped_to_one_client(self):
        for _ in range(state.LOGIN_MAX_ATTEMPTS):
            self.fail_once(host="203.0.113.2")
        self.login(host="203.0.113.3")
        self.assertEqual(len(state.active_sessions), 1)

    def test_attempts_outside_the_window_are_forgotten(self):
        stale = time.time() - state.LOGIN_WINDOW_SECS - 1
        state.failed_login_attempts["203.0.113.2"] = [stale] * state.LOGIN_MAX_ATTEMPTS
        self.login()
        self.assertEqual(len(state.active_sessions), 1)

    def test_a_successful_login_clears_the_failure_count(self):
        self.fail_once()
        self.login()
        self.assertNotIn("203.0.113.2", state.failed_login_attempts)


class SessionHelperTests(AuthTestCase):
    def test_returns_the_username_behind_a_valid_cookie(self):
        token = self.open_session("alice")
        request = FakeRequest(cookies={"session_id": token})
        self.assertEqual(auth.get_session_username(request), "alice")

    def test_rejects_a_missing_cookie(self):
        with self.assertRaises(HTTPException) as caught:
            auth.get_session_username(FakeRequest())
        self.assertEqual(caught.exception.status_code, 401)

    def test_rejects_an_unknown_token(self):
        with self.assertRaises(HTTPException):
            auth.get_session_username(FakeRequest(cookies={"session_id": "made up"}))

    def test_revoking_drops_every_session_for_that_user(self):
        self.open_session("alice")
        state.active_sessions["second"] = {"username": "alice", "last_active": time.time()}
        auth.revoke_sessions_for_user("alice")
        self.assertEqual(state.active_sessions, {})

    def test_revoking_leaves_other_users_signed_in(self):
        self.open_session("alice")
        bob = self.open_session("bob")
        auth.revoke_sessions_for_user("alice")
        self.assertEqual(list(state.active_sessions), [bob])

    def test_revoking_an_unknown_user_is_a_no_op(self):
        token = self.open_session("alice")
        auth.revoke_sessions_for_user("nobody")
        self.assertEqual(list(state.active_sessions), [token])

    def test_logout_drops_the_session(self):
        token = self.open_session()
        auth.logout(FakeRequest(cookies={"session_id": token}))
        self.assertEqual(state.active_sessions, {})

    def test_logout_without_a_session_does_not_raise(self):
        auth.logout(FakeRequest())


class MiddlewareTests(AuthTestCase):
    def test_a_valid_session_reaches_the_route(self):
        token = self.open_session()
        request = FakeRequest("/api/state", cookies={"session_id": token})
        self.assertEqual(run_middleware(auth.auth_middleware, request), "passed through")

    def test_an_api_call_without_a_session_gets_401(self):
        response = run_middleware(auth.auth_middleware, FakeRequest("/api/state"))
        self.assertEqual(response.status_code, 401)

    def test_a_page_without_a_session_redirects_to_login(self):
        response = run_middleware(auth.auth_middleware, FakeRequest("/static/index.html"))
        self.assertEqual(response.headers["location"], "/static/login.html")

    def test_the_login_page_is_reachable_unauthenticated(self):
        request = FakeRequest("/static/login.html")
        self.assertEqual(run_middleware(auth.auth_middleware, request), "passed through")

    def test_the_login_endpoint_is_reachable_unauthenticated(self):
        request = FakeRequest("/api/login")
        self.assertEqual(run_middleware(auth.auth_middleware, request), "passed through")

    def test_the_stylesheet_is_reachable_unauthenticated(self):
        request = FakeRequest("/static/base.css")
        self.assertEqual(run_middleware(auth.auth_middleware, request), "passed through")

    def test_an_idle_session_expires(self):
        token = self.open_session()
        state.active_sessions[token]["last_active"] = time.time() - 601
        response = run_middleware(auth.auth_middleware, FakeRequest("/api/state", cookies={"session_id": token}))
        self.assertEqual(response.status_code, 401)

    def test_an_expired_session_is_discarded(self):
        token = self.open_session()
        state.active_sessions[token]["last_active"] = time.time() - 601
        run_middleware(auth.auth_middleware, FakeRequest("/api/state", cookies={"session_id": token}))
        self.assertNotIn(token, state.active_sessions)

    def test_activity_refreshes_the_idle_timer(self):
        token = self.open_session()
        state.active_sessions[token]["last_active"] = time.time() - 599
        run_middleware(auth.auth_middleware, FakeRequest("/api/state", cookies={"session_id": token}))
        self.assertGreater(state.active_sessions[token]["last_active"], time.time() - 5)

    def test_an_oversized_body_is_refused(self):
        request = FakeRequest("/api/report", headers={"content-length": str(auth.MAX_REQUEST_BODY_BYTES + 1)})
        self.assertEqual(run_middleware(auth.auth_middleware, request).status_code, 413)

    def test_the_size_check_runs_before_authentication(self):
        # Otherwise an unauthenticated caller could still make the server
        # buffer an arbitrarily large body.
        request = FakeRequest("/api/report", headers={"content-length": str(auth.MAX_REQUEST_BODY_BYTES + 1)})
        self.assertEqual(run_middleware(auth.auth_middleware, request).status_code, 413)

    def test_a_body_at_the_limit_is_allowed(self):
        token = self.open_session()
        request = FakeRequest(
            "/api/report",
            cookies={"session_id": token},
            headers={"content-length": str(auth.MAX_REQUEST_BODY_BYTES)},
        )
        self.assertEqual(run_middleware(auth.auth_middleware, request), "passed through")

    def test_a_junk_content_length_is_ignored(self):
        token = self.open_session()
        request = FakeRequest("/api/state", cookies={"session_id": token}, headers={"content-length": "abc"})
        self.assertEqual(run_middleware(auth.auth_middleware, request), "passed through")

    def test_the_hyphenated_page_name_is_normalised(self):
        response = run_middleware(auth.auth_middleware, FakeRequest("/active-ips.html"))
        self.assertEqual(response.headers["location"], "/static/active_ips.html")

    def test_a_root_level_page_is_moved_under_static(self):
        response = run_middleware(auth.auth_middleware, FakeRequest("/logs.html"))
        self.assertEqual(response.headers["location"], "/static/logs.html")

    def test_an_unprotected_asset_path_is_not_gated(self):
        request = FakeRequest("/static/theme.js")
        self.assertEqual(run_middleware(auth.auth_middleware, request), "passed through")


if __name__ == "__main__":
    unittest.main()
