"""
users.py: Admin account management: list, create, delete, change password.

Single-tier system (no roles), any authenticated session can manage any
account. Sensitive actions require the caller's own current password, the
delete/create guards are atomic SQL statements (no separate check-then-act
race), and changing or deleting an account revokes its live sessions (see
auth.revoke_sessions_for_user).
"""

import time
import sqlite3
import logging

import bcrypt
from fastapi import APIRouter, HTTPException, Request

import config
import db
import state
from auth import get_session_username, revoke_sessions_for_user
from models import CreateUserPayload, SetPasswordPayload, DeleteUserPayload

router = APIRouter()


def _reauth_locked_out(username: str) -> bool:
    now = time.time()
    attempts = [t for t in state.failed_reauth_attempts.get(username, []) if now - t <= state.LOGIN_WINDOW_SECS]
    state.failed_reauth_attempts[username] = attempts
    return len(attempts) >= state.LOGIN_MAX_ATTEMPTS


def _record_reauth_failure(username: str):
    state.failed_reauth_attempts.setdefault(username, []).append(time.time())


def _verify_admin_password(username: str, password: str):
    """Raise 401/403/429 unless `password` is the CURRENT password for
    `username` (the caller re-authenticating themselves, not the target
    of the action being performed). Throttled the same as login: an
    authenticated session must not be able to guess its own password
    unboundedly."""
    if _reauth_locked_out(username):
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in up to {state.LOGIN_LOCKOUT_SECS // 60} minutes."
        )

    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Could not verify your credentials.")
    try:
        ok = bcrypt.checkpw(password.encode("utf-8"), row[0].encode("utf-8"))
    except ValueError:
        ok = False
    if not ok:
        _record_reauth_failure(username)
        raise HTTPException(status_code=403, detail="Your current password is incorrect.")
    state.failed_reauth_attempts.pop(username, None)


@router.get("/api/users")
def list_users():
    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users ORDER BY username")
    usernames = [r[0] for r in cursor.fetchall()]
    conn.close()
    return {"users": usernames}


@router.post("/api/users")
def create_user(payload: CreateUserPayload, request: Request):
    caller = get_session_username(request)
    _verify_admin_password(caller, payload.admin_password)

    password_hash = bcrypt.hashpw(payload.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn = db.connect()
    cursor = conn.cursor()
    try:
        # username is the PRIMARY KEY, the IntegrityError on a duplicate
        # is the atomic guard, not a separate SELECT-then-INSERT.
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (payload.username, password_hash, "")
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail=f"User '{payload.username}' already exists.")
    conn.close()
    logging.warning(f"[+] Admin account created: {payload.username} (by {caller})")
    return {"status": "success"}


@router.delete("/api/users")
def delete_user(payload: DeleteUserPayload, request: Request):
    # Body, not query params, a password shouldn't end up in access logs.
    caller = get_session_username(request)
    _verify_admin_password(caller, payload.admin_password)
    username = payload.username

    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail=f"User '{username}' not found.")

    # Guard and delete are the same statement, SQLite serializes writes,
    # so a concurrent delete can't race the "> 1" count check.
    cursor.execute(
        "DELETE FROM users WHERE username = ? AND (SELECT COUNT(*) FROM users) > 1",
        (username,)
    )
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()

    if not deleted:
        raise HTTPException(status_code=400, detail="Cannot delete the last remaining administrator account.")

    revoke_sessions_for_user(username)
    logging.warning(f"[+] Admin account deleted: {username} (by {caller})")
    return {"status": "success"}


@router.post("/api/users/password")
def set_password(payload: SetPasswordPayload, request: Request):
    caller = get_session_username(request)
    _verify_admin_password(caller, payload.admin_password)

    conn = db.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (payload.username,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail=f"User '{payload.username}' not found.")

    password_hash = bcrypt.hashpw(payload.new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    cursor.execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
        (password_hash, "", payload.username)
    )
    conn.commit()
    conn.close()

    revoke_sessions_for_user(payload.username)
    logging.warning(f"[+] Password changed for admin account: {payload.username} (by {caller})")
    return {"status": "success"}
