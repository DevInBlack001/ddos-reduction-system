"""
users.py — Admin account management: list, create, delete, change password.

Single-tier system (no roles) -- any authenticated session can manage any
account. Two safety nets on top of that, both closing gaps found in review:

  - Sensitive actions (create, delete, change password) require the CALLER
    to re-enter their OWN current password. A session cookie alone (e.g.
    one that leaked through a brief XSS window, or was left signed in on a
    shared machine) used to be sufficient to durably take over every
    account; now it isn't.
  - The "can't delete the last admin" guard and the duplicate-username
    check are each enforced as a single atomic SQL statement rather than a
    separate check-then-act pair. Two concurrent requests could previously
    both pass a check before either committed -- e.g. two deletes for two
    different users, with only 2 accounts total, both reading count=2
    before either delete landed, leaving zero accounts behind.
  - Changing a password or deleting an account now also revokes every
    live session for that username (see auth.revoke_sessions_for_user),
    so a hijacked session doesn't just keep working until its own idle
    timeout after the credential it was minted under has changed.
"""

import sqlite3
import logging

import bcrypt
from fastapi import APIRouter, HTTPException, Request

import config
from auth import get_session_username, revoke_sessions_for_user
from models import CreateUserPayload, SetPasswordPayload, DeleteUserPayload

router = APIRouter()


def _verify_admin_password(username: str, password: str):
    """Raise 401/403 unless `password` is the CURRENT password for
    `username` (the caller re-authenticating themselves, not the target
    of the action being performed)."""
    conn = sqlite3.connect(config.DB_PATH)
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
        raise HTTPException(status_code=403, detail="Your current password is incorrect.")


@router.get("/api/users")
def list_users():
    conn = sqlite3.connect(config.DB_PATH)
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
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    try:
        # username is the PRIMARY KEY -- a duplicate INSERT raises
        # IntegrityError, which is the actual atomic guard against the
        # race a separate SELECT-then-INSERT would be vulnerable to.
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
    # Body, not query params -- a query string is the wrong place for a
    # password (server access logs, browser history, proxy logs all tend
    # to capture URLs but not bodies).
    caller = get_session_username(request)
    _verify_admin_password(caller, payload.admin_password)
    username = payload.username

    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail=f"User '{username}' not found.")

    # The guard and the delete are the SAME statement -- SQLite serializes
    # writes, so a second concurrent DELETE (for a different username)
    # can't evaluate its own "> 1" subquery until the first one has fully
    # committed, and will correctly see the post-delete count.
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

    conn = sqlite3.connect(config.DB_PATH)
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
