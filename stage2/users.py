"""
users.py — Admin account management: list, create, delete, change password.

Single-tier system (no roles) -- any authenticated session can manage any
account. The only hard guard is refusing to delete the last remaining user,
since that would lock every admin out with no recovery path short of
re-running setup_admin.py directly on the box.
"""

import sqlite3
import logging

import bcrypt
from fastapi import APIRouter, HTTPException

import config
from models import CreateUserPayload, SetPasswordPayload

router = APIRouter()


@router.get("/api/users")
def list_users():
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users ORDER BY username")
    usernames = [r[0] for r in cursor.fetchall()]
    conn.close()
    return {"users": usernames}


@router.post("/api/users")
def create_user(payload: CreateUserPayload):
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (payload.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail=f"User '{payload.username}' already exists.")

    password_hash = bcrypt.hashpw(payload.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    cursor.execute(
        "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
        (payload.username, password_hash, "")
    )
    conn.commit()
    conn.close()
    logging.warning(f"[+] Admin account created: {payload.username}")
    return {"status": "success"}


@router.delete("/api/users")
def delete_user(username: str):
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    exists = cursor.fetchone() is not None

    if not exists:
        conn.close()
        raise HTTPException(status_code=404, detail=f"User '{username}' not found.")
    if total <= 1:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot delete the last remaining administrator account.")

    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    logging.warning(f"[+] Admin account deleted: {username}")
    return {"status": "success"}


@router.post("/api/users/password")
def set_password(payload: SetPasswordPayload):
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
    logging.warning(f"[+] Password changed for admin account: {payload.username}")
    return {"status": "success"}
