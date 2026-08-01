"""
auth.py — Session auth: login/logout routes, the request-gating middleware,
and login brute-force throttling.

`auth_middleware` is a plain async function, not registered via a decorator
here -- middleware can only be attached to the FastAPI `app` object itself,
not to an APIRouter, so stage2.py imports this function and registers it
with `app.middleware("http")(auth.auth_middleware)`.
"""

import time
import sqlite3
import secrets
import logging

import bcrypt
from fastapi import APIRouter, HTTPException, Request, Form, status
from fastapi.responses import RedirectResponse, JSONResponse

import config
import state

router = APIRouter()

MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024  # 10 MB -- comfortably above the largest legitimate body (a PDF export's two base64 chart images)


def _login_locked_out(client_ip: str) -> bool:
    now = time.time()
    attempts = [t for t in state.failed_login_attempts.get(client_ip, []) if now - t <= state.LOGIN_WINDOW_SECS]
    state.failed_login_attempts[client_ip] = attempts
    return len(attempts) >= state.LOGIN_MAX_ATTEMPTS

def _record_login_failure(client_ip: str):
    state.failed_login_attempts.setdefault(client_ip, []).append(time.time())


async def auth_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body too large."})
        except ValueError:
            pass

    path = request.url.path
    # Automatically normalize active-ips.html (hyphen) to active_ips.html (underscore)
    if "active-ips.html" in path:
        new_path = path.replace("active-ips.html", "active_ips.html")
        if not new_path.startswith("/static/"):
            new_path = f"/static{new_path}"
        return RedirectResponse(url=new_path)

    # Automatically redirect root-level HTML file requests to /static/ path
    if path != "/" and path.endswith(".html") and not path.startswith("/static/"):
        return RedirectResponse(url=f"/static{path}")

    # Skip auth checks for login pages, API endpoints, css assets
    if path.startswith("/static/login.html") or path.startswith("/api/login") or path.startswith("/static/base.css"):
        return await call_next(request)

    # Protected paths: static HTMLs, API routes, root path
    if path.endswith(".html") or path == "/" or path.startswith("/api/"):
        session_id = request.cookies.get("session_id")
        is_valid = False
        if session_id in state.active_sessions:
            # Check 10 minutes timeout (600s)
            if time.time() - state.active_sessions[session_id] <= 600:
                state.active_sessions[session_id] = time.time()  # refresh
                is_valid = True
            else:
                del state.active_sessions[session_id]

        if not is_valid:
            if path.startswith("/api/"):
                return JSONResponse(status_code=401, content={"detail": "Session expired. Re-authenticate."})
            return RedirectResponse(url="/static/login.html")

    return await call_next(request)


@router.post("/api/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"
    try:
        if _login_locked_out(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Try again in up to {state.LOGIN_LOCKOUT_SECS // 60} minutes."
            )

        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            _record_login_failure(client_ip)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials.")

        stored_hash = row[0]
        try:
            password_ok = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except ValueError:
            # Hash isn't in bcrypt format -- almost always a pre-migration
            # SHA-256 row. Re-run setup_admin.py to reset the account.
            logging.error(f"[-] Stored hash for user '{username}' isn't bcrypt-formatted; rerun setup_admin.py.")
            password_ok = False

        if password_ok:
            session_token = secrets.token_hex(24)
            state.active_sessions[session_token] = time.time()
            state.failed_login_attempts.pop(client_ip, None)
            response = RedirectResponse(url="/static/index.html", status_code=status.HTTP_303_SEE_OTHER)
            response.set_cookie(
                key="session_id",
                value=session_token,
                max_age=600,
                httponly=True,
                samesite="lax"
            )
            return response
        else:
            _record_login_failure(client_ip)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Handshake credentials rejected.")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in state.active_sessions:
        del state.active_sessions[session_id]
    response = RedirectResponse(url="/static/login.html")
    response.delete_cookie("session_id")
    return response
