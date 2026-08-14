#!/usr/bin/env python3
"""Create the first administrator account."""

import os
import sys
import sqlite3
import secrets
import bcrypt

import schema
from models import _check_password_strength

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "stage2.db"))

def generate_random_password(length=16):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def hash_password(password):
    # bcrypt generates and embeds its own per-hash salt (unlike the old
    # single-round SHA-256 scheme, it also applies a deliberate work
    # factor, so a leaked stage2.db can't be brute-forced at GPU speed).
    # The 72-byte input cap is bcrypt's own limit, not a weakening of this
    # implementation.
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def init_db(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    schema.apply(conn)
    conn.close()
    # Both stage1/stage2 systemd units run as root; without this the DB
    # inherits the process umask (often world-readable) and any local
    # account can read the admin password hash/salt straight off disk.
    os.chmod(db_path, 0o600)

def main():
    print("========================================================================")
    print("           FLOD SYSTEM - ADMINISTRATOR INITIALIZATION")
    print("========================================================================")

    init_db(DB_PATH)
    print(f"[+] Initialized SQLite database at: {DB_PATH}")

    # Check if users already exist to allow non-interactive upgrades
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        if count > 0:
            print("[+] Existing administrator account detected. Skipping interactive setup.")
            print("========================================================================")
            return
    except Exception as e:
        print(f"[-] Error checking for existing users: {e}")

    # Prompt for admin setup
    try:
        username = input("[?] Enter admin username [default: admin]: ").strip() or "admin"
        
        password = input("[?] Enter admin password (or press ENTER to auto-generate): ").strip()
        is_generated = False
        if not password:
            password = generate_random_password()
            is_generated = True
        else:
            while True:
                try:
                    _check_password_strength(password)
                    break
                except ValueError as e:
                    password = input(f"[!] {e} Try again (or press ENTER to auto-generate): ").strip()
                    if not password:
                        password = generate_random_password()
                        is_generated = True
                        break

        password_hash = hash_password(password)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, password_hash, ""))
        conn.commit()
        conn.close()

        print("[+] Administrator account configured successfully.")
        if is_generated:
            # Print password in bold yellow style
            print("\033[1;33m" + "========================================================================" + "\033[0m")
            print("\033[1;33m" + f"[!] GENERATED ADMIN USERNAME: {username}" + "\033[0m")
            print("\033[1;33m" + f"[!] GENERATED ADMIN PASSWORD: {password}" + "\033[0m")
            print("\033[1;33m" + "========================================================================" + "\033[0m")
            print("[!] WARNING: Please save this password securely. It will not be shown again.")
            print("========================================================================")
        else:
            print("[+] Password verified and encrypted.")
            print("========================================================================")

    except KeyboardInterrupt:
        print("\n[!] Setup cancelled.")
        sys.exit(1)

if __name__ == "__main__":
    main()
