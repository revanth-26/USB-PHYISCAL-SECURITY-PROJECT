from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import DATA_DIR, ensure_dirs


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


DB_PATH = DATA_DIR / "app.db"


def connect() -> sqlite3.Connection:
    ensure_dirs()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON;")
    con.execute("PRAGMA journal_mode = WAL;")
    return con


def init_db() -> None:
    with connect() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              email TEXT,
              role TEXT NOT NULL CHECK(role IN ('admin','user')),
              password_hash BLOB NOT NULL,
              created_at TEXT NOT NULL,
              must_change_password INTEGER NOT NULL DEFAULT 0,
              is_active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS settings (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL,
              success INTEGER NOT NULL,
              reason TEXT,
              at TEXT NOT NULL,
              intruder_image_path TEXT
            );

            CREATE TABLE IF NOT EXISTS usb_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_type TEXT NOT NULL,
              device_name TEXT,
              pnp_device_id TEXT,
              vid TEXT,
              pid TEXT,
              serial TEXT,
              allowed INTEGER,
              action_taken TEXT,
              at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS usb_whitelist (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              label TEXT,
              pnp_device_id TEXT UNIQUE,
              vid TEXT,
              pid TEXT,
              serial TEXT,
              added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS password_reset_otps (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL,
              otp_hash BLOB NOT NULL,
              expires_at TEXT NOT NULL,
              used INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL
            );
            """
        )


def setting_get(key: str) -> str | None:
    with connect() as con:
        row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])


def setting_set(key: str, value: str) -> None:
    with connect() as con:
        con.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


@dataclass(frozen=True)
class UserRecord:
    id: int
    username: str
    email: str | None
    role: str
    password_hash: bytes
    must_change_password: bool
    is_active: bool


def user_get_by_username(username: str) -> UserRecord | None:
    with connect() as con:
        row = con.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None:
            return None
        return UserRecord(
            id=int(row["id"]),
            username=str(row["username"]),
            email=None if row["email"] is None else str(row["email"]),
            role=str(row["role"]),
            password_hash=bytes(row["password_hash"]),
            must_change_password=bool(row["must_change_password"]),
            is_active=bool(row["is_active"]),
        )


def user_create(username: str, email: str | None, role: str, password_hash: bytes, must_change_password: bool) -> None:
    with connect() as con:
        con.execute(
            """
            INSERT INTO users(username,email,role,password_hash,created_at,must_change_password,is_active)
            VALUES(?,?,?,?,?,?,1)
            """,
            (username, email, role, password_hash, utc_now_iso(), 1 if must_change_password else 0),
        )


def user_set_password(username: str, password_hash: bytes, must_change_password: bool) -> None:
    with connect() as con:
        con.execute(
            "UPDATE users SET password_hash=?, must_change_password=? WHERE username=?",
            (password_hash, 1 if must_change_password else 0, username),
        )


def log_login_attempt(username: str, success: bool, reason: str | None, intruder_image_path: str | None) -> None:
    with connect() as con:
        con.execute(
            """
            INSERT INTO login_attempts(username, success, reason, at, intruder_image_path)
            VALUES(?,?,?,?,?)
            """,
            (username, 1 if success else 0, reason, utc_now_iso(), intruder_image_path),
        )


def log_usb_event(
    event_type: str,
    device_name: str | None,
    pnp_device_id: str | None,
    vid: str | None,
    pid: str | None,
    serial: str | None,
    allowed: bool | None,
    action_taken: str | None,
) -> None:
    with connect() as con:
        con.execute(
            """
            INSERT INTO usb_events(event_type, device_name, pnp_device_id, vid, pid, serial, allowed, action_taken, at)
            VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                event_type,
                device_name,
                pnp_device_id,
                vid,
                pid,
                serial,
                None if allowed is None else (1 if allowed else 0),
                action_taken,
                utc_now_iso(),
            ),
        )


def whitelist_add(label: str | None, pnp_device_id: str, vid: str | None, pid: str | None, serial: str | None) -> None:
    with connect() as con:
        con.execute(
            """
            INSERT OR IGNORE INTO usb_whitelist(label, pnp_device_id, vid, pid, serial, added_at)
            VALUES(?,?,?,?,?,?)
            """,
            (label, pnp_device_id, vid, pid, serial, utc_now_iso()),
        )


def whitelist_remove(pnp_device_id: str) -> None:
    with connect() as con:
        con.execute("DELETE FROM usb_whitelist WHERE pnp_device_id = ?", (pnp_device_id,))


def whitelist_all() -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute(
            "SELECT label,pnp_device_id,vid,pid,serial,added_at FROM usb_whitelist ORDER BY added_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def whitelist_is_allowed(pnp_device_id: str | None, vid: str | None, pid: str | None, serial: str | None) -> bool:
    with connect() as con:
        if pnp_device_id:
            row = con.execute(
                "SELECT 1 FROM usb_whitelist WHERE pnp_device_id = ? LIMIT 1", (pnp_device_id,)
            ).fetchone()
            if row is not None:
                return True
        if vid and pid and serial:
            row = con.execute(
                "SELECT 1 FROM usb_whitelist WHERE vid=? AND pid=? AND serial=? LIMIT 1",
                (vid, pid, serial),
            ).fetchone()
            return row is not None
        return False


def usb_events_recent(limit: int = 200) -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute(
            """
            SELECT event_type, device_name, pnp_device_id, vid, pid, serial, allowed, action_taken, at
            FROM usb_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
        return [dict(r) for r in rows]


def login_attempts_recent(limit: int = 200) -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute(
            """
            SELECT username, success, reason, at, intruder_image_path
            FROM login_attempts
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
        return [dict(r) for r in rows]


def otp_store(username: str, otp_hash: bytes, expires_at: str) -> None:
    with connect() as con:
        con.execute("UPDATE password_reset_otps SET used=1 WHERE username=? AND used=0", (username,))
        con.execute(
            """
            INSERT INTO password_reset_otps(username, otp_hash, expires_at, used, created_at)
            VALUES(?,?,?,?,?)
            """,
            (username, otp_hash, expires_at, 0, utc_now_iso()),
        )


def otp_get_latest_active(username: str) -> dict[str, Any] | None:
    with connect() as con:
        row = con.execute(
            """
            SELECT id, otp_hash, expires_at, used
            FROM password_reset_otps
            WHERE username=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (username,),
        ).fetchone()
        return None if row is None else dict(row)


def otp_mark_used(otp_id: int) -> None:
    with connect() as con:
        con.execute("UPDATE password_reset_otps SET used=1 WHERE id=?", (otp_id,))
