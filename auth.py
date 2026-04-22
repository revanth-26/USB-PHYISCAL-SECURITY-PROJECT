from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
import sqlite3

import db
from emailer import send_password_reset_otp
from security import hash_password, verify_password


ROLE_ADMIN = "admin"
ROLE_USER = "user"


@dataclass(frozen=True)
class Session:
    username: str
    role: str
    email: str | None
    must_change_password: bool

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN


def ensure_admin_exists(admin_email: str, temp_password: str) -> None:
    """
    Creates the initial admin user if it doesn't exist yet.
    """
    existing = db.user_get_by_username("admin")
    if existing is not None:
        return
    ph = hash_password(temp_password)
    db.user_create(
        username="admin",
        email=admin_email,
        role=ROLE_ADMIN,
        password_hash=ph.hashed,
        must_change_password=True,
    )


def authenticate(username: str, password: str) -> Session | None:
    user = db.user_get_by_username(username.strip())
    if user is None or not user.is_active:
        db.log_login_attempt(username=username, success=False, reason="User not found/disabled", intruder_image_path=None)
        return None
    if not verify_password(password, user.password_hash):
        db.log_login_attempt(username=username, success=False, reason="Wrong password", intruder_image_path=None)
        return None

    db.log_login_attempt(username=username, success=True, reason=None, intruder_image_path=None)
    return Session(
        username=user.username,
        role=user.role,
        email=user.email,
        must_change_password=user.must_change_password,
    )


def change_password(username: str, new_password: str) -> None:
    ph = hash_password(new_password)
    db.user_set_password(username=username, password_hash=ph.hashed, must_change_password=False)


def register_user(username: str, email: str, password: str) -> None:
    clean_user = username.strip()
    clean_email = email.strip()
    if not clean_user or len(clean_user) < 3:
        raise ValueError("Username must be at least 3 characters.")
    if "@" not in clean_email:
        raise ValueError("Please provide a valid email.")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    if db.user_get_by_username(clean_user) is not None:
        raise ValueError("Username already exists.")

    ph = hash_password(password)
    try:
        db.user_create(
            username=clean_user,
            email=clean_email,
            role=ROLE_USER,
            password_hash=ph.hashed,
            must_change_password=False,
        )
    except sqlite3.IntegrityError as e:
        raise ValueError("Could not create account. Username may already exist.") from e


OTP_EXPIRES_MINUTES = 5


def request_password_reset_otp(username: str) -> None:
    user = db.user_get_by_username(username.strip())
    if user is None or not user.email:
        raise ValueError("User/email not found for OTP reset.")

    otp = f"{secrets.randbelow(1_000_000):06d}"
    otp_hash = hash_password(otp).hashed
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRES_MINUTES)).isoformat(timespec="seconds")

    db.otp_store(username=user.username, otp_hash=otp_hash, expires_at=expires_at)
    send_password_reset_otp(
        to_email=user.email,
        username=user.username,
        otp=otp,
        expires_minutes=OTP_EXPIRES_MINUTES,
    )


def reset_password_with_otp(username: str, otp: str, new_password: str) -> None:
    row = db.otp_get_latest_active(username.strip())
    if row is None:
        raise ValueError("No OTP request found. Generate a new OTP.")
    if int(row["used"]) == 1:
        raise ValueError("OTP already used.")

    expires_at = datetime.fromisoformat(str(row["expires_at"]))
    if datetime.now(timezone.utc) > expires_at:
        raise ValueError("OTP expired. Generate a new OTP.")

    if not verify_password(otp.strip(), bytes(row["otp_hash"])):
        raise ValueError("Invalid OTP.")

    ph = hash_password(new_password)
    db.user_set_password(username=username.strip(), password_hash=ph.hashed, must_change_password=False)
    db.otp_mark_used(int(row["id"]))
