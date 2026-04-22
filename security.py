from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

import bcrypt


DEFAULT_PASSWORD_LENGTH = 16


def generate_password(length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    """
    Generates a strong password with a mix of upper/lower/digits/symbols.
    Uses `secrets` for cryptographic randomness.
    """
    if length < 12:
        length = 12

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/<>"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(not c.isalnum() for c in pwd)
        ):
            return pwd


@dataclass(frozen=True)
class PasswordHash:
    hashed: bytes


def hash_password(plain: str) -> PasswordHash:
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain.encode("utf-8"), salt)
    return PasswordHash(hashed=hashed)


def verify_password(plain: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed)
    except Exception:
        return False
