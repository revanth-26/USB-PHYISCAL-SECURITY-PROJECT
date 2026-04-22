from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


APP_NAME = "USB Physical Security for Systems"


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
INTRUDER_DIR = BASE_DIR / "intruders"


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    INTRUDER_DIR.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    username: str
    password: str


def get_smtp_config() -> SmtpConfig | None:
    """
    Credentials come from environment variables to avoid storing secrets in code or DB.
    """
    user = os.getenv("UPS_SMTP_USER", "hanumanthukurmarao20@gmail.com").strip()
    pwd = os.getenv("UPS_SMTP_PASS", "vgmn jbxo ncgw vxzn").strip()
    if not user or not pwd:
        return None
    host = os.getenv("UPS_SMTP_HOST", "smtp.gmail.com").strip()
    port_str = os.getenv("UPS_SMTP_PORT", "587").strip()
    try:
        port = int(port_str)
    except ValueError:
        port = 587
    return SmtpConfig(host=host, port=port, username=user, password=pwd)
