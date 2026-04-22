from __future__ import annotations

import smtplib
from email.message import EmailMessage
from pathlib import Path

from config import APP_NAME, get_smtp_config


def send_email(to_email: str, subject: str, body: str) -> None:
    cfg = get_smtp_config()
    if cfg is None:
        raise RuntimeError(
            "SMTP is not configured. Set UPS_SMTP_USER and UPS_SMTP_PASS environment variables."
        )

    msg = EmailMessage()
    msg["From"] = cfg.username
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(cfg.host, cfg.port, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(cfg.username, cfg.password)
        server.send_message(msg)


def send_email_with_attachment(to_email: str, subject: str, body: str, attachment_path: str | None) -> None:
    cfg = get_smtp_config()
    if cfg is None:
        raise RuntimeError(
            "SMTP is not configured. Set UPS_SMTP_USER and UPS_SMTP_PASS environment variables."
        )

    msg = EmailMessage()
    msg["From"] = cfg.username
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    if attachment_path:
        p = Path(attachment_path)
        if p.exists() and p.is_file():
            data = p.read_bytes()
            msg.add_attachment(data, maintype="image", subtype="jpeg", filename=p.name)

    with smtplib.SMTP(cfg.host, cfg.port, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(cfg.username, cfg.password)
        server.send_message(msg)


def send_admin_onboarding_password(to_email: str, username: str, password: str) -> None:
    subject = f"{APP_NAME} – Admin Password"
    body = f"""Hello,

Your admin account has been initialized.

Username: {username}
Temporary password: {password}

Security tips:
- Change this password after first login.
- Do not share it.
- Use an App Password for SMTP (recommended).
"""
    send_email(to_email=to_email, subject=subject, body=body)


def send_usb_alert(to_email: str, message: str) -> None:
    subject = f"{APP_NAME} – USB Security Alert"
    body = f"""USB Security Alert

{message}
"""
    send_email(to_email=to_email, subject=subject, body=body)


def send_password_reset_otp(to_email: str, username: str, otp: str, expires_minutes: int) -> None:
    subject = f"{APP_NAME} – Password Reset OTP"
    body = f"""Hello,

A password reset was requested for username: {username}

OTP: {otp}
Expires in: {expires_minutes} minutes

If you did not request this, ignore this email.
"""
    send_email(to_email=to_email, subject=subject, body=body)


def send_intruder_alert(to_email: str, username: str, image_path: str | None) -> None:
    subject = f"{APP_NAME} – Intruder Login Alert"
    body = f"""Security Alert

Three failed login attempts were detected.
Username entered: {username}

A snapshot is attached (if capture succeeded).
"""
    send_email_with_attachment(to_email=to_email, subject=subject, body=body, attachment_path=image_path)
