from __future__ import annotations

import sys

import db
from emailer import send_admin_onboarding_password
from security import generate_password, hash_password


def main() -> int:
    db.init_db()
    admin = db.user_get_by_username("admin")
    if admin is None:
        print("No admin user exists yet. Run the app and use 'First Run: Create Admin'.")
        return 1

    # Prefer admin.email, fallback to saved alert email.
    to_email = admin.email or (db.setting_get("alert_email") or "").strip()
    if not to_email:
        print("Admin exists but no email is stored. Can't email a reset password.")
        print("Fix: login if you know the password, or delete data/app.db to re-onboard.")
        return 2

    new_pwd = generate_password(16)
    db.user_set_password("admin", hash_password(new_pwd).hashed, must_change_password=True)

    try:
        send_admin_onboarding_password(to_email=to_email, username="admin", password=new_pwd)
        print(f"Admin password reset and emailed to: {to_email}")
        return 0
    except Exception as e:
        print("Admin password reset in DB, but email sending failed:")
        print(str(e))
        print("")
        print("Temporary password (change it after login):")
        print(new_pwd)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

