# USB Physical Security for Systems (Windows)

A production-style cybersecurity project that controls and monitors USB storage on Windows with:

- Tkinter GUI (Dashboard/Security/Whitelist/Logs/Settings)
- Role-Based Access Control (Admin/User) using SQLite
- USB storage enable/disable via Windows registry (`USBSTOR`)
- USB insert/remove monitoring via WMI
- USB device whitelist database + auto-block unknown devices
- Intruder detection: 3 failed logins → webcam snapshot (OpenCV) + DB log
- Email onboarding + alert notifications via SMTP (Gmail TLS)

## Requirements

- Windows 10/11
- Python 3.10+ recommended
- Admin privileges (required to write USB registry keys)
- A webcam (for intruder snapshots)
- Gmail App Password (recommended) for SMTP

## Install

Open PowerShell in the project folder:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Configure Email (securely)

Set environment variables (recommended; do **not** hardcode credentials):

PowerShell (current session):

```powershell
$env:UPS_SMTP_USER="yourgmail@gmail.com"
$env:UPS_SMTP_PASS="your_gmail_app_password"
```

Optional overrides:

```powershell
$env:UPS_SMTP_HOST="smtp.gmail.com"
$env:UPS_SMTP_PORT="587"
```

## Run

```bash
python main.py
```

### First run (onboarding)

- The app will ask for the **Admin email**.
- It will generate a strong random password and email it to that address.
- You then log in as:
  - Username: `admin`
  - Password: (sent by email)

## Project structure

- `main.py` – entry point
- `gui.py` – Tkinter UI + navigation tabs
- `db.py` – SQLite schema + queries
- `auth.py` – login + RBAC helpers
- `security.py` – password hashing + secure generation
- `emailer.py` – SMTP TLS email sender
- `usb_control.py` – registry-based USB storage control
- `usb_monitor.py` – WMI insert/remove watcher + logging
- `whitelist.py` – whitelist logic + device parsing
- `intruder.py` – webcam snapshot capture

Data created at runtime:

- `data/app.db` – SQLite database
- `intruders/*.jpg` – captured intruder snapshots
- `data/logs/*.log` – optional file logs (if enabled)

## Notes (security & production hardening)

- Use Gmail **App Passwords** (not your normal password).
- Run the app **as Administrator** to actually enforce USB policy.
- For stronger whitelisting enforcement, consider device-level disable using Windows device installation restrictions / GPO, or `pnputil` + signed driver policies (enterprise approach).
- Consider Windows Event Log integration and a dedicated service for always-on monitoring.

## Disclaimer

This project modifies Windows registry settings that affect USB storage. Use carefully and test in a VM or non-production machine first.
