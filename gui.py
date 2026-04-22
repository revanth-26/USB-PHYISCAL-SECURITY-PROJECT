from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox

import auth
import db
from emailer import send_admin_onboarding_password, send_usb_alert, send_intruder_alert
from security import generate_password
from usb_control import get_usb_storage_enabled, set_usb_storage_enabled, is_admin as is_windows_admin
from usb_monitor import UsbMonitor, get_whitelist_enforcement, set_whitelist_enforcement
from intruder import capture_intruder_snapshot


APP_BG = "#0b1220"
CARD_BG = "#111a2d"
ACCENT = "#22d3ee"
DANGER = "#fb7185"
TEXT = "#e5e7eb"
MUTED = "#9ca3af"
SECONDARY = "#334155"


class App(ttk.Frame):
    def __init__(self, root: tk.Tk):
        super().__init__(root)
        self.root = root
        self.session: auth.Session | None = None
        self.failed_count = 0
        self.last_user = ""
        self.live_refresh_job: str | None = None

        self.monitor = UsbMonitor(poll_seconds=2.0)
        self.monitor.add_callback(self._on_usb_event)
        self.monitor.start()

        self._build_style()
        self._build_login()

    def _build_style(self) -> None:
        self.root.title("USB Physical Security for Systems")
        self.root.geometry("1100x650")
        self.root.minsize(980, 600)
        self.root.configure(bg=APP_BG)

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(".", background=APP_BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=APP_BG)
        style.configure("Card.TFrame", background=CARD_BG)
        style.configure("TLabel", background=APP_BG, foreground=TEXT)
        style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), foreground=ACCENT)
        
        style.configure("TButton", padding=8, font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[("active", "#1e293b")])
        style.configure("Accent.TButton", background=ACCENT, foreground="#00110d")
        style.map("Accent.TButton", background=[("active", "#1fb6a9")])
        style.configure("Secondary.TButton", background=SECONDARY, foreground=TEXT)
        style.map("Secondary.TButton", background=[("active", "#475569")])
        style.configure("Danger.TButton", background=DANGER, foreground="#220009")
        style.map("Danger.TButton", background=[("active", "#f43f5e")])
        
        style.configure("TNotebook", background=APP_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#111827", foreground=MUTED, padding=(16, 10), font=("Segoe UI", 11, "bold"), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", APP_BG), ("active", SECONDARY)], foreground=[("selected", ACCENT), ("active", TEXT)])
        
        style.configure("Treeview", background=CARD_BG, fieldbackground=CARD_BG, foreground=TEXT, rowheight=28, borderwidth=0)
        style.configure("Treeview.Heading", background="#1e293b", foreground=TEXT, font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", SECONDARY)], foreground=[("selected", TEXT)])
        
        style.configure("TEntry", fieldbackground="#1e293b", foreground=TEXT, insertcolor=TEXT, borderwidth=1, padding=6)
        style.map("TEntry", fieldbackground=[("focus", "#0f172a")], bordercolor=[("focus", ACCENT)])

    def _clear(self) -> None:
        for w in list(self.root.winfo_children()):
            w.destroy()

    def _build_login(self) -> None:
        self._clear()
        
        top_bar = ttk.Frame(self.root)
        top_bar.pack(fill="x", side="top", pady=(16, 0))
        btn_info = ttk.Button(top_bar, text="Project Info", style="Accent.TButton", command=self._show_project_info)
        btn_info.pack(anchor="center")

        container = ttk.Frame(self.root, padding=24)
        container.pack(fill="both", expand=True)

        header = ttk.Frame(container)
        header.pack(fill="x", pady=(0, 16))
        ttk.Label(header, text="USB Physical Security for Systems", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Login with RBAC (Admin can control USB, User can view status).",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        card = ttk.Frame(container, style="Card.TFrame", padding=18)
        card.pack(anchor="center", fill="x", pady=12)

        self.var_user = tk.StringVar(value="admin")
        self.var_pass = tk.StringVar()

        grid = ttk.Frame(card, style="Card.TFrame")
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)

        ttk.Label(grid, text="Username", background=CARD_BG).grid(row=0, column=0, sticky="w", padx=(0, 12), pady=8)
        ttk.Entry(grid, textvariable=self.var_user).grid(row=0, column=1, sticky="ew", pady=8)

        ttk.Label(grid, text="Password", background=CARD_BG).grid(row=1, column=0, sticky="w", padx=(0, 12), pady=8)
        ttk.Entry(grid, textvariable=self.var_pass, show="•").grid(row=1, column=1, sticky="ew", pady=8)

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.pack(fill="x", pady=(10, 0))

        ttk.Button(btns, text="Login", style="Accent.TButton", command=self._login).pack(side="left")
        ttk.Button(btns, text="Create User Account", style="Secondary.TButton", command=self._open_register_user).pack(
            side="left", padx=10
        )
        ttk.Button(btns, text="Forgot Password (OTP)", style="Secondary.TButton", command=self._open_forgot_password).pack(
            side="left", padx=10
        )
        ttk.Button(btns, text="First Run: Create Admin", command=self._first_run_onboarding).pack(side="left", padx=10)
        ttk.Button(btns, text="Exit", command=self.root.destroy).pack(side="right")

        foot = ttk.Frame(container)
        foot.pack(fill="x", pady=10)
        self.lbl_hint = ttk.Label(
            foot,
            text="Tip: run as Administrator to enforce USB blocking.",
            style="Muted.TLabel",
        )
        self.lbl_hint.pack(anchor="w")

    def _show_project_info(self) -> None:
        import webbrowser
        import os
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        html_path = os.path.join(repo_dir, "project_info.html")
        webbrowser.open(f"file://{html_path}")

    def _first_run_onboarding(self) -> None:
        if db.user_get_by_username("admin") is not None:
            messagebox.showinfo("Already Initialized", "Admin already exists. Please login.")
            return

        win = tk.Toplevel(self.root)
        win.title("Admin Onboarding")
        win.configure(bg=APP_BG)
        win.geometry("520x240")
        win.transient(self.root)
        win.grab_set()

        frm = ttk.Frame(win, padding=18)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Create Admin Account", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            frm,
            text="Enter admin email to receive a one-time password.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(4, 10))

        email_var = tk.StringVar()
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=8)
        ttk.Label(row, text="Admin email").pack(side="left")
        ttk.Entry(row, textvariable=email_var).pack(side="left", fill="x", expand=True, padx=10)

        def do_create() -> None:
            email = email_var.get().strip()
            if "@" not in email:
                messagebox.showerror("Invalid Email", "Please enter a valid email.")
                return
            pwd = generate_password(16)
            try:
                auth.ensure_admin_exists(admin_email=email, temp_password=pwd)
                send_admin_onboarding_password(to_email=email, username="admin", password=pwd)
                db.setting_set("alert_email", email)
            except Exception as e:
                messagebox.showerror("Onboarding Failed", str(e))
                return
            messagebox.showinfo("Admin Created", "Admin user created. Password sent by email.")
            win.destroy()

        actions = ttk.Frame(frm)
        actions.pack(fill="x", pady=(14, 0))
        ttk.Button(actions, text="Create & Send Password", style="Accent.TButton", command=do_create).pack(side="left")
        ttk.Button(actions, text="Cancel", command=win.destroy).pack(side="right")

    def _login(self) -> None:
        u = self.var_user.get().strip()
        p = self.var_pass.get()
        self.last_user = u

        sess = auth.authenticate(u, p)
        if sess is None:
            self.failed_count += 1
            if self.failed_count >= 3:
                img_path = None
                try:
                    img_path = capture_intruder_snapshot(prefix=f"login_{u or 'unknown'}")
                except Exception:
                    img_path = None
                db.log_login_attempt(username=u or "unknown", success=False, reason="3_failed_attempts_intruder", intruder_image_path=img_path)
                # Notify intended user email first; fallback to global alert email.
                target_email = ""
                user = db.user_get_by_username(u) if u else None
                if user and user.email:
                    target_email = user.email
                if not target_email:
                    target_email = db.setting_get("alert_email") or ""
                if target_email:
                    try:
                        send_intruder_alert(to_email=target_email, username=u or "unknown", image_path=img_path)
                    except Exception:
                        pass
                self.failed_count = 0
                messagebox.showerror(
                    "Intruder Alert",
                    "3 failed attempts detected. Snapshot captured (if webcam available), logged, and email alert sent.",
                )
            else:
                messagebox.showerror("Login Failed", f"Invalid credentials. Attempts: {self.failed_count}/3")
            return

        self.failed_count = 0
        self.session = sess
        self._build_main()

        if sess.must_change_password:
            self._prompt_change_password()

    def _prompt_change_password(self) -> None:
        if not self.session:
            return
        win = tk.Toplevel(self.root)
        win.title("Change Password")
        win.configure(bg=APP_BG)
        win.geometry("560x260")
        win.transient(self.root)
        win.grab_set()

        frm = ttk.Frame(win, padding=18)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Change Password", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            frm,
            text="For security, you must change the temporary password now.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(4, 10))

        new_var = tk.StringVar()
        confirm_var = tk.StringVar()

        g = ttk.Frame(frm)
        g.pack(fill="x")
        g.columnconfigure(1, weight=1)

        ttk.Label(g, text="New password").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=new_var, show="•").grid(row=0, column=1, sticky="ew", pady=6, padx=(10, 0))
        ttk.Label(g, text="Confirm").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=confirm_var, show="•").grid(row=1, column=1, sticky="ew", pady=6, padx=(10, 0))

        def do_change() -> None:
            a = new_var.get()
            b = confirm_var.get()
            if len(a) < 12:
                messagebox.showerror("Weak Password", "Use at least 12 characters.")
                return
            if a != b:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return
            try:
                auth.change_password(self.session.username, a)
            except Exception as e:
                messagebox.showerror("Failed", str(e))
                return
            messagebox.showinfo("Updated", "Password changed successfully.")
            win.destroy()

        actions = ttk.Frame(frm)
        actions.pack(fill="x", pady=(14, 0))
        ttk.Button(actions, text="Update Password", style="Accent.TButton", command=do_change).pack(side="left")

    def _open_forgot_password(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Forgot Password (OTP)")
        win.configure(bg=APP_BG)
        win.geometry("560x350")
        win.transient(self.root)
        win.grab_set()

        frm = ttk.Frame(win, padding=18)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Reset Password with OTP", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            frm,
            text="Enter username, request OTP by email, then set a new password.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(4, 12))

        user_var = tk.StringVar(value=self.var_user.get().strip() or "admin")
        otp_var = tk.StringVar()
        new_var = tk.StringVar()
        confirm_var = tk.StringVar()

        g = ttk.Frame(frm)
        g.pack(fill="x")
        g.columnconfigure(1, weight=1)

        ttk.Label(g, text="Username").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=user_var).grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=6)
        ttk.Label(g, text="OTP code").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=otp_var).grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=6)
        ttk.Label(g, text="New password").grid(row=2, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=new_var, show="•").grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=6)
        ttk.Label(g, text="Confirm password").grid(row=3, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=confirm_var, show="•").grid(row=3, column=1, sticky="ew", padx=(10, 0), pady=6)

        def request_otp() -> None:
            username = user_var.get().strip()
            if not username:
                messagebox.showerror("Invalid", "Enter username.")
                return
            try:
                auth.request_password_reset_otp(username)
            except Exception as e:
                messagebox.showerror("OTP Failed", str(e))
                return
            messagebox.showinfo("OTP Sent", "OTP sent to registered user email. It expires in 5 minutes.")

        def do_reset() -> None:
            username = user_var.get().strip()
            otp = otp_var.get().strip()
            new_pw = new_var.get()
            confirm_pw = confirm_var.get()
            if len(new_pw) < 12:
                messagebox.showerror("Weak Password", "Use at least 12 characters.")
                return
            if new_pw != confirm_pw:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return
            try:
                auth.reset_password_with_otp(username=username, otp=otp, new_password=new_pw)
            except Exception as e:
                messagebox.showerror("Reset Failed", str(e))
                return
            messagebox.showinfo("Done", "Password reset successful. You can now login.")
            self.var_user.set(username)
            self.var_pass.set("")
            win.destroy()

        actions = ttk.Frame(frm)
        actions.pack(fill="x", pady=(14, 0))
        ttk.Button(actions, text="Request OTP", style="Secondary.TButton", command=request_otp).pack(side="left")
        ttk.Button(actions, text="Reset Password", style="Accent.TButton", command=do_reset).pack(side="left", padx=10)
        ttk.Button(actions, text="Close", command=win.destroy).pack(side="right")

    def _open_register_user(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Create User Account")
        win.configure(bg=APP_BG)
        win.geometry("560x330")
        win.transient(self.root)
        win.grab_set()

        frm = ttk.Frame(win, padding=18)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Create New User Login", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            frm,
            text="Creates a User role account (view-only permissions).",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(4, 12))

        user_var = tk.StringVar()
        email_var = tk.StringVar()
        pass_var = tk.StringVar()
        confirm_var = tk.StringVar()

        g = ttk.Frame(frm)
        g.pack(fill="x")
        g.columnconfigure(1, weight=1)

        ttk.Label(g, text="Username").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=user_var).grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=6)
        ttk.Label(g, text="Email").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=email_var).grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=6)
        ttk.Label(g, text="Password").grid(row=2, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=pass_var, show="•").grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=6)
        ttk.Label(g, text="Confirm Password").grid(row=3, column=0, sticky="w", pady=6)
        ttk.Entry(g, textvariable=confirm_var, show="•").grid(row=3, column=1, sticky="ew", padx=(10, 0), pady=6)

        def do_create_user() -> None:
            username = user_var.get().strip()
            email = email_var.get().strip()
            pw = pass_var.get()
            cpw = confirm_var.get()
            if pw != cpw:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return
            try:
                auth.register_user(username=username, email=email, password=pw)
            except Exception as e:
                messagebox.showerror("Create Failed", str(e))
                return
            messagebox.showinfo("Account Created", "User account created successfully. You can login now.")
            self.var_user.set(username)
            self.var_pass.set("")
            win.destroy()

        actions = ttk.Frame(frm)
        actions.pack(fill="x", pady=(14, 0))
        ttk.Button(actions, text="Create Account", style="Accent.TButton", command=do_create_user).pack(side="left")
        ttk.Button(actions, text="Close", command=win.destroy).pack(side="right")

    def _build_main(self) -> None:
        self._clear()
        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True)

        top = ttk.Frame(outer, padding=(18, 14))
        top.pack(fill="x")

        left = ttk.Frame(top)
        left.pack(side="left", fill="x", expand=True)

        ttk.Label(left, text="Dashboard", style="Title.TLabel").pack(anchor="w")
        role = self.session.role if self.session else "unknown"
        ttk.Label(left, text=f"Logged in as {self.session.username} ({role})", style="Muted.TLabel").pack(anchor="w", pady=(2, 0))

        right = ttk.Frame(top)
        right.pack(side="right")
        ttk.Button(right, text="Logout", command=self._logout).pack(side="right")

        self.status_var = tk.StringVar(value="Checking…")
        self.usb_var = tk.StringVar(value="Unknown")
        self.admin_var = tk.StringVar(value="No")

        status_row = ttk.Frame(outer, padding=(18, 0))
        status_row.pack(fill="x")
        self._status_chip(status_row, title="USB Storage", value_var=self.usb_var).pack(side="left", padx=(0, 10))
        self._status_chip(status_row, title="Windows Admin", value_var=self.admin_var).pack(side="left", padx=(0, 10))
        self._status_chip(status_row, title="Monitor", value_var=self.status_var).pack(side="left", padx=(0, 10))

        nb = ttk.Notebook(outer)
        nb.pack(fill="both", expand=True, padx=18, pady=14)

        self.tab_dash = ttk.Frame(nb)
        self.tab_security = ttk.Frame(nb)
        self.tab_whitelist = ttk.Frame(nb)
        self.tab_logs = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)

        nb.add(self.tab_dash, text="Dashboard")
        nb.add(self.tab_security, text="Security")
        nb.add(self.tab_whitelist, text="Whitelist")
        nb.add(self.tab_logs, text="Logs")
        nb.add(self.tab_settings, text="Settings")

        self._build_dashboard_tab()
        self._build_security_tab()
        self._build_whitelist_tab()
        self._build_logs_tab()
        self._build_settings_tab()

        if self.live_refresh_job:
            try:
                self.root.after_cancel(self.live_refresh_job)
            except Exception:
                pass
            self.live_refresh_job = None
        self._refresh_status()
        self._refresh_tables()
        self._schedule_live_refresh()

    def _schedule_live_refresh(self) -> None:
        self._refresh_live_devices()
        self.live_refresh_job = self.root.after(2500, self._schedule_live_refresh)

    def _status_chip(self, parent: ttk.Frame, title: str, value_var: tk.StringVar) -> ttk.Frame:
        f = ttk.Frame(parent, style="Card.TFrame", padding=(12, 8))
        ttk.Label(f, text=title, style="Muted.TLabel", background=CARD_BG).pack(anchor="w")
        ttk.Label(f, textvariable=value_var, background=CARD_BG, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        return f

    def _build_dashboard_tab(self) -> None:
        wrap = ttk.Frame(self.tab_dash, padding=16)
        wrap.pack(fill="both", expand=True)

        card = ttk.Frame(wrap, style="Card.TFrame", padding=16)
        card.pack(fill="x")

        ttk.Label(card, text="Quick Actions", background=CARD_BG, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(
            card,
            text="Admin can enable/disable USB storage. User can view status only.",
            background=CARD_BG,
            foreground=MUTED,
        ).pack(anchor="w", pady=(6, 12))

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.pack(fill="x")

        self.btn_enable = ttk.Button(btns, text="Enable USB Storage", style="Accent.TButton", command=lambda: self._set_usb(True))
        self.btn_disable = ttk.Button(btns, text="Disable USB Storage", style="Danger.TButton", command=lambda: self._set_usb(False))
        self.btn_refresh = ttk.Button(btns, text="Refresh", command=self._refresh_status)

        self.btn_enable.pack(side="left")
        self.btn_disable.pack(side="left", padx=10)
        self.btn_refresh.pack(side="left", padx=10)

        if not (self.session and self.session.is_admin):
            self.btn_enable.state(["disabled"])
            self.btn_disable.state(["disabled"])

        live = ttk.Frame(wrap, style="Card.TFrame", padding=16)
        live.pack(fill="both", expand=True, pady=(14, 0))
        ttk.Label(live, text="Live Connected USB Devices", background=CARD_BG, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(
            live,
            text="Real-time view of connected USB storage devices (detected even when blocked).",
            background=CARD_BG,
            foreground=MUTED,
        ).pack(anchor="w", pady=(4, 10))

        cols = ("device_name", "pnp_device_id", "vid", "pid", "serial", "trusted")
        self.tbl_live = ttk.Treeview(live, columns=cols, show="headings", height=8)
        widths = {"device_name": 170, "pnp_device_id": 360, "vid": 65, "pid": 65, "serial": 170, "trusted": 90}
        for c in cols:
            self.tbl_live.heading(c, text=c.replace("_", " ").title())
            self.tbl_live.column(c, width=widths[c], anchor="w")
        self.tbl_live.pack(fill="both", expand=True)

        ttk.Button(live, text="Refresh Live Devices", style="Secondary.TButton", command=self._refresh_live_devices).pack(
            anchor="w", pady=(10, 0)
        )

    def _build_security_tab(self) -> None:
        wrap = ttk.Frame(self.tab_security, padding=16)
        wrap.pack(fill="both", expand=True)

        card = ttk.Frame(wrap, style="Card.TFrame", padding=16)
        card.pack(fill="x")

        ttk.Label(card, text="Intruder Detection", background=CARD_BG, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(
            card,
            text="After 3 failed logins, the app captures a webcam snapshot and logs the attempt.",
            background=CARD_BG,
            foreground=MUTED,
        ).pack(anchor="w", pady=(6, 10))

        ttk.Button(card, text="Test Snapshot (Admin)", command=self._test_snapshot).pack(anchor="w")

        if not (self.session and self.session.is_admin):
            for child in card.winfo_children():
                if isinstance(child, ttk.Button):
                    child.state(["disabled"])

    def _build_whitelist_tab(self) -> None:
        wrap = ttk.Frame(self.tab_whitelist, padding=16)
        wrap.pack(fill="both", expand=True)

        top = ttk.Frame(wrap)
        top.pack(fill="x")
        ttk.Label(top, text="USB Whitelist", font=("Segoe UI", 12, "bold")).pack(side="left")

        self.enforce_var = tk.BooleanVar(value=get_whitelist_enforcement())
        chk = ttk.Checkbutton(
            top,
            text="Enforce whitelist (auto-block unknown USB storage)",
            variable=self.enforce_var,
            command=self._toggle_enforce,
        )
        chk.pack(side="right")

        table_wrap = ttk.Frame(wrap, style="Card.TFrame", padding=10)
        table_wrap.pack(fill="both", expand=True, pady=12)

        cols = ("label", "pnp_device_id", "vid", "pid", "serial", "added_at")
        self.tbl_wl = ttk.Treeview(table_wrap, columns=cols, show="headings", height=12)
        for c in cols:
            self.tbl_wl.heading(c, text=c)
            self.tbl_wl.column(c, width=140 if c != "pnp_device_id" else 460, anchor="w")
        self.tbl_wl.pack(fill="both", expand=True)

        actions = ttk.Frame(wrap)
        actions.pack(fill="x")
        ttk.Button(actions, text="Refresh", command=self._refresh_tables).pack(side="left")
        ttk.Button(actions, text="Add Connected USB Storage (Admin)", style="Accent.TButton", command=self._add_connected_usb).pack(
            side="left", padx=10
        )
        ttk.Button(actions, text="Remove Selected (Admin)", style="Danger.TButton", command=self._remove_selected_wl).pack(
            side="left"
        )

        if not (self.session and self.session.is_admin):
            for child in actions.winfo_children():
                if isinstance(child, ttk.Button) and "Admin" in child.cget("text"):
                    child.state(["disabled"])

    def _build_logs_tab(self) -> None:
        wrap = ttk.Frame(self.tab_logs, padding=16)
        wrap.pack(fill="both", expand=True)

        pan = ttk.Panedwindow(wrap, orient=tk.VERTICAL)
        pan.pack(fill="both", expand=True)

        f1 = ttk.Frame(pan, style="Card.TFrame", padding=10)
        f2 = ttk.Frame(pan, style="Card.TFrame", padding=10)
        pan.add(f1, weight=1)
        pan.add(f2, weight=1)

        ttk.Label(f1, text="USB Activity Logs", background=CARD_BG, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.lst_usb = tk.Listbox(f1, height=8, bg=CARD_BG, fg=TEXT, highlightthickness=0, selectbackground="#1f2937")
        self.lst_usb.pack(fill="both", expand=True, pady=(8, 0))

        ttk.Label(f2, text="Login Attempts", background=CARD_BG, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.lst_login = tk.Listbox(f2, height=8, bg=CARD_BG, fg=TEXT, highlightthickness=0, selectbackground="#1f2937")
        self.lst_login.pack(fill="both", expand=True, pady=(8, 0))

        bar = ttk.Frame(wrap)
        bar.pack(fill="x", pady=(10, 0))
        ttk.Button(bar, text="Refresh", command=self._refresh_tables).pack(side="left")

    def _build_settings_tab(self) -> None:
        wrap = ttk.Frame(self.tab_settings, padding=16)
        wrap.pack(fill="both", expand=True)

        card = ttk.Frame(wrap, style="Card.TFrame", padding=16)
        card.pack(fill="x")

        ttk.Label(card, text="Alerting", background=CARD_BG, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(
            card,
            text="Email alerts use UPS_SMTP_USER/UPS_SMTP_PASS environment variables.",
            background=CARD_BG,
            foreground=MUTED,
        ).pack(anchor="w", pady=(6, 12))

        self.alert_email_var = tk.StringVar(value=db.setting_get("alert_email") or "")
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="Alert email", background=CARD_BG).pack(side="left")
        ttk.Entry(row, textvariable=self.alert_email_var).pack(side="left", fill="x", expand=True, padx=10)
        ttk.Button(row, text="Save", style="Accent.TButton", command=self._save_alert_email).pack(side="left")

        if not (self.session and self.session.is_admin):
            for child in row.winfo_children():
                if isinstance(child, ttk.Button):
                    child.state(["disabled"])

    def _logout(self) -> None:
        if self.live_refresh_job:
            try:
                self.root.after_cancel(self.live_refresh_job)
            except Exception:
                pass
            self.live_refresh_job = None
        self.session = None
        self.failed_count = 0
        self.var_pass.set("")
        self._build_login()

    def _refresh_status(self) -> None:
        enabled = get_usb_storage_enabled()
        self.usb_var.set("Enabled" if enabled else "Disabled")
        self.admin_var.set("Yes" if is_windows_admin() else "No")
        self.status_var.set("Running")

    def _set_usb(self, enable: bool) -> None:
        if not (self.session and self.session.is_admin):
            messagebox.showerror("Forbidden", "Only Admin can change USB policy.")
            return
        try:
            set_usb_storage_enabled(enable)
        except PermissionError as e:
            messagebox.showerror("Admin Required", str(e) + "\n\nPlease run the app as Administrator.")
            return
        except Exception as e:
            messagebox.showerror("Failed", str(e))
            return
        self._refresh_status()
        if enable:
            messagebox.showinfo("USB Policy", "USB storage enabled. Offline USB disks were brought online where possible.")
        else:
            messagebox.showinfo(
                "USB Policy",
                "USB storage disabled.\n\nNote: the system can still detect physical USB insertion events, "
                "but storage access should be blocked/offlined.",
            )

    def _toggle_enforce(self) -> None:
        if not (self.session and self.session.is_admin):
            self.enforce_var.set(get_whitelist_enforcement())
            messagebox.showerror("Forbidden", "Only Admin can change whitelist enforcement.")
            return
        set_whitelist_enforcement(bool(self.enforce_var.get()))

    def _save_alert_email(self) -> None:
        email = self.alert_email_var.get().strip()
        if email and "@" not in email:
            messagebox.showerror("Invalid Email", "Please enter a valid email.")
            return
        db.setting_set("alert_email", email)
        messagebox.showinfo("Saved", "Alert email saved.")

    def _refresh_tables(self) -> None:
        # Whitelist
        for i in self.tbl_wl.get_children():
            self.tbl_wl.delete(i)
        for r in db.whitelist_all():
            self.tbl_wl.insert("", "end", values=(r["label"], r["pnp_device_id"], r["vid"], r["pid"], r["serial"], r["added_at"]))

        # Logs
        self.lst_usb.delete(0, tk.END)
        for e in db.usb_events_recent(120):
            allowed = e["allowed"]
            allowed_str = "allowed" if allowed == 1 else ("blocked" if allowed == 0 else "n/a")
            msg = f'{e["at"]} | {e["event_type"]} | {allowed_str} | {e.get("device_name") or ""}'
            self.lst_usb.insert(tk.END, msg)

        self.lst_login.delete(0, tk.END)
        for a in db.login_attempts_recent(120):
            ok = "OK" if a["success"] == 1 else "FAIL"
            extra = a.get("reason") or ""
            if a.get("intruder_image_path"):
                extra = (extra + f' | img={a["intruder_image_path"]}').strip()
            self.lst_login.insert(tk.END, f'{a["at"]} | {ok} | {a["username"]} | {extra}')
        self._refresh_live_devices()

    def _refresh_live_devices(self) -> None:
        if not hasattr(self, "tbl_live"):
            return
        for i in self.tbl_live.get_children():
            self.tbl_live.delete(i)
        for dev in self.monitor.current_devices():
            trusted = db.whitelist_is_allowed(dev.pnp_device_id, dev.vid, dev.pid, dev.serial)
            self.tbl_live.insert(
                "",
                "end",
                values=(
                    dev.device_name or "",
                    dev.pnp_device_id or "",
                    dev.vid or "",
                    dev.pid or "",
                    dev.serial or "",
                    "Yes" if trusted else "No",
                ),
            )

    def _test_snapshot(self) -> None:
        if not (self.session and self.session.is_admin):
            return
        try:
            p = capture_intruder_snapshot(prefix="manual_test")
            messagebox.showinfo("Snapshot Saved", p)
        except Exception as e:
            messagebox.showerror("Failed", str(e))

    def _add_connected_usb(self) -> None:
        if not (self.session and self.session.is_admin):
            return
        # For simplicity, we whitelist "whatever is currently connected" by reading latest insert events.
        events = db.usb_events_recent(20)
        inserted = [e for e in events if e["event_type"] == "insert" and e.get("pnp_device_id")]
        if not inserted:
            messagebox.showinfo("No Devices", "No recently detected USB storage devices to add. Plug one in and wait 2-3 seconds.")
            return
        e = inserted[0]
        pnp = e["pnp_device_id"]
        label = e.get("device_name") or "USB Device"
        try:
            db.whitelist_add(label=label, pnp_device_id=pnp, vid=e.get("vid"), pid=e.get("pid"), serial=e.get("serial"))
        except Exception as ex:
            messagebox.showerror("Failed", str(ex))
            return
        self._refresh_tables()

    def _remove_selected_wl(self) -> None:
        if not (self.session and self.session.is_admin):
            return
        sel = self.tbl_wl.selection()
        if not sel:
            return
        item = sel[0]
        values = self.tbl_wl.item(item, "values")
        if not values:
            return
        pnp = values[1]
        if not pnp:
            return
        if not messagebox.askyesno("Confirm", "Remove selected device from whitelist?"):
            return
        db.whitelist_remove(pnp)
        self._refresh_tables()

    def _on_usb_event(self, ev) -> None:
        # Alerting: email + popup for unknown device insert when enforcement is ON.
        try:
            if ev.event_type != "insert" or not ev.identity:
                return
            enforce = db.setting_get("enforce_whitelist") == "1"
            if not enforce:
                return
            allowed = db.whitelist_is_allowed(ev.identity.pnp_device_id, ev.identity.vid, ev.identity.pid, ev.identity.serial)
            if allowed:
                return

            msg = f"Unknown USB storage detected: {ev.identity.device_name or 'Unknown'} | {ev.identity.pnp_device_id or ''}"
            alert_email = db.setting_get("alert_email") or ""
            if alert_email:
                try:
                    send_usb_alert(to_email=alert_email, message=msg)
                except Exception:
                    pass

            # GUI popups must be done on main thread.
            self.root.after(0, lambda: messagebox.showwarning("USB Alert", msg))
            self.root.after(0, self._refresh_status)
            self.root.after(0, self._refresh_tables)
            self.root.after(0, self._refresh_live_devices)
        except Exception:
            pass


def run_gui() -> None:
    db.init_db()
    root = tk.Tk()
    app = App(root)

    def on_close() -> None:
        app.monitor.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

