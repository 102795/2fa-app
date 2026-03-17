import base64
import hashlib
import hmac
import secrets
import sqlite3
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox
from tkinter import ttk

import pyotp

DB_PATH = Path(__file__).parent / "users.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    return conn


def hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return base64.b64encode(digest).decode("utf-8")


def create_user(username: str, password: str) -> tuple[bool, str]:
    if not username or not password:
        return False, "Username and password are required."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    salt = secrets.token_bytes(16)
    password_hash = hash_password(password, salt)

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
            (username, base64.b64encode(salt).decode("utf-8"), password_hash),
        )
        conn.commit()
        return True, "Account created. You can now log in."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    finally:
        conn.close()


def verify_user(username: str, password: str) -> bool:
    conn = get_connection()
    row = conn.execute(
        "SELECT salt, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if row is None:
        return False

    salt_b64, saved_hash = row
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    candidate_hash = hash_password(password, salt)
    return hmac.compare_digest(saved_hash, candidate_hash)


class TwoFAApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("2FA App")
        self.geometry("420x380")
        self.resizable(False, False)

        self.username = ""

        self.auth_frame = ttk.Frame(self, padding=16)
        self.dashboard_frame = ttk.Frame(self, padding=16)

        self._build_auth_frame()
        self._build_dashboard_frame()
        self.show_auth_frame()

    def _build_auth_frame(self) -> None:
        ttk.Label(
            self.auth_frame,
            text="Create an account or log in to access your 2FA dashboard.",
            wraplength=360,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        notebook = ttk.Notebook(self.auth_frame)
        notebook.pack(fill="both", expand=True)

        signup_tab = ttk.Frame(notebook, padding=12)
        login_tab = ttk.Frame(notebook, padding=12)

        notebook.add(signup_tab, text="Create Account")
        notebook.add(login_tab, text="Log In")

        self.signup_username_var = tk.StringVar()
        self.signup_password_var = tk.StringVar()

        ttk.Label(signup_tab, text="Username").pack(anchor="w")
        ttk.Entry(signup_tab, textvariable=self.signup_username_var).pack(
            fill="x", pady=(0, 10)
        )

        ttk.Label(signup_tab, text="Password").pack(anchor="w")
        ttk.Entry(signup_tab, textvariable=self.signup_password_var, show="*").pack(
            fill="x", pady=(0, 12)
        )

        ttk.Button(signup_tab, text="Create Account", command=self.handle_signup).pack(
            anchor="e"
        )

        self.login_username_var = tk.StringVar()
        self.login_password_var = tk.StringVar()

        ttk.Label(login_tab, text="Username").pack(anchor="w")
        ttk.Entry(login_tab, textvariable=self.login_username_var).pack(
            fill="x", pady=(0, 10)
        )

        ttk.Label(login_tab, text="Password").pack(anchor="w")
        ttk.Entry(login_tab, textvariable=self.login_password_var, show="*").pack(
            fill="x", pady=(0, 12)
        )

        ttk.Button(login_tab, text="Log In", command=self.handle_login).pack(anchor="e")

    def _build_dashboard_frame(self) -> None:
        self.welcome_label = ttk.Label(self.dashboard_frame, text="")
        self.welcome_label.pack(anchor="w", pady=(0, 12))

        self.security_key_var = tk.StringVar()
        ttk.Label(self.dashboard_frame, text="TOTP security key").pack(anchor="w")
        ttk.Entry(self.dashboard_frame, textvariable=self.security_key_var).pack(
            fill="x", pady=(0, 12)
        )

        button_row = ttk.Frame(self.dashboard_frame)
        button_row.pack(fill="x", pady=(0, 12))
        ttk.Button(button_row, text="Generate Code", command=self.handle_generate).pack(
            side="left"
        )
        ttk.Button(button_row, text="Log Out", command=self.handle_logout).pack(
            side="right"
        )

        self.code_label = ttk.Label(self.dashboard_frame, text="Current 2FA code: -")
        self.code_label.pack(anchor="w", pady=(0, 6))

        self.expires_label = ttk.Label(self.dashboard_frame, text="Code expires in: -")
        self.expires_label.pack(anchor="w")

    def show_auth_frame(self) -> None:
        self.dashboard_frame.pack_forget()
        self.auth_frame.pack(fill="both", expand=True)

    def show_dashboard_frame(self) -> None:
        self.auth_frame.pack_forget()
        self.welcome_label.config(text=f"Welcome, {self.username}")
        self.dashboard_frame.pack(fill="both", expand=True)

    def handle_signup(self) -> None:
        username = self.signup_username_var.get().strip()
        password = self.signup_password_var.get()
        ok, message = create_user(username, password)
        if ok:
            self.signup_password_var.set("")
            messagebox.showinfo("Create Account", message)
        else:
            messagebox.showerror("Create Account", message)

    def handle_login(self) -> None:
        username = self.login_username_var.get().strip()
        password = self.login_password_var.get()
        if verify_user(username, password):
            self.username = username
            self.login_password_var.set("")
            self.show_dashboard_frame()
        else:
            messagebox.showerror("Log In", "Invalid username or password.")

    def handle_generate(self) -> None:
        raw_key = self.security_key_var.get().strip()
        if not raw_key:
            messagebox.showerror("Generate Code", "Security key is required.")
            return

        try:
            totp = pyotp.TOTP(raw_key.replace(" ", ""))
            code = totp.now()
            seconds_left = 30 - (int(time.time()) % 30)
            self.code_label.config(text=f"Current 2FA code: {code}")
            self.expires_label.config(text=f"Code expires in: {seconds_left} seconds")
        except Exception:
            messagebox.showerror(
                "Generate Code", "Invalid security key. Please enter a valid base32 key."
            )

    def handle_logout(self) -> None:
        self.username = ""
        self.security_key_var.set("")
        self.code_label.config(text="Current 2FA code: -")
        self.expires_label.config(text="Code expires in: -")
        self.show_auth_frame()


def main() -> None:
    app = TwoFAApp()
    app.mainloop()


if __name__ == "__main__":
    main()
