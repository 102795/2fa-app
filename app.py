import base64
import hashlib
import hmac
import secrets
import sqlite3
import time
from pathlib import Path

import pyotp
import streamlit as st

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


def render_auth_page() -> None:
    st.title("2FA App")
    st.caption("Create an account or log in to access your 2FA dashboard.")

    signup_tab, login_tab = st.tabs(["Create Account", "Log In"])

    with signup_tab:
        with st.form("signup_form", clear_on_submit=True):
            new_username = st.text_input("Username", key="signup_username")
            new_password = st.text_input(
                "Password", type="password", key="signup_password"
            )
            signup_submit = st.form_submit_button("Create Account")

        if signup_submit:
            ok, message = create_user(new_username.strip(), new_password)
            if ok:
                st.success(message)
            else:
                st.error(message)

    with login_tab:
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            login_submit = st.form_submit_button("Log In")

        if login_submit:
            if verify_user(username.strip(), password):
                st.session_state.authenticated = True
                st.session_state.username = username.strip()
                st.success("Logged in successfully.")
                st.rerun()
            else:
                st.error("Invalid username or password.")


def render_dashboard() -> None:
    st.title("Dashboard")
    st.write(f"Welcome, **{st.session_state.username}**")

    col1, col2 = st.columns([4, 1])
    with col1:
        security_key = st.text_input(
            "Enter your TOTP security key",
            help="Use a base32 key like one from Google Authenticator setup.",
        )
    with col2:
        st.write("")
        st.write("")
        refresh_clicked = st.button("Refresh Code")

    if security_key:
        try:
            totp = pyotp.TOTP(security_key.strip().replace(" ", ""))
            code = totp.now()
            seconds_left = 30 - (int(time.time()) % 30)

            st.subheader("Current 2FA Code")
            st.code(code, language="text")
            st.info(f"Code expires in {seconds_left} seconds.")
            st.progress(seconds_left / 30)

            if refresh_clicked:
                st.rerun()
        except Exception:
            st.error("Invalid security key. Please enter a valid base32 key.")

    if st.button("Log Out"):
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.rerun()


def main() -> None:
    st.set_page_config(page_title="2FA App", page_icon="🔐", layout="centered")

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "username" not in st.session_state:
        st.session_state.username = ""

    if st.session_state.authenticated:
        render_dashboard()
    else:
        render_auth_page()


if __name__ == "__main__":
    main()
