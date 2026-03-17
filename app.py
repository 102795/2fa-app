"""2FA App — a terminal interface for managing TOTP two-factor authentication codes."""

import getpass
import json
import os
import sys
import time

import bcrypt
import pyotp


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")


def _ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_users() -> dict:
    _ensure_data_dir()
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_users(users: dict) -> None:
    _ensure_data_dir()
    with open(USERS_FILE, "w", encoding="utf-8") as fh:
        json.dump(users, fh, indent=2)


# ---------------------------------------------------------------------------
# Account management
# ---------------------------------------------------------------------------

def create_account(username: str, password: str) -> tuple[bool, str]:
    """Create a new user account.

    Returns (success, message).
    """
    if not username or not password:
        return False, "Username and password must not be empty."

    users = _load_users()
    if username in users:
        return False, f"Username '{username}' is already taken."

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {"password_hash": hashed, "keys": {}}
    _save_users(users)
    return True, "Account created successfully."


def login(username: str, password: str) -> tuple[bool, str]:
    """Verify credentials.

    Returns (success, message).
    """
    if not username or not password:
        return False, "Username and password must not be empty."

    users = _load_users()
    user = users.get(username)
    if user is None:
        return False, "Invalid username or password."

    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return False, "Invalid username or password."

    return True, "Login successful."


# ---------------------------------------------------------------------------
# 2FA key management
# ---------------------------------------------------------------------------

def add_key(username: str, key_name: str, secret: str) -> tuple[bool, str]:
    """Add (or replace) a TOTP secret for *username* under *key_name*.

    The secret is validated by attempting to generate a TOTP code before saving.
    Returns (success, message).
    """
    secret = secret.strip().upper().replace(" ", "")
    if not key_name:
        return False, "Key name must not be empty."

    try:
        totp = pyotp.TOTP(secret)
        totp.now()  # validate the secret is usable
    except Exception:
        return False, "Invalid secret key. Please provide a valid Base32 TOTP secret."

    users = _load_users()
    if username not in users:
        return False, "User not found."

    users[username]["keys"][key_name] = secret
    _save_users(users)
    return True, f"Key '{key_name}' saved."


def delete_key(username: str, key_name: str) -> tuple[bool, str]:
    """Delete a TOTP key for *username*. Returns (success, message)."""
    users = _load_users()
    if username not in users:
        return False, "User not found."
    if key_name not in users[username]["keys"]:
        return False, f"Key '{key_name}' not found."
    del users[username]["keys"][key_name]
    _save_users(users)
    return True, f"Key '{key_name}' deleted."


def get_codes(username: str) -> list[dict]:
    """Return current TOTP codes for all keys of *username*.

    Each entry is a dict with keys: name, code, seconds_remaining.
    """
    users = _load_users()
    user = users.get(username, {})
    results = []
    for name, secret in user.get("keys", {}).items():
        try:
            totp = pyotp.TOTP(secret)
            code = totp.now()
            remaining = 30 - (int(time.time()) % 30)
        except Exception:
            code = "ERROR"
            remaining = 0
        results.append({"name": name, "code": code, "seconds_remaining": remaining})
    return results


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _print_header(title: str) -> None:
    width = 50
    print("=" * width)
    print(title.center(width))
    print("=" * width)


def _prompt(label: str, secret: bool = False) -> str:
    if secret:
        return getpass.getpass(f"  {label}: ")
    return input(f"  {label}: ").strip()


def _pause() -> None:
    input("\n  Press Enter to continue...")


# ---------------------------------------------------------------------------
# CLI screens
# ---------------------------------------------------------------------------

def screen_main_menu():
    """Display the main menu and return the chosen username on login/create, or None."""
    while True:
        _clear()
        _print_header("2FA App")
        print()
        print("  [1] Create Account")
        print("  [2] Login")
        print("  [3] Exit")
        print()
        choice = input("  Select an option: ").strip()

        if choice == "1":
            _clear()
            _print_header("Create Account")
            print()
            username = _prompt("Username")
            password = _prompt("Password", secret=True)
            confirm = _prompt("Confirm Password", secret=True)
            if password != confirm:
                print("\n  Passwords do not match.")
                _pause()
                continue
            ok, msg = create_account(username, password)
            print(f"\n  {msg}")
            _pause()

        elif choice == "2":
            _clear()
            _print_header("Login")
            print()
            username = _prompt("Username")
            password = _prompt("Password", secret=True)
            ok, msg = login(username, password)
            print(f"\n  {msg}")
            if ok:
                _pause()
                return username
            _pause()

        elif choice == "3":
            return None

        else:
            print("\n  Invalid choice.")
            _pause()


def screen_dashboard(username: str) -> None:
    """Main dashboard for a logged-in user."""
    while True:
        _clear()
        _print_header(f"Dashboard — {username}")
        print()
        print("  [1] View 2FA Codes")
        print("  [2] Add Security Key")
        print("  [3] Delete Security Key")
        print("  [4] Logout")
        print()
        choice = input("  Select an option: ").strip()

        if choice == "1":
            screen_view_codes(username)
        elif choice == "2":
            screen_add_key(username)
        elif choice == "3":
            screen_delete_key(username)
        elif choice == "4":
            break
        else:
            print("\n  Invalid choice.")
            _pause()


def screen_view_codes(username: str) -> None:
    """Display current TOTP codes and auto-refresh every second."""
    _clear()
    _print_header("2FA Codes  (press Ctrl+C to return)")
    print()

    codes = get_codes(username)
    if not codes:
        print("  No security keys added yet.")
        _pause()
        return

    try:
        while True:
            _clear()
            _print_header("2FA Codes  (press Ctrl+C to return)")
            print()
            codes = get_codes(username)
            for entry in codes:
                bar = "█" * entry["seconds_remaining"] + "░" * (
                    30 - entry["seconds_remaining"]
                )
                print(f"  {entry['name']:<20}  {entry['code']}  [{bar}] {entry['seconds_remaining']:>2}s")
            print()
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def screen_add_key(username: str) -> None:
    """Prompt for a new TOTP key and save it."""
    _clear()
    _print_header("Add Security Key")
    print()
    key_name = _prompt("Key name (e.g. GitHub)")
    secret = _prompt("Secret key (Base32 TOTP secret)")
    ok, msg = add_key(username, key_name, secret)
    print(f"\n  {msg}")
    _pause()


def screen_delete_key(username: str) -> None:
    """Delete an existing TOTP key."""
    codes = get_codes(username)
    if not codes:
        print("\n  No keys to delete.")
        _pause()
        return

    _clear()
    _print_header("Delete Security Key")
    print()
    for i, entry in enumerate(codes, 1):
        print(f"  [{i}] {entry['name']}")
    print(f"  [{len(codes) + 1}] Cancel")
    print()
    choice = input("  Select a key to delete: ").strip()
    try:
        idx = int(choice) - 1
        if idx == len(codes):
            return
        if 0 <= idx < len(codes):
            ok, msg = delete_key(username, codes[idx]["name"])
            print(f"\n  {msg}")
        else:
            print("\n  Invalid choice.")
    except ValueError:
        print("\n  Invalid choice.")
    _pause()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        while True:
            username = screen_main_menu()
            if username is None:
                print("\n  Goodbye!\n")
                sys.exit(0)
            screen_dashboard(username)
    except (KeyboardInterrupt, EOFError):
        print("\n\n  Goodbye!\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
