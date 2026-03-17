# 2FA App

A simple Python desktop GUI app to:

- Create an account
- Log in
- Open a desktop dashboard
- Enter a TOTP security key
- View current 2FA codes and expiration time

The app uses Tkinter for the GUI and SQLite for account storage.

## Requirements

- Python 3.10+

## Run locally

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Start the app:

```bash
python app.py
```

3. Use the desktop window to create accounts, log in, and generate TOTP codes.

## Notes

- User accounts are stored in `users.db`.
- Passwords are hashed with PBKDF2-HMAC-SHA256 + random salt.
- The dashboard expects a valid Base32 TOTP secret key.