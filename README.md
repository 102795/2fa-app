# 2FA App

A simple Python 2FA web app with a user interface to:

- Create an account
- Log in
- Open a dashboard
- Enter a TOTP security key
- View current 2FA codes

The app is built with Streamlit and uses SQLite for account storage.

## Requirements

- Python 3.10+

## Run locally

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Start the app:

```bash
streamlit run app.py
```

3. Open the URL shown in the terminal (usually `http://localhost:8501`).

## Notes

- User accounts are stored in `users.db`.
- Passwords are hashed with PBKDF2-HMAC-SHA256 + random salt.
- The dashboard expects a valid Base32 TOTP secret key.