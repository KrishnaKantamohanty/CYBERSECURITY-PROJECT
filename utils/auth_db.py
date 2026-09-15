"""
Persistent app-level user authentication backed by vault.db.

Stores: username (plaintext), password (bcrypt hash), totp_secret (plaintext, optional).
Never stores plaintext passwords.
"""
import sqlite3
from pathlib import Path

from utils.hashing import hash_password, verify_password

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "vault.db"


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------

def _ensure_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash BLOB    NOT NULL,
            totp_secret   TEXT    DEFAULT '',
            totp_enabled  INTEGER DEFAULT 0,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def user_exists(username: str) -> bool:
    """Return True if username is already registered."""
    _ensure_db()
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT 1 FROM app_users WHERE username = ?", (username.strip(),)
    ).fetchone()
    conn.close()
    return row is not None


def register_user(username: str, password: str) -> None:
    """
    Register a new user. Raises ValueError on duplicate or bad input.
    Password is stored as a bcrypt hash — never in plaintext.
    """
    _ensure_db()
    username = username.strip()
    if not username or not password:
        raise ValueError("Username and password are required.")
    if user_exists(username):
        raise ValueError(f"Username '{username}' is already registered.")

    pw_hash = hash_password(password)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO app_users (username, password_hash) VALUES (?, ?)",
        (username, pw_hash),
    )
    conn.commit()
    conn.close()


def verify_user(username: str, password: str) -> bool:
    """Return True if username/password match the stored bcrypt hash."""
    _ensure_db()
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT password_hash FROM app_users WHERE username = ?",
        (username.strip(),),
    ).fetchone()
    conn.close()
    if not row:
        return False
    return verify_password(password, row[0])


def get_totp_info(username: str) -> dict:
    """Return {'enabled': bool, 'secret': str} for the given user."""
    _ensure_db()
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT totp_enabled, totp_secret FROM app_users WHERE username = ?",
        (username.strip(),),
    ).fetchone()
    conn.close()
    if not row:
        return {"enabled": False, "secret": ""}
    return {"enabled": bool(row[0]), "secret": row[1] or ""}


def save_totp_secret(username: str, secret: str, enabled: bool) -> None:
    """Persist a TOTP secret and enabled flag for the given user."""
    _ensure_db()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE app_users SET totp_secret = ?, totp_enabled = ? WHERE username = ?",
        (secret, 1 if enabled else 0, username.strip()),
    )
    conn.commit()
    conn.close()
