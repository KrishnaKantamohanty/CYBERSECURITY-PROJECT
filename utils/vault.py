import base64
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils.hashing import hash_password, verify_password

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "vault.db"
KEY_PATH = PROJECT_ROOT / "data" / "vault_key.bin"
SALT_PATH = PROJECT_ROOT / "data" / "vault_salt.bin"


def _ensure_storage():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)


def initialize():
    _ensure_storage()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY,
            password_hash BLOB NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password_blob BLOB NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def _get_connection():
    return sqlite3.connect(DB_PATH)


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=260_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _read_file(path: Path) -> bytes:
    return path.read_bytes()


def _write_file(path: Path, data: bytes):
    path.write_bytes(data)


def has_master_password() -> bool:
    initialize()
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM master")
    exists = cursor.fetchone()[0] > 0
    conn.close()
    return exists


def set_master_password(master_password: str):
    initialize()
    if has_master_password():
        raise RuntimeError("A master password already exists.")
    if not master_password:
        raise ValueError("Master password must not be empty.")

    salt = os.urandom(16)
    vault_key = Fernet.generate_key()
    key_encryption = _derive_key(master_password, salt)
    encrypted_vault_key = Fernet(key_encryption).encrypt(vault_key)

    _write_file(SALT_PATH, salt)
    _write_file(KEY_PATH, encrypted_vault_key)

    hashed_password = hash_password(master_password)
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO master (password_hash) VALUES (?)", (hashed_password,))
    conn.commit()
    conn.close()


def _load_fernet(master_password: str) -> Fernet:
    if not SALT_PATH.exists() or not KEY_PATH.exists():
        raise RuntimeError("Vault storage is missing or not initialized.")

    salt = _read_file(SALT_PATH)
    encrypted_vault_key = _read_file(KEY_PATH)
    key_encryption = _derive_key(master_password, salt)
    vault_key = Fernet(key_encryption).decrypt(encrypted_vault_key)
    return Fernet(vault_key)


def verify_master_password(master_password: str) -> bool:
    if not has_master_password():
        return False
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM master ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    if not row:
        return False
    return verify_password(master_password, row[0])


def unlock_vault(master_password: str) -> Fernet:
    if not verify_master_password(master_password):
        raise ValueError("Invalid master password.")
    return _load_fernet(master_password)


def add_entry(
    fernet: Fernet,
    service: str,
    username: str,
    password: str,
    notes: str | None = None,
):
    if not service or not username or not password:
        raise ValueError("Service, username, and password are required.")

    encrypted_password = fernet.encrypt(password.encode("utf-8"))
    timestamp = datetime.utcnow().isoformat()
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO vault_entries (
            service, username, password_blob, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (service.strip(), username.strip(), encrypted_password, notes or "", timestamp, timestamp),
    )
    conn.commit()
    conn.close()


def _decrypt_password(fernet: Fernet, blob: bytes) -> str:
    return fernet.decrypt(blob).decode("utf-8")


def list_entries(fernet: Fernet) -> list[dict]:
    conn = _get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vault_entries ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()

    entries = []
    for row in rows:
        try:
            decrypted_password = _decrypt_password(fernet, row["password_blob"])
        except Exception:
            decrypted_password = "[decryption failed]"
        entries.append(
            {
                "id": row["id"],
                "service": row["service"],
                "username": row["username"],
                "password": decrypted_password,
                "notes": row["notes"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return entries


def search_entries(fernet: Fernet, query: str) -> list[dict]:
    entries = list_entries(fernet)
    query = query.strip().lower()
    if not query:
        return entries
    return [
        entry
        for entry in entries
        if query in entry["service"].lower() or query in entry["username"].lower()
    ]


def delete_entry(entry_id: int):
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
