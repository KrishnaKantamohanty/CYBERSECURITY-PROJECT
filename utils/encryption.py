import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HEADER = b"CYBERENCRv1"
SALT_SIZE = 16
KDF_ITERATIONS = 260_000
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_bytes(password: str, data: bytes) -> bytes:
    if not password:
        raise ValueError("Encryption password must not be empty.")
    if len(data) > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"File size exceeds limit of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB.")
    salt = os.urandom(SALT_SIZE)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(data)
    return HEADER + salt + token


def decrypt_bytes(password: str, encrypted_data: bytes) -> bytes:
    if not password:
        raise ValueError("Decryption password must not be empty.")
    if not encrypted_data:
        raise ValueError("Encrypted file is empty.")

    # Check for header tag
    if encrypted_data.startswith(HEADER):
        payload = encrypted_data[len(HEADER):]
        if len(payload) < SALT_SIZE:
            raise ValueError("Decryption failed: incorrect password or corrupted encrypted file.")
        salt = payload[:SALT_SIZE]
        token = payload[SALT_SIZE:]
    else:
        # Fallback for legacy files without header
        if len(encrypted_data) < SALT_SIZE:
            raise ValueError("Decryption failed: incorrect password or corrupted encrypted file.")
        salt = encrypted_data[:SALT_SIZE]
        token = encrypted_data[SALT_SIZE:]

    try:
        key = _derive_key(password, salt)
        return Fernet(key).decrypt(token)
    except (InvalidToken, Exception):
        raise ValueError("Decryption failed: incorrect password or corrupted encrypted file.")


def encrypt_file(input_path: Path, output_path: Path, password: str) -> Path:
    if not input_path.exists():
        raise ValueError("Input file does not exist.")
    data = input_path.read_bytes()
    encrypted = encrypt_bytes(password, data)
    output_path.write_bytes(encrypted)
    return output_path


def decrypt_file(input_path: Path, output_path: Path, password: str) -> Path:
    if not input_path.exists():
        raise ValueError("Input file does not exist.")
    encrypted = input_path.read_bytes()
    decrypted = decrypt_bytes(password, encrypted)
    output_path.write_bytes(decrypted)
    return output_path

