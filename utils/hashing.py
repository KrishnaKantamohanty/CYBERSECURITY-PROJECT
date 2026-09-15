import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password with bcrypt and a random salt."""
    if not password:
        raise ValueError("Password must not be empty.")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def verify_password(password: str, password_hash: bytes) -> bool:
    """Verify a password against its bcrypt hash."""
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash)
    except ValueError:
        return False
