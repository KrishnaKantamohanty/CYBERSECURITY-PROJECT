import re
import urllib.parse


def is_valid_username(username: str) -> bool:
    return bool(username and 3 <= len(username.strip()) <= 100)


def is_valid_service_name(service: str) -> bool:
    return bool(service and 1 <= len(service.strip()) <= 120)


def is_valid_url(url: str) -> bool:
    try:
        result = urllib.parse.urlparse(url)
        return result.scheme in {"http", "https"} and bool(result.netloc)
    except Exception:
        return False


def is_valid_password(password: str) -> bool:
    return bool(password and len(password) >= 8)
