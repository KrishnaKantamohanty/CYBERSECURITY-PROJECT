import datetime
import secrets
import string
import streamlit as st

COMMON_PASSWORDS = {
    "123456",
    "password",
    "123456789",
    "12345678",
    "12345",
    "qwerty",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "admin",
    "welcome",
    "login",
    "pass1234",
}


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Generate a secure random password using the secrets module."""
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    character_sets = []
    if use_upper:
        character_sets.append(string.ascii_uppercase)
    if use_lower:
        character_sets.append(string.ascii_lowercase)
    if use_digits:
        character_sets.append(string.digits)
    if use_symbols:
        character_sets.append("!@#$%^&*()-_=+[]{}|;:,.<>?/~`")

    if not character_sets:
        raise ValueError("At least one character type must be enabled.")

    characters = "".join(character_sets)
    return "".join(secrets.choice(characters) for _ in range(length))


def check_password_strength(password: str) -> dict:
    """Analyze password strength and provide 5-tier ratings (Very Weak to Very Strong) and score (0-100)."""
    if not password:
        return {
            "score": 0,
            "rating": "Very Weak",
            "length": 0,
            "has_upper": False,
            "has_lower": False,
            "has_digit": False,
            "has_special": False,
            "is_common": False,
            "warnings": ["Please enter a password to evaluate."],
            "suggestions": [
                "Use at least 12 characters.",
                "Include uppercase, lowercase, numbers, and special symbols.",
            ],
        }

    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    is_common = password.lower() in COMMON_PASSWORDS

    warnings = []
    suggestions = []

    # Score calculation out of 100
    points = 0

    # Length points (up to 40)
    if length >= 16:
        points += 40
    elif length >= 12:
        points += 30
    elif length >= 8:
        points += 15
    else:
        points += max(5, length * 2)

    # Character variety (up to 40 points, 10 per character class)
    char_types = sum([has_upper, has_lower, has_digit, has_special])
    points += char_types * 10

    # Unique character count bonus (up to 20 points)
    unique_ratio = len(set(password)) / max(length, 1)
    points += int(unique_ratio * 20)

    # Penalties
    if is_common:
        points = min(points, 15)
        warnings.append("This is a commonly used, easily guessable password.")

    if length < 8:
        warnings.append("Password is shorter than 8 characters (vulnerable to brute-force).")

    if not has_upper:
        suggestions.append("Add at least one uppercase letter (A-Z).")
    if not has_lower:
        suggestions.append("Add at least one lowercase letter (a-z).")
    if not has_digit:
        suggestions.append("Add at least one number (0-9).")
    if not has_special:
        suggestions.append("Add at least one special character (!@#$%^&*).")
    if length < 12:
        suggestions.append("Increase password length to 12+ characters for improved security.")
    if is_common:
        suggestions.append("Choose a unique passphrase instead of common words.")

    score = max(0, min(100, points))

    # 5-tier visual indicators: Very Weak, Weak, Moderate, Strong, Very Strong
    if score >= 85 and not is_common and length >= 12 and char_types >= 3:
        rating = "Very Strong"
    elif score >= 65:
        rating = "Strong"
    elif score >= 45:
        rating = "Moderate"
    elif score >= 25:
        rating = "Weak"
    else:
        rating = "Very Weak"

    return {
        "score": score,
        "rating": rating,
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "is_common": is_common,
        "warnings": warnings,
        "suggestions": suggestions,
    }


def record_activity(action: str, category: str = "general") -> None:
    """Record session-only security activity and update counters safely."""
    if "recent_activity" not in st.session_state:
        st.session_state.recent_activity = []

    if "stats" not in st.session_state:
        st.session_state.stats = {
            "security_checks": 0,
            "files_processed": 0,
            "phishing_checks": 0,
            "integrity_checks": 0,
        }

    now_str = datetime.datetime.now().strftime("%H:%M:%S")
    st.session_state.recent_activity.insert(0, {"time": now_str, "action": action, "category": category})
    # Keep last 15 activities
    st.session_state.recent_activity = st.session_state.recent_activity[:15]

    st.session_state.stats["security_checks"] += 1
    if category == "file":
        st.session_state.stats["files_processed"] += 1
    elif category == "url":
        st.session_state.stats["phishing_checks"] += 1
    elif category == "integrity":
        st.session_state.stats["integrity_checks"] += 1


def get_session_stats() -> dict:
    """Retrieve session counters and recent activity list."""
    if "stats" not in st.session_state:
        st.session_state.stats = {
            "security_checks": 0,
            "files_processed": 0,
            "phishing_checks": 0,
            "integrity_checks": 0,
        }
    if "recent_activity" not in st.session_state:
        st.session_state.recent_activity = []
    return {
        "stats": st.session_state.stats,
        "recent_activity": st.session_state.recent_activity,
    }

