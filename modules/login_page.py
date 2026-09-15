"""
Full-screen login / register gate for the Cybersecurity Security Center.
Credentials are persisted in vault.db (app_users table) using bcrypt hashing.
TOTP state is also read from / written to the database.
"""
import pyotp
import streamlit as st

from utils.auth_db import (
    register_user,
    user_exists,
    verify_user,
    get_totp_info,
)
from utils.security import record_activity
from utils.validation import is_valid_username, is_valid_password
from modules.security_events import log_event


# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

def _init_auth_state() -> None:
    defaults = {
        "app_logged_in": False,
        "stored_user": "",
        # kept for intra-app compatibility (sidebar, authentication.py, etc.)
        "logged_in": False,
        "2fa_enabled": False,
        "2fa_secret": "",
        "_login_tab": "signin",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def _sync_totp_from_db(username: str) -> None:
    """Load persisted TOTP state into session state after login."""
    info = get_totp_info(username)
    st.session_state["2fa_enabled"] = info["enabled"]
    st.session_state["2fa_secret"] = info["secret"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_authenticated() -> bool:
    return bool(st.session_state.get("app_logged_in", False))


def logout() -> None:
    user = st.session_state.get("stored_user", "")
    for key in ("app_logged_in", "logged_in"):
        st.session_state[key] = False
    record_activity(f"User '{user}' logged out of Security Center", "auth")
    log_event("LOGOUT", f"User '{user}' signed out", "INFO")
    st.rerun()


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def _render_logo_banner() -> None:
    st.markdown(
        """
        <div style="text-align:center; padding: 2rem 1rem 1rem;">
            <div style="
                display: inline-flex; align-items: center; justify-content: center;
                width: 90px; height: 90px;
                background: radial-gradient(circle at top left, rgba(0,255,255,0.28), rgba(4,20,36,0.92));
                border-radius: 16px; border: 1px solid rgba(0,255,255,0.28);
                font-size: 3rem; box-shadow: 0 0 40px rgba(0,255,255,0.20);
                margin-bottom: 1rem;
            ">🛡️</div>
            <h1 style="
                margin: 0; font-size: 2.1rem; letter-spacing: 0.4px;
                background: linear-gradient(90deg, #6ee7b7 0%, #22d3ee 100%);
                -webkit-background-clip: text; -webkit-text-fill-color: transparent;
                background-clip: text;
            ">Cybersecurity Security Center</h1>
            <p style="margin: 0.4rem 0 0; font-size: 0.95rem; opacity: 0.65; letter-spacing: 0.3px;">
                Defensive Cybersecurity Platform — Protected Access
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_feature_pills() -> None:
    features = [
        ("🔐", "Password Vault"),
        ("🔑", "2FA / TOTP"),
        ("🔒", "Encryption"),
        ("🦠", "Malware Scan"),
        ("🌐", "Network & IOC"),
        ("🚨", "Risk Engine"),
    ]
    cols = st.columns(len(features))
    for col, (icon, label) in zip(cols, features):
        col.markdown(
            f"""
            <div style="
                background: rgba(255,255,255,0.04);
                border: 1px solid rgba(0,255,255,0.12);
                border-radius: 8px; text-align:center;
                padding: 10px 4px; font-size: 0.78rem; opacity: 0.85;
            ">{icon}<br/><strong>{label}</strong></div>
            """,
            unsafe_allow_html=True,
        )


def _card_wrap(content_fn) -> None:
    st.markdown(
        """
        <div style="
            max-width: 480px; margin: 1.5rem auto 0;
            background: rgba(4, 20, 36, 0.92);
            border: 1px solid rgba(0, 255, 255, 0.16);
            border-radius: 14px; padding: 2rem 2.2rem 2.2rem;
            box-shadow: 0 24px 72px rgba(0,0,0,0.45);
            backdrop-filter: blur(10px);
        ">
        """,
        unsafe_allow_html=True,
    )
    content_fn()
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sign-in form
# ---------------------------------------------------------------------------

def _render_signin() -> None:
    st.markdown(
        """
        <h3 style="margin-top:0; color:#6ee7b7; font-size:1.25rem;">🔓 Sign In</h3>
        <p style="font-size:0.85rem; opacity:0.65; margin-bottom:1.2rem;">
            Enter your credentials to access the Security Center.
        </p>
        """,
        unsafe_allow_html=True,
    )

    username = st.text_input("Username", key="login_username_field", placeholder="Your username")
    password = st.text_input("Password", type="password", key="login_password_field", placeholder="Your password")

    # Determine if this user has 2FA enabled in DB
    totp_code = ""
    db_totp = {}
    if username.strip():
        try:
            db_totp = get_totp_info(username.strip())
        except Exception:
            db_totp = {"enabled": False, "secret": ""}

    if db_totp.get("enabled") and db_totp.get("secret"):
        st.info("🔒 **2FA Active** — Enter the 6-digit code from your authenticator app.")
        totp_code = st.text_input("TOTP Code", max_chars=6, placeholder="e.g. 123456", key="login_totp_field")

    if not user_exists(username.strip()) and username.strip():
        st.caption("💡 No account found for this username. Switch to **Register** to create one.")

    st.markdown("<br/>", unsafe_allow_html=True)

    if st.button("Sign In →", key="btn_login_submit", use_container_width=True):
        un = username.strip()
        if not un or not password.strip():
            st.error("Please enter both your username and password.")
            return

        if not user_exists(un):
            st.error("❌ No account found. Please **Register** first.")
            return

        if not verify_user(un, password):
            log_event("LOGIN_FAILED", f"Invalid password for '{un}'", "WARNING")
            st.error("❌ Incorrect username or password.")
            return

        # 2FA verification
        if db_totp.get("enabled") and db_totp.get("secret"):
            if not totp_code.strip():
                st.error("❌ 2FA is active — please enter your TOTP code.")
                return
            totp = pyotp.TOTP(db_totp["secret"])
            if not totp.verify(totp_code.strip()):
                log_event("LOGIN_FAILED_2FA", f"Bad 2FA code for '{un}'", "WARNING")
                st.error("❌ Incorrect TOTP code. Check your authenticator app.")
                return

        # ✅ SUCCESS — populate session state
        st.session_state["app_logged_in"] = True
        st.session_state["logged_in"] = True
        st.session_state["stored_user"] = un
        st.session_state["stored_password"] = password   # kept for auth.py compat
        _sync_totp_from_db(un)

        record_activity(f"Signed in: {un}", "auth")
        log_event(
            "LOGIN_SUCCESS",
            f"User '{un}' authenticated" + (" (2FA)" if db_totp.get("enabled") else ""),
            "INFO",
        )
        st.success("✅ Authenticated! Loading Security Center…")
        st.rerun()


# ---------------------------------------------------------------------------
# Register form
# ---------------------------------------------------------------------------

def _render_register() -> None:
    st.markdown(
        """
        <h3 style="margin-top:0; color:#6ee7b7; font-size:1.25rem;">📝 Create Account</h3>
        <p style="font-size:0.85rem; opacity:0.65; margin-bottom:1.2rem;">
            Register a persistent account — credentials are saved to the local database.
        </p>
        """,
        unsafe_allow_html=True,
    )

    new_username = st.text_input("Choose Username", key="reg_username_field", placeholder="3–32 characters")
    new_password = st.text_input("Choose Password", type="password", key="reg_password_field", placeholder="Minimum 8 characters")
    confirm_pw   = st.text_input("Confirm Password", type="password", key="reg_confirm_field", placeholder="Repeat password")

    st.markdown("<br/>", unsafe_allow_html=True)

    if st.button("Create Account →", key="btn_register_submit", use_container_width=True):
        un = new_username.strip()
        if not un or not new_password.strip() or not confirm_pw.strip():
            st.error("Please fill in all fields.")
            return
        if not is_valid_username(un):
            st.error("Username must be 3–32 alphanumeric or underscore characters.")
            return
        if not is_valid_password(new_password):
            st.error("Password must be at least 8 characters long.")
            return
        if new_password != confirm_pw:
            st.error("Passwords do not match.")
            return
        if user_exists(un):
            st.error(f"❌ Username **{un}** is already taken. Choose a different one or sign in.")
            return

        try:
            register_user(un, new_password)
        except ValueError as exc:
            st.error(str(exc))
            return

        record_activity(f"Account created: {un}", "auth")
        log_event("ACCOUNT_CREATED", f"New persistent account registered: {un}", "INFO")
        st.success(
            f"✅ Account **{un}** created and saved to database! "
            "Your credentials will persist across restarts. Switch to **Sign In** to log in."
        )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def render() -> None:
    """
    Render the full-screen authentication gate.
    Call at the top of app.py; check is_authenticated() after.
    """
    _init_auth_state()

    # Hide sidebar on login screen
    st.markdown(
        """
        <style>
        [data-testid="stSidebar"]   { display: none !important; }
        [data-testid="collapsedControl"] { display: none !important; }
        header { visibility: hidden; }
        footer { visibility: hidden; }
        #MainMenu { visibility: hidden; }
        </style>
        """,
        unsafe_allow_html=True,
    )

    _render_logo_banner()
    st.markdown("<br/>", unsafe_allow_html=True)
    _render_feature_pills()
    st.markdown("<br/>", unsafe_allow_html=True)

    # Tab selector
    col_a, col_b = st.columns(2)
    active_tab = st.session_state.get("_login_tab", "signin")

    with col_a:
        if st.button("🔓 Sign In", key="btn_tab_signin", use_container_width=True):
            st.session_state["_login_tab"] = "signin"
            st.rerun()
    with col_b:
        if st.button("📝 Register", key="btn_tab_register", use_container_width=True):
            st.session_state["_login_tab"] = "register"
            st.rerun()

    if active_tab == "signin":
        _card_wrap(_render_signin)
    else:
        _card_wrap(_render_register)

    st.markdown(
        """
        <p style="text-align:center; margin-top:2.5rem; font-size:0.78rem; opacity:0.45;">
        🛡️ Cybersecurity Security Center &nbsp;·&nbsp; Local Defensive Platform
        &nbsp;·&nbsp; Passwords stored as bcrypt hashes &nbsp;·&nbsp; No data leaves your machine
        </p>
        """,
        unsafe_allow_html=True,
    )
