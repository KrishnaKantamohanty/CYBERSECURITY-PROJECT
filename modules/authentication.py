import pyotp
import streamlit as st
from utils.security import generate_password, record_activity
from utils.validation import is_valid_username, is_valid_password
from utils.theme import page_header
from modules.security_events import log_event


def render():
    page_header(
        "Authentication Demo",
        "Experiment with login controls and a secure local auth flow.",
        "👤",
    )

    if "stored_user" not in st.session_state:
        st.session_state.stored_user = ""
        st.session_state.stored_password = ""
        st.session_state.logged_in = False
    if "2fa_enabled" not in st.session_state:
        st.session_state["2fa_enabled"] = False
    if "2fa_secret" not in st.session_state:
        st.session_state["2fa_secret"] = ""

    tab1, tab2 = st.tabs(["Create account", "Sign in"])

    with tab1:
        username = st.text_input("New username", key="new_username")
        password = st.text_input("New password", type="password", key="new_password")
        confirm = st.text_input("Confirm password", type="password", key="confirm_password")

        if st.button("Create account"):
            if not is_valid_username(username):
                st.error("Enter a valid username.")
            elif not is_valid_password(password):
                st.error("Password must be at least 8 characters.")
            elif password != confirm:
                st.error("Passwords do not match.")
            else:
                st.session_state.stored_user = username
                st.session_state.stored_password = password
                record_activity(f"User account created: {username}", "auth")
                log_event("ACCOUNT_CREATED", f"User registered account: {username}", "INFO")
                st.success("Account created successfully. Use the Sign in tab to log in.")

    with tab2:
        username = st.text_input("Username", key="signin_username")
        password = st.text_input("Password", type="password", key="signin_password")

        tfa_enabled = st.session_state.get("2fa_enabled", False)
        tfa_secret = st.session_state.get("2fa_secret", "")

        if tfa_enabled and tfa_secret:
            st.info("🔒 **Two-Factor Authentication (2FA) is Active**: Enter the 6-digit code from your authenticator app.")
            totp_code = st.text_input("6-Digit TOTP Code", max_chars=6, placeholder="e.g. 123456", key="signin_totp_code")
        else:
            totp_code = ""

        if st.button("Sign in"):
            if not username or not password:
                st.error("Please enter your username and password.")
            elif username == st.session_state.stored_user and password == st.session_state.stored_password:
                if tfa_enabled and tfa_secret:
                    if not totp_code.strip():
                        st.error("❌ 2FA Required: Please enter the 6-digit code from your authenticator app.")
                    else:
                        totp = pyotp.TOTP(tfa_secret)
                        if totp.verify(totp_code.strip()):
                            st.session_state.logged_in = True
                            record_activity("Signed in with password + 2FA", "auth")
                            log_event("LOGIN_SUCCESS", f"User '{username}' logged in successfully with 2FA", "INFO")
                            st.success("Signed in successfully with 2FA verification.")
                            st.rerun()
                        else:
                            log_event("LOGIN_FAILED_2FA", f"Failed 2FA verification for user '{username}'", "WARNING")
                            st.error("❌ Incorrect 2FA TOTP Code. Authentication failed.")
                else:
                    st.session_state.logged_in = True
                    record_activity("Signed in successfully", "auth")
                    log_event("LOGIN_SUCCESS", f"User '{username}' logged in successfully", "INFO")
                    st.success("Signed in successfully.")
                    st.rerun()
            else:
                log_event("LOGIN_FAILED", f"Failed login attempt for username '{username}'", "WARNING")
                st.error("Incorrect username or password.")

    if st.session_state.logged_in:
        st.info(f"Logged in as **{st.session_state.stored_user}**.")
        if st.button("Log out"):
            st.session_state.logged_in = False
            record_activity("Logged out", "auth")
            log_event("LOGOUT", f"User '{st.session_state.stored_user}' logged out", "INFO")
            st.success("Logged out.")
            st.rerun()

        st.markdown("---")
        st.subheader("Password Suggestion")
        length = st.slider("Suggested password length", 12, 32, 16)
        if st.button("Generate strong password", key="auth_generate"):
            st.code(generate_password(length=length, use_upper=True, use_lower=True, use_digits=True, use_symbols=True))
