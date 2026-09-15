import io
import pyotp
import qrcode
import streamlit as st
from utils.theme import page_header
from utils.security import record_activity
from utils.auth_db import save_totp_secret
from modules.security_events import log_event


def render():
    page_header(
        "Two-Factor Authentication (2FA)",
        "Configure and verify Time-based One-Time Passwords (TOTP) compatible with Google Authenticator, Microsoft Authenticator, or Authy.",
        "🔑",
    )

    if "2fa_secret" not in st.session_state:
        st.session_state["2fa_secret"] = ""
    if "2fa_enabled" not in st.session_state:
        st.session_state["2fa_enabled"] = False

    user_name = st.session_state.get("stored_user", "User") or "User"

    st.subheader("2FA Configuration Status")
    col_status, col_btn = st.columns([2, 1])
    with col_status:
        if st.session_state["2fa_enabled"]:
            st.success("✅ **2FA Enabled**: Two-Factor Authentication is active for your account.")
        else:
            st.warning("⚠️ **2FA Disabled**: Two-Factor Authentication is not yet activated.")

    with col_btn:
        if st.session_state["2fa_enabled"]:
            if st.button("Disable 2FA", key="btn_disable_2fa"):
                st.session_state["2fa_enabled"] = False
                st.session_state["2fa_secret"] = ""
                # persist to DB
                username = st.session_state.get("stored_user", "")
                if username:
                    save_totp_secret(username, "", False)
                record_activity("2FA disabled", "auth")
                log_event("2FA_DISABLED", f"Two-Factor Authentication disabled for user '{user_name}'", "MEDIUM")
                st.rerun()

    st.markdown("---")

    if not st.session_state["2fa_enabled"]:
        st.subheader("Setup Authenticator App")
        st.write("Scan the QR code below using Google Authenticator, Microsoft Authenticator, Authy, or 1Password, then enter the 6-digit TOTP code to verify and enable 2FA.")

        if not st.session_state["2fa_secret"]:
            if st.button("Generate TOTP Secret & QR Code", key="btn_gen_2fa_secret"):
                st.session_state["2fa_secret"] = pyotp.random_base32()
                record_activity("2FA secret generated", "auth")
                st.rerun()

        secret = st.session_state["2fa_secret"]
        if secret:
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(name=user_name, issuer_name="CyberSecurity Security Center")

            # Generate QR Code image
            qr_img = qrcode.make(provisioning_uri)
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")

            c1, c2 = st.columns([1, 2])
            with c1:
                st.image(buf.getvalue(), caption="Scan QR Code in Authenticator App", width=220)
            with c2:
                st.markdown(
                    f"""
                    <div class="result-card">
                        <h4 style="margin-top:0; color:#6ee7b7;">Manual Secret Key</h4>
                        <code style="font-size:1.2rem; color:#6ee7b7; padding:8px 14px; background:rgba(0,0,0,0.4); border-radius:6px; display:inline-block; word-break:break-all;">{secret}</code>
                        <p style="margin-top:10px; font-size:0.88rem; opacity:0.85;">If you cannot scan the QR code, manually type or paste this secret key into your authenticator app.</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.markdown("---")
            st.subheader("Verify 6-Digit TOTP Code")
            otp_code = st.text_input("Enter 6-Digit Code from Authenticator", max_chars=6, placeholder="e.g. 123456", key="otp_input_field")

            if st.button("Verify & Enable 2FA", key="btn_verify_otp"):
                if not otp_code.strip():
                    st.error("Please enter the 6-digit code from your authenticator app.")
                elif totp.verify(otp_code.strip()):
                    st.session_state["2fa_enabled"] = True
                    # persist to DB
                    username = st.session_state.get("stored_user", "")
                    if username:
                        save_totp_secret(username, secret, True)
                    record_activity("2FA successfully verified and enabled", "auth")
                    log_event("2FA_ENABLED", f"Two-Factor Authentication verified and activated for '{user_name}'", "INFO")
                    st.success("🎉 **2FA Activated Successfully!** Two-Factor Authentication is now enforced for your account.")
                    st.rerun()
                else:
                    st.error("❌ **Invalid TOTP Code**: The code entered is incorrect or expired. Please check your device clock and try again.")
    else:
        st.subheader("Test Active 2FA Verification")
        st.write("Test verification with your active authenticator app:")
        test_code = st.text_input("Enter current 6-digit TOTP code", max_chars=6, key="test_otp_input")
        if st.button("Test Code", key="btn_test_otp"):
            totp = pyotp.TOTP(st.session_state["2fa_secret"])
            if totp.verify(test_code.strip()):
                st.success("✅ **Code Verified!** TOTP code matched successfully.")
            else:
                st.error("❌ **Verification Failed**: Invalid or expired TOTP code.")
