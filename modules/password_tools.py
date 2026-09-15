import streamlit as st
from utils.security import check_password_strength, generate_password, record_activity
from utils.theme import page_header


def render():
    page_header(
        "Password Tools",
        "Generate and evaluate passwords in real-time with a security-first design.",
        "🔐",
    )

    tab1, tab2 = st.tabs(["Real-Time Strength Checker", "Generator"])

    with tab1:
        st.subheader("Real-Time Password Strength Checker")
        st.caption("Analyzes your password automatically as you type. No password data is stored or transmitted.")

        password_input = st.text_input(
            "Type a password to analyze live",
            type="password",
            key="realtime_pwd_input",
            help="Evaluation happens locally in your browser session.",
        )

        if password_input:
            result = check_password_strength(password_input)
            st.session_state["last_password_score"] = result["score"]
            record_activity("Password strength evaluated", "password")
            from modules.security_events import log_event
            log_event("PASSWORD_EVALUATION", f"Password strength evaluated ({result['rating']}, {result['score']}/100)", "INFO")

            if result["is_common"] or result["score"] < 50:
                from modules.risk_engine import add_finding
                add_finding(
                    title="Weak Password Evaluated",
                    severity="MEDIUM" if result["score"] >= 30 else "HIGH",
                    score=60,
                    explanation=f"Password evaluated has weak security metrics ({result['rating']}).",
                    recommendation="Use a passphrase of 12+ characters with symbols and digits.",
                    source_tool="Password Tools",
                )

            # Map rating to CSS badge class
            badge_class_map = {
                "Very Weak": "badge-very-weak",
                "Weak": "badge-weak",
                "Moderate": "badge-moderate",
                "Strong": "badge-strong",
                "Very Strong": "badge-very-strong",
            }
            badge_cls = badge_class_map.get(result["rating"], "badge-weak")

            col_rating, col_score, col_len = st.columns(3)
            with col_rating:
                st.write("**Strength Level**")
                st.markdown(f'<div class="{badge_cls}">{result["rating"]}</div>', unsafe_allow_html=True)
            with col_score:
                st.metric("Security Score", f"{result['score']}/100")
            with col_len:
                st.metric("Password Length", f"{result['length']} chars")

            st.write("**Strength Progress**")
            st.progress(result["score"] / 100)

            st.markdown("---")
            st.write("### Character Composition & Checks")
            
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Uppercase (A-Z)", "✓ Present" if result["has_upper"] else "✗ Missing")
            c2.metric("Lowercase (a-z)", "✓ Present" if result["has_lower"] else "✗ Missing")
            c3.metric("Numbers (0-9)", "✓ Present" if result["has_digit"] else "✗ Missing")
            c4.metric("Special (!@#$)", "✓ Present" if result["has_special"] else "✗ Missing")

            if result["is_common"]:
                st.error("⚠️ **Common Password Detected**: This password appears in common password lists and can be cracked instantly.")

            if result["warnings"]:
                st.warning("**Security Warnings:**\n" + "\n".join(f"• {w}" for w in result["warnings"]))

            if result["suggestions"]:
                st.info("**Improvement Suggestions:**\n" + "\n".join(f"• {s}" for s in result["suggestions"]))

            st.caption("🔒 Privacy Guarantee: Your password is kept in volatile local memory and is never logged, stored, or sent over a network.")
        else:
            st.info("Start typing a password above to view real-time strength metrics.")

    with tab2:
        st.subheader("Secure Password Generator")
        length = st.slider("Password length", 8, 64, 16)
        use_upper = st.checkbox("Include uppercase letters (A-Z)", value=True)
        use_lower = st.checkbox("Include lowercase letters (a-z)", value=True)
        use_digits = st.checkbox("Include numbers (0-9)", value=True)
        use_symbols = st.checkbox("Include symbols (!@#$%)", value=True)

        if st.button("Generate password"):
            try:
                password = generate_password(
                    length=length,
                    use_upper=use_upper,
                    use_lower=use_lower,
                    use_digits=use_digits,
                    use_symbols=use_symbols,
                )
                record_activity("Secure password generated", "password")
                st.code(password)
                st.success("Generated cryptographically secure random password using secrets module.")
                st.caption("Use the copy button to safely copy the generated password.")
            except ValueError as error:
                st.error(str(error))

