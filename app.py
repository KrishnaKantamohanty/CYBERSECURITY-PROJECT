import streamlit as st
from pathlib import Path
from modules import (
    password_tools,
    password_manager,
    encryption_tools,
    authentication,
    network_tools,
    phishing_detector,
    file_integrity,
    virustotal_scanner,
    ioc_analyzer,
    risk_engine,
    alert_manager,
    security_events,
    report_generator,
    two_factor,
    security_lab,
    security_health,
    login_page,
)
from utils.theme import inject_theme, page_header, section_card
from utils.security import get_session_stats


st.set_page_config(
    page_title="Cybersecurity Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_theme()

# =============================================================================
# 🔒 AUTHENTICATION GATE
# =============================================================================
if not login_page.is_authenticated():
    login_page.render()
    st.stop()

PAGES = [
    "🏠 Dashboard",
    "🔐 Identity & Passwords",
    "🔑 Authentication & 2FA",
    "🔒 Encryption & Cipher",
    "🦠 Malware & File Security",
    "🌐 Network & Web Security",
    "🚨 Security Center & Risk Engine",
    "📊 Reports & Exporter",
    "🧪 Security Lab",
    "⚙️ Settings",
    "📖 About & Security Health",
]


def set_page(page: str) -> None:
    st.session_state.selected_page = page


if "selected_page" not in st.session_state:
    st.session_state.selected_page = "🏠 Dashboard"

selected_index = (
    PAGES.index(st.session_state.selected_page)
    if st.session_state.selected_page in PAGES
    else 0
)

# Sidebar Header
st.sidebar.markdown(
    """
    <div style="text-align: center; padding: 10px 0 18px 0; border-bottom: 1px solid rgba(0, 255, 255, 0.16);">
        <div style="font-size: 2.2rem; margin-bottom: 4px;">🛡️</div>
        <h3 style="margin: 0; color: #6ee7b7; font-size: 1.15rem; letter-spacing: 0.5px;">SECURITY CENTER</h3>
        <p style="font-size: 0.78rem; opacity: 0.7; margin: 2px 0 0 0;">Defensive Cybersecurity Platform</p>
    </div>
    """,
    unsafe_allow_html=True,
)

choice = st.sidebar.radio(
    "Navigation",
    PAGES,
    index=selected_index,
)
set_page(choice)

# Sidebar Quick Status Footer
st.sidebar.markdown("---")
current_user = st.session_state.get("stored_user", "")
is_2fa_enabled = st.session_state.get("2fa_enabled", False)

session_str = f"Session: {current_user if current_user else 'Active User'}"
tfa_str = "🔐 2FA: 🟢 Enabled" if is_2fa_enabled else "2FA: ⚠️ Disabled"

st.sidebar.markdown(
    f"""
    <div style="font-size: 0.88rem; padding: 6px 0;">
        <p style="margin: 0 0 4px 0;"><strong>{session_str}</strong></p>
        <p style="margin: 0;"><strong>{tfa_str}</strong></p>
    </div>
    """,
    unsafe_allow_html=True,
)

if st.sidebar.button("🚪 Log Out", key="sidebar_logout_btn", use_container_width=True):
    login_page.logout()

# =============================================================================
# 🏠 DASHBOARD PAGE
# =============================================================================
if choice == "🏠 Dashboard":
    page_header(
        "Cybersecurity Security Center",
        "Unified interactive defensive security platform — live session monitoring, threat intelligence, and security scoring.",
        "🛡️",
    )

    score, rating, breakdown = risk_engine.calculate_overall_security_score()
    session_data = get_session_stats()
    stats = session_data["stats"]
    activities = session_data["recent_activity"]
    findings = risk_engine.get_all_findings()

    # 1. OVERALL SECURITY SCORE BANNER
    score_color = "#10b981" if score >= 85 else "#3b82f6" if score >= 70 else "#eab308" if score >= 50 else "#ef4444"
    st.markdown(
        f"""
        <div class="result-card" style="background: radial-gradient(circle at top left, rgba(0, 255, 255, 0.12), rgba(4, 20, 36, 0.95)); border: 1px solid rgba(0, 255, 255, 0.25);">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                    <h4 style="color: #94a3b8; text-transform: uppercase; letter-spacing: 0.1em; margin: 0 0 6px 0;">OVERALL SECURITY SCORE</h4>
                    <div style="font-size: 3.2rem; font-weight: 900; color: {score_color}; line-height: 1;">
                        {score} <span style="font-size: 1.5rem; color: #94a3b8; font-weight: 500;">/ 100</span>
                    </div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: {score_color}; margin-top: 6px;">
                        STATUS: {rating}
                    </div>
                </div>
                <div style="max-width: 480px;">
                    <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">
                        Calculated deterministically from live application findings (Password strength, 2FA enforcement, VirusTotal detections, Phishing flags, and File integrity checks).
                    </p>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("ℹ️ How the Security Score was Calculated", expanded=False):
        st.dataframe(breakdown, use_container_width=True, hide_index=True)

    st.markdown("---")

    # 2. THREAT SEVERITY COUNTERS ROW
    st.subheader("Threat Status Overview")
    crit_cnt = len([f for f in findings if f["severity"] == "CRITICAL"])
    high_cnt = len([f for f in findings if f["severity"] == "HIGH"])
    med_cnt = len([f for f in findings if f["severity"] == "MEDIUM"])
    low_cnt = len([f for f in findings if f["severity"] == "LOW"])
    info_cnt = len([f for f in findings if f["severity"] == "INFO"])

    t1, t2, t3, t4, t5 = st.columns(5)
    t1.metric("Critical 🚨", str(crit_cnt))
    t2.metric("High ⚠️", str(high_cnt))
    t3.metric("Medium ⚡", str(med_cnt))
    t4.metric("Low ℹ️", str(low_cnt))
    t5.metric("Informational", str(info_cnt))

    st.markdown("---")

    # 3. INTERACTIVE DASHBOARD CARDS GRID
    st.subheader("Security Controls & Modules")
    st.caption("Click any card button to switch directly to the corresponding security module.")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(
            """
            <div class="result-card" style="min-height: 180px;">
                <h4 style="margin-top:0; color:#6ee7b7;">🔐 Password Security</h4>
                <p style="font-size:0.88rem; opacity:0.85;">Strength evaluation, secure random generator, and encrypted local vault.</p>
                <div style="font-size:0.82rem; color:#6ee7b7; margin-top:10px;">● Status: Active</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open Identity & Passwords", key="dash_btn_pwd", use_container_width=True):
            set_page("🔐 Identity & Passwords")
            st.rerun()

    with c2:
        st.markdown(
            """
            <div class="result-card" style="min-height: 180px;">
                <h4 style="margin-top:0; color:#6ee7b7;">🔑 Authentication & 2FA</h4>
                <p style="font-size:0.88rem; opacity:0.85;">User registration, bcrypt password practice, and TOTP Two-Factor setup.</p>
                <div style="font-size:0.82rem; color:#6ee7b7; margin-top:10px;">● Status: Active</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open Authentication", key="dash_btn_auth", use_container_width=True):
            set_page("🔑 Authentication & 2FA")
            st.rerun()

    with c3:
        st.markdown(
            """
            <div class="result-card" style="min-height: 180px;">
                <h4 style="margin-top:0; color:#6ee7b7;">🔒 File Encryption</h4>
                <p style="font-size:0.88rem; opacity:0.85;">Authenticated file encryption (PBKDF2 + Fernet) & Caesar cipher demo.</p>
                <div style="font-size:0.82rem; color:#6ee7b7; margin-top:10px;">● Status: Active</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open Encryption", key="dash_btn_enc", use_container_width=True):
            set_page("🔒 Encryption & Cipher")
            st.rerun()

    c4, c5, c6 = st.columns(3)

    with c4:
        st.markdown(
            """
            <div class="result-card" style="min-height: 180px;">
                <h4 style="margin-top:0; color:#6ee7b7;">🦠 Malware & File Security</h4>
                <p style="font-size:0.88rem; opacity:0.85;">SHA-256 integrity digests & VirusTotal multi-engine malware analysis.</p>
                <div style="font-size:0.82rem; color:#6ee7b7; margin-top:10px;">● Status: Active</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open Malware Scanner", key="dash_btn_malware", use_container_width=True):
            set_page("🦠 Malware & File Security")
            st.rerun()

    with c5:
        st.markdown(
            """
            <div class="result-card" style="min-height: 180px;">
                <h4 style="margin-top:0; color:#6ee7b7;">🌐 Web Security & IOC</h4>
                <p style="font-size:0.88rem; opacity:0.85;">IP geolocation, phishing heuristics, and automated IOC classification.</p>
                <div style="font-size:0.82rem; color:#6ee7b7; margin-top:10px;">● Status: Active</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open Network & Web Security", key="dash_btn_net", use_container_width=True):
            set_page("🌐 Network & Web Security")
            st.rerun()

    with c6:
        st.markdown(
            """
            <div class="result-card" style="min-height: 180px;">
                <h4 style="margin-top:0; color:#6ee7b7;">🚨 Security Center & Risk</h4>
                <p style="font-size:0.88rem; opacity:0.85;">Central risk engine, alerts, audit event logging, and MITRE ATT&CK mapping.</p>
                <div style="font-size:0.82rem; color:#6ee7b7; margin-top:10px;">● Status: Active</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open Security Center", key="dash_btn_sec_center", use_container_width=True):
            set_page("🚨 Security Center & Risk Engine")
            st.rerun()

    st.markdown("---")

    # 4. RECENT SESSION ACTIVITY LOG
    st.subheader("Recent Session Activity")
    if activities:
        for item in activities[:6]:
            st.markdown(
                f"""
                <div class="activity-item">
                    <span>✓ {item['action']}</span>
                    <span class="activity-time">{item['time']}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.info("No activity recorded yet in this session. Try using any tool above!")

# =============================================================================
# 🔐 IDENTITY & PASSWORDS PAGE
# =============================================================================
elif choice == "🔐 Identity & Passwords":
    tab1, tab2 = st.tabs(["Password Tools", "Local Encrypted Vault"])
    with tab1:
        password_tools.render()
    with tab2:
        password_manager.render()

# =============================================================================
# 🔑 AUTHENTICATION & 2FA PAGE
# =============================================================================
elif choice == "🔑 Authentication & 2FA":
    tab1, tab2 = st.tabs(["User Authentication Practice", "Two-Factor Authentication (2FA)"])
    with tab1:
        authentication.render()
    with tab2:
        two_factor.render()

# =============================================================================
# 🔒 ENCRYPTION & CIPHER PAGE
# =============================================================================
elif choice == "🔒 Encryption & Cipher":
    encryption_tools.render()

# =============================================================================
# 🦠 MALWARE & FILE SECURITY PAGE
# =============================================================================
elif choice == "🦠 Malware & File Security":
    file_integrity.render()

# =============================================================================
# 🌐 NETWORK & WEB SECURITY PAGE
# =============================================================================
elif choice == "🌐 Network & Web Security":
    tab1, tab2 = st.tabs(["Network & Phishing Tools", "IOC Analyzer"])
    with tab1:
        network_tools.render()
        st.markdown("---")
        phishing_detector.render()
    with tab2:
        ioc_analyzer.render()

# =============================================================================
# 🚨 SECURITY CENTER & RISK ENGINE PAGE
# =============================================================================
elif choice == "🚨 Security Center & Risk Engine":
    tab1, tab2 = st.tabs(["Alert Center & Risk Engine", "Security Event Log"])
    with tab1:
        alert_manager.render()
    with tab2:
        security_events.render()

# =============================================================================
# 📊 REPORTS & EXPORTER PAGE
# =============================================================================
elif choice == "📊 Reports & Exporter":
    report_generator.render()

# =============================================================================
# 🧪 SECURITY LAB PAGE
# =============================================================================
elif choice == "🧪 Security Lab":
    security_lab.render()

# =============================================================================
# ⚙️ SETTINGS PAGE
# =============================================================================
elif choice == "⚙️ Settings":
    page_header(
        "Toolkit Settings & Configuration",
        "Centralized session configuration and preferences for the Cybersecurity Security Center.",
        "⚙️",
    )

    st.subheader("VirusTotal API Key Configuration")
    api_key = virustotal_scanner.get_api_key()
    if api_key:
        st.success("✅ **VirusTotal API Key Active**: API key detected and configured.")
    else:
        st.warning("⚠️ **No VirusTotal API Key**: Enter key below or set `VIRUSTOTAL_API_KEY` in environment variables.")

    new_key = st.text_input("Session VirusTotal API Key", type="password", value=st.session_state.get("vt_api_key_override", ""))
    if st.button("Save Session Key", key="btn_save_vt_key"):
        st.session_state.vt_api_key_override = new_key.strip()
        st.success("Session API key saved.")
        st.rerun()

    st.markdown("---")
    st.subheader("Session & Limits Preferences")
    c1, c2 = st.columns(2)
    with c1:
        st.text_input("Maximum File Upload Limit (MB)", value="50", disabled=True, help="Configured in utils/encryption.py")
    with c2:
        st.text_input("Analysis Polling Timeout (Seconds)", value="120", disabled=True, help="Configured in modules/virustotal_scanner.py")

# =============================================================================
# 📖 ABOUT & SECURITY HEALTH PAGE
# =============================================================================
elif choice == "📖 About & Security Health":
    tab1, tab2 = st.tabs(["Application Security Health Check", "About Project"])
    with tab1:
        security_health.render()
    with tab2:
        page_header(
            "About Cybersecurity Security Center",
            "A unified defensive cybersecurity platform for learning, analysis, and threat detection.",
            "📖",
        )
        section_card(
            """
            <strong>Platform Architecture & Design</strong>
            <p>The Cybersecurity Security Center is built locally using Python 3.11+, Streamlit, and SQLite. It provides modular defensive controls spanning identity management, authentication, encryption, malware scanning, network safety, and risk assessment.</p>
            <ul>
                <li><strong>Cryptographic Randomness:</strong> Password generation utilizes the Python <code>secrets</code> module.</li>
                <li><strong>Local Vault Security:</strong> Password vault relies on PBKDF2 key derivation and Fernet authenticated encryption.</li>
                <li><strong>Threat Intelligence:</strong> VirusTotal API v3 multi-engine scanning with explicit user consent & hash pre-checks.</li>
                <li><strong>Defensive Focus:</strong> Passive heuristics, zero offensive scanning, no execution of uploaded payloads.</li>
            </ul>
            """
        )
