import streamlit as st
from urllib.parse import urlparse
from utils.security import record_activity
from utils.theme import page_header


def render():
    page_header(
        "Phishing & Suspicious Link Detector",
        "Analyze URLs for phishing heuristics, deceptive patterns, and red flags.",
        "🛡️",
    )

    url = st.text_input("Enter a website URL to inspect", placeholder="e.g. http://login-paypal-verify.com.sec-update.info/login")
    if st.button("Analyze URL for Phishing Risk"):
        if not url:
            st.error("Please enter a URL to inspect.")
            return

        parsed = urlparse(url.strip())
        if not parsed.scheme or not parsed.netloc:
            st.error("The URL format is invalid. Please include http:// or https://")
            return

        record_activity(f"Phishing analysis run on {parsed.netloc}", "url")

        indicators = []
        score_penalty = 0
        hostname = parsed.hostname or ""

        if "@" in url:
            indicators.append("URL contains an '@' symbol (often used to obscure destination host).")
            score_penalty += 25
        if hostname.replace(".", "").isdigit():
            indicators.append("IP address used as hostname instead of a domain name.")
            score_penalty += 30
        if len(url) > 75:
            indicators.append("Excessively long URL (frequently used in phishing to obscure real domain).")
            score_penalty += 15
        if parsed.scheme == "http":
            indicators.append("Unencrypted connection scheme (HTTP).")
            score_penalty += 15
        elif parsed.scheme not in ["http", "https"]:
            indicators.append(f"Unusual URI scheme '{parsed.scheme}'.")
            score_penalty += 20
        if hostname.count("-") > 2:
            indicators.append("Excessive hyphens in domain name (common in spoofed brand domains).")
            score_penalty += 15
        if hostname.count(".") > 3:
            indicators.append("Excessive subdomains (used to create fake brand URLs).")
            score_penalty += 20
        if hostname.endswith((".zip", ".exe", ".scr", ".jar", ".bat")):
            indicators.append("URL points directly to an executable file download.")
            score_penalty += 35

        risk_score = min(100, score_penalty)

        if risk_score >= 60:
            risk_level = "High"
            recommendation = "Do NOT enter credentials or download files from this website. Highly suspicious indicators found."
            from modules.risk_engine import add_finding
            add_finding(
                title=f"High Risk Phishing URL: {hostname}",
                severity="HIGH",
                score=risk_score,
                explanation=f"Url flagged with high risk score ({risk_score}/100). Indicators: {'; '.join(indicators)}",
                recommendation=recommendation,
                source_tool="Phishing Detector",
                mitre_tactic="Credential Access",
                mitre_technique="T1566 — Phishing",
            )
        elif risk_score >= 30:
            risk_level = "Moderate"
            recommendation = "Exercise caution. Verify the domain carefully before proceeding."
            from modules.risk_engine import add_finding
            add_finding(
                title=f"Moderate Risk URL: {hostname}",
                severity="MEDIUM",
                score=risk_score,
                explanation=f"URL flagged with moderate risk score ({risk_score}/100). Indicators: {'; '.join(indicators)}",
                recommendation=recommendation,
                source_tool="Phishing Detector",
            )
        else:
            risk_level = "Low"
            recommendation = "No obvious phishing indicators detected. Always double-check domain authenticity."

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Risk Level", risk_level)
        with col2:
            st.metric("Risk Score", f"{risk_score}/100")

        st.markdown(
            f"""
            <div class="result-card">
                <h4>URL Analysis Summary</h4>
                <p><strong>Inspected Domain:</strong> {hostname}</p>
                <p><strong>Protocol Scheme:</strong> {parsed.scheme.upper()}</p>
                <p><strong>Path Component:</strong> {parsed.path or '/'}</p>
                <p><strong>Risk Rating:</strong> {risk_level} ({risk_score}/100)</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.write("### Detected Indicators")
        if indicators:
            st.warning("\n".join(f"• {ind}" for ind in indicators))
        else:
            st.success("• No deceptive structural patterns detected in the URL.")

        st.write("### Recommendation")
        if risk_score >= 60:
            st.error(recommendation)
        elif risk_score >= 30:
            st.warning(recommendation)
        else:
            st.info(recommendation)

