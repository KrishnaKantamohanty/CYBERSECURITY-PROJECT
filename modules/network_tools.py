import streamlit as st
import requests
from urllib.parse import urlparse
from utils.security import record_activity
from utils.theme import page_header


def render():
    page_header(
        "Network & Web Safety",
        "Inspect network details and analyze web URLs with security insight.",
        "🌐",
    )

    tab1, tab2 = st.tabs(["IP Information Lookup", "URL Structure & Safety Check"])

    with tab1:
        st.subheader("IP Address Inspection")
        ip = st.text_input("Enter IP address to inspect", placeholder="e.g. 8.8.8.8")
        
        if st.button("Lookup IP"):
            if not ip:
                st.error("Please enter an IP address.")
            else:
                try:
                    response = requests.get(f"https://ipinfo.io/{ip.strip()}/json", timeout=10)
                    data = response.json()
                    if response.status_code != 200:
                        st.error("Unable to fetch details for the provided IP address.")
                    else:
                        record_activity(f"IP address looked up: {ip.strip()}", "url")
                        st.success("✅ **IP Details Retrieved Successfully**")
                        
                        col1, col2, col3 = st.columns(3)
                        col1.metric("IP Address", data.get("ip", "N/A"))
                        col2.metric("City / Location", f"{data.get('city', 'N/A')}, {data.get('country', 'N/A')}")
                        col3.metric("Timezone", data.get("timezone", "N/A"))

                        st.markdown(
                            f"""
                            <div class="result-card">
                                <h4>Network Identity & Geolocation</h4>
                                <p><strong>IP Address:</strong> {data.get('ip', 'N/A')}</p>
                                <p><strong>Hostname:</strong> {data.get('hostname', 'N/A')}</p>
                                <p><strong>City:</strong> {data.get('city', 'N/A')}</p>
                                <p><strong>Region:</strong> {data.get('region', 'N/A')}</p>
                                <p><strong>Country:</strong> {data.get('country', 'N/A')}</p>
                                <p><strong>Coordinates (Lat, Long):</strong> {data.get('loc', 'N/A')}</p>
                                <p><strong>Organization / ISP:</strong> {data.get('org', 'N/A')}</p>
                                <p><strong>Postal Code:</strong> {data.get('postal', 'N/A')}</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                except Exception as exc:
                    st.error(f"IP lookup failed: {exc}")

    with tab2:
        st.subheader("URL Scheme & Safety Inspection")
        url = st.text_input("Enter Website URL", placeholder="https://example.com/login")

        if st.button("Check URL Safety"):
            if not url:
                st.error("Please enter a valid URL.")
                return
            parsed = urlparse(url.strip())
            if not parsed.scheme or not parsed.netloc:
                st.error("Malformed URL format. Please include http:// or https://")
                return

            record_activity(f"URL inspected: {parsed.netloc}", "url")
            warnings = []
            if parsed.scheme not in ["http", "https"]:
                warnings.append("Non-standard web scheme detected.")
            elif parsed.scheme == "http":
                warnings.append("Unencrypted connection (HTTP). Credentials submitted over HTTP can be intercepted.")
            if any(c in url for c in ["@", "..", "\\"]) or parsed.username:
                warnings.append("URL contains embedded credentials (@) or path traversal characters.")

            col1, col2, col3 = st.columns(3)
            col1.metric("Protocol Scheme", parsed.scheme.upper())
            col2.metric("Domain / Host", parsed.netloc)
            col3.metric("Status", "⚠️ Warnings Found" if warnings else "✓ Well-Formed")

            st.markdown(
                f"""
                <div class="result-card">
                    <h4>Parsed Components</h4>
                    <p><strong>Scheme:</strong> {parsed.scheme}</p>
                    <p><strong>Host / Domain:</strong> {parsed.netloc}</p>
                    <p><strong>Path:</strong> {parsed.path or '/'}</p>
                    <p><strong>Query Parameters:</strong> {parsed.query or '(none)'}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if warnings:
                st.warning("**Potential Security Flags:**\n" + "\n".join(f"• {w}" for w in warnings))
            else:
                st.success("The URL structure is clean and standard. Always verify the domain reputation before entering confidential info.")

