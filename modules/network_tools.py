import socket
import concurrent.futures
import streamlit as st
import requests
from urllib.parse import urlparse
from utils.security import record_activity
from utils.theme import page_header
from modules.security_events import log_event
from modules.risk_engine import add_finding


COMMON_PORTS = {
    20: {"service": "FTP-Data", "protocol": "TCP", "risk": "MEDIUM", "desc": "File Transfer Protocol (Data channel, unencrypted)"},
    21: {"service": "FTP", "protocol": "TCP", "risk": "HIGH", "desc": "File Transfer Protocol (Plaintext authentication)", "insecure": True},
    22: {"service": "SSH", "protocol": "TCP", "risk": "LOW", "desc": "Secure Shell (Encrypted remote administration)"},
    23: {"service": "Telnet", "protocol": "TCP", "risk": "CRITICAL", "desc": "Telnet (Legacy unencrypted terminal, transmits credentials in cleartext)", "insecure": True},
    25: {"service": "SMTP", "protocol": "TCP", "risk": "MEDIUM", "desc": "Simple Mail Transfer Protocol (Check for open relay)"},
    53: {"service": "DNS", "protocol": "TCP/UDP", "risk": "LOW", "desc": "Domain Name System"},
    80: {"service": "HTTP", "protocol": "TCP", "risk": "MEDIUM", "desc": "Hypertext Transfer Protocol (Unencrypted web traffic)"},
    110: {"service": "POP3", "protocol": "TCP", "risk": "HIGH", "desc": "Post Office Protocol v3 (Plaintext email retrieval)", "insecure": True},
    139: {"service": "NetBIOS", "protocol": "TCP", "risk": "HIGH", "desc": "NetBIOS Session Service (Legacy Windows sharing)", "insecure": True},
    143: {"service": "IMAP", "protocol": "TCP", "risk": "MEDIUM", "desc": "Internet Message Access Protocol"},
    443: {"service": "HTTPS", "protocol": "TCP", "risk": "LOW", "desc": "HTTP Secure (TLS/SSL encrypted web traffic)"},
    445: {"service": "SMB", "protocol": "TCP", "risk": "HIGH", "desc": "Server Message Block (Windows File Sharing / IPC; vulnerable to EternalBlue if unpatched)"},
    1433: {"service": "MSSQL", "protocol": "TCP", "risk": "HIGH", "desc": "Microsoft SQL Server Database (Should not be exposed on public WAN)"},
    1521: {"service": "Oracle-DB", "protocol": "TCP", "risk": "HIGH", "desc": "Oracle Database Listener (Sensitive database port)"},
    3306: {"service": "MySQL", "protocol": "TCP", "risk": "HIGH", "desc": "MySQL / MariaDB Database (Sensitive database port)"},
    3389: {"service": "RDP", "protocol": "TCP", "risk": "HIGH", "desc": "Remote Desktop Protocol (Windows GUI access; high brute-force target)"},
    5432: {"service": "PostgreSQL", "protocol": "TCP", "risk": "HIGH", "desc": "PostgreSQL Database (Sensitive database port)"},
    5900: {"service": "VNC", "protocol": "TCP", "risk": "HIGH", "desc": "Virtual Network Computing (Remote desktop)"},
    6379: {"service": "Redis", "protocol": "TCP", "risk": "CRITICAL", "desc": "Redis In-Memory Store (Defaults to no auth; severe risk if exposed)", "insecure": True},
    8000: {"service": "HTTP-Dev", "protocol": "TCP", "risk": "LOW", "desc": "Alternative HTTP / Development Web Server"},
    8080: {"service": "HTTP-Proxy", "protocol": "TCP", "risk": "LOW", "desc": "HTTP Alternate / Tomcat / Proxy"},
    8443: {"service": "HTTPS-Alt", "protocol": "TCP", "risk": "LOW", "desc": "HTTPS Alternate Service"},
    8888: {"service": "Jupyter/Web", "protocol": "TCP", "risk": "MEDIUM", "desc": "Jupyter Notebook / Web Application"},
    27017: {"service": "MongoDB", "protocol": "TCP", "risk": "HIGH", "desc": "MongoDB NoSQL Database (Sensitive data store)"},
}

PORT_PRESETS = {
    "Top Common Services (20 Ports)": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 27017],
    "Web & API Services": [80, 443, 8000, 8080, 8443, 8888, 5000, 3000],
    "Database & Cache Services": [1433, 1521, 3306, 5432, 6379, 27017],
    "Remote Administration": [22, 23, 3389, 5900, 8080],
}


def _scan_single_port(host: str, port: int, timeout: float = 0.6) -> dict:
    """Safely test connection to a single TCP port with a strict timeout."""
    info = COMMON_PORTS.get(port, {"service": f"Custom-{port}", "protocol": "TCP", "risk": "INFO", "desc": "Custom Port"})
    result = {
        "port": port,
        "service": info["service"],
        "protocol": info.get("protocol", "TCP"),
        "risk": info.get("risk", "INFO"),
        "desc": info.get("desc", ""),
        "insecure": info.get("insecure", False),
        "status": "Closed",
        "banner": "",
    }
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        res = sock.connect_ex((host, port))
        if res == 0:
            result["status"] = "Open"
            # Try a lightweight banner grab
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(128).decode("utf-8", errors="ignore").strip()
                if banner:
                    result["banner"] = banner.split("\n")[0][:60]
            except Exception:
                pass
        else:
            result["status"] = "Closed"
    except (socket.timeout, socket.error):
        result["status"] = "Filtered / Timeout"
    finally:
        sock.close()
        
    return result


def scan_ports(host: str, ports: list[int], max_workers: int = 20, timeout: float = 0.6) -> list[dict]:
    """Multi-threaded defensive port scan."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_single_port, host, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                port = futures[future]
                results.append({"port": port, "service": "Unknown", "protocol": "TCP", "risk": "INFO", "desc": "", "status": "Error", "banner": ""})
    
    # Sort results by port number
    results.sort(key=lambda x: x["port"])
    return results


def render():
    page_header(
        "Network & Web Security",
        "Defensive network reconnaissance, active port auditing, and URL security inspection.",
        "🌐",
    )

    tab_ip, tab_ports, tab_url = st.tabs([
        "📍 IP Intelligence Lookup",
        "🛡️ Network & Port Scanner",
        "🔗 URL Structure & Safety",
    ])

    # -------------------------------------------------------------------------
    # TAB 1: IP Intelligence Lookup
    # -------------------------------------------------------------------------
    with tab_ip:
        st.subheader("IP Address Intelligence")
        st.caption("Perform passive geolocation and ASN identity reconnaissance via public threat feeds.")

        col_in, col_btn = st.columns([3, 1])
        with col_in:
            ip = st.text_input("Enter IP address to inspect", placeholder="e.g. 8.8.8.8 or 1.1.1.1", key="input_ip_inspect")
        with col_btn:
            st.write("")
            st.write("")
            lookup_clicked = st.button("Lookup IP", key="btn_lookup_ip", use_container_width=True)
        
        if lookup_clicked:
            if not ip:
                st.error("Please enter an IP address.")
            else:
                try:
                    with st.spinner("Fetching IP intelligence details..."):
                        response = requests.get(f"https://ipinfo.io/{ip.strip()}/json", timeout=10)
                        data = response.json()
                    
                    if response.status_code != 200:
                        st.error("Unable to fetch details for the provided IP address.")
                    else:
                        record_activity(f"IP address looked up: {ip.strip()}", "network")
                        log_event("IP_LOOKUP", f"Retrieved intelligence for IP: {ip.strip()} ({data.get('org', 'N/A')})", "INFO")
                        st.success("✅ **IP Details Retrieved Successfully**")
                        
                        col1, col2, col3 = st.columns(3)
                        col1.metric("IP Address", data.get("ip", "N/A"))
                        col2.metric("City / Location", f"{data.get('city', 'N/A')}, {data.get('country', 'N/A')}")
                        col3.metric("Timezone", data.get("timezone", "N/A"))

                        st.markdown(
                            f"""
                            <div class="result-card">
                                <h4>Network Identity & Geolocation</h4>
                                <p><strong>IP Address:</strong> <code>{data.get('ip', 'N/A')}</code></p>
                                <p><strong>Hostname:</strong> {data.get('hostname', 'N/A')}</p>
                                <p><strong>City / Region:</strong> {data.get('city', 'N/A')}, {data.get('region', 'N/A')}</p>
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

    # -------------------------------------------------------------------------
    # TAB 2: Defensive Network & Port Scanner
    # -------------------------------------------------------------------------
    with tab_ports:
        st.subheader("Defensive Port & Service Auditor")
        st.caption("Audit exposed network service ports on local endpoints, internal gateways, or authorized servers to verify firewall rules.")

        st.info("🔒 **Defensive Scope Notice**: Use this service auditor only on systems you own or have explicit authorization to inspect (e.g. `localhost` / `127.0.0.1`).")

        col_t1, col_t2 = st.columns([2, 2])
        with col_t1:
            target_host = st.text_input("Target Host / IP", value="127.0.0.1", help="Scan localhost or authorized IP/domain.", key="scan_target_host")
        with col_t2:
            preset_choice = st.selectbox("Port Preset Selection", list(PORT_PRESETS.keys()) + ["Custom Port Range", "Custom Port List"], key="scan_preset_choice")

        ports_to_scan = []
        if preset_choice in PORT_PRESETS:
            ports_to_scan = PORT_PRESETS[preset_choice]
            st.caption(f"Ports to audit ({len(ports_to_scan)} ports): `{', '.join(str(p) for p in ports_to_scan)}`")
        elif preset_choice == "Custom Port Range":
            col_r1, col_r2 = st.columns(2)
            with col_r1:
                start_p = st.number_input("Start Port", min_value=1, max_value=65535, value=20, key="scan_start_p")
            with col_r2:
                end_p = st.number_input("End Port", min_value=1, max_value=65535, value=100, key="scan_end_p")
            if start_p <= end_p:
                if (end_p - start_p) > 200:
                    st.warning("⚠️ For fast response in Streamlit, custom ranges are limited to 200 ports per batch.")
                    end_p = start_p + 199
                ports_to_scan = list(range(int(start_p), int(end_p) + 1))
        else:
            custom_list_str = st.text_input("Enter comma-separated ports", value="80, 443, 8080, 8443, 3000, 5000", key="scan_custom_list_str")
            try:
                ports_to_scan = [int(p.strip()) for p in custom_list_str.split(",") if p.strip().isdigit()]
            except Exception:
                ports_to_scan = [80, 443]

        col_s1, col_s2 = st.columns([1, 3])
        with col_s1:
            timeout_val = st.slider("Socket Timeout (seconds)", min_value=0.2, max_value=2.0, value=0.5, step=0.1, key="scan_timeout_slider")
        with col_s2:
            st.write("")
            st.write("")
            start_scan = st.button("🚀 Start Port Audit", key="btn_start_port_scan", type="primary")

        if start_scan:
            if not target_host:
                st.error("Please specify a target hostname or IP address.")
            elif not ports_to_scan:
                st.error("Please specify valid ports to scan.")
            else:
                with st.spinner(f"Auditing {len(ports_to_scan)} ports on {target_host}..."):
                    results = scan_ports(target_host, ports_to_scan, max_workers=25, timeout=timeout_val)
                    st.session_state["last_port_scan_results"] = results
                    st.session_state["last_port_scan_target"] = target_host

                open_ports = [r for r in results if r["status"] == "Open"]
                insecure_open = [r for r in open_ports if r.get("insecure")]

                record_activity(f"Port audit completed for {target_host} ({len(open_ports)} open)", "network")
                log_event("PORT_SCAN", f"Audited {len(ports_to_scan)} ports on {target_host}. Open: {len(open_ports)}", "WARNING" if insecure_open else "INFO")

                # Register findings in Risk Engine for open high-risk or insecure ports
                for op in open_ports:
                    if op.get("insecure"):
                        add_finding(
                            title=f"Insecure Service Port Open: {op['service']} (Port {op['port']})",
                            severity="HIGH" if op["port"] in [23, 6379] else "MEDIUM",
                            score=70,
                            explanation=f"Target {target_host} has port {op['port']} ({op['service']}) exposed. {op['desc']}",
                            recommendation=f"Disable unencrypted {op['service']} service or enforce TLS/SSH encapsulation and restrictive firewall ACLs.",
                            source_tool="Network Scanner",
                            mitre_tactic="Initial Access",
                            mitre_technique="T1190 — Exploit Public-Facing Application",
                        )
                    elif op["risk"] in ["HIGH", "CRITICAL"]:
                        add_finding(
                            title=f"Database/Admin Port Open: {op['service']} (Port {op['port']})",
                            severity="MEDIUM",
                            score=50,
                            explanation=f"Administrative service {op['service']} is actively listening on port {op['port']}.",
                            recommendation="Verify this service is bound to localhost or protected behind a VPN/firewall.",
                            source_tool="Network Scanner",
                            mitre_tactic="Discovery",
                            mitre_technique="T1046 — Network Service Discovery",
                        )

        # Render Previous / Current Results
        if "last_port_scan_results" in st.session_state:
            res = st.session_state["last_port_scan_results"]
            tgt = st.session_state.get("last_port_scan_target", target_host)
            open_count = len([r for r in res if r["status"] == "Open"])
            closed_count = len([r for r in res if r["status"] != "Open"])

            st.markdown("---")
            st.markdown(f"### Audit Results for `{tgt}`")

            m1, m2, m3 = st.columns(3)
            m1.metric("Total Ports Audited", str(len(res)))
            m2.metric("Open Ports 🟢", str(open_count))
            m3.metric("Closed / Filtered 🛡️", str(closed_count))

            # Display Open Ports Table
            open_ports = [r for r in res if r["status"] == "Open"]
            if open_ports:
                st.subheader("Open Ports & Identified Services")
                for p in open_ports:
                    badge_color = "#ef4444" if p.get("insecure") else ("#f59e0b" if p["risk"] == "HIGH" else "#10b981")
                    badge_text = "INSECURE / HIGH RISK" if p.get("insecure") else f"{p['risk']} RISK"
                    
                    st.markdown(
                        f"""
                        <div style="background:rgba(255,255,255,0.03); border-left: 4px solid {badge_color}; border-top:1px solid rgba(255,255,255,0.08); border-right:1px solid rgba(255,255,255,0.08); border-bottom:1px solid rgba(255,255,255,0.08); padding:12px 16px; border-radius:6px; margin-bottom:10px;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <div>
                                    <strong style="font-size:1.1rem; color:#6ee7b7;">Port {p['port']} ({p['protocol']}) — {p['service']}</strong>
                                </div>
                                <span style="background:{badge_color}22; color:{badge_color}; padding:3px 10px; border-radius:12px; font-size:0.75rem; font-weight:700; border:1px solid {badge_color}44;">
                                    {badge_text}
                                </span>
                            </div>
                            <p style="margin:6px 0 0 0; opacity:0.85; font-size:0.9rem;">{p['desc']}</p>
                            {f"<p style='margin:4px 0 0 0; font-family:monospace; font-size:0.8rem; color:#93c5fd;'>Banner: {p['banner']}</p>" if p['banner'] else ""}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.success("✅ **No open ports detected.** All audited ports responded as closed or filtered.")

            with st.expander("📋 Full Port Status Breakdown", expanded=False):
                table_rows = [
                    {
                        "Port": r["port"],
                        "Service": r["service"],
                        "Protocol": r["protocol"],
                        "Status": r["status"],
                        "Risk Level": r["risk"],
                        "Description": r["desc"],
                    }
                    for r in res
                ]
                st.dataframe(table_rows, use_container_width=True, hide_index=True)

    # -------------------------------------------------------------------------
    # TAB 3: URL Scheme & Safety Inspection
    # -------------------------------------------------------------------------
    with tab_url:
        st.subheader("URL Scheme & Safety Inspection")
        st.caption("Inspect web URLs for protocol encryption, path traversal risks, and suspicious parameter structures.")

        url = st.text_input("Enter Website URL", placeholder="https://example.com/login", key="input_url_inspect")

        if st.button("Check URL Safety", key="btn_check_url_safety"):
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
                    <p><strong>Scheme:</strong> <code>{parsed.scheme}</code></p>
                    <p><strong>Host / Domain:</strong> <code>{parsed.netloc}</code></p>
                    <p><strong>Path:</strong> <code>{parsed.path or '/'}</code></p>
                    <p><strong>Query Parameters:</strong> <code>{parsed.query or '(none)'}</code></p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if warnings:
                st.warning("**Potential Security Flags:**\n" + "\n".join(f"• {w}" for w in warnings))
            else:
                st.success("The URL structure is clean and standard. Always verify the domain reputation before entering confidential info.")
