import hashlib
import datetime
import streamlit as st
from utils.security import record_activity
from utils.theme import page_header
from modules.virustotal_scanner import (
    get_api_key,
    check_existing_report,
    upload_file,
    poll_analysis_status,
    parse_vt_data,
    get_risk_interpretation,
)


def render_scan_results(parsed: dict) -> None:
    """Render structured cards, risk interpretation, engine table, and report link."""
    total_engines = parsed["total_engines"]
    malicious = parsed["malicious"]
    suspicious = parsed["suspicious"]
    undetected = parsed["undetected"]
    harmless = parsed["harmless"]
    timeout = parsed["timeout"]
    unsupported = parsed["unsupported"]

    sev_level, badge_class, risk_title, risk_msg = get_risk_interpretation(
        malicious, suspicious, total_engines
    )

    # 1. Summary Header Card
    st.markdown(
        f"""
        <div class="result-card">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                    <h3 style="margin:0; color:#6ee7b7;">Malware Scan Analysis</h3>
                    <p style="margin:4px 0 0 0; opacity:0.8;">Filename: <strong>{parsed['filename']}</strong></p>
                </div>
                <div style="text-align: right;">
                    <span class="{badge_class}">{risk_title}</span>
                </div>
            </div>
            <div style="margin-top: 15px; font-family: monospace; font-size:0.85rem; word-break: break-all; opacity: 0.85;">
                SHA-256: {parsed['sha256']}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Risk Interpretation Banner
    if sev_level == "HIGH_RISK":
        st.error(f"**{risk_title}**\n\n{risk_msg}")
    elif sev_level == "LOW_RISK":
        st.warning(f"**{risk_title}**\n\n{risk_msg}")
    else:
        st.success(f"**{risk_title}**\n\n{risk_msg}")

    # 3. Quick Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Engines", str(total_engines))
    m2.metric("Malicious 🚨", str(malicious))
    m3.metric("Suspicious ⚠️", str(suspicious))
    m4.metric("Undetected 🛡️", str(undetected))
    m5.metric("Harmless ✅", str(harmless))

    st.markdown("---")

    # 4. Result Breakdown Table
    st.subheader("Result Breakdown")
    breakdown_data = [
        {"Result Category": "Malicious Detections", "Count": malicious},
        {"Result Category": "Suspicious Detections", "Count": suspicious},
        {"Result Category": "Undetected / Clean", "Count": undetected},
        {"Result Category": "Confirmed Harmless", "Count": harmless},
        {"Result Category": "Timeout / Unresponsive", "Count": timeout},
        {"Result Category": "Unsupported File Type", "Count": unsupported},
    ]
    st.table(breakdown_data)

    # 5. Security Engine Results Table (Expandable)
    with st.expander("🔍 Security Engine Results Details", expanded=True):
        st.caption("Individual security vendor detections and analysis results returned by VirusTotal.")
        if parsed["engines"]:
            display_engines = [
                {
                    "Security Engine": eng["engine"],
                    "Detection / Result": eng["result"],
                    "Status Category": eng["category"],
                }
                for eng in parsed["engines"]
            ]
            st.dataframe(display_engines, use_container_width=True, hide_index=True)
        else:
            st.info("No detailed engine breakdown returned for this query.")

    # 6. External VirusTotal Report Link
    if parsed["report_url"]:
        st.markdown(
            f"""
            <div style="margin-top: 15px; margin-bottom: 20px;">
                <a href="{parsed['report_url']}" target="_blank" style="text-decoration: none;">
                    <button style="
                        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
                        color: white;
                        border: none;
                        padding: 10px 20px;
                        border-radius: 6px;
                        font-weight: 600;
                        cursor: pointer;
                        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
                    ">
                        🔗 View Full VirusTotal Report
                    </button>
                </a>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render():
    page_header(
        "File Integrity & Malware Scanner",
        "Verify file authenticity via SHA-256 cryptographic hashes and analyze files with VirusTotal multi-engine security scanners.",
        "📁",
    )

    # Session storage for scan results and history
    if "current_scan_result" not in st.session_state:
        st.session_state.current_scan_result = None
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []

    tab_integrity, tab_malware, tab_results, tab_history = st.tabs(
        ["🔐 Integrity", "🦠 Malware Scan", "📊 Scan Results", "📋 Scan History"]
    )

    # -------------------------------------------------------------------------
    # TAB 1: 🔐 Integrity (Local SHA-256 Check)
    # -------------------------------------------------------------------------
    with tab_integrity:
        st.subheader("SHA-256 File Integrity Check")
        st.caption("Calculate local SHA-256 hash digests to verify file authenticity and detect unauthorized modifications.")

        uploaded_file = st.file_uploader(
            "Choose a file to calculate cryptographic hash",
            key="integrity_file_uploader",
        )
        expected_hash = st.text_input(
            "Expected SHA-256 Hash (optional comparison)",
            placeholder="Paste expected 64-character hash string",
        )

        if uploaded_file and st.button("Compute File Hash", key="btn_compute_integrity"):
            contents = uploaded_file.getvalue()
            file_hash = hashlib.sha256(contents).hexdigest()
            file_size_kb = len(contents) / 1024

            record_activity(
                f"File integrity hash computed: {uploaded_file.name}", "integrity"
            )

            st.success("✅ **SHA-256 Hash Computed Successfully**")

            st.markdown(
                f"""
                <div class="result-card">
                    <h4>File Cryptographic Fingerprint</h4>
                    <p><strong>Filename:</strong> {uploaded_file.name}</p>
                    <p><strong>File Size:</strong> {file_size_kb:.2f} KB ({len(contents)} bytes)</p>
                    <p><strong>Algorithm:</strong> SHA-256 (256-bit secure hash)</p>
                    <p><strong>Computed Digest:</strong></p>
                    <code style="display:block; padding:8px; background:rgba(0,0,0,0.4); color:#6ee7b7; border-radius:4px; word-break:break-all;">{file_hash}</code>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if expected_hash:
                exp_clean = expected_hash.strip().lower()
                if file_hash.lower() == exp_clean:
                    st.success(
                        "✅ **Hash Verification MATCH**: The computed SHA-256 hash matches the expected checksum. The file is authentic and unaltered."
                    )
                else:
                    st.error(
                        "❌ **Hash Verification MISMATCH**: The computed SHA-256 hash does NOT match the expected value. The file may be modified, corrupted, or tampered with."
                    )
                    from modules.risk_engine import add_finding
                    add_finding(
                        title=f"SHA-256 Hash Mismatch: {uploaded_file.name}",
                        severity="HIGH",
                        score=70,
                        explanation=f"Computed SHA-256 digest ({file_hash[:16]}...) does not match expected checksum.",
                        recommendation="Do not trust or execute the file without verifying its origin and cryptographic signature.",
                        source_tool="File Integrity",
                        mitre_tactic="Defense Evasion",
                        mitre_technique="T1565 — Data Manipulation",
                    )

            st.info(
                "💡 **Cryptographic Note**: Cryptographic hash functions are one-way functions. Any single-bit change in the input file results in an entirely different SHA-256 hash."
            )

    # -------------------------------------------------------------------------
    # TAB 2: 🦠 Malware Scan (VirusTotal Integration)
    # -------------------------------------------------------------------------
    with tab_malware:
        st.subheader("Multi-Engine Malware Scan")
        st.markdown(
            "Submit this file to VirusTotal for multi-engine security analysis. "
            "VirusTotal aggregates detections from multiple security vendors."
        )

        malware_file = st.file_uploader(
            "Choose a file to analyze for malware",
            key="malware_file_uploader",
        )

        if malware_file:
            file_bytes = malware_file.getvalue()
            local_hash = hashlib.sha256(file_bytes).hexdigest()
            file_size_kb = len(file_bytes) / 1024
            file_type = malware_file.type or "Unknown / Binary"

            # Display uploaded file details
            st.markdown(
                f"""
                <div class="result-card">
                    <h4 style="margin-top:0; color:#6ee7b7;">Uploaded File Details</h4>
                    <p><strong>Filename:</strong> {malware_file.name}</p>
                    <p><strong>File Size:</strong> {file_size_kb:.2f} KB ({len(file_bytes)} bytes)</p>
                    <p><strong>File Type:</strong> {file_type}</p>
                    <p><strong>SHA-256:</strong></p>
                    <code style="display:block; padding:6px; background:rgba(0,0,0,0.4); color:#6ee7b7; border-radius:4px; word-break:break-all;">{local_hash}</code>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Privacy Warning Box
            st.warning(
                "**Privacy Warning**\n\n"
                "The selected file will be uploaded to VirusTotal for analysis. Do not upload confidential, "
                "personal, proprietary, sensitive, or otherwise restricted files unless you are authorized to submit them."
            )

            consent_given = st.checkbox(
                "I understand that this file will be uploaded to an external malware-analysis service.",
                key="vt_consent_checkbox",
            )

            # API Key management
            api_key = get_api_key()
            if not api_key:
                st.info(
                    "🔑 **VirusTotal API Key Required**\n\n"
                    "No VirusTotal API key was detected in environment variables (`VIRUSTOTAL_API_KEY`) or secrets. "
                    "You can enter a temporary API key below for this session:"
                )
                user_key_input = st.text_input(
                    "VirusTotal API Key",
                    type="password",
                    placeholder="Paste VirusTotal API key...",
                    key="vt_key_input_field",
                )
                if user_key_input.strip():
                    st.session_state.vt_api_key_override = user_key_input.strip()
                    api_key = user_key_input.strip()

            scan_disabled = not consent_given or not api_key

            if not api_key:
                st.caption("⚠️ Please configure or enter a VirusTotal API key to enable scanning.")
            elif not consent_given:
                st.caption("⚠️ Please confirm the privacy warning checkbox above to enable scanning.")

            if st.button("Scan with VirusTotal", disabled=scan_disabled, key="btn_scan_virustotal"):
                status_container = st.empty()
                progress_bar = st.progress(10)

                status_container.info("Step 1/3: Checking VirusTotal database for existing analysis...")

                # 1. Check existing report by hash
                check_res = check_existing_report(local_hash, api_key)

                if not check_res["success"]:
                    progress_bar.empty()
                    status_container.error(f"❌ {check_res['error']}")
                elif check_res.get("found"):
                    progress_bar.progress(100)
                    status_container.success("✅ **Existing VirusTotal Analysis Found!** Using pre-computed multi-engine report.")

                    parsed = parse_vt_data(
                        check_res["data"],
                        fallback_filename=malware_file.name,
                        fallback_sha256=local_hash,
                    )
                    st.session_state.current_scan_result = parsed

                    # Add to session history
                    history_entry = {
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "filename": malware_file.name,
                        "sha256": local_hash,
                        "ratio": f"{parsed['malicious']} / {parsed['total_engines']}",
                        "status": "Completed (Cached)",
                        "result_data": parsed,
                    }
                    st.session_state.scan_history.insert(0, history_entry)
                    record_activity(
                        f"VirusTotal scan completed for {malware_file.name} ({parsed['malicious']}/{parsed['total_engines']} detections)",
                        "integrity",
                    )
                    if parsed['malicious'] > 0 or parsed['suspicious'] > 0:
                        from modules.risk_engine import add_finding
                        add_finding(
                            title=f"Malware Detections Flagged: {malware_file.name}",
                            severity="HIGH" if parsed['malicious'] >= 3 else "MEDIUM",
                            score=85 if parsed['malicious'] >= 3 else 50,
                            explanation=f"{parsed['malicious']} security engine(s) flagged this file as malicious and {parsed['suspicious']} as suspicious.",
                            recommendation="Quarantine or delete the file immediately. Do not open or execute.",
                            source_tool="Malware Scanner",
                            mitre_tactic="Execution",
                            mitre_technique="T1204 — User Execution",
                        )
                    st.rerun()

                else:
                    # 2. Upload file if no existing analysis
                    status_container.info("Step 2/3: Uploading file to VirusTotal security engines...")
                    progress_bar.progress(35)

                    upload_res = upload_file(malware_file.name, file_bytes, api_key)

                    if not upload_res["success"]:
                        progress_bar.empty()
                        status_container.error(f"❌ {upload_res['error']}")
                    else:
                        analysis_id = upload_res["analysis_id"]
                        status_container.info("Step 3/3: Analysis submitted. Waiting for antivirus engines...")
                        progress_bar.progress(60)

                        def update_progress(msg: str):
                            status_container.info(f"⏳ {msg}")

                        # 3. Poll analysis status
                        poll_res = poll_analysis_status(
                            analysis_id,
                            api_key,
                            progress_callback=update_progress,
                            max_timeout=120,
                            poll_interval=5,
                        )

                        if not poll_res["success"]:
                            progress_bar.empty()
                            status_container.error(f"❌ {poll_res['error']}")
                        else:
                            progress_bar.progress(100)
                            status_container.success("✅ **Multi-Engine Scan Completed!**")

                            parsed = parse_vt_data(
                                poll_res["data"],
                                fallback_filename=malware_file.name,
                                fallback_sha256=local_hash,
                            )
                            st.session_state.current_scan_result = parsed

                            history_entry = {
                                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "filename": malware_file.name,
                                "sha256": local_hash,
                                "ratio": f"{parsed['malicious']} / {parsed['total_engines']}",
                                "status": "Completed (New Upload)",
                                "result_data": parsed,
                            }
                            st.session_state.scan_history.insert(0, history_entry)
                            record_activity(
                                f"VirusTotal scan completed for {malware_file.name} ({parsed['malicious']}/{parsed['total_engines']} detections)",
                                "integrity",
                            )
                            st.rerun()

    # -------------------------------------------------------------------------
    # TAB 3: 📊 Scan Results
    # -------------------------------------------------------------------------
    with tab_results:
        st.subheader("Security Engine Scan Report")

        if st.session_state.current_scan_result:
            render_scan_results(st.session_state.current_scan_result)
        else:
            st.info("💡 **No active scan results.** Upload a file in the **Malware Scan** tab to perform multi-engine analysis.")

        st.markdown("---")
        with st.expander("ℹ️ VirusTotal API Limitations & Safety Guidelines", expanded=False):
            st.markdown(
                """
                - **API Limits & Permissions**: Public VirusTotal API access is subject to rate limits and vendor availability.
                - **Vendor Variation**: Not every file is necessarily analyzed by every security engine.
                - **No Guaranteed Safety**: A clean result (0 detections) does **NOT** guarantee that a file is malware-free or safe.
                - **False Positives/Negatives**: Security engine detections can produce false positives or miss brand-new zero-day threats.
                - **Privacy Implications**: Uploading a file to external services submits data to third-party security vendors.
                """
            )

    # -------------------------------------------------------------------------
    # TAB 4: 📋 Scan History
    # -------------------------------------------------------------------------
    with tab_history:
        st.subheader("Session Scan History")
        st.caption("Temporary record of files scanned during the current browser session. No permanent logs or file contents are stored.")

        if st.session_state.scan_history:
            for idx, entry in enumerate(st.session_state.scan_history):
                col_info, col_btn = st.columns([3, 1])
                with col_info:
                    st.markdown(
                        f"""
                        <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.1); padding:10px 14px; border-radius:6px; margin-bottom:8px;">
                            <strong>{entry['filename']}</strong> ({entry['timestamp']})<br/>
                            <span style="font-family:monospace; font-size:0.8rem; opacity:0.8;">SHA-256: {entry['sha256'][:16]}...{entry['sha256'][-16:]}</span><br/>
                            <span style="color:#6ee7b7; font-weight:600;">Detections: {entry['ratio']}</span> | Status: {entry['status']}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                with col_btn:
                    if st.button("View Report", key=f"hist_view_btn_{idx}"):
                        st.session_state.current_scan_result = entry["result_data"]
                        st.rerun()
        else:
            st.info("No scan history recorded in this session yet.")
