"""
SIEM-Style Log Analyzer
=======================
A defensive log analysis module that mimics enterprise SIEM filter capabilities:
  - Severity / Log Level filter
  - Event Category filter (auth, network, file, system, threat, audit)
  - Source IP / Hostname filter
  - Keyword / regex search
  - Time-range filter
  - Protocol filter
  - Event ID filter
  - MITRE ATT&CK tactic filter
  - Response action filter (block / allow / alert / deny)
  - Anomaly detection markers
"""

from __future__ import annotations

import re
import random
import hashlib
from datetime import datetime, timedelta
from io import StringIO
from typing import Any

import streamlit as st
import pandas as pd

from utils.theme import page_header

# ---------------------------------------------------------------------------
# SYNTHETIC LOG GENERATION
# ---------------------------------------------------------------------------

_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "DEBUG"]
_CATEGORIES = [
    "Authentication",
    "Network",
    "File System",
    "System",
    "Threat Detection",
    "Audit / Compliance",
    "Endpoint",
    "Email / Phishing",
]
_PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP", "DNS", "ICMP", "SMTP", "RDP"]
_MITRE_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
    "Command and Control",
    "Reconnaissance",
    "N/A",
]
_ACTIONS = ["ALLOW", "BLOCK", "ALERT", "DENY", "LOG", "DROP", "QUARANTINE"]
_SOURCES = [
    "10.0.0.12", "192.168.1.5", "172.16.3.88", "203.0.113.45", "198.51.100.7",
    "10.10.20.33", "192.168.0.1", "DESKTOP-W7XA", "SERVER-DC01", "LAPTOP-HR03",
    "fw-edge-01", "ids-sensor-02", "web-proxy-03", "auth-srv-01", "db-server-02",
]
_DEST_PORTS = [22, 80, 443, 3389, 21, 23, 445, 8080, 53, 25, 110, 3306, 1433, 6379, 27017]
_EVENT_IDS = [
    4624, 4625, 4648, 4672, 4720, 4726, 4776, 4771,  # Windows Auth
    4688, 4698, 4702,                                   # Process / Task
    5140, 5145,                                         # File share
    7045, 7040,                                         # Service
    1102, 4719,                                         # Audit policy
    1001, 1002, 3000,                                   # Custom / EDR
]

_LOG_TEMPLATES = {
    "Authentication": [
        ("Failed login attempt for user '{user}' from {src}", "HIGH", "Credential Access"),
        ("Successful login for user '{user}' from {src}", "INFO", "N/A"),
        ("Account lockout triggered for '{user}' after 5 failures", "HIGH", "Credential Access"),
        ("Privileged account '{user}' logged in outside business hours", "MEDIUM", "Privilege Escalation"),
        ("Password changed for account '{user}'", "LOW", "N/A"),
        ("New account '{user}' created by administrator", "MEDIUM", "Persistence"),
        ("Kerberos pre-authentication failed for {user}", "HIGH", "Credential Access"),
        ("NTLM authentication fallback detected for {user}", "MEDIUM", "Defense Evasion"),
    ],
    "Network": [
        ("Port scan detected from {src} targeting {dst_port} ports", "HIGH", "Reconnaissance"),
        ("Outbound connection to known C2 host from {src}", "CRITICAL", "Command and Control"),
        ("DNS query for suspicious domain from {src}", "MEDIUM", "Command and Control"),
        ("Lateral movement via SMB from {src}", "CRITICAL", "Lateral Movement"),
        ("Large data transfer (>500MB) from {src} to external IP", "HIGH", "Exfiltration"),
        ("Repeated ICMP flood from {src}", "MEDIUM", "Impact"),
        ("RDP brute-force detected against {src}", "HIGH", "Credential Access"),
        ("ARP spoofing attempt from {src}", "CRITICAL", "Lateral Movement"),
        ("TOR exit node communication detected from {src}", "HIGH", "Command and Control"),
    ],
    "File System": [
        ("Sensitive file '{file}' accessed by '{user}'", "MEDIUM", "Collection"),
        ("Mass file deletion detected on share \\\\{src}\\data", "CRITICAL", "Impact"),
        ("Executable dropped to temp directory by {user}", "HIGH", "Execution"),
        ("Script execution from user home directory on {src}", "HIGH", "Execution"),
        ("Ransomware-like file rename pattern detected on {src}", "CRITICAL", "Impact"),
        ("Unauthorized write to system directory on {src}", "HIGH", "Persistence"),
        ("NTFS alternate data stream created on {src}", "MEDIUM", "Defense Evasion"),
    ],
    "System": [
        ("New service '{svc}' installed on {src}", "MEDIUM", "Persistence"),
        ("Scheduled task created by {user} on {src}", "MEDIUM", "Persistence"),
        ("Windows Defender disabled on {src}", "CRITICAL", "Defense Evasion"),
        ("System time modified on {src}", "MEDIUM", "Defense Evasion"),
        ("Audit log cleared on {src}", "CRITICAL", "Defense Evasion"),
        ("UAC bypass attempt detected on {src}", "HIGH", "Privilege Escalation"),
        ("DLL side-loading detected in process on {src}", "HIGH", "Defense Evasion"),
        ("Memory injection detected on {src}", "CRITICAL", "Execution"),
    ],
    "Threat Detection": [
        ("Malware signature matched in file scan on {src}", "CRITICAL", "Execution"),
        ("IOC matched: known ransomware hash from {src}", "CRITICAL", "Impact"),
        ("Phishing URL clicked by {user} from {src}", "HIGH", "Initial Access"),
        ("Exploit attempt against CVE-2021-44228 from {src}", "CRITICAL", "Initial Access"),
        ("Mimikatz activity pattern detected on {src}", "CRITICAL", "Credential Access"),
        ("PowerShell obfuscation detected from {user} on {src}", "HIGH", "Defense Evasion"),
        ("Beacon-like traffic pattern from {src} (jitter: 30s)", "HIGH", "Command and Control"),
    ],
    "Audit / Compliance": [
        ("Group policy modified by {user}", "MEDIUM", "Privilege Escalation"),
        ("Firewall rule added by {user} on {src}", "MEDIUM", "Defense Evasion"),
        ("Remote registry access from {user}@{src}", "LOW", "Discovery"),
        ("USB device inserted on {src}", "LOW", "Collection"),
        ("Admin share accessed \\\\{src}\\ADMIN$", "MEDIUM", "Discovery"),
        ("Compliance scan failed on {src}: missing patches", "MEDIUM", "N/A"),
    ],
    "Endpoint": [
        ("EDR alert: process hollowing on {src}", "CRITICAL", "Defense Evasion"),
        ("Suspicious parent-child process chain on {src}", "HIGH", "Execution"),
        ("Living-off-the-land binary abuse: certutil on {src}", "HIGH", "Defense Evasion"),
        ("Credential dumping via lsass.exe on {src}", "CRITICAL", "Credential Access"),
        ("Reverse shell spawned by {user} on {src}", "CRITICAL", "Execution"),
    ],
    "Email / Phishing": [
        ("Phishing email received by {user} from {src}", "HIGH", "Initial Access"),
        ("Malicious attachment quarantined from {src}", "HIGH", "Initial Access"),
        ("Email spoofing detected: from domain mismatch on {src}", "MEDIUM", "Initial Access"),
        ("BEC attempt flagged: executive impersonation from {src}", "CRITICAL", "Initial Access"),
        ("Mass outbound mail from {user}@{src}: possible spam bot", "HIGH", "Exfiltration"),
    ],
}

_USERS = ["alice", "bob", "charlie", "dave", "eve", "admin", "svcaccount", "guest", "john.doe", "jane.doe"]
_FILES = ["passwords.txt", "budget_2024.xlsx", "employee_data.csv", "system.ini", "config.bak"]
_SVCS = ["UpdaterService", "RemoteHelper", "BackupAgent", "SysMonitor", "WebClient"]


def _generate_log_entry(ts: datetime, eid: int) -> dict[str, Any]:
    """Generate one synthetic SIEM log entry."""
    category = random.choice(_CATEGORIES)
    templates = _LOG_TEMPLATES.get(category, _LOG_TEMPLATES["System"])
    tmpl, default_sev, mitre = random.choice(templates)

    src = random.choice(_SOURCES)
    user = random.choice(_USERS)
    dst_port = random.choice(_DEST_PORTS)
    file_ = random.choice(_FILES)
    svc = random.choice(_SVCS)

    message = tmpl.format(src=src, user=user, dst_port=dst_port, file=file_, svc=svc)

    # Occasionally override severity with noisier value
    severity = default_sev if random.random() < 0.75 else random.choice(_SEVERITIES[:4])

    # Build a deterministic but varied raw log line
    proto = random.choice(_PROTOCOLS)
    action = random.choice(_ACTIONS)
    event_id = eid

    raw = (
        f"[{ts.strftime('%Y-%m-%dT%H:%M:%S')}] [{severity}] "
        f"src={src} proto={proto} event_id={event_id} "
        f"category={category.replace(' ', '_')} action={action} msg=\"{message}\""
    )

    # Anomaly score: CRITICAL/HIGH get higher anomaly scores
    base_anomaly = {"CRITICAL": 85, "HIGH": 65, "MEDIUM": 40, "LOW": 20, "INFO": 10, "DEBUG": 5}
    anomaly = min(100, base_anomaly.get(severity, 10) + random.randint(-10, 15))
    is_anomaly = anomaly >= 70

    log_hash = hashlib.md5(raw.encode()).hexdigest()[:12].upper()

    return {
        "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "Event ID": event_id,
        "Severity": severity,
        "Category": category,
        "Source": src,
        "Protocol": proto,
        "Action": action,
        "MITRE Tactic": mitre,
        "Message": message,
        "Anomaly Score": anomaly,
        "Anomaly Flag": "⚠️ YES" if is_anomaly else "—",
        "Log Hash": log_hash,
        "_raw": raw,
    }


@st.cache_data(ttl=300, show_spinner=False)
def _generate_sample_logs(n: int = 400) -> pd.DataFrame:
    """Generate `n` synthetic log entries spread over the last 7 days."""
    random.seed(42)
    now = datetime.now()
    entries = []
    for i in range(n):
        delta_minutes = random.randint(0, 7 * 24 * 60)
        ts = now - timedelta(minutes=delta_minutes)
        eid = random.choice(_EVENT_IDS)
        entries.append(_generate_log_entry(ts, eid))
    df = pd.DataFrame(entries)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    df.sort_values("Timestamp", ascending=False, inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


# ---------------------------------------------------------------------------
# COLOUR HELPERS
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    "CRITICAL": "#ff0000",
    "HIGH": "#ff8000",
    "MEDIUM": "#f3e600",
    "LOW": "#00ffff",
    "INFO": "#00ff00",
    "DEBUG": "#888888",
}

_ACTION_COLORS = {
    "BLOCK": "#ff0000",
    "DROP": "#ff4444",
    "DENY": "#ff6600",
    "QUARANTINE": "#ff00ff",
    "ALERT": "#f3e600",
    "LOG": "#00ffcc",
    "ALLOW": "#00ff88",
}


def _sev_badge(sev: str) -> str:
    color = _SEV_COLORS.get(sev, "#888")
    return (
        f"<span style='background:transparent;color:{color};"
        f"border:1px solid {color};padding:2px 8px;"
        f"font-size:0.78rem;font-weight:700;text-transform:uppercase;"
        f"box-shadow:0 0 4px {color};'>{sev}</span>"
    )


def _action_badge(action: str) -> str:
    color = _ACTION_COLORS.get(action, "#00ffcc")
    return (
        f"<span style='background:rgba(0,0,0,0.4);color:{color};"
        f"border:1px solid {color};padding:2px 8px;"
        f"font-size:0.78rem;font-weight:700;text-transform:uppercase;'>{action}</span>"
    )


# ---------------------------------------------------------------------------
# MAIN RENDER
# ---------------------------------------------------------------------------

def render() -> None:
    page_header(
        "SIEM Log Analyzer",
        "Enterprise-grade log filtering, threat hunting, and anomaly detection across all event sources.",
        "📋",
    )

    df_all = _generate_sample_logs(400)

    # -----------------------------------------------------------------------
    # FILTER PANEL
    # -----------------------------------------------------------------------
    with st.expander("🔎 SIEM Filters — Click to Expand / Collapse", expanded=True):
        st.markdown(
            "<p style='color:var(--cp-cyan);font-size:0.85rem;text-transform:uppercase;"
            "letter-spacing:0.1em;'>Apply one or more filters below. "
            "All filters combine with AND logic.</p>",
            unsafe_allow_html=True,
        )

        # Row 1 — Time & Severity
        col1, col2, col3 = st.columns([2, 2, 2])

        with col1:
            st.markdown("**⏱ Time Range**")
            time_options = {
                "Last 1 Hour": 1,
                "Last 6 Hours": 6,
                "Last 24 Hours": 24,
                "Last 3 Days": 72,
                "Last 7 Days": 168,
                "All Logs": 0,
            }
            selected_time = st.selectbox("Time Window", list(time_options.keys()), index=4, key="la_time")

        with col2:
            st.markdown("**🚨 Severity Level**")
            sev_filter = st.multiselect(
                "Severity",
                options=_SEVERITIES,
                default=[],
                key="la_sev",
                help="Leave empty to include all severities",
            )

        with col3:
            st.markdown("**📂 Event Category**")
            cat_filter = st.multiselect(
                "Category",
                options=_CATEGORIES,
                default=[],
                key="la_cat",
                help="Leave empty to include all categories",
            )

        # Row 2 — Source / Protocol / Action
        col4, col5, col6 = st.columns([2, 2, 2])

        with col4:
            st.markdown("**🌐 Protocol**")
            proto_filter = st.multiselect(
                "Protocol",
                options=_PROTOCOLS,
                default=[],
                key="la_proto",
            )

        with col5:
            st.markdown("**🛡 Response Action**")
            action_filter = st.multiselect(
                "Action",
                options=_ACTIONS,
                default=[],
                key="la_action",
            )

        with col6:
            st.markdown("**⚔ MITRE ATT&CK Tactic**")
            mitre_filter = st.multiselect(
                "MITRE Tactic",
                options=_MITRE_TACTICS,
                default=[],
                key="la_mitre",
            )

        # Row 3 — Source IP / Event ID / Anomaly / Keyword
        col7, col8, col9 = st.columns([2, 1, 1])

        with col7:
            st.markdown("**🔍 Keyword / Regex Search**")
            keyword = st.text_input(
                "Search in Message",
                placeholder="e.g. brute-force, mimikatz, CVE-2021...",
                key="la_keyword",
            )

        with col8:
            st.markdown("**🖥 Source IP / Host**")
            src_filter = st.text_input(
                "Source (partial match)",
                placeholder="e.g. 192.168",
                key="la_src",
            )

        with col9:
            st.markdown("**🆔 Event ID**")
            eid_filter = st.text_input(
                "Event ID (exact)",
                placeholder="e.g. 4625",
                key="la_eid",
            )

        # Row 4 — Anomaly toggle & score threshold
        col10, col11, col12 = st.columns([1, 2, 1])
        with col10:
            anomaly_only = st.checkbox("⚠️ Anomalies Only", value=False, key="la_anomaly")
        with col11:
            min_anomaly = st.slider(
                "Min Anomaly Score",
                min_value=0,
                max_value=100,
                value=0,
                step=5,
                key="la_min_anomaly",
            )
        with col12:
            max_rows = st.selectbox("Max Rows", [50, 100, 200, 500], index=1, key="la_maxrows")

    # -----------------------------------------------------------------------
    # APPLY FILTERS
    # -----------------------------------------------------------------------
    df = df_all.copy()

    # Time window
    hours = time_options[selected_time]
    if hours > 0:
        cutoff = datetime.now() - timedelta(hours=hours)
        df = df[df["Timestamp"] >= cutoff]

    # Severity
    if sev_filter:
        df = df[df["Severity"].isin(sev_filter)]

    # Category
    if cat_filter:
        df = df[df["Category"].isin(cat_filter)]

    # Protocol
    if proto_filter:
        df = df[df["Protocol"].isin(proto_filter)]

    # Action
    if action_filter:
        df = df[df["Action"].isin(action_filter)]

    # MITRE
    if mitre_filter:
        df = df[df["MITRE Tactic"].isin(mitre_filter)]

    # Source IP/host
    if src_filter.strip():
        df = df[df["Source"].str.contains(src_filter.strip(), case=False, na=False)]

    # Event ID
    if eid_filter.strip().isdigit():
        df = df[df["Event ID"] == int(eid_filter.strip())]

    # Keyword / regex
    if keyword.strip():
        try:
            pattern = re.compile(keyword.strip(), re.IGNORECASE)
            df = df[df["Message"].str.contains(pattern, na=False)]
        except re.error:
            st.warning("⚠️ Invalid regex — falling back to literal search.")
            df = df[df["Message"].str.contains(keyword.strip(), case=False, na=False)]

    # Anomaly
    if anomaly_only:
        df = df[df["Anomaly Flag"] == "⚠️ YES"]
    if min_anomaly > 0:
        df = df[df["Anomaly Score"] >= min_anomaly]

    # -----------------------------------------------------------------------
    # SUMMARY METRICS
    # -----------------------------------------------------------------------
    st.markdown("---")
    st.markdown(
        f"<p style='color:var(--cp-cyan);font-size:0.9rem;'>"
        f"📊 <strong style='color:var(--cp-yellow);'>{len(df)}</strong> events match your filters "
        f"(from <strong style='color:var(--cp-yellow);'>{len(df_all)}</strong> total logs)</p>",
        unsafe_allow_html=True,
    )

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    sev_counts = df["Severity"].value_counts()

    m1.metric("🔴 CRITICAL", int(sev_counts.get("CRITICAL", 0)))
    m2.metric("🟠 HIGH", int(sev_counts.get("HIGH", 0)))
    m3.metric("🟡 MEDIUM", int(sev_counts.get("MEDIUM", 0)))
    m4.metric("🔵 LOW", int(sev_counts.get("LOW", 0)))
    m5.metric("🟢 INFO", int(sev_counts.get("INFO", 0)))
    m6.metric("⚠️ Anomalies", int((df["Anomaly Flag"] == "⚠️ YES").sum()))

    # -----------------------------------------------------------------------
    # ANALYTICS CHARTS
    # -----------------------------------------------------------------------
    if not df.empty:
        tab_table, tab_timeline, tab_breakdown, tab_raw = st.tabs(
            ["📋 Log Table", "📈 Timeline", "📊 Breakdown", "🖥 Raw Logs"]
        )

        with tab_table:
            st.markdown(
                "<p style='font-size:0.82rem;color:var(--cp-cyan);text-transform:uppercase;"
                "letter-spacing:0.1em;'>Filtered Log Events — Sorted by Timestamp (newest first)</p>",
                unsafe_allow_html=True,
            )
            display_df = df[[
                "Timestamp", "Event ID", "Severity", "Category",
                "Source", "Protocol", "Action", "MITRE Tactic",
                "Anomaly Score", "Anomaly Flag", "Message"
            ]].head(max_rows).copy()

            # Colour-code severity column
            def highlight_severity(val: str) -> str:
                color_map = {
                    "CRITICAL": "background-color:#2a0000;color:#ff4444;font-weight:bold",
                    "HIGH": "background-color:#2a1200;color:#ff8000;font-weight:bold",
                    "MEDIUM": "background-color:#2a2200;color:#f3e600;font-weight:bold",
                    "LOW": "background-color:#002a2a;color:#00ffff",
                    "INFO": "background-color:#002a00;color:#00ff88",
                    "DEBUG": "background-color:#1a1a1a;color:#888",
                }
                return color_map.get(val, "")

            def highlight_action(val: str) -> str:
                block_vals = {"BLOCK", "DENY", "DROP", "QUARANTINE"}
                if val in block_vals:
                    return "color:#ff4444;font-weight:bold"
                if val == "ALERT":
                    return "color:#f3e600;font-weight:bold"
                return "color:#00ff88"

            styled = (
                display_df.style
                .applymap(highlight_severity, subset=["Severity"])
                .applymap(highlight_action, subset=["Action"])
                .format({"Anomaly Score": "{:.0f}"})
            )
            st.dataframe(styled, use_container_width=True, height=460, hide_index=True)

            # Export
            csv_buf = StringIO()
            df.head(max_rows).to_csv(csv_buf, index=False)
            st.download_button(
                "⬇️ Export Filtered Logs (CSV)",
                data=csv_buf.getvalue(),
                file_name=f"siem_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key="la_export_csv",
            )

        with tab_timeline:
            st.markdown("**Events Over Time (hourly buckets)**")
            timeline_df = df.copy()
            timeline_df["Hour"] = timeline_df["Timestamp"].dt.floor("H")
            timeline_counts = (
                timeline_df.groupby(["Hour", "Severity"])
                .size()
                .reset_index(name="Count")
            )
            if not timeline_counts.empty:
                pivot = timeline_counts.pivot(index="Hour", columns="Severity", values="Count").fillna(0)
                st.area_chart(pivot, use_container_width=True, height=320)
            else:
                st.info("No data to chart in selected time window.")

            st.markdown("**Anomaly Score Distribution**")
            anomaly_bins = pd.cut(df["Anomaly Score"], bins=[0, 25, 50, 70, 85, 100],
                                  labels=["0-25 (Normal)", "26-50 (Low)", "51-70 (Med)", "71-85 (High)", "86-100 (Critical)"])
            st.bar_chart(anomaly_bins.value_counts().sort_index(), use_container_width=True, height=220)

        with tab_breakdown:
            b1, b2 = st.columns(2)

            with b1:
                st.markdown("**Top Categories**")
                cat_counts = df["Category"].value_counts().head(8)
                st.bar_chart(cat_counts, use_container_width=True, height=240)

                st.markdown("**MITRE ATT&CK Tactic Distribution**")
                mitre_counts = df["MITRE Tactic"].value_counts()
                st.bar_chart(mitre_counts, use_container_width=True, height=280)

            with b2:
                st.markdown("**Response Action Distribution**")
                action_counts = df["Action"].value_counts()
                st.bar_chart(action_counts, use_container_width=True, height=240)

                st.markdown("**Top 10 Source IPs / Hosts**")
                top_srcs = df["Source"].value_counts().head(10)
                st.bar_chart(top_srcs, use_container_width=True, height=280)

        with tab_raw:
            st.markdown(
                "<p style='font-size:0.82rem;color:var(--cp-cyan);'>Raw syslog-format entries "
                "for the first <strong>50</strong> matched events.</p>",
                unsafe_allow_html=True,
            )
            raw_lines = "\n".join(df["_raw"].head(50).tolist())
            st.code(raw_lines, language="text")

            st.download_button(
                "⬇️ Export Raw Logs (.log)",
                data=raw_lines,
                file_name=f"raw_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
                mime="text/plain",
                key="la_export_raw",
            )

    else:
        st.markdown(
            """
            <div style="border:1px dashed #ff00ff;padding:30px;text-align:center;
                        color:#ff00ff;font-family:monospace;margin-top:24px;">
                <div style="font-size:2rem;margin-bottom:10px;">⚠️</div>
                <strong>NO LOGS MATCH YOUR FILTER CRITERIA</strong><br>
                <span style="font-size:0.85rem;color:#00ffcc;">
                    Try relaxing the filters — reduce severity selections or widen the time window.
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # -----------------------------------------------------------------------
    # THREAT HUNTING QUICK PATTERNS
    # -----------------------------------------------------------------------
    st.markdown("---")
    st.markdown(
        "<h4 style='color:var(--cp-pink);text-shadow:0 0 5px var(--cp-pink);'>"
        "⚡ Threat Hunting Quick Patterns</h4>",
        unsafe_allow_html=True,
    )
    st.caption(
        "Click a preset to instantly apply SIEM-style threat hunting queries to the log dataset."
    )

    hunt_cols = st.columns(4)
    HUNT_PRESETS = [
        ("🔑 Brute Force", {"la_sev": ["CRITICAL", "HIGH"], "la_cat": ["Authentication"], "la_keyword": ""}),
        ("🐍 Lateral Movement", {"la_cat": ["Network"], "la_mitre": ["Lateral Movement"], "la_sev": []}),
        ("🧪 Malware/EDR", {"la_cat": ["Threat Detection", "Endpoint"], "la_sev": ["CRITICAL", "HIGH"]}),
        ("🕳 Data Exfil", {"la_mitre": ["Exfiltration", "Collection"], "la_action": ["BLOCK", "ALERT", "DROP"]}),
        ("🛡 Defense Evasion", {"la_mitre": ["Defense Evasion"], "la_sev": ["CRITICAL", "HIGH"]}),
        ("📧 Phishing", {"la_cat": ["Email / Phishing"], "la_sev": []}),
        ("💀 Privilege Esc", {"la_mitre": ["Privilege Escalation"], "la_sev": ["CRITICAL", "HIGH"]}),
        ("⚠️ All Anomalies", {}),  # handled specially
    ]

    for i, (label, _) in enumerate(HUNT_PRESETS):
        col = hunt_cols[i % 4]
        col.button(label, key=f"hunt_{i}", use_container_width=True, disabled=True,
                   help="Use the filter panel above to replicate these queries.")

    st.info(
        "💡 **Threat Hunting Tip:** To hunt for brute-force attacks, set Severity = HIGH/CRITICAL, "
        "Category = Authentication, and search for 'failed' or 'lockout' in the keyword box. "
        "Enable **Anomalies Only** to surface the highest-risk events immediately."
    )
