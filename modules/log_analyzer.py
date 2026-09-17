"""
SIEM-Style Log Analyzer
=======================
Supports:
  - Upload real log files (.log, .txt, .csv, .json, .evtx text export)
  - Auto-parse common formats: syslog, Apache/Nginx, Windows Event, JSON, CSV
  - 10 SIEM-grade filters (severity, category, time, protocol, action, MITRE,
    source IP, event ID, keyword/regex, anomaly score)
  - Timeline, breakdown charts, raw log viewer, CSV export
"""

from __future__ import annotations

import re
import csv
import json
import random
import hashlib
from datetime import datetime, timedelta
from io import StringIO
from typing import Any

import streamlit as st
import pandas as pd

from utils.theme import page_header

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

SEVERITIES   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "DEBUG"]
CATEGORIES   = [
    "Authentication", "Network", "File System", "System",
    "Threat Detection", "Audit / Compliance", "Endpoint", "Email / Phishing",
]
PROTOCOLS    = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP", "DNS", "ICMP", "SMTP", "RDP"]
MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Impact", "Command and Control",
    "Reconnaissance", "N/A",
]
ACTIONS      = ["ALLOW", "BLOCK", "ALERT", "DENY", "LOG", "DROP", "QUARANTINE"]
SOURCES      = [
    "10.0.0.12", "192.168.1.5", "172.16.3.88", "203.0.113.45", "198.51.100.7",
    "10.10.20.33", "192.168.0.1", "DESKTOP-W7XA", "SERVER-DC01", "LAPTOP-HR03",
    "fw-edge-01", "ids-sensor-02", "web-proxy-03", "auth-srv-01", "db-server-02",
]
EVENT_IDS    = [
    4624, 4625, 4648, 4672, 4720, 4726, 4776, 4771,
    4688, 4698, 4702, 5140, 5145, 7045, 7040, 1102, 4719, 1001, 1002, 3000,
]
USERS  = ["alice", "bob", "charlie", "dave", "admin", "svcaccount", "guest", "john.doe"]
FILES  = ["passwords.txt", "budget_2024.xlsx", "employee_data.csv", "system.ini"]
SVCS   = ["UpdaterService", "RemoteHelper", "BackupAgent", "SysMonitor"]

_LOG_TEMPLATES: dict[str, list[tuple[str, str, str]]] = {
    "Authentication": [
        ("Failed login attempt for user '{user}' from {src}", "HIGH", "Credential Access"),
        ("Successful login for user '{user}' from {src}", "INFO", "N/A"),
        ("Account lockout triggered for '{user}' after 5 failures", "HIGH", "Credential Access"),
        ("Privileged account '{user}' logged in outside business hours", "MEDIUM", "Privilege Escalation"),
        ("Password changed for account '{user}'", "LOW", "N/A"),
        ("Kerberos pre-auth failed for {user}", "HIGH", "Credential Access"),
        ("NTLM auth fallback for {user}", "MEDIUM", "Defense Evasion"),
    ],
    "Network": [
        ("Port scan detected from {src}", "HIGH", "Reconnaissance"),
        ("Outbound connection to known C2 host from {src}", "CRITICAL", "Command and Control"),
        ("DNS query for suspicious domain from {src}", "MEDIUM", "Command and Control"),
        ("Lateral movement via SMB from {src}", "CRITICAL", "Lateral Movement"),
        ("Large data transfer >500MB from {src}", "HIGH", "Exfiltration"),
        ("RDP brute-force detected against {src}", "HIGH", "Credential Access"),
        ("ARP spoofing attempt from {src}", "CRITICAL", "Lateral Movement"),
    ],
    "File System": [
        ("Sensitive file '{file}' accessed by '{user}'", "MEDIUM", "Collection"),
        ("Mass file deletion on share from {src}", "CRITICAL", "Impact"),
        ("Executable dropped to temp by {user}", "HIGH", "Execution"),
        ("Ransomware-like rename pattern on {src}", "CRITICAL", "Impact"),
        ("NTFS alternate data stream created on {src}", "MEDIUM", "Defense Evasion"),
    ],
    "System": [
        ("New service '{svc}' installed on {src}", "MEDIUM", "Persistence"),
        ("Scheduled task created by {user}", "MEDIUM", "Persistence"),
        ("Windows Defender disabled on {src}", "CRITICAL", "Defense Evasion"),
        ("Audit log cleared on {src}", "CRITICAL", "Defense Evasion"),
        ("UAC bypass attempt on {src}", "HIGH", "Privilege Escalation"),
        ("Memory injection on {src}", "CRITICAL", "Execution"),
    ],
    "Threat Detection": [
        ("Malware signature matched on {src}", "CRITICAL", "Execution"),
        ("IOC matched: known ransomware hash from {src}", "CRITICAL", "Impact"),
        ("Phishing URL clicked by {user}", "HIGH", "Initial Access"),
        ("Exploit attempt CVE-2021-44228 from {src}", "CRITICAL", "Initial Access"),
        ("Mimikatz activity on {src}", "CRITICAL", "Credential Access"),
        ("PowerShell obfuscation by {user}", "HIGH", "Defense Evasion"),
    ],
    "Audit / Compliance": [
        ("Group policy modified by {user}", "MEDIUM", "Privilege Escalation"),
        ("Firewall rule added by {user}", "MEDIUM", "Defense Evasion"),
        ("USB device inserted on {src}", "LOW", "Collection"),
        ("Compliance scan failed on {src}: missing patches", "MEDIUM", "N/A"),
    ],
    "Endpoint": [
        ("EDR alert: process hollowing on {src}", "CRITICAL", "Defense Evasion"),
        ("Suspicious parent-child process chain on {src}", "HIGH", "Execution"),
        ("Certutil abuse on {src}", "HIGH", "Defense Evasion"),
        ("Credential dumping via lsass.exe on {src}", "CRITICAL", "Credential Access"),
    ],
    "Email / Phishing": [
        ("Phishing email received by {user}", "HIGH", "Initial Access"),
        ("Malicious attachment quarantined from {src}", "HIGH", "Initial Access"),
        ("BEC attempt: executive impersonation from {src}", "CRITICAL", "Initial Access"),
    ],
}


# ---------------------------------------------------------------------------
# SYNTHETIC SAMPLE LOG GENERATION
# ---------------------------------------------------------------------------

@st.cache_data(ttl=300, show_spinner=False)
def _generate_sample_logs(n: int = 300) -> pd.DataFrame:
    random.seed(42)
    now = datetime.now()
    rows: list[dict[str, Any]] = []
    for i in range(n):
        category  = random.choice(CATEGORIES)
        templates = _LOG_TEMPLATES.get(category, _LOG_TEMPLATES["System"])
        tmpl, default_sev, mitre = random.choice(templates)
        src  = random.choice(SOURCES)
        user = random.choice(USERS)
        file_ = random.choice(FILES)
        svc   = random.choice(SVCS)
        msg   = tmpl.format(src=src, user=user, file=file_, svc=svc)
        sev   = default_sev if random.random() < 0.75 else random.choice(SEVERITIES[:4])
        proto  = random.choice(PROTOCOLS)
        action = random.choice(ACTIONS)
        eid    = random.choice(EVENT_IDS)
        ts     = now - timedelta(minutes=random.randint(0, 7 * 24 * 60))
        base_a = {"CRITICAL": 85, "HIGH": 65, "MEDIUM": 40, "LOW": 20, "INFO": 10, "DEBUG": 5}
        anomaly = min(100, base_a.get(sev, 10) + random.randint(-10, 15))
        raw = (
            f"[{ts.strftime('%Y-%m-%dT%H:%M:%S')}] [{sev}] src={src} "
            f"proto={proto} event_id={eid} action={action} msg=\"{msg}\""
        )
        rows.append({
            "Timestamp":    ts,
            "Event ID":     eid,
            "Severity":     sev,
            "Category":     category,
            "Source":       src,
            "Protocol":     proto,
            "Action":       action,
            "MITRE Tactic": mitre,
            "Message":      msg,
            "Anomaly Score": anomaly,
            "Anomaly":      "YES" if anomaly >= 70 else "NO",
            "_raw":         raw,
        })
    df = pd.DataFrame(rows)
    df.sort_values("Timestamp", ascending=False, inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


# ---------------------------------------------------------------------------
# LOG FILE PARSERS
# ---------------------------------------------------------------------------

_SEV_KEYWORDS = {
    "critical": "CRITICAL", "crit": "CRITICAL",
    "error": "HIGH",    "err": "HIGH",
    "warning": "MEDIUM","warn": "MEDIUM",
    "notice": "LOW",
    "info": "INFO",     "information": "INFO",
    "debug": "DEBUG",
}

_SYSLOG_RE   = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.*)$"
)
_APACHE_RE   = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]+)"\s+(?P<status>\d+)\s+\S+',
)
_WIN_RE      = re.compile(
    r"(?:EventID|Event ID)[:\s]+(?P<eid>\d+).*?(?:Level|Severity)[:\s]+(?P<sev>\w+)",
    re.IGNORECASE,
)
_BRACKET_RE  = re.compile(
    r"\[(?P<ts>[\d\-T: ]+)\]\s*\[?(?P<sev>\w+)\]?\s*(?P<msg>.*)"
)
_GENERIC_TS  = re.compile(
    r"(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[T \t]\d{2}:\d{2}:\d{2})"
)


def _detect_severity(text: str) -> str:
    low = text.lower()
    for kw, sev in _SEV_KEYWORDS.items():
        if kw in low:
            return sev
    return "INFO"


def _parse_syslog(lines: list[str]) -> pd.DataFrame:
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = _SYSLOG_RE.match(line)
        if m:
            ts_raw = m.group("ts")
            try:
                ts = datetime.strptime(f"{datetime.now().year} {ts_raw}", "%Y %b %d %H:%M:%S")
            except ValueError:
                ts = datetime.now()
            rows.append({
                "Timestamp": ts, "Source": m.group("host"),
                "Message": m.group("msg"), "Severity": _detect_severity(m.group("msg")),
                "Category": "System", "Protocol": "N/A", "Action": "LOG",
                "MITRE Tactic": "N/A", "Event ID": 0,
                "Anomaly Score": 10 if _detect_severity(m.group("msg")) == "INFO" else 50,
                "Anomaly": "NO", "_raw": line,
            })
        else:
            rows.append(_generic_row(line))
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _parse_apache(lines: list[str]) -> pd.DataFrame:
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = _APACHE_RE.match(line)
        if m:
            status = int(m.group("status"))
            sev = "CRITICAL" if status >= 500 else "HIGH" if status >= 400 else "INFO"
            try:
                ts = datetime.strptime(m.group("ts").split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                ts = datetime.now()
            rows.append({
                "Timestamp": ts, "Source": m.group("ip"),
                "Message": f"{m.group('req')} → HTTP {status}",
                "Severity": sev, "Category": "Network",
                "Protocol": "HTTP", "Action": "LOG",
                "MITRE Tactic": "Initial Access" if status in (401, 403) else "N/A",
                "Event ID": status,
                "Anomaly Score": 70 if status >= 400 else 10,
                "Anomaly": "YES" if status >= 400 else "NO",
                "_raw": line,
            })
        else:
            rows.append(_generic_row(line))
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _parse_json_logs(text: str) -> pd.DataFrame:
    rows = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip().rstrip(",")
        if not line or line in ("{", "}", "[", "]"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts_raw = (obj.get("timestamp") or obj.get("time") or
                  obj.get("@timestamp") or obj.get("date") or "")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", ""))
        except Exception:
            ts = datetime.now() - timedelta(minutes=i)
        msg = (obj.get("message") or obj.get("msg") or
               obj.get("event") or str(obj))
        sev_raw = (obj.get("level") or obj.get("severity") or
                   obj.get("log_level") or "INFO")
        sev = _SEV_KEYWORDS.get(str(sev_raw).lower(), "INFO")
        rows.append({
            "Timestamp": ts,
            "Source":   str(obj.get("host") or obj.get("source") or obj.get("src") or "uploaded"),
            "Message":  str(msg)[:300],
            "Severity": sev,
            "Category": str(obj.get("category") or obj.get("type") or "System"),
            "Protocol": str(obj.get("protocol") or obj.get("proto") or "N/A"),
            "Action":   str(obj.get("action") or obj.get("outcome") or "LOG"),
            "MITRE Tactic": str(obj.get("mitre_tactic") or "N/A"),
            "Event ID": int(obj.get("event_id") or obj.get("eventid") or 0),
            "Anomaly Score": 50 if sev in ("CRITICAL", "HIGH") else 10,
            "Anomaly": "YES" if sev in ("CRITICAL", "HIGH") else "NO",
            "_raw": line,
        })
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _parse_csv_logs(text: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(StringIO(text))
    except Exception:
        return pd.DataFrame()
    # Normalise common column aliases
    col_map = {}
    for c in df.columns:
        cl = c.lower().replace(" ", "_")
        if cl in ("ts", "time", "datetime", "@timestamp", "date"):
            col_map[c] = "Timestamp"
        elif cl in ("severity", "level", "log_level", "priority"):
            col_map[c] = "Severity"
        elif cl in ("src", "source_ip", "host", "hostname", "source"):
            col_map[c] = "Source"
        elif cl in ("msg", "message", "description", "event"):
            col_map[c] = "Message"
        elif cl in ("cat", "category", "type"):
            col_map[c] = "Category"
        elif cl in ("proto", "protocol"):
            col_map[c] = "Protocol"
        elif cl in ("action", "outcome", "response"):
            col_map[c] = "Action"
        elif cl in ("event_id", "eventid", "id"):
            col_map[c] = "Event ID"
    df.rename(columns=col_map, inplace=True)
    defaults = {
        "Timestamp": datetime.now(), "Severity": "INFO",
        "Source": "uploaded", "Message": "N/A",
        "Category": "System", "Protocol": "N/A",
        "Action": "LOG", "MITRE Tactic": "N/A",
        "Event ID": 0, "Anomaly Score": 10, "Anomaly": "NO",
        "_raw": "",
    }
    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default
    if "Severity" in df.columns:
        df["Severity"] = df["Severity"].apply(
            lambda v: _SEV_KEYWORDS.get(str(v).lower(), str(v).upper()[:8])
        )
    if "_raw" not in df.columns or df["_raw"].eq("").all():
        df["_raw"] = df["Message"].astype(str)
    try:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    except Exception:
        df["Timestamp"] = datetime.now()
    return df


def _generic_row(line: str) -> dict[str, Any]:
    """Fallback parser for unrecognised lines."""
    ts = datetime.now()
    m_ts = _GENERIC_TS.search(line)
    if m_ts:
        try:
            ts = datetime.fromisoformat(m_ts.group("ts").replace(" ", "T"))
        except ValueError:
            pass
    m_br = _BRACKET_RE.match(line)
    if m_br:
        sev_raw = m_br.group("sev").upper()
        sev = sev_raw if sev_raw in SEVERITIES else _detect_severity(line)
        msg = m_br.group("msg")
    else:
        sev = _detect_severity(line)
        msg = line[:300]

    src_m = re.search(r"\b(?:src|host|ip)[=:\s]+(\S+)", line, re.IGNORECASE)
    src = src_m.group(1) if src_m else "unknown"
    anomaly = 60 if sev in ("CRITICAL", "HIGH") else 10
    return {
        "Timestamp": ts, "Source": src, "Message": msg,
        "Severity": sev, "Category": "System",
        "Protocol": "N/A", "Action": "LOG",
        "MITRE Tactic": "N/A", "Event ID": 0,
        "Anomaly Score": anomaly,
        "Anomaly": "YES" if anomaly >= 70 else "NO",
        "_raw": line,
    }


def _parse_raw_text(lines: list[str]) -> pd.DataFrame:
    """Generic line-by-line parser used as final fallback."""
    rows = [_generic_row(ln) for ln in lines if ln.strip()]
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _parse_uploaded_file(uploaded_file) -> pd.DataFrame:
    """Detect format and parse an uploaded log file into a DataFrame."""
    name = uploaded_file.name.lower()
    raw_bytes = uploaded_file.read()
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = raw_bytes.decode("latin-1", errors="replace")

    lines = text.splitlines()

    # JSON / NDJSON
    if name.endswith(".json") or name.endswith(".ndjson"):
        df = _parse_json_logs(text)
        if not df.empty:
            return df

    # CSV
    if name.endswith(".csv"):
        df = _parse_csv_logs(text)
        if not df.empty:
            return df

    # Apache / Nginx access log heuristic
    if lines and _APACHE_RE.match(lines[0].strip()):
        df = _parse_apache(lines)
        if not df.empty:
            return df

    # Syslog heuristic
    if lines and _SYSLOG_RE.match(lines[0].strip()):
        df = _parse_syslog(lines)
        if not df.empty:
            return df

    # JSON array wrapped in brackets
    if text.strip().startswith("["):
        try:
            objs = json.loads(text)
            if isinstance(objs, list):
                ndjson = "\n".join(json.dumps(o) for o in objs)
                df = _parse_json_logs(ndjson)
                if not df.empty:
                    return df
        except Exception:
            pass

    # Generic / Windows Event text export / unknown .log/.txt
    return _parse_raw_text(lines)


# ---------------------------------------------------------------------------
# ENSURE REQUIRED COLUMNS
# ---------------------------------------------------------------------------

_REQUIRED_COLS = {
    "Timestamp": datetime.now(),
    "Event ID": 0,
    "Severity": "INFO",
    "Category": "System",
    "Source": "unknown",
    "Protocol": "N/A",
    "Action": "LOG",
    "MITRE Tactic": "N/A",
    "Message": "",
    "Anomaly Score": 10,
    "Anomaly": "NO",
    "_raw": "",
}


def _ensure_cols(df: pd.DataFrame) -> pd.DataFrame:
    for col, default in _REQUIRED_COLS.items():
        if col not in df.columns:
            df[col] = default
    try:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    except Exception:
        df["Timestamp"] = datetime.now()
    df["Anomaly Score"] = pd.to_numeric(df["Anomaly Score"], errors="coerce").fillna(10)
    df["Event ID"]      = pd.to_numeric(df["Event ID"], errors="coerce").fillna(0).astype(int)
    return df


# ---------------------------------------------------------------------------
# FILTER LOGIC
# ---------------------------------------------------------------------------

def _apply_filters(df: pd.DataFrame, filters: dict) -> pd.DataFrame:
    # Time window
    hours = filters["hours"]
    if hours > 0:
        cutoff = datetime.now() - timedelta(hours=hours)
        df = df[df["Timestamp"] >= cutoff]

    if filters["sev"]:
        df = df[df["Severity"].isin(filters["sev"])]
    if filters["cat"]:
        df = df[df["Category"].isin(filters["cat"])]
    if filters["proto"]:
        df = df[df["Protocol"].isin(filters["proto"])]
    if filters["action"]:
        df = df[df["Action"].isin(filters["action"])]
    if filters["mitre"]:
        df = df[df["MITRE Tactic"].isin(filters["mitre"])]

    if filters["src"].strip():
        df = df[df["Source"].astype(str).str.contains(filters["src"].strip(), case=False, na=False)]

    if filters["eid"].strip().isdigit():
        df = df[df["Event ID"] == int(filters["eid"].strip())]

    kw = filters["keyword"].strip()
    if kw:
        try:
            pattern = re.compile(kw, re.IGNORECASE)
            df = df[df["Message"].astype(str).str.contains(pattern, na=False)]
        except re.error:
            df = df[df["Message"].astype(str).str.contains(kw, case=False, na=False)]

    if filters["anomaly_only"]:
        df = df[df["Anomaly"] == "YES"]
    if filters["min_anomaly"] > 0:
        df = df[df["Anomaly Score"] >= filters["min_anomaly"]]

    return df


# ---------------------------------------------------------------------------
# RENDER
# ---------------------------------------------------------------------------

def render() -> None:
    page_header(
        "SIEM Log Analyzer",
        "Enterprise-grade log filtering, threat hunting, and anomaly detection. "
        "Upload your own log files or explore synthetic sample data.",
        "📋",
    )

    # -----------------------------------------------------------------------
    # DATA SOURCE SECTION
    # -----------------------------------------------------------------------
    st.markdown(
        "<h4 style='color:var(--cp-pink);text-shadow:0 0 5px var(--cp-pink);"
        "text-transform:uppercase;letter-spacing:0.1em;'>📂 Data Source</h4>",
        unsafe_allow_html=True,
    )

    src_col1, src_col2 = st.columns([2, 1])
    with src_col1:
        uploaded_files = st.file_uploader(
            "Upload Log Files (any format)",
            type=["log", "txt", "csv", "json", "ndjson", "evtx"],
            accept_multiple_files=True,
            help=(
                "Supported: Syslog, Apache/Nginx access logs, Windows Event text export, "
                "JSON / NDJSON, CSV, generic .log/.txt files. "
                "Multiple files will be merged."
            ),
            key="la_uploader",
        )
    with src_col2:
        use_sample = st.checkbox(
            "Use built-in sample data",
            value=(not bool(uploaded_files)),
            key="la_sample_chk",
            help="400 synthetic SIEM events covering all categories.",
        )

    # Build working DataFrame
    df_all = pd.DataFrame()

    if uploaded_files:
        parsed_frames: list[pd.DataFrame] = []
        for f in uploaded_files:
            with st.spinner(f"Parsing {f.name} …"):
                parsed = _parse_uploaded_file(f)
            if parsed.empty:
                st.warning(f"⚠️ Could not parse **{f.name}** — no rows extracted.")
            else:
                st.success(f"✅ **{f.name}** — {len(parsed):,} events loaded.")
                parsed_frames.append(parsed)
        if parsed_frames:
            df_all = pd.concat(parsed_frames, ignore_index=True)

    if df_all.empty or use_sample:
        sample_df = _generate_sample_logs(300)
        if df_all.empty:
            df_all = sample_df
        else:
            df_all = pd.concat([df_all, sample_df], ignore_index=True)

    df_all = _ensure_cols(df_all)
    df_all.sort_values("Timestamp", ascending=False, inplace=True)
    df_all.reset_index(drop=True, inplace=True)

    st.markdown("---")

    # -----------------------------------------------------------------------
    # FILTER PANEL
    # -----------------------------------------------------------------------
    st.markdown(
        "<h4 style='color:var(--cp-cyan);text-shadow:0 0 5px var(--cp-cyan);"
        "text-transform:uppercase;letter-spacing:0.1em;'>🔎 SIEM Filters</h4>",
        unsafe_allow_html=True,
    )
    st.caption("All active filters combine with AND logic. Leave a filter empty to skip it.")

    with st.container():
        r1c1, r1c2, r1c3 = st.columns(3)

        time_options = {
            "Last 1 Hour": 1, "Last 6 Hours": 6, "Last 24 Hours": 24,
            "Last 3 Days": 72, "Last 7 Days": 168, "All Logs": 0,
        }
        with r1c1:
            selected_time = st.selectbox("⏱ Time Window", list(time_options.keys()), index=4, key="la_time")
        with r1c2:
            sev_filter = st.multiselect("🚨 Severity", SEVERITIES, default=[], key="la_sev")
        with r1c3:
            # Use categories present in data (plus fixed list)
            present_cats = sorted(df_all["Category"].dropna().unique().tolist())
            all_cats = sorted(set(CATEGORIES) | set(present_cats))
            cat_filter = st.multiselect("📂 Category", all_cats, default=[], key="la_cat")

        r2c1, r2c2, r2c3 = st.columns(3)
        with r2c1:
            present_protos = sorted(df_all["Protocol"].dropna().unique().tolist())
            all_protos = sorted(set(PROTOCOLS) | set(present_protos))
            proto_filter = st.multiselect("🌐 Protocol", all_protos, default=[], key="la_proto")
        with r2c2:
            present_actions = sorted(df_all["Action"].dropna().unique().tolist())
            all_actions = sorted(set(ACTIONS) | set(present_actions))
            action_filter = st.multiselect("🛡 Response Action", all_actions, default=[], key="la_action")
        with r2c3:
            mitre_filter = st.multiselect("⚔ MITRE ATT&CK Tactic", MITRE_TACTICS, default=[], key="la_mitre")

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1:
            keyword = st.text_input("🔍 Keyword / Regex (in Message)", placeholder="e.g. brute.force|mimikatz", key="la_keyword")
        with r3c2:
            src_filter = st.text_input("🖥 Source IP / Host (partial)", placeholder="e.g. 192.168", key="la_src")
        with r3c3:
            eid_filter = st.text_input("🆔 Event ID (exact)", placeholder="e.g. 4625", key="la_eid")

        r4c1, r4c2, r4c3 = st.columns([1, 2, 1])
        with r4c1:
            anomaly_only = st.checkbox("⚠️ Anomalies Only", value=False, key="la_anomaly")
        with r4c2:
            min_anomaly = st.slider("Min Anomaly Score", 0, 100, 0, 5, key="la_min_anomaly")
        with r4c3:
            max_rows = st.selectbox("Max Rows", [50, 100, 200, 500], index=1, key="la_maxrows")

    # -----------------------------------------------------------------------
    # APPLY FILTERS
    # -----------------------------------------------------------------------
    filters = {
        "hours": time_options[selected_time],
        "sev": sev_filter, "cat": cat_filter, "proto": proto_filter,
        "action": action_filter, "mitre": mitre_filter,
        "src": src_filter, "eid": eid_filter, "keyword": keyword,
        "anomaly_only": anomaly_only, "min_anomaly": min_anomaly,
    }
    df = _apply_filters(df_all.copy(), filters)

    # -----------------------------------------------------------------------
    # SUMMARY METRICS BAR
    # -----------------------------------------------------------------------
    st.markdown("---")
    total   = len(df_all)
    matched = len(df)
    sc = df["Severity"].value_counts()
    st.markdown(
        f"<p style='color:var(--cp-text);font-size:0.9rem;'>"
        f"📊 <strong style='color:var(--cp-yellow);'>{matched:,}</strong> events matched "
        f"of <strong style='color:var(--cp-yellow);'>{total:,}</strong> total</p>",
        unsafe_allow_html=True,
    )
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("🔴 CRITICAL",  int(sc.get("CRITICAL", 0)))
    m2.metric("🟠 HIGH",      int(sc.get("HIGH",     0)))
    m3.metric("🟡 MEDIUM",    int(sc.get("MEDIUM",   0)))
    m4.metric("🔵 LOW",       int(sc.get("LOW",      0)))
    m5.metric("🟢 INFO",      int(sc.get("INFO",     0)))
    m6.metric("⚠️ Anomalies", int((df["Anomaly"] == "YES").sum()))

    # -----------------------------------------------------------------------
    # TABS
    # -----------------------------------------------------------------------
    if df.empty:
        st.markdown(
            """
            <div style="border:1px dashed #ff00ff;padding:30px;text-align:center;
                        color:#ff00ff;font-family:monospace;margin-top:24px;">
                <div style="font-size:2rem;margin-bottom:10px;">⚠️</div>
                <strong>NO LOGS MATCH YOUR FILTERS</strong><br>
                <span style="font-size:0.85rem;color:#00ffcc;">
                    Relax the filters — widen the time window or remove severity selections.
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    tab_table, tab_timeline, tab_breakdown, tab_raw = st.tabs(
        ["📋 Log Table", "📈 Timeline", "📊 Breakdown", "🖥 Raw Logs"]
    )

    # ── Log Table ──────────────────────────────────────────────────────────
    with tab_table:
        display_cols = [
            "Timestamp", "Event ID", "Severity", "Category",
            "Source", "Protocol", "Action", "MITRE Tactic",
            "Anomaly Score", "Anomaly", "Message",
        ]
        # Only include columns that actually exist
        display_cols = [c for c in display_cols if c in df.columns]
        display_df = df[display_cols].head(max_rows).copy()
        display_df["Timestamp"] = display_df["Timestamp"].astype(str).str[:19]

        st.dataframe(display_df, use_container_width=True, height=480, hide_index=True)

        csv_buf = StringIO()
        df.head(max_rows)[display_cols].to_csv(csv_buf, index=False)
        st.download_button(
            "⬇️ Export Filtered Logs (CSV)",
            data=csv_buf.getvalue(),
            file_name=f"siem_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="la_export_csv",
        )

    # ── Timeline ───────────────────────────────────────────────────────────
    with tab_timeline:
        st.markdown("**Events Over Time (hourly buckets)**")
        tdf = df.copy()
        tdf["Hour"] = tdf["Timestamp"].dt.floor("h")
        timeline_counts = (
            tdf.groupby(["Hour", "Severity"]).size()
            .reset_index(name="Count")
        )
        if not timeline_counts.empty:
            pivot = (
                timeline_counts.pivot(index="Hour", columns="Severity", values="Count")
                .fillna(0)
            )
            st.area_chart(pivot, use_container_width=True, height=300)
        else:
            st.info("No timeline data for current filters.")

        st.markdown("**Anomaly Score Distribution**")
        bins = pd.cut(
            df["Anomaly Score"],
            bins=[0, 25, 50, 70, 85, 100],
            labels=["0-25 Normal", "26-50 Low", "51-70 Med", "71-85 High", "86-100 Critical"],
        )
        st.bar_chart(bins.value_counts().sort_index(), use_container_width=True, height=220)

    # ── Breakdown ──────────────────────────────────────────────────────────
    with tab_breakdown:
        b1, b2 = st.columns(2)
        with b1:
            st.markdown("**Top Categories**")
            st.bar_chart(df["Category"].value_counts().head(8), use_container_width=True, height=220)
            st.markdown("**MITRE ATT&CK Tactic Distribution**")
            st.bar_chart(df["MITRE Tactic"].value_counts(), use_container_width=True, height=260)
        with b2:
            st.markdown("**Response Action Distribution**")
            st.bar_chart(df["Action"].value_counts(), use_container_width=True, height=220)
            st.markdown("**Top 10 Source IPs / Hosts**")
            st.bar_chart(df["Source"].value_counts().head(10), use_container_width=True, height=260)

    # ── Raw Logs ───────────────────────────────────────────────────────────
    with tab_raw:
        st.markdown(
            "<p style='font-size:0.82rem;color:var(--cp-cyan);'>Raw log lines for "
            f"the first <strong>50</strong> matched events.</p>",
            unsafe_allow_html=True,
        )
        raw_lines = "\n".join(df["_raw"].head(50).astype(str).tolist())
        st.code(raw_lines, language="text")
        st.download_button(
            "⬇️ Export Raw Logs (.log)",
            data=raw_lines,
            file_name=f"raw_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            mime="text/plain",
            key="la_export_raw",
        )

    # -----------------------------------------------------------------------
    # THREAT HUNTING TIPS
    # -----------------------------------------------------------------------
    st.markdown("---")
    st.info(
        "💡 **Threat Hunting Tips:**\n\n"
        "- **Brute-force**: Severity = HIGH/CRITICAL + Category = Authentication + keyword `failed`\n"
        "- **Lateral movement**: MITRE = Lateral Movement + Protocol = TCP/SMB\n"
        "- **Exfiltration**: MITRE = Exfiltration + Action = ALERT/BLOCK\n"
        "- **Malware**: Category = Threat Detection/Endpoint + Anomalies Only ✓\n"
        "- **Privilege escalation**: MITRE = Privilege Escalation + Severity = HIGH"
    )
