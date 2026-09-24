"""
SIEM-Style Log Analyzer
=======================
Pure-Python implementation (no pandas) with:
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
from datetime import datetime, timedelta
from io import StringIO
from typing import Any

import streamlit as st

from utils.theme import page_header

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "DEBUG"]
CATEGORIES = [
    "Authentication", "Network", "File System", "System",
    "Threat Detection", "Audit / Compliance", "Endpoint", "Email / Phishing",
]
PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP", "DNS", "ICMP", "SMTP", "RDP"]
MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Impact", "Command and Control",
    "Reconnaissance", "N/A",
]
ACTIONS = ["ALLOW", "BLOCK", "ALERT", "DENY", "LOG", "DROP", "QUARANTINE"]
SOURCES = [
    "10.0.0.12", "192.168.1.5", "172.16.3.88", "203.0.113.45", "198.51.100.7",
    "10.10.20.33", "192.168.0.1", "DESKTOP-W7XA", "SERVER-DC01", "LAPTOP-HR03",
    "fw-edge-01", "ids-sensor-02", "web-proxy-03", "auth-srv-01", "db-server-02",
]
EVENT_IDS = [
    4624, 4625, 4648, 4672, 4720, 4726, 4776, 4771,
    4688, 4698, 4702, 5140, 5145, 7045, 7040, 1102, 4719, 1001, 1002, 3000,
]
USERS = ["alice", "bob", "charlie", "dave", "admin", "svcaccount", "guest", "john.doe"]
FILES_LIST = ["passwords.txt", "budget_2024.xlsx", "employee_data.csv", "system.ini"]
SVCS = ["UpdaterService", "RemoteHelper", "BackupAgent", "SysMonitor"]

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
# LOG ROW TYPE
# ---------------------------------------------------------------------------
# Each log entry is a plain dict with these keys:
#   Timestamp (datetime), Event ID (int), Severity (str), Category (str),
#   Source (str), Protocol (str), Action (str), MITRE Tactic (str),
#   Message (str), Anomaly Score (int), Anomaly (str "YES"/"NO"), _raw (str)
# ---------------------------------------------------------------------------


def _make_row(
    ts: datetime, eid: int, sev: str, cat: str, src: str,
    proto: str, action: str, mitre: str, msg: str,
    anomaly_score: int, raw: str,
) -> dict[str, Any]:
    return {
        "Timestamp": ts,
        "Event ID": eid,
        "Severity": sev,
        "Category": cat,
        "Source": src,
        "Protocol": proto,
        "Action": action,
        "MITRE Tactic": mitre,
        "Message": msg,
        "Anomaly Score": anomaly_score,
        "Anomaly": "YES" if anomaly_score >= 70 else "NO",
        "_raw": raw,
    }


# ---------------------------------------------------------------------------
# SYNTHETIC SAMPLE LOG GENERATION
# ---------------------------------------------------------------------------

def _generate_sample_logs(n: int = 300) -> list[dict[str, Any]]:
    random.seed(42)
    now = datetime.now()
    rows: list[dict[str, Any]] = []
    for _ in range(n):
        category = random.choice(CATEGORIES)
        templates = _LOG_TEMPLATES.get(category, _LOG_TEMPLATES["System"])
        tmpl, default_sev, mitre = random.choice(templates)
        src = random.choice(SOURCES)
        user = random.choice(USERS)
        file_ = random.choice(FILES_LIST)
        svc = random.choice(SVCS)
        msg = tmpl.format(src=src, user=user, file=file_, svc=svc)
        sev = default_sev if random.random() < 0.75 else random.choice(SEVERITIES[:4])
        proto = random.choice(PROTOCOLS)
        action = random.choice(ACTIONS)
        eid = random.choice(EVENT_IDS)
        ts = now - timedelta(minutes=random.randint(0, 7 * 24 * 60))
        base_a = {"CRITICAL": 85, "HIGH": 65, "MEDIUM": 40, "LOW": 20, "INFO": 10, "DEBUG": 5}
        anomaly = min(100, base_a.get(sev, 10) + random.randint(-10, 15))
        raw = (
            f"[{ts.strftime('%Y-%m-%dT%H:%M:%S')}] [{sev}] src={src} "
            f"proto={proto} event_id={eid} action={action} msg=\"{msg}\""
        )
        rows.append(_make_row(ts, eid, sev, category, src, proto, action, mitre, msg, anomaly, raw))
    rows.sort(key=lambda r: r["Timestamp"], reverse=True)
    return rows


# ---------------------------------------------------------------------------
# LOG FILE PARSERS (pure Python, no pandas)
# ---------------------------------------------------------------------------

_SEV_KEYWORDS = {
    "critical": "CRITICAL", "crit": "CRITICAL", "emergency": "CRITICAL", "emerg": "CRITICAL",
    "error": "HIGH", "err": "HIGH", "alert": "HIGH",
    "warning": "MEDIUM", "warn": "MEDIUM",
    "notice": "LOW",
    "info": "INFO", "information": "INFO",
    "debug": "DEBUG",
}

_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.*)$"
)
_APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]+)"\s+(?P<status>\d+)\s+\S+',
)
_GENERIC_TS = re.compile(
    r"(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[T \t]\d{2}:\d{2}:\d{2})"
)
_BRACKET_RE = re.compile(
    r"\[(?P<ts>[\d\-T: .]+)\]\s*\[?(?P<sev>\w+)\]?\s*(?P<msg>.*)"
)


def _detect_severity(text: str) -> str:
    low = text.lower()
    for kw, sev in _SEV_KEYWORDS.items():
        if kw in low:
            return sev
    return "INFO"


def _generic_row(line: str) -> dict[str, Any]:
    ts = datetime.now()
    m_ts = _GENERIC_TS.search(line)
    if m_ts:
        try:
            ts = datetime.fromisoformat(m_ts.group("ts").replace(" ", "T").replace("/", "-"))
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
    src_m = re.search(r"\b(?:src|host|ip|from)[=:\s]+(\S+)", line, re.IGNORECASE)
    src = src_m.group(1) if src_m else "unknown"
    anomaly = 70 if sev in ("CRITICAL",) else 55 if sev == "HIGH" else 10
    return _make_row(ts, 0, sev, "System", src, "N/A", "LOG", "N/A", msg, anomaly, line)


def _parse_lines_syslog(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = _SYSLOG_RE.match(line)
        if m:
            try:
                ts = datetime.strptime(f"{datetime.now().year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
            except ValueError:
                ts = datetime.now()
            sev = _detect_severity(m.group("msg"))
            anomaly = 70 if sev == "CRITICAL" else 55 if sev == "HIGH" else 10
            rows.append(_make_row(
                ts, 0, sev, "System", m.group("host"), "N/A", "LOG", "N/A",
                m.group("msg"), anomaly, line
            ))
        else:
            rows.append(_generic_row(line))
    return rows


def _parse_lines_apache(lines: list[str]) -> list[dict[str, Any]]:
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
            anomaly = 75 if status >= 400 else 10
            mitre = "Initial Access" if status in (401, 403) else "N/A"
            rows.append(_make_row(
                ts, status, sev, "Network", m.group("ip"), "HTTP", "LOG",
                mitre, f"{m.group('req')} → HTTP {status}", anomaly, line
            ))
        else:
            rows.append(_generic_row(line))
    return rows


def _parse_json_text(text: str) -> list[dict[str, Any]]:
    rows = []
    # Try JSON array first
    try:
        data = json.loads(text)
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = [data]
        else:
            items = []
    except json.JSONDecodeError:
        # Try NDJSON (line-delimited)
        items = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("{", "}", "[", "]"):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for i, obj in enumerate(items):
        ts_raw = (obj.get("timestamp") or obj.get("time") or obj.get("@timestamp") or obj.get("date") or "")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", ""))
        except Exception:
            ts = datetime.now() - timedelta(minutes=i)
        msg = str(obj.get("message") or obj.get("msg") or obj.get("event") or str(obj))[:300]
        sev_raw = str(obj.get("level") or obj.get("severity") or obj.get("log_level") or "INFO").lower()
        sev = _SEV_KEYWORDS.get(sev_raw, "INFO")
        src = str(obj.get("host") or obj.get("source") or obj.get("src") or "uploaded")
        proto = str(obj.get("protocol") or obj.get("proto") or "N/A")
        action_val = str(obj.get("action") or obj.get("outcome") or "LOG")
        mitre = str(obj.get("mitre_tactic") or "N/A")
        try:
            eid = int(obj.get("event_id") or obj.get("eventid") or 0)
        except (ValueError, TypeError):
            eid = 0
        cat = str(obj.get("category") or obj.get("type") or "System")
        anomaly = 70 if sev in ("CRITICAL", "HIGH") else 10
        rows.append(_make_row(ts, eid, sev, cat, src, proto, action_val, mitre, msg, anomaly, json.dumps(obj)))
    return rows


def _parse_csv_text(text: str) -> list[dict[str, Any]]:
    rows = []
    reader = csv.DictReader(StringIO(text))
    if reader.fieldnames is None:
        return rows
    # Build column alias map
    col_map: dict[str, str] = {}
    for c in reader.fieldnames:
        cl = c.lower().replace(" ", "_").strip()
        if cl in ("ts", "time", "datetime", "@timestamp", "date", "timestamp"):
            col_map["timestamp"] = c
        elif cl in ("severity", "level", "log_level", "priority"):
            col_map["severity"] = c
        elif cl in ("src", "source_ip", "host", "hostname", "source"):
            col_map["source"] = c
        elif cl in ("msg", "message", "description", "event"):
            col_map["message"] = c
        elif cl in ("cat", "category", "type"):
            col_map["category"] = c
        elif cl in ("proto", "protocol"):
            col_map["protocol"] = c
        elif cl in ("action", "outcome", "response"):
            col_map["action"] = c
        elif cl in ("event_id", "eventid", "id"):
            col_map["event_id"] = c

    for i, row_dict in enumerate(reader):
        ts_raw = row_dict.get(col_map.get("timestamp", ""), "")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "").replace("/", "-"))
        except Exception:
            ts = datetime.now() - timedelta(minutes=i)
        msg = row_dict.get(col_map.get("message", ""), str(row_dict))[:300]
        sev_raw = row_dict.get(col_map.get("severity", ""), "INFO").lower()
        sev = _SEV_KEYWORDS.get(sev_raw, sev_raw.upper()[:8] if sev_raw else "INFO")
        if sev not in SEVERITIES:
            sev = "INFO"
        src = row_dict.get(col_map.get("source", ""), "uploaded")
        proto = row_dict.get(col_map.get("protocol", ""), "N/A")
        action_val = row_dict.get(col_map.get("action", ""), "LOG")
        cat = row_dict.get(col_map.get("category", ""), "System")
        try:
            eid = int(row_dict.get(col_map.get("event_id", ""), 0))
        except (ValueError, TypeError):
            eid = 0
        anomaly = 70 if sev in ("CRITICAL", "HIGH") else 10
        raw_line = ",".join(f"{v}" for v in row_dict.values())
        rows.append(_make_row(ts, eid, sev, cat, src, proto, action_val, "N/A", msg, anomaly, raw_line))
    return rows


def _parse_uploaded_file(uploaded_file) -> list[dict[str, Any]]:
    """Detect format and parse an uploaded log file into a list of row dicts."""
    name = uploaded_file.name.lower()
    raw_bytes = uploaded_file.read()
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = raw_bytes.decode("latin-1", errors="replace")

    lines = text.splitlines()
    if not lines:
        return []

    # JSON / NDJSON
    if name.endswith(".json") or name.endswith(".ndjson"):
        result = _parse_json_text(text)
        if result:
            return result

    # CSV
    if name.endswith(".csv"):
        result = _parse_csv_text(text)
        if result:
            return result

    # Apache / Nginx access log heuristic
    if _APACHE_RE.match(lines[0].strip()):
        result = _parse_lines_apache(lines)
        if result:
            return result

    # Syslog heuristic
    if _SYSLOG_RE.match(lines[0].strip()):
        result = _parse_lines_syslog(lines)
        if result:
            return result

    # JSON array wrapped in brackets
    if text.strip().startswith("["):
        try:
            objs = json.loads(text)
            if isinstance(objs, list):
                ndjson = "\n".join(json.dumps(o) for o in objs)
                result = _parse_json_text(ndjson)
                if result:
                    return result
        except Exception:
            pass

    # Generic / Windows Event text export / unknown
    return [_generic_row(ln) for ln in lines if ln.strip()]


# ---------------------------------------------------------------------------
# FILTER LOGIC (pure Python)
# ---------------------------------------------------------------------------

def _apply_filters(rows: list[dict[str, Any]], filters: dict) -> list[dict[str, Any]]:
    result = rows

    # Time window
    hours = filters["hours"]
    if hours > 0:
        cutoff = datetime.now() - timedelta(hours=hours)
        result = [r for r in result if r["Timestamp"] >= cutoff]

    if filters["sev"]:
        sev_set = set(filters["sev"])
        result = [r for r in result if r["Severity"] in sev_set]
    if filters["cat"]:
        cat_set = set(filters["cat"])
        result = [r for r in result if r["Category"] in cat_set]
    if filters["proto"]:
        proto_set = set(filters["proto"])
        result = [r for r in result if r["Protocol"] in proto_set]
    if filters["action"]:
        action_set = set(filters["action"])
        result = [r for r in result if r["Action"] in action_set]
    if filters["mitre"]:
        mitre_set = set(filters["mitre"])
        result = [r for r in result if r["MITRE Tactic"] in mitre_set]

    src_q = filters["src"].strip()
    if src_q:
        src_lower = src_q.lower()
        result = [r for r in result if src_lower in str(r["Source"]).lower()]

    eid_q = filters["eid"].strip()
    if eid_q.isdigit():
        eid_int = int(eid_q)
        result = [r for r in result if r["Event ID"] == eid_int]

    kw = filters["keyword"].strip()
    if kw:
        try:
            pattern = re.compile(kw, re.IGNORECASE)
            result = [r for r in result if pattern.search(str(r["Message"]))]
        except re.error:
            kw_lower = kw.lower()
            result = [r for r in result if kw_lower in str(r["Message"]).lower()]

    if filters["anomaly_only"]:
        result = [r for r in result if r["Anomaly"] == "YES"]
    if filters["min_anomaly"] > 0:
        threshold = filters["min_anomaly"]
        result = [r for r in result if r["Anomaly Score"] >= threshold]

    return result


# ---------------------------------------------------------------------------
# HELPER: rows → CSV string
# ---------------------------------------------------------------------------

_DISPLAY_COLS = [
    "Timestamp", "Event ID", "Severity", "Category",
    "Source", "Protocol", "Action", "MITRE Tactic",
    "Anomaly Score", "Anomaly", "Message",
]


def _rows_to_csv(rows: list[dict[str, Any]], columns: list[str] | None = None) -> str:
    cols = columns or _DISPLAY_COLS
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        out = {}
        for c in cols:
            val = r.get(c, "")
            if isinstance(val, datetime):
                val = val.strftime("%Y-%m-%d %H:%M:%S")
            out[c] = val
        writer.writerow(out)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# HELPER: build table HTML (replaces st.dataframe + Styler)
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    "CRITICAL": "#ff0000", "HIGH": "#ff8000", "MEDIUM": "#f3e600",
    "LOW": "#00ffff", "INFO": "#00ff88", "DEBUG": "#888888",
}


def _build_log_table_html(rows: list[dict[str, Any]], max_rows: int = 100) -> str:
    """Build an HTML table for the log entries with severity colour coding."""
    html_parts = [
        "<div style='max-height:500px;overflow-y:auto;border:1px solid var(--cp-cyan);'>",
        "<table style='width:100%;border-collapse:collapse;font-family:monospace;font-size:0.78rem;'>",
        "<thead><tr style='background:rgba(0,255,255,0.08);'>",
    ]
    cols = ["Timestamp", "EID", "Severity", "Category", "Source", "Proto", "Action", "MITRE", "Score", "Anom", "Message"]
    for c in cols:
        html_parts.append(
            f"<th style='padding:6px 8px;text-align:left;color:var(--cp-pink);"
            f"border-bottom:1px solid var(--cp-cyan);text-transform:uppercase;'>{c}</th>"
        )
    html_parts.append("</tr></thead><tbody>")

    for i, r in enumerate(rows[:max_rows]):
        bg = "rgba(0,0,0,0.3)" if i % 2 == 0 else "rgba(0,0,0,0.15)"
        sev = r.get("Severity", "INFO")
        sev_color = _SEV_COLORS.get(sev, "#888")
        ts_str = r["Timestamp"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(r["Timestamp"], datetime) else str(r["Timestamp"])[:19]
        anomaly_str = "⚠️" if r.get("Anomaly") == "YES" else "—"
        msg = str(r.get("Message", ""))[:120]

        html_parts.append(f"<tr style='background:{bg};'>")
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);color:var(--cp-text);'>{ts_str}</td>")
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);color:var(--cp-text);'>{r.get('Event ID', 0)}</td>")
        html_parts.append(
            f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);"
            f"color:{sev_color};font-weight:bold;'>{sev}</td>"
        )
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);color:var(--cp-text);'>{r.get('Category', '')}</td>")
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);color:var(--cp-cyan);'>{r.get('Source', '')}</td>")
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);color:var(--cp-text);'>{r.get('Protocol', '')}</td>")
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);color:var(--cp-text);'>{r.get('Action', '')}</td>")
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);color:var(--cp-text);'>{r.get('MITRE Tactic', '')}</td>")
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);color:var(--cp-yellow);'>{r.get('Anomaly Score', 0)}</td>")
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);'>{anomaly_str}</td>")
        html_parts.append(f"<td style='padding:4px 8px;border-bottom:1px solid rgba(0,255,255,0.08);color:var(--cp-text);'>{msg}</td>")
        html_parts.append("</tr>")

    html_parts.append("</tbody></table></div>")
    return "".join(html_parts)


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
                "JSON / NDJSON, CSV, generic .log/.txt files. Multiple files merged."
            ),
            key="la_uploader",
        )
    with src_col2:
        use_sample = st.checkbox(
            "Include built-in sample data",
            value=(not bool(uploaded_files)),
            key="la_sample_chk",
            help="300 synthetic SIEM events covering all categories.",
        )

    # Build working list
    all_rows: list[dict[str, Any]] = []

    if uploaded_files:
        for f in uploaded_files:
            with st.spinner(f"Parsing {f.name} …"):
                parsed = _parse_uploaded_file(f)
            if not parsed:
                st.warning(f"⚠️ Could not parse **{f.name}** — no rows extracted.")
            else:
                st.success(f"✅ **{f.name}** — {len(parsed):,} events loaded.")
                all_rows.extend(parsed)

    if not all_rows or use_sample:
        all_rows.extend(_generate_sample_logs(300))

    all_rows.sort(key=lambda r: r["Timestamp"], reverse=True)

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
        present_cats = sorted({r["Category"] for r in all_rows})
        all_cats = sorted(set(CATEGORIES) | set(present_cats))
        cat_filter = st.multiselect("📂 Category", all_cats, default=[], key="la_cat")

    r2c1, r2c2, r2c3 = st.columns(3)
    with r2c1:
        present_protos = sorted({r["Protocol"] for r in all_rows})
        all_protos = sorted(set(PROTOCOLS) | set(present_protos))
        proto_filter = st.multiselect("🌐 Protocol", all_protos, default=[], key="la_proto")
    with r2c2:
        present_actions = sorted({r["Action"] for r in all_rows})
        all_actions = sorted(set(ACTIONS) | set(present_actions))
        action_filter = st.multiselect("🛡 Response Action", all_actions, default=[], key="la_action")
    with r2c3:
        mitre_filter = st.multiselect("⚔ MITRE ATT&CK Tactic", MITRE_TACTICS, default=[], key="la_mitre")

    r3c1, r3c2, r3c3 = st.columns(3)
    with r3c1:
        keyword = st.text_input("🔍 Keyword / Regex (in Message)", placeholder="e.g. brute.force|mimikatz", key="la_keyword")
    with r3c2:
        src_input = st.text_input("🖥 Source IP / Host (partial)", placeholder="e.g. 192.168", key="la_src")
    with r3c3:
        eid_input = st.text_input("🆔 Event ID (exact)", placeholder="e.g. 4625", key="la_eid")

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
        "src": src_input, "eid": eid_input, "keyword": keyword,
        "anomaly_only": anomaly_only, "min_anomaly": min_anomaly,
    }
    filtered = _apply_filters(all_rows, filters)

    # -----------------------------------------------------------------------
    # SUMMARY METRICS
    # -----------------------------------------------------------------------
    st.markdown("---")
    total = len(all_rows)
    matched = len(filtered)

    sev_counts: dict[str, int] = {}
    anomaly_count = 0
    for r in filtered:
        sev_counts[r["Severity"]] = sev_counts.get(r["Severity"], 0) + 1
        if r["Anomaly"] == "YES":
            anomaly_count += 1

    st.markdown(
        f"<p style='color:var(--cp-text);font-size:0.9rem;'>"
        f"📊 <strong style='color:var(--cp-yellow);'>{matched:,}</strong> events matched "
        f"of <strong style='color:var(--cp-yellow);'>{total:,}</strong> total</p>",
        unsafe_allow_html=True,
    )

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("🔴 CRITICAL", sev_counts.get("CRITICAL", 0))
    m2.metric("🟠 HIGH",     sev_counts.get("HIGH", 0))
    m3.metric("🟡 MEDIUM",   sev_counts.get("MEDIUM", 0))
    m4.metric("🔵 LOW",      sev_counts.get("LOW", 0))
    m5.metric("🟢 INFO",     sev_counts.get("INFO", 0))
    m6.metric("⚠️ Anomalies", anomaly_count)

    # -----------------------------------------------------------------------
    # TABS
    # -----------------------------------------------------------------------
    if not filtered:
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

    tab_table, tab_breakdown, tab_raw = st.tabs(
        ["📋 Log Table", "📊 Breakdown", "🖥 Raw Logs"]
    )

    # ── Log Table ──────────────────────────────────────────────────────────
    with tab_table:
        st.markdown(
            "<p style='font-size:0.82rem;color:var(--cp-cyan);text-transform:uppercase;"
            "letter-spacing:0.1em;'>Filtered Log Events — Newest First</p>",
            unsafe_allow_html=True,
        )
        table_html = _build_log_table_html(filtered, max_rows)
        st.markdown(table_html, unsafe_allow_html=True)

        csv_data = _rows_to_csv(filtered[:max_rows])
        st.download_button(
            "⬇️ Export Filtered Logs (CSV)",
            data=csv_data,
            file_name=f"siem_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="la_export_csv",
        )

    # ── Breakdown ──────────────────────────────────────────────────────────
    with tab_breakdown:
        b1, b2 = st.columns(2)

        with b1:
            st.markdown("**Severity Distribution**")
            sev_data = {}
            for r in filtered:
                sev_data[r["Severity"]] = sev_data.get(r["Severity"], 0) + 1
            if sev_data:
                for sev_name in SEVERITIES:
                    cnt = sev_data.get(sev_name, 0)
                    if cnt > 0:
                        color = _SEV_COLORS.get(sev_name, "#888")
                        pct = (cnt / matched) * 100
                        st.markdown(
                            f"<div style='margin-bottom:6px;'>"
                            f"<span style='color:{color};font-weight:bold;width:80px;display:inline-block;'>{sev_name}</span>"
                            f"<span style='color:var(--cp-text);'>{cnt} ({pct:.1f}%)</span>"
                            f"<div style='background:rgba(0,255,255,0.1);height:8px;border:1px solid {color};margin-top:2px;'>"
                            f"<div style='height:100%;width:{pct}%;background:{color};box-shadow:0 0 5px {color};'></div>"
                            f"</div></div>",
                            unsafe_allow_html=True,
                        )

            st.markdown("---")
            st.markdown("**Top Categories**")
            cat_data: dict[str, int] = {}
            for r in filtered:
                cat_data[r["Category"]] = cat_data.get(r["Category"], 0) + 1
            for cat_name, cnt in sorted(cat_data.items(), key=lambda x: x[1], reverse=True)[:8]:
                pct = (cnt / matched) * 100
                st.markdown(
                    f"<div style='margin-bottom:4px;'>"
                    f"<span style='color:var(--cp-pink);'>{cat_name}</span>: "
                    f"<span style='color:var(--cp-yellow);'>{cnt}</span> "
                    f"<span style='color:var(--cp-text);font-size:0.8rem;'>({pct:.1f}%)</span></div>",
                    unsafe_allow_html=True,
                )

        with b2:
            st.markdown("**MITRE ATT&CK Tactic Distribution**")
            mitre_data: dict[str, int] = {}
            for r in filtered:
                mitre_data[r["MITRE Tactic"]] = mitre_data.get(r["MITRE Tactic"], 0) + 1
            for tactic, cnt in sorted(mitre_data.items(), key=lambda x: x[1], reverse=True):
                pct = (cnt / matched) * 100
                st.markdown(
                    f"<div style='margin-bottom:4px;'>"
                    f"<span style='color:var(--cp-cyan);'>{tactic}</span>: "
                    f"<span style='color:var(--cp-yellow);'>{cnt}</span> "
                    f"<span style='color:var(--cp-text);font-size:0.8rem;'>({pct:.1f}%)</span></div>",
                    unsafe_allow_html=True,
                )

            st.markdown("---")
            st.markdown("**Top 10 Sources**")
            src_data: dict[str, int] = {}
            for r in filtered:
                src_data[r["Source"]] = src_data.get(r["Source"], 0) + 1
            for src_name, cnt in sorted(src_data.items(), key=lambda x: x[1], reverse=True)[:10]:
                st.markdown(
                    f"<div style='margin-bottom:4px;'>"
                    f"<span style='color:var(--cp-cyan);font-family:monospace;'>{src_name}</span>: "
                    f"<span style='color:var(--cp-yellow);'>{cnt}</span></div>",
                    unsafe_allow_html=True,
                )

            st.markdown("---")
            st.markdown("**Response Actions**")
            act_data: dict[str, int] = {}
            for r in filtered:
                act_data[r["Action"]] = act_data.get(r["Action"], 0) + 1
            for act_name, cnt in sorted(act_data.items(), key=lambda x: x[1], reverse=True):
                st.markdown(
                    f"<div style='margin-bottom:4px;'>"
                    f"<span style='color:var(--cp-pink);'>{act_name}</span>: "
                    f"<span style='color:var(--cp-yellow);'>{cnt}</span></div>",
                    unsafe_allow_html=True,
                )

    # ── Raw Logs ───────────────────────────────────────────────────────────
    with tab_raw:
        st.markdown(
            "<p style='font-size:0.82rem;color:var(--cp-cyan);'>Raw log lines for "
            "the first <strong>50</strong> matched events.</p>",
            unsafe_allow_html=True,
        )
        raw_lines = "\n".join(str(r["_raw"]) for r in filtered[:50])
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
