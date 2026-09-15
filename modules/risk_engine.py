import datetime
import streamlit as st
from typing import List, Dict, Any, Tuple

SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_COLORS = {
    "INFO": "#3b82f6",
    "LOW": "#10b981",
    "MEDIUM": "#eab308",
    "HIGH": "#f97316",
    "CRITICAL": "#ef4444",
}


def initialize_risk_state():
    """Ensure session state contains risk findings and alert queues."""
    if "risk_findings" not in st.session_state:
        st.session_state.risk_findings = []


def add_finding(
    title: str,
    severity: str,
    score: int,
    explanation: str,
    recommendation: str,
    source_tool: str,
    mitre_tactic: str = "",
    mitre_technique: str = "",
) -> Dict[str, Any]:
    """Add a risk finding to the central risk session state."""
    initialize_risk_state()

    sev = severity.upper()
    if sev not in SEVERITY_LEVELS:
        sev = "INFO"

    finding = {
        "id": f"find_{len(st.session_state.risk_findings) + 1}_{int(datetime.datetime.now().timestamp())}",
        "title": title,
        "severity": sev,
        "score": max(0, min(100, score)),
        "explanation": explanation,
        "recommendation": recommendation,
        "source_tool": source_tool,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reviewed": False,
    }

    # Prepend to findings list
    st.session_state.risk_findings.insert(0, finding)
    return finding


def get_all_findings() -> List[Dict[str, Any]]:
    """Retrieve all findings recorded in current session."""
    initialize_risk_state()
    return st.session_state.risk_findings


def calculate_overall_security_score() -> Tuple[int, str, List[Dict[str, Any]]]:
    """
    Calculate real overall security score (0-100) from active session metrics.
    No random numbers. Clear breakdown returned.
    """
    initialize_risk_state()

    base_score = 80  # Default baseline for operational application
    breakdown = []

    # 1. 2FA Status check
    if st.session_state.get("2fa_enabled", False):
        base_score += 10
        breakdown.append({"category": "Authentication", "impact": "+10", "detail": "Two-Factor Authentication (2FA) is enabled."})
    else:
        base_score -= 5
        breakdown.append({"category": "Authentication", "impact": "-5", "detail": "2FA is not yet enabled for current session."})

    # 2. Last evaluated password strength
    last_pwd_score = st.session_state.get("last_password_score", None)
    if last_pwd_score is not None:
        if last_pwd_score >= 80:
            base_score += 5
            breakdown.append({"category": "Password Security", "impact": "+5", "detail": f"Strong password evaluated ({last_pwd_score}/100)."})
        elif last_pwd_score < 50:
            base_score -= 10
            breakdown.append({"category": "Password Security", "impact": "-10", "detail": f"Weak password detected in session ({last_pwd_score}/100)."})
    else:
        breakdown.append({"category": "Password Security", "impact": "0", "detail": "No password evaluated in current session yet."})

    # 3. Malware & File Scan Findings
    findings = st.session_state.risk_findings
    high_critical_malware = [f for f in findings if f["source_tool"] == "Malware Scanner" and f["severity"] in ("HIGH", "CRITICAL")]
    if high_critical_malware:
        deduction = len(high_critical_malware) * 15
        base_score -= deduction
        breakdown.append({"category": "Malware Detections", "impact": f"-{deduction}", "detail": f"{len(high_critical_malware)} malicious file scan finding(s)."})
    else:
        breakdown.append({"category": "Malware Detections", "impact": "0", "detail": "No high/critical malware detections."})

    # 4. Phishing Findings
    high_phishing = [f for f in findings if f["source_tool"] == "Phishing Detector" and f["severity"] in ("HIGH", "CRITICAL")]
    if high_phishing:
        deduction = len(high_phishing) * 10
        base_score -= deduction
        breakdown.append({"category": "Phishing Detector", "impact": f"-{deduction}", "detail": f"{len(high_phishing)} high-risk phishing URL(s) detected."})

    # 5. File Integrity Mismatches
    mismatches = [f for f in findings if f["source_tool"] == "File Integrity" and "MISMATCH" in f["title"].upper()]
    if mismatches:
        deduction = len(mismatches) * 10
        base_score -= deduction
        breakdown.append({"category": "File Integrity", "impact": f"-{deduction}", "detail": f"{len(mismatches)} SHA-256 hash mismatch(es) recorded."})

    # Final score clamping
    final_score = max(0, min(100, base_score))

    if final_score >= 85:
        rating = "EXCELLENT"
    elif final_score >= 70:
        rating = "GOOD"
    elif final_score >= 50:
        rating = "MODERATE"
    elif final_score >= 30:
        rating = "POOR"
    else:
        rating = "CRITICAL"

    return final_score, rating, breakdown
