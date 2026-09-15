import datetime
import streamlit as st
from utils.theme import page_header


def log_event(event_type: str, details: str, severity: str = "INFO") -> None:
    """Log a safe security audit event (excluding sensitive credentials/keys)."""
    if "security_event_logs" not in st.session_state:
        st.session_state.security_event_logs = []

    # Sanitize inputs to strictly exclude credentials or keys if accidentally passed
    clean_details = str(details)
    for sensitive_word in ["password", "secret", "api_key", "token"]:
        if f"{sensitive_word}=" in clean_details.lower():
            clean_details = "[REDACTED SENSITIVE DATA]"

    log_entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type.upper(),
        "details": clean_details,
        "severity": severity.upper(),
    }

    st.session_state.security_event_logs.insert(0, log_entry)
    # Keep up to 100 session events
    st.session_state.security_event_logs = st.session_state.security_event_logs[:100]


def render():
    page_header(
        "Security Event Log",
        "Safe timeline audit log of defensive events, checks, and administrative activities in your active session.",
        "📜",
    )

    if "security_event_logs" not in st.session_state or not st.session_state.security_event_logs:
        st.info("No security events recorded in current session yet.")
        return

    logs = st.session_state.security_event_logs

    col1, col2 = st.columns([3, 1])
    with col1:
        search = st.text_input("Filter Event Logs", placeholder="Search by event type or details...")
    with col2:
        if st.button("Export Event Log (CSV)", key="btn_export_events_csv"):
            import csv
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=["timestamp", "event_type", "severity", "details"])
            writer.writeheader()
            writer.writerows(logs)
            st.download_button(
                "📥 Download CSV",
                output.getvalue(),
                file_name="security_event_log.csv",
                mime="text/csv",
                key="dl_events_csv",
            )

    filtered = logs
    if search.strip():
        q = search.strip().lower()
        filtered = [l for l in filtered if q in l["event_type"].lower() or q in l["details"].lower()]

    st.write(f"Displaying **{len(filtered)}** session security event(s).")
    st.dataframe(filtered, use_container_width=True, hide_index=True)
