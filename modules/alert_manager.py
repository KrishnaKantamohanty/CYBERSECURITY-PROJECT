import streamlit as st
from modules.risk_engine import get_all_findings
from utils.theme import page_header


def render():
    page_header(
        "Security Alert Center",
        "Monitor, filter, and review active security alerts and risk findings recorded across all defensive modules.",
        "🚨",
    )

    findings = get_all_findings()

    if not findings:
        st.info("✅ **No Security Alerts Recorded**: No risk findings or security alerts have been generated in this session yet.")
        return

    # Filter controls
    col_sev, col_status, col_search = st.columns([1, 1, 2])
    with col_sev:
        sev_filter = st.selectbox("Severity Filter", ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    with col_status:
        status_filter = st.selectbox("Review Status", ["All Alerts", "Unreviewed Only", "Reviewed Only"])
    with col_search:
        search_query = st.text_input("Search Alerts", placeholder="Search title, explanation, tool...")

    filtered = findings
    if sev_filter != "All Severities":
        filtered = [f for f in filtered if f["severity"] == sev_filter]
    if status_filter == "Unreviewed Only":
        filtered = [f for f in filtered if not f["reviewed"]]
    elif status_filter == "Reviewed Only":
        filtered = [f for f in filtered if f["reviewed"]]

    if search_query.strip():
        q = search_query.strip().lower()
        filtered = [
            f for f in filtered
            if q in f["title"].lower() or q in f["explanation"].lower() or q in f["source_tool"].lower()
        ]

    st.write(f"Showing **{len(filtered)}** of **{len(findings)}** total alert(s)")

    if st.button("Clear Reviewed Session Alerts", key="btn_clear_reviewed_alerts"):
        st.session_state.risk_findings = [f for f in st.session_state.risk_findings if not f["reviewed"]]
        st.success("Reviewed alerts cleared from session state.")
        st.rerun()

    st.markdown("---")

    for f in filtered:
        sev = f["severity"]
        badge_style = "background:#ef4444; color:white;" if sev == "CRITICAL" else \
                      "background:#f97316; color:white;" if sev == "HIGH" else \
                      "background:#eab308; color:black;" if sev == "MEDIUM" else \
                      "background:#10b981; color:white;" if sev == "LOW" else "background:#3b82f6; color:white;"

        status_tag = "✓ Reviewed" if f["reviewed"] else "⚠️ Pending Review"
        status_color = "#6ee7b7" if f["reviewed"] else "#fde047"

        st.markdown(
            f"""
            <div class="result-card">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; margin-bottom:8px;">
                    <div>
                        <span style="{badge_style} padding:4px 10px; border-radius:4px; font-weight:700; font-size:0.8rem; margin-right:8px;">{sev}</span>
                        <strong style="font-size:1.1rem;">{f['title']}</strong>
                    </div>
                    <div style="font-size:0.85rem; color:{status_color}; font-weight:600;">
                        {status_tag} | <span style="opacity:0.8;">{f['timestamp']}</span>
                    </div>
                </div>
                <p style="margin:6px 0; color:rgba(255,255,255,0.9);"><strong>Source Tool:</strong> {f['source_tool']} | <strong>Risk Score Impact:</strong> {f['score']}/100</p>
                <p style="margin:4px 0; color:rgba(255,255,255,0.85);">{f['explanation']}</p>
                <div style="margin-top:10px; padding:10px; background:rgba(0,0,0,0.3); border-radius:6px;">
                    <strong style="color:#6ee7b7;">Recommendation:</strong> {f['recommendation']}
                </div>
            """,
            unsafe_allow_html=True,
        )

        if f.get("mitre_technique"):
            st.caption(f"🎯 **MITRE ATT&CK Mapping**: Tactic: `{f.get('mitre_tactic', 'N/A')}` | Technique: `{f.get('mitre_technique', 'N/A')}`")

        c1, c2 = st.columns([1, 4])
        with c1:
            if not f["reviewed"]:
                if st.button("Mark Reviewed", key=f"btn_review_{f['id']}"):
                    f["reviewed"] = True
                    st.rerun()
            else:
                if st.button("Mark Unreviewed", key=f"btn_unreview_{f['id']}"):
                    f["reviewed"] = False
                    st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
