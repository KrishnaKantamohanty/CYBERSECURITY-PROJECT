import csv
import io
import datetime
import streamlit as st
from utils.theme import page_header
from utils.security import get_session_stats
from modules.risk_engine import calculate_overall_security_score, get_all_findings


def generate_html_report() -> str:
    """Generate a standalone printable HTML security report."""
    score, rating, breakdown = calculate_overall_security_score()
    findings = get_all_findings()
    session_data = get_session_stats()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    findings_html = ""
    for f in findings:
        findings_html += f"""
        <tr>
            <td><strong>{f['title']}</strong></td>
            <td><span class="badge {f['severity'].lower()}">{f['severity']}</span></td>
            <td>{f['source_tool']}</td>
            <td>{f['score']}/100</td>
            <td>{f['explanation']}</td>
        </tr>
        """

    if not findings_html:
        findings_html = "<tr><td colspan='5'>No security findings recorded in current session.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>Cybersecurity Security Center - Executive Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; color: #1e293b; background: #f8fafc; }}
        .header {{ background: #0f172a; color: white; padding: 24px; border-radius: 8px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .header p {{ margin: 6px 0 0 0; opacity: 0.8; font-size: 14px; }}
        .card {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        .score-box {{ display: flex; align-items: center; gap: 20px; }}
        .score-val {{ font-size: 48px; font-weight: 800; color: #0284c7; }}
        .score-rating {{ font-size: 20px; font-weight: 700; color: #0f172a; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px 12px; border: 1px solid #cbd5e1; text-align: left; font-size: 14px; }}
        th {{ background: #f1f5f9; font-weight: 600; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 12px; color: white; }}
        .critical {{ background: #ef4444; }}
        .high {{ background: #f97316; }}
        .medium {{ background: #eab308; color: black; }}
        .low {{ background: #10b981; }}
        .info {{ background: #3b82f6; }}
        .footer {{ font-size: 12px; color: #64748b; margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Cybersecurity Security Center — Assessment Report</h1>
        <p>Generated on: {now_str} | Target System: Local Browser Session</p>
    </div>

    <div class="card">
        <h2>Overall Security Posture</h2>
        <div class="score-box">
            <div class="score-val">{score} / 100</div>
            <div>
                <div class="score-rating">Status: {rating}</div>
                <p style="margin:4px 0 0 0; color:#64748b;">Calculated deterministically from active session security controls.</p>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Risk Findings & Security Alerts</h2>
        <table>
            <thead>
                <tr>
                    <th>Finding Title</th>
                    <th>Severity</th>
                    <th>Source Module</th>
                    <th>Score</th>
                    <th>Explanation</th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Session Audit Statistics</h2>
        <p><strong>Total Security Checks:</strong> {session_data['stats']['security_checks']}</p>
        <p><strong>Files Processed & Scanned:</strong> {session_data['stats']['files_processed']}</p>
        <p><strong>Network & Port Audits:</strong> {session_data['stats'].get('network_checks', session_data['stats']['security_checks'])}</p>
        <p><strong>Phishing & IOC Checks:</strong> {session_data['stats']['phishing_checks']}</p>
        <p><strong>File Integrity Checks:</strong> {session_data['stats']['integrity_checks']}</p>
    </div>

    <div class="footer">
        <p><strong>Disclaimer:</strong> This security report is generated for defensive and educational security assessment purposes. Clean scan results do not guarantee absolute safety. Confidential passwords and secret API keys are strictly excluded from report logs.</p>
    </div>
</body>
</html>"""
    return html_content


def generate_csv_report() -> str:
    """Generate CSV report containing risk findings and stats."""
    score, rating, _ = calculate_overall_security_score()
    findings = get_all_findings()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["REPORT_HEADER", "Cybersecurity Security Center Report"])
    writer.writerow(["GENERATED_AT", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow(["OVERALL_SCORE", score])
    writer.writerow(["OVERALL_RATING", rating])
    writer.writerow([])
    writer.writerow(["ID", "Title", "Severity", "Source_Tool", "Score", "Explanation", "Recommendation", "Timestamp"])

    for f in findings:
        writer.writerow([
            f.get("id"),
            f.get("title"),
            f.get("severity"),
            f.get("source_tool"),
            f.get("score"),
            f.get("explanation"),
            f.get("recommendation"),
            f.get("timestamp"),
        ])

    return output.getvalue()


def render():
    page_header(
        "Security Report Generator",
        "Export comprehensive executive defensive security reports in PDF, HTML, and CSV formats.",
        "📊",
    )

    score, rating, breakdown = calculate_overall_security_score()
    findings = get_all_findings()

    st.subheader("Report Summary Preview")
    col1, col2, col3 = st.columns(3)
    col1.metric("Overall Score", f"{score} / 100")
    col2.metric("Rating", rating)
    col3.metric("Total Findings", len(findings))

    st.markdown("---")

    st.subheader("Export Formats")
    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(
            """
            <div class="result-card">
                <h4>📄 HTML Report</h4>
                <p>Standalone printable HTML report styled for web browser viewing or PDF printing.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        html_str = generate_html_report()
        st.download_button(
            "📥 Download HTML Report",
            data=html_str,
            file_name=f"security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            mime="text/html",
            key="dl_report_html",
        )

    with c2:
        st.markdown(
            """
            <div class="result-card">
                <h4>📊 CSV Data Report</h4>
                <p>Structured CSV file containing raw finding records for spreadsheet analysis.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        csv_str = generate_csv_report()
        st.download_button(
            "📥 Download CSV Report",
            data=csv_str,
            file_name=f"security_findings_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="dl_report_csv",
        )

    with c3:
        st.markdown(
            """
            <div class="result-card">
                <h4>🖨️ PDF Print View</h4>
                <p>Download the HTML report and use your browser's Print feature (Ctrl+P / Cmd+P) -> Save as PDF.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Preview Report in Browser", key="btn_preview_report"):
            st.components.v1.html(html_str, height=500, scrolling=True)
