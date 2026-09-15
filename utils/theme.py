import streamlit as st


def inject_theme() -> None:
    st.markdown(
        """
        <style>
        :root {
            color-scheme: dark;
        }
        body {
            background: #050c16;
            color: #e4f7ff;
        }
        [data-testid="stAppViewContainer"] {
            background: linear-gradient(180deg, #071220 0%, #071013 100%);
            color: #e4f7ff;
        }
        [data-testid="stSidebar"] {
            background: radial-gradient(circle at top left, rgba(0, 255, 255, 0.12), transparent 40%), #02121f;
            border-right: 1px solid rgba(0, 255, 255, 0.12);
            box-shadow: inset 0 0 35px rgba(0, 255, 255, 0.08);
        }
        .stSidebar .css-1d391kg {
            color: #8ef7ff;
        }
        .css-18e3th9 {
            padding-top: 1rem;
        }
        .css-1v0mbdj {
            color: #e7f7ff;
        }
        .stButton>button {
            background: linear-gradient(135deg, #08f7ff 0%, #0d6e9f 100%) !important;
            color: #f8ffff !important;
            border: 1px solid rgba(0, 255, 255, 0.25) !important;
            border-radius: 8px !important;
            box-shadow: 0 0 18px rgba(0, 255, 255, 0.16) !important;
            transition: transform 0.22s ease, box-shadow 0.22s ease;
            min-height: 3rem;
            white-space: normal;
        }
        .stButton>button:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 36px rgba(0, 255, 255, 0.28) !important;
        }
        .stCheckbox>div>div {
            color: #e4f7ff;
        }
        .stTextInput>div>div>input {
            background: rgba(255,255,255,0.04) !important;
            color: #e4f7ff !important;
            border: 1px solid rgba(255,255,255,0.12) !important;
        }
        .stTextArea>div>div>textarea {
            background: rgba(255,255,255,0.04) !important;
            color: #e4f7ff !important;
            border: 1px solid rgba(255,255,255,0.12) !important;
        }
        h1, h2, h3, h4, h5 {
            color: #e4f7ff;
        }
        .hero-card {
            background: rgba(2, 28, 48, 0.90);
            border: 1px solid rgba(0, 209, 255, 0.18);
            border-radius: 8px;
            padding: 26px;
            margin-bottom: 26px;
            display: flex;
            align-items: center;
            gap: 20px;
            box-shadow: 0 28px 80px rgba(0, 0, 0, 0.30);
            backdrop-filter: blur(8px);
        }
        .hero-card .hero-icon {
            width: 72px;
            height: 72px;
            display: grid;
            place-items: center;
            background: radial-gradient(circle at top left, rgba(0, 255, 255, 0.28), rgba(10, 35, 55, 0.95));
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 255, 0.24);
            font-size: 2.2rem;
            color: #d1f9ff;
            box-shadow: 0 0 24px rgba(0, 255, 255, 0.18);
        }
        .hero-card h1 {
            margin: 0;
            font-size: 2.4rem;
            letter-spacing: 0.5px;
        }
        .hero-card p {
            margin: 0.25rem 0 0;
            opacity: 0.82;
            line-height: 1.5;
        }
        .section-card {
            background: rgba(0, 18, 28, 0.88);
            border: 1px solid rgba(0, 203, 255, 0.18);
            border-radius: 8px;
            padding: 22px;
            margin-bottom: 18px;
            box-shadow: 0 0 30px rgba(0, 255, 255, 0.07);
        }
        .divider {
            border-top: 1px solid rgba(0, 255, 255, 0.16);
            margin: 1.5rem 0;
        }
        .dashboard-grid {
            display: grid;
            gap: 18px;
            grid-template-columns: 1fr;
            margin-bottom: 24px;
        }
        .popup-panel {
            background: rgba(1, 12, 24, 0.95);
            border: 1px solid rgba(0, 255, 255, 0.18);
            border-radius: 8px;
            padding: 24px;
            max-width: 980px;
            box-shadow: 0 0 60px rgba(0, 255, 255, 0.16);
            animation: popupEntry 0.35s ease-out;
        }
        .popup-title {
            font-size: 1.45rem;
            font-weight: 800;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            margin-bottom: 10px;
            color: #9bf4ff;
        }
        .popup-subtitle {
            color: rgba(255, 255, 255, 0.72);
            margin-bottom: 24px;
            line-height: 1.6;
        }
        .popup-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 16px;
        }
        .popup-option {
            background: rgba(0, 29, 53, 0.95);
            border: 1px solid rgba(0, 255, 255, 0.14);
            border-radius: 20px;
            padding: 18px 16px;
            text-align: center;
            font-weight: 700;
            color: #c8f7ff;
            transition: transform 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
            cursor: pointer;
            box-shadow: 0 0 18px rgba(0, 255, 255, 0.08);
        }
        .popup-option:hover {
            transform: translateY(-2px);
            background: rgba(0, 255, 255, 0.10);
            box-shadow: 0 0 26px rgba(0, 255, 255, 0.16);
        }
        .popup-note {
            margin-top: 18px;
            color: rgba(255, 255, 255, 0.62);
            font-size: 0.92rem;
        }
        @keyframes popupEntry {
            from { opacity: 0; transform: translateY(-16px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .dashboard-card {
            display: none;
        }
        .metric-card {
            min-height: 190px;
            position: relative;
        }
        .metric-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            color: #84dfff;
            font-size: 0.94rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }
        .metric-value {
            font-size: 2.75rem;
            font-weight: 700;
            color: #9bf1ff;
        }
        .metric-meta {
            color: rgba(255, 255, 255, 0.68);
            margin-bottom: 14px;
        }
        .metric-pill {
            display: inline-block;
            padding: 8px 16px;
            background: rgba(0, 255, 255, 0.12);
            border-radius: 999px;
            color: #b7f8ff;
            font-size: 0.82rem;
            letter-spacing: 0.08em;
        }
        .status-card {
            grid-column: span 1;
        }
        .status-title {
            color: #97f8ff;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            margin-bottom: 20px;
        }
        .status-value {
            font-size: 3rem;
            font-weight: 800;
            color: #6ef6ff;
            margin-bottom: 12px;
        }
        .status-detail {
            color: rgba(255, 255, 255, 0.72);
            line-height: 1.6;
        }
        .chart-card, .chart-summary, .activity-card, .calendar-card, .progress-card {
            min-height: 310px;
        }
        .card-title {
            font-size: 1rem;
            text-transform: uppercase;
            color: #89e7ff;
            letter-spacing: 0.12em;
            margin-bottom: 20px;
        }
        .line-chart {
            height: 170px;
            background: linear-gradient(180deg, rgba(3, 35, 61, 0.95), rgba(4, 17, 30, 0.75));
            border-radius: 18px;
            position: relative;
            overflow: hidden;
            box-shadow: inset 0 0 25px rgba(0, 191, 255, 0.08);
        }
        .line-plot {
            position: absolute;
            top: 24px;
            left: 16px;
            right: 16px;
            bottom: 16px;
            background: linear-gradient(135deg, transparent 20%, rgba(0, 255, 255, 0.08) 60%);
            border-radius: 14px;
        }
        .chart-legend {
            display: flex;
            justify-content: space-between;
            color: rgba(255, 255, 255, 0.65);
            margin-top: 16px;
            font-size: 0.88rem;
        }
        .chart-bars {
            display: grid;
            gap: 14px;
        }
        .chart-bars span {
            display: block;
            margin-bottom: 6px;
            font-size: 0.9rem;
            color: #b8f7ff;
        }
        .bar-row {
            height: 10px;
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.08);
            overflow: hidden;
        }
        .bar-row div {
            height: 100%;
            background: linear-gradient(90deg, #7ef0ff, #2e87f1);
        }
        .calendar-header {
            font-weight: 700;
            margin-bottom: 18px;
            font-size: 1rem;
            color: #7ee3ff;
        }
        .calendar-grid {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 8px;
            color: rgba(255, 255, 255, 0.72);
        }
        .calendar-day {
            min-height: 42px;
            display: grid;
            place-items: center;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.04);
        }
        .calendar-day.active {
            background: linear-gradient(135deg, rgba(0, 214, 255, 0.24), rgba(2, 112, 175, 0.24));
            color: #d8fbff;
            font-weight: 700;
        }
        .inline-metrics {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .inline-metrics div {
            background: rgba(0, 255, 255, 0.05);
            border: 1px solid rgba(0, 255, 255, 0.12);
            border-radius: 18px;
            padding: 14px;
            text-align: center;
        }
        .metric-ring {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 70px;
            height: 70px;
        .popup-title {
            font-size: 1.45rem;
            font-weight: 800;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            margin-bottom: 10px;
            color: #9bf4ff;
        }
        .popup-subtitle {
            color: rgba(255, 255, 255, 0.72);
            margin-bottom: 24px;
            line-height: 1.6;
        }
        .popup-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 16px;
        }
        .popup-option {
            background: rgba(0, 29, 53, 0.95);
            border: 1px solid rgba(0, 255, 255, 0.14);
            border-radius: 20px;
            padding: 18px 16px;
            text-align: center;
            font-weight: 700;
            color: #c8f7ff;
            transition: transform 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
            cursor: pointer;
            box-shadow: 0 0 18px rgba(0, 255, 255, 0.08);
        }
        .popup-option:hover {
            transform: translateY(-2px);
            background: rgba(0, 255, 255, 0.10);
            box-shadow: 0 0 26px rgba(0, 255, 255, 0.16);
        }
        .popup-note {
            margin-top: 18px;
            color: rgba(255, 255, 255, 0.62);
            font-size: 0.92rem;
        }
        @keyframes popupEntry {
            from { opacity: 0; transform: translateY(-16px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .dashboard-card {
            display: none;
        }
        .metric-card {
            min-height: 190px;
            position: relative;
        }
        .metric-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            color: #84dfff;
            font-size: 0.94rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }
        .metric-value {
            font-size: 2.75rem;
            font-weight: 700;
            color: #9bf1ff;
        }
        .metric-meta {
            color: rgba(255, 255, 255, 0.68);
            margin-bottom: 14px;
        }
        .metric-pill {
            display: inline-block;
            padding: 8px 16px;
            background: rgba(0, 255, 255, 0.12);
            border-radius: 999px;
            color: #b7f8ff;
            font-size: 0.82rem;
            letter-spacing: 0.08em;
        }
        .status-card {
            grid-column: span 1;
        }
        .status-title {
            color: #97f8ff;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            margin-bottom: 20px;
        }
        .status-value {
            font-size: 3rem;
            font-weight: 800;
            color: #6ef6ff;
            margin-bottom: 12px;
        }
        .status-detail {
            color: rgba(255, 255, 255, 0.72);
            line-height: 1.6;
        }
        .chart-card, .chart-summary, .activity-card, .calendar-card, .progress-card {
            min-height: 310px;
        }
        .card-title {
            font-size: 1rem;
            text-transform: uppercase;
            color: #89e7ff;
            letter-spacing: 0.12em;
            margin-bottom: 20px;
        }
        .line-chart {
            height: 170px;
            background: linear-gradient(180deg, rgba(3, 35, 61, 0.95), rgba(4, 17, 30, 0.75));
            border-radius: 18px;
            position: relative;
            overflow: hidden;
            box-shadow: inset 0 0 25px rgba(0, 191, 255, 0.08);
        }
        .line-plot {
            position: absolute;
            top: 24px;
            left: 16px;
            right: 16px;
            bottom: 16px;
            background: linear-gradient(135deg, transparent 20%, rgba(0, 255, 255, 0.08) 60%);
            border-radius: 14px;
        }
        .chart-legend {
            display: flex;
            justify-content: space-between;
            color: rgba(255, 255, 255, 0.65);
            margin-top: 16px;
            font-size: 0.88rem;
        }
        .chart-bars {
            display: grid;
            gap: 14px;
        }
        .chart-bars span {
            display: block;
            margin-bottom: 6px;
            font-size: 0.9rem;
            color: #b8f7ff;
        }
        .bar-row {
            height: 10px;
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.08);
            overflow: hidden;
        }
        .bar-row div {
            height: 100%;
            background: linear-gradient(90deg, #7ef0ff, #2e87f1);
        }
        .calendar-header {
            font-weight: 700;
            margin-bottom: 18px;
            font-size: 1rem;
            color: #7ee3ff;
        }
        .calendar-grid {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 8px;
            color: rgba(255, 255, 255, 0.72);
        }
        .calendar-day {
            min-height: 42px;
            display: grid;
            place-items: center;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.04);
        }
        .calendar-day.active {
            background: linear-gradient(135deg, rgba(0, 214, 255, 0.24), rgba(2, 112, 175, 0.24));
            color: #d8fbff;
            font-weight: 700;
        }
        .inline-metrics {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .inline-metrics div {
            background: rgba(0, 255, 255, 0.05);
            border: 1px solid rgba(0, 255, 255, 0.12);
            border-radius: 18px;
            padding: 14px;
            text-align: center;
        }
        .metric-ring {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 70px;
            height: 70px;
            margin-bottom: 10px;
            border-radius: 50%;
            background: rgba(0, 255, 255, 0.08);
            color: #c6f8ff;
            font-weight: 700;
            box-shadow: inset 0 0 18px rgba(0, 255, 255, 0.12);
        }
        .badge-very-weak {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid #ef4444;
            padding: 6px 14px;
            border-radius: 6px;
            font-weight: 700;
            display: inline-block;
        }
        .badge-weak {
            background: rgba(249, 115, 22, 0.2);
            color: #fdba74;
            border: 1px solid #f97316;
            padding: 6px 14px;
            border-radius: 6px;
            font-weight: 700;
            display: inline-block;
        }
        .badge-moderate {
            background: rgba(234, 179, 8, 0.2);
            color: #fde047;
            border: 1px solid #eab308;
            padding: 6px 14px;
            border-radius: 6px;
            font-weight: 700;
            display: inline-block;
        }
        .badge-strong {
            background: rgba(34, 197, 94, 0.2);
            color: #86efac;
            border: 1px solid #22c55e;
            padding: 6px 14px;
            border-radius: 6px;
            font-weight: 700;
            display: inline-block;
        }
        .badge-very-strong {
            background: rgba(16, 185, 129, 0.25);
            color: #6ee7b7;
            border: 1px solid #10b981;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.3);
            padding: 6px 14px;
            border-radius: 6px;
            font-weight: 700;
            display: inline-block;
        }
        .result-card {
            background: rgba(4, 20, 36, 0.85);
            border: 1px solid rgba(0, 255, 255, 0.16);
            border-radius: 8px;
            padding: 20px;
            margin-top: 16px;
            margin-bottom: 16px;
        }
        .activity-item {
            padding: 10px 14px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .activity-time {
            color: #7dd3fc;
            font-size: 0.82rem;
            font-family: monospace;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def page_header(title: str, subtitle: str = "", icon: str = "DEF") -> None:
    subtitle_html = f"<p>{subtitle}</p>" if subtitle else ""
    st.markdown(
        f"""
        <div class="hero-card">
            <div class="hero-icon">{icon}</div>
            <div>
                <h1>{title}</h1>
                {subtitle_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_card(content: str) -> None:
    st.markdown("<div class='section-card'>", unsafe_allow_html=True)
    st.markdown(content, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
