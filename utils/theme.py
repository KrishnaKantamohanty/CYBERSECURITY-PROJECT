import streamlit as st


def inject_theme() -> None:
    st.markdown(
        """
        <style>
        :root {
            color-scheme: dark;
            --cp-cyan: #00ffff;
            --cp-pink: #ff00ff;
            --cp-yellow: #f3e600;
            --cp-bg: #09090b;
            --cp-bg-card: rgba(15, 15, 20, 0.85);
            --cp-text: #00ffcc;
        }
        body {
            background: var(--cp-bg);
            color: var(--cp-text);
            font-family: "Courier New", Courier, monospace;
        }
        [data-testid="stAppViewContainer"] {
            background: var(--cp-bg);
            background-image: 
                linear-gradient(rgba(0, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 30px 30px;
            color: var(--cp-text);
        }
        [data-testid="stSidebar"] {
            background: rgba(10, 10, 15, 0.95);
            border-right: 2px solid var(--cp-pink);
            box-shadow: inset 0 0 20px rgba(255, 0, 255, 0.1);
        }
        .stSidebar .css-1d391kg, .css-1v0mbdj {
            color: var(--cp-cyan);
            font-family: "Courier New", Courier, monospace;
        }
        .stButton>button {
            background: transparent !important;
            color: var(--cp-cyan) !important;
            border: 1px solid var(--cp-cyan) !important;
            border-radius: 0 !important;
            box-shadow: 0 0 5px var(--cp-cyan), inset 0 0 5px var(--cp-cyan) !important;
            text-transform: uppercase;
            font-weight: bold;
            font-family: "Courier New", Courier, monospace;
            transition: all 0.2s ease;
            min-height: 3rem;
        }
        .stButton>button:hover {
            transform: translateY(-2px);
            background: rgba(0, 255, 255, 0.1) !important;
            box-shadow: 0 0 15px var(--cp-cyan), inset 0 0 10px var(--cp-cyan) !important;
            border-color: var(--cp-pink) !important;
            color: var(--cp-pink) !important;
        }
        .stCheckbox>div>div {
            color: var(--cp-text);
        }
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background: rgba(0, 255, 255, 0.05) !important;
            color: var(--cp-pink) !important;
            border: 1px solid var(--cp-cyan) !important;
            border-radius: 0 !important;
            font-family: "Courier New", Courier, monospace;
        }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
            border-color: var(--cp-pink) !important;
            box-shadow: 0 0 10px var(--cp-pink) !important;
        }
        h1, h2, h3, h4, h5 {
            color: var(--cp-cyan);
            text-transform: uppercase;
            font-weight: bold;
            letter-spacing: 0.1em;
            text-shadow: 0 0 5px var(--cp-cyan);
        }
        .hero-card {
            background: var(--cp-bg-card);
            border: 1px solid var(--cp-pink);
            border-left: 5px solid var(--cp-cyan);
            border-radius: 0;
            padding: 26px;
            margin-bottom: 26px;
            display: flex;
            align-items: center;
            gap: 20px;
            box-shadow: 0 0 15px rgba(255, 0, 255, 0.2);
            backdrop-filter: blur(8px);
        }
        .hero-card .hero-icon {
            width: 72px;
            height: 72px;
            display: grid;
            place-items: center;
            background: transparent;
            border: 1px solid var(--cp-cyan);
            font-size: 2.2rem;
            color: var(--cp-yellow);
            box-shadow: 0 0 10px var(--cp-cyan), inset 0 0 10px var(--cp-cyan);
            border-radius: 0;
        }
        .hero-card h1 {
            margin: 0;
            font-size: 2.4rem;
            color: var(--cp-pink);
            text-shadow: 0 0 10px var(--cp-pink);
        }
        .hero-card p {
            margin: 0.25rem 0 0;
            color: var(--cp-text);
            line-height: 1.5;
        }
        .section-card {
            background: var(--cp-bg-card);
            border: 1px solid var(--cp-cyan);
            border-radius: 0;
            padding: 22px;
            margin-bottom: 18px;
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.1);
        }
        .divider {
            border-top: 1px dashed var(--cp-pink);
            margin: 1.5rem 0;
        }
        .dashboard-grid {
            display: grid;
            gap: 18px;
            grid-template-columns: 1fr;
            margin-bottom: 24px;
        }
        .popup-panel {
            background: var(--cp-bg-card);
            border: 1px solid var(--cp-cyan);
            border-left: 4px solid var(--cp-pink);
            border-radius: 0;
            padding: 24px;
            max-width: 980px;
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.2);
            animation: popupEntry 0.35s ease-out;
        }
        .popup-title {
            font-size: 1.45rem;
            font-weight: 800;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            margin-bottom: 10px;
            color: var(--cp-yellow);
            text-shadow: 0 0 5px var(--cp-yellow);
        }
        .popup-subtitle {
            color: var(--cp-cyan);
            margin-bottom: 24px;
        }
        .popup-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 16px;
        }
        .popup-option {
            background: rgba(0, 0, 0, 0.6);
            border: 1px solid var(--cp-cyan);
            border-radius: 0;
            padding: 18px 16px;
            text-align: center;
            font-weight: 700;
            color: var(--cp-pink);
            text-transform: uppercase;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        .popup-option:hover {
            transform: scale(1.05);
            background: rgba(255, 0, 255, 0.1);
            border-color: var(--cp-pink);
            box-shadow: 0 0 15px var(--cp-pink);
            color: var(--cp-yellow);
        }
        .popup-note {
            margin-top: 18px;
            color: var(--cp-cyan);
            opacity: 0.7;
            font-size: 0.92rem;
        }
        @keyframes popupEntry {
            from { opacity: 0; transform: translateY(-16px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .dashboard-card { display: none; }
        .metric-card {
            min-height: 190px;
            position: relative;
        }
        .metric-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            color: var(--cp-pink);
            font-size: 0.94rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }
        .metric-value {
            font-size: 2.75rem;
            font-weight: 700;
            color: var(--cp-cyan);
            text-shadow: 0 0 10px var(--cp-cyan);
        }
        .metric-meta {
            color: var(--cp-text);
            margin-bottom: 14px;
        }
        .metric-pill {
            display: inline-block;
            padding: 8px 16px;
            background: transparent;
            border: 1px solid var(--cp-yellow);
            border-radius: 0;
            color: var(--cp-yellow);
            font-size: 0.82rem;
            text-transform: uppercase;
            box-shadow: 0 0 5px var(--cp-yellow);
        }
        .status-card { grid-column: span 1; }
        .status-title {
            color: var(--cp-pink);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            margin-bottom: 20px;
        }
        .status-value {
            font-size: 3rem;
            font-weight: 800;
            color: var(--cp-yellow);
            margin-bottom: 12px;
            text-shadow: 0 0 10px var(--cp-yellow);
        }
        .status-detail { color: var(--cp-text); }
        .chart-card, .chart-summary, .activity-card, .calendar-card, .progress-card {
            min-height: 310px;
        }
        .card-title {
            font-size: 1rem;
            text-transform: uppercase;
            color: var(--cp-cyan);
            letter-spacing: 0.12em;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--cp-cyan);
            padding-bottom: 5px;
        }
        .line-chart {
            height: 170px;
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid var(--cp-cyan);
            position: relative;
            overflow: hidden;
        }
        .line-plot {
            position: absolute;
            top: 24px;
            left: 16px;
            right: 16px;
            bottom: 16px;
            background: linear-gradient(135deg, transparent 20%, rgba(255, 0, 255, 0.1) 60%);
            border: 1px solid rgba(0, 255, 255, 0.2);
        }
        .chart-legend {
            display: flex;
            justify-content: space-between;
            color: var(--cp-cyan);
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
            color: var(--cp-pink);
            text-transform: uppercase;
        }
        .bar-row {
            height: 10px;
            background: rgba(0, 255, 255, 0.1);
            border: 1px solid var(--cp-cyan);
            overflow: hidden;
        }
        .bar-row div {
            height: 100%;
            background: var(--cp-yellow);
            box-shadow: 0 0 10px var(--cp-yellow);
        }
        .calendar-header {
            font-weight: 700;
            margin-bottom: 18px;
            font-size: 1rem;
            color: var(--cp-pink);
        }
        .calendar-grid {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 8px;
            color: var(--cp-text);
        }
        .calendar-day {
            min-height: 42px;
            display: grid;
            place-items: center;
            background: rgba(0, 255, 255, 0.05);
            border: 1px solid rgba(0, 255, 255, 0.2);
        }
        .calendar-day.active {
            background: rgba(255, 0, 255, 0.2);
            border: 1px solid var(--cp-pink);
            color: var(--cp-yellow);
            font-weight: 700;
            box-shadow: 0 0 10px var(--cp-pink);
        }
        .inline-metrics {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }
        .inline-metrics div {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid var(--cp-cyan);
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
            border-radius: 0;
            background: transparent;
            border: 2px solid var(--cp-cyan);
            color: var(--cp-cyan);
            font-weight: 700;
            box-shadow: inset 0 0 10px var(--cp-cyan), 0 0 10px var(--cp-cyan);
        }
        .badge-very-weak {
            background: rgba(255, 0, 0, 0.2);
            color: #ff0000;
            border: 1px solid #ff0000;
            padding: 6px 14px;
            font-weight: 700;
            display: inline-block;
            text-transform: uppercase;
            box-shadow: 0 0 5px #ff0000;
        }
        .badge-weak {
            background: rgba(255, 128, 0, 0.2);
            color: #ff8000;
            border: 1px solid #ff8000;
            padding: 6px 14px;
            font-weight: 700;
            display: inline-block;
            text-transform: uppercase;
            box-shadow: 0 0 5px #ff8000;
        }
        .badge-moderate {
            background: rgba(255, 255, 0, 0.2);
            color: var(--cp-yellow);
            border: 1px solid var(--cp-yellow);
            padding: 6px 14px;
            font-weight: 700;
            display: inline-block;
            text-transform: uppercase;
            box-shadow: 0 0 5px var(--cp-yellow);
        }
        .badge-strong {
            background: rgba(0, 255, 255, 0.2);
            color: var(--cp-cyan);
            border: 1px solid var(--cp-cyan);
            padding: 6px 14px;
            font-weight: 700;
            display: inline-block;
            text-transform: uppercase;
            box-shadow: 0 0 5px var(--cp-cyan);
        }
        .badge-very-strong {
            background: rgba(0, 255, 0, 0.2);
            color: #00ff00;
            border: 1px solid #00ff00;
            padding: 6px 14px;
            font-weight: 700;
            display: inline-block;
            text-transform: uppercase;
            box-shadow: 0 0 8px #00ff00;
        }
        .result-card {
            background: var(--cp-bg-card);
            border: 1px solid var(--cp-pink);
            padding: 20px;
            margin-top: 16px;
            margin-bottom: 16px;
            box-shadow: 0 0 10px rgba(255, 0, 255, 0.2);
        }
        .activity-item {
            padding: 10px 14px;
            border-bottom: 1px dashed var(--cp-cyan);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .activity-time {
            color: var(--cp-yellow);
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
