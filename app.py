import streamlit as st


st.set_page_config(
    page_title="网页检测",
    page_icon="🔎",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
        :root {
            color-scheme: dark;
        }

        html, body, .stApp, [data-testid="stAppViewContainer"],
        [data-testid="stMain"] {
            background-color: #000;
            color: #f5f5f5;
        }

        [data-testid="stHeader"], [data-testid="stToolbar"] {
            display: none;
        }

        [data-testid="stMainBlockContainer"] {
            display: flex;
            flex-direction: column;
            justify-content: center;
            min-height: 100vh;
            min-height: 100dvh;
            max-width: 680px;
            padding: 32px 24px;
        }

        .st-key-url_panel {
            background: #101010;
            border: 1px solid #2b2b2b;
            border-radius: 20px;
            padding: clamp(24px, 5vw, 40px);
        }

        .st-key-url_panel [data-testid="stWidgetLabel"] p {
            color: #f5f5f5;
            font-size: clamp(18px, 4vw, 24px);
            font-weight: 600;
            margin-bottom: 12px;
        }

        .st-key-url_panel [data-baseweb="input"] {
            background: #181818;
            border-color: #3a3a3a;
            border-radius: 10px;
        }

        .st-key-url_panel input {
            color: #f5f5f5;
            background: #181818;
            min-height: 48px;
        }

        .st-key-url_panel input::placeholder {
            color: #858585;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.container(key="url_panel", border=True):
    url = st.text_input(
        "请输入要检测的网页网址",
        placeholder="https://example.com",
        key="website_url",
    )
