from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parent
PAGEGRAPH_DIR = PROJECT_ROOT / "pagegraph-crawl-main"
OUTPUT_DIR = PROJECT_ROOT / "output"
HISTORY_FILE = OUTPUT_DIR / ".detection_history.json"
BRAVE_BINARY = Path(
    "/Applications/Brave Browser Nightly.app/Contents/MacOS/Brave Browser Nightly"
)
CRAWL_SECONDS = 5


def load_history() -> list[dict[str, object]]:
    """Load previous detection records, ignoring an incomplete history file."""
    try:
        records = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        return records if isinstance(records, list) else []
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []


def save_history(records: list[dict[str, object]]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    temporary_file = HISTORY_FILE.with_suffix(".tmp")
    temporary_file.write_text(
        json.dumps(records[:50], ensure_ascii=False, indent=2), encoding="utf-8"
    )
    temporary_file.replace(HISTORY_FILE)


def is_http_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def output_files_before_run() -> set[Path]:
    return {path for path in OUTPUT_DIR.glob("*") if path.is_file()}


def run_detection(url: str) -> tuple[int, str, list[Path]]:
    """Run pagegraph-crawl and return its exit code, log, and new output files."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    files_before = output_files_before_run()
    command = [
        "npm",
        "run",
        "crawl",
        "--",
        "-b",
        str(BRAVE_BINARY),
        "-u",
        url.strip(),
        "-t",
        str(CRAWL_SECONDS),
        "-o",
        str(OUTPUT_DIR),
    ]

    try:
        result = subprocess.run(
            command,
            cwd=PAGEGRAPH_DIR,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        log = "\n".join(part for part in (result.stdout, result.stderr) if part)
        exit_code = result.returncode
    except FileNotFoundError as error:
        exit_code = 1
        log = f"无法启动采集命令：{error}"
    except subprocess.TimeoutExpired as error:
        exit_code = 1
        partial_log = error.stdout or error.stderr or ""
        log = f"采集超过 300 秒，已停止。\n{partial_log}"

    new_files = sorted(
        (
            path
            for path in OUTPUT_DIR.glob("*")
            if path.is_file() and path not in files_before
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return exit_code, log, new_files


st.set_page_config(
    page_title="网页检测",
    page_icon="🔎",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
        :root { color-scheme: dark; }
        html, body, .stApp, [data-testid="stAppViewContainer"],
        [data-testid="stMain"] { background-color: #000; color: #f5f5f5; }
        [data-testid="stHeader"], [data-testid="stToolbar"] { display: none; }
        [data-testid="stMainBlockContainer"] {
            display: flex; flex-direction: column; justify-content: center;
            min-height: 100vh; min-height: 100dvh; max-width: 680px;
            padding: 32px 24px;
        }
        .st-key-url_panel, .st-key-history_panel {
            background: #101010; border: 1px solid #2b2b2b;
            border-radius: 20px; padding: clamp(24px, 5vw, 40px);
        }
        .st-key-url_panel [data-testid="stWidgetLabel"] p {
            color: #f5f5f5; font-size: clamp(18px, 4vw, 24px);
            font-weight: 600; margin-bottom: 12px;
        }
        .st-key-url_panel [data-baseweb="input"] {
            background: #181818; border-color: #3a3a3a; border-radius: 10px;
        }
        .st-key-url_panel input {
            color: #f5f5f5; background: #181818; min-height: 48px;
        }
        .st-key-url_panel input::placeholder { color: #858585; }
        .st-key-url_panel button[kind="primary"] {
            width: 100%; margin-top: 12px; min-height: 44px;
        }
        .st-key-history_panel h3 { margin-top: 0; }
        .history-empty { color: #858585; padding: 8px 0; }
    </style>
    """,
    unsafe_allow_html=True,
)

if "detection_history" not in st.session_state:
    st.session_state.detection_history = load_history()

with st.container(key="url_panel", border=True):
    with st.form("detection_form", clear_on_submit=False):
        url = st.text_input(
            "请输入要检测的网页网址",
            placeholder="https://example.com",
            key="website_url",
        )
        submitted = st.form_submit_button("开始检测", type="primary")

if submitted:
    clean_url = url.strip()
    if not is_http_url(clean_url):
        st.error("请输入有效的 HTTP 或 HTTPS 网页网址。")
    elif not PAGEGRAPH_DIR.is_dir():
        st.error(f"找不到采集目录：{PAGEGRAPH_DIR}")
    elif not BRAVE_BINARY.is_file():
        st.error(f"找不到 Brave 浏览器：{BRAVE_BINARY}")
    else:
        with st.status("正在采集网页，请稍候…", expanded=False) as status:
            exit_code, log, new_files = run_detection(clean_url)
            success = exit_code == 0
            record = {
                "url": clean_url,
                "time": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "成功" if success else "失败",
                "files": [
                    path.name for path in new_files if not path.name.startswith(".")
                ],
            }
            st.session_state.detection_history.insert(0, record)
            save_history(st.session_state.detection_history)
            status.update(
                label="采集完成" if success else "采集失败",
                state="complete" if success else "error",
            )

        if exit_code == 0:
            st.success(f"检测完成，结果已保存到：{OUTPUT_DIR}")
            if new_files:
                st.caption("本次生成：" + "、".join(path.name for path in new_files))
        else:
            st.error("采集命令执行失败，请展开日志查看原因。")
        with st.expander("查看采集日志"):
            st.code(log or "（命令没有输出日志）", language="text")

with st.container(key="history_panel", border=True):
    st.markdown("### 检测历史")
    history = st.session_state.detection_history
    if not history:
        st.markdown(
            '<div class="history-empty">暂无检测记录</div>', unsafe_allow_html=True
        )
    else:
        for item in history[:20]:
            status = str(item.get("status", "未知"))
            icon = "✅" if status == "成功" else "❌"
            with st.expander(f"{icon} {item.get('url', '')}"):
                st.caption(f"{item.get('time', '')} · {status}")
                files = item.get("files", [])
                if files:
                    st.caption("结果文件：" + "、".join(str(file) for file in files))
