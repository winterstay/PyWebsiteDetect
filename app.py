from __future__ import annotations

import json
import re
import subprocess
import sys
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
PYTHON = sys.executable
MODEL_DIR = PROJECT_ROOT / "src" / "model"


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


def package_name(url: str, timestamp: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "website"
    suffix = parsed.path.strip("/").replace("/", "_")
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", "_".join(filter(None, (host, suffix))))
    return f"{safe_name[:100]}_{timestamp}"


def run_command(command: list[str], cwd: Path, timeout: int = 300) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.returncode, "\n".join(
            part for part in (result.stdout, result.stderr) if part
        )
    except FileNotFoundError as error:
        return 1, f"无法启动命令：{error}"
    except subprocess.TimeoutExpired as error:
        partial = error.stdout or error.stderr or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        return 1, f"命令执行超时（{timeout} 秒）。\n{partial}"


def run_pipeline(
    url: str, package_dir: Path
) -> tuple[bool, dict[str, str], list[dict[str, str]]]:
    """Run crawl, graph cleanup, sink/path extraction and model prediction."""
    original_dir = package_dir / "original"
    clear_dir = package_dir / "clear"
    cleaned_dir = clear_dir / "final"
    extract_dir = package_dir / "extract"
    model_dir = package_dir / "model"
    logs_dir = package_dir / "logs"
    for directory in (original_dir, clear_dir, cleaned_dir, extract_dir, model_dir, logs_dir):
        directory.mkdir(parents=True, exist_ok=True)

    logs: dict[str, str] = {}
    stages: list[dict[str, str]] = []

    def stage(name: str, command: list[str], cwd: Path, timeout: int = 300) -> bool:
        code, log = run_command(command, cwd, timeout)
        logs[name] = log
        safe_log_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
        log_path = logs_dir / f"{len(stages) + 1:02d}_{safe_log_name}.log"
        log_path.write_text(log or "（命令没有输出日志）\n", encoding="utf-8")
        stages.append({"name": name, "status": "成功" if code == 0 else "失败"})
        return code == 0

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
        str(original_dir),
    ]
    if not stage("PageGraph采集", command, PAGEGRAPH_DIR, timeout=300):
        return False, logs, stages

    original_graphs = sorted(original_dir.glob("*.graphml"))
    if not original_graphs:
        logs["PageGraph采集"] += "\n采集命令结束，但没有生成 GraphML 文件。"
        stages[-1]["status"] = "失败"
        return False, logs, stages

    for graph_index, original_graph in enumerate(original_graphs, start=1):
        cleaned_graph = cleaned_dir / original_graph.name
        if not stage(
            f"Graph清理与裁剪（{graph_index}/{len(original_graphs)}）",
            [
                PYTHON,
                str(PROJECT_ROOT / "src/clear/run.py"),
                str(original_graph),
                str(cleaned_graph),
                "--cache",
                "--workdir",
                str(clear_dir / "work" / original_graph.stem),
            ],
            PROJECT_ROOT,
            timeout=900,
        ):
            return False, logs, stages

    sink_report = extract_dir / "sink_report.txt"
    if not stage(
        "Sink识别",
        [
            PYTHON,
            str(PROJECT_ROOT / "src/extract/sink.py"),
            str(cleaned_dir),
            str(sink_report),
        ],
        PROJECT_ROOT,
        timeout=300,
    ):
        return False, logs, stages

    paths_dir = extract_dir / "paths"
    if not stage(
        "路径与特征抽取",
        [
            PYTHON,
            str(PROJECT_ROOT / "src/extract/pathTQ.py"),
            str(cleaned_dir),
            str(sink_report),
            str(paths_dir),
        ],
        PROJECT_ROOT,
        timeout=300,
    ):
        return False, logs, stages

    jsonl_path = extract_dir / "webpage.jsonl"
    if not stage(
        "网页样本整理",
        [
            PYTHON,
            str(PROJECT_ROOT / "src/extract/process.py"),
            "--single-json-dir",
            str(paths_dir),
            "--url",
            url,
            "--out-jsonl",
            str(jsonl_path),
        ],
        PROJECT_ROOT,
        timeout=300,
    ):
        return False, logs, stages

    vocab_path = MODEL_DIR / "pro2" / "vocabs.json"
    stats_path = MODEL_DIR / "pro2" / "num_stats.json"
    model_path = MODEL_DIR / "best_model.pt"
    missing = [
        str(path.relative_to(PROJECT_ROOT))
        for path in (vocab_path, stats_path, model_path)
        if not path.is_file()
    ]
    try:
        import torch  # noqa: F401
    except ImportError:
        missing.append("akup 环境未安装 PyTorch")
    if missing:
        logs["模型预测"] = "模型预测所需资源缺失：\n" + "\n".join(missing)
        (logs_dir / f"{len(stages) + 1:02d}_模型预测.log").write_text(
            logs["模型预测"], encoding="utf-8"
        )
        stages.append({"name": "模型预测", "status": "未运行（资源缺失）"})
        return False, logs, stages

    if not stage(
        "模型预测",
        [
            PYTHON,
            str(MODEL_DIR / "predict.py"),
            "--jsonl",
            str(jsonl_path),
            "--vocabs",
            str(vocab_path),
            "--num-stats",
            str(stats_path),
            "--checkpoint",
            str(model_path),
            "--output",
            str(model_dir / "prediction.json"),
        ],
        PROJECT_ROOT,
        timeout=300,
    ):
        return False, logs, stages
    return True, logs, stages


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
        timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
        package_dir = OUTPUT_DIR / package_name(clean_url, timestamp)
        with st.status("正在执行网页检测流程…", expanded=False) as status:
            success, stage_logs, stages = run_pipeline(clean_url, package_dir)
            record = {
                "url": clean_url,
                "time": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "成功" if success else "未完成",
                "package_dir": str(package_dir.relative_to(PROJECT_ROOT)),
                "stages": stages,
            }
            prediction_file = package_dir / "model" / "prediction.json"
            if prediction_file.is_file():
                try:
                    prediction = json.loads(prediction_file.read_text(encoding="utf-8"))
                    record["prediction"] = prediction.get("prediction")
                    record["probabilities"] = prediction.get("probabilities")
                except (OSError, json.JSONDecodeError):
                    pass
            st.session_state.detection_history.insert(0, record)
            save_history(st.session_state.detection_history)
            status.update(
                label="检测流程完成" if success else "检测流程未完成",
                state="complete" if success else "error",
            )

        if success:
            st.success(f"检测完成，结果包：{package_dir.relative_to(PROJECT_ROOT)}")
            prediction_file = package_dir / "model" / "prediction.json"
            if prediction_file.is_file():
                prediction = json.loads(prediction_file.read_text(encoding="utf-8"))
                st.metric("模型判定", prediction["prediction"])
                st.caption(
                    "良性概率：{:.2%} · 恶意概率：{:.2%}".format(
                        prediction["probabilities"]["benign"],
                        prediction["probabilities"]["malicious"],
                    )
                )
        else:
            st.warning(
                f"流程未全部完成。已生成的中间结果保留在：{package_dir.relative_to(PROJECT_ROOT)}"
            )
        for stage_info in stages:
            st.write(
                f"{'✅' if stage_info['status'] == '成功' else '⚠️'} "
                f"{stage_info['name']}：{stage_info['status']}"
            )
        for stage_name, log in stage_logs.items():
            with st.expander(f"查看{stage_name}日志"):
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
            icon = "✅" if status == "成功" else "⚠️"
            with st.expander(f"{icon} {item.get('url', '')}"):
                st.caption(f"{item.get('time', '')} · {status}")
                if item.get("package_dir"):
                    st.caption(f"结果包：{item['package_dir']}")
                if item.get("prediction"):
                    st.write(f"预测：**{item['prediction']}**")
                for stage_info in item.get("stages", []):
                    st.caption(
                        f"{stage_info.get('name', '')}：{stage_info.get('status', '')}"
                    )
