#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).parent

# ✅ 按你当前命令顺序配置
STEPS = [
    {"script": "gl.py",        "extra_args": []},
    {"script": "gl_parser.py", "extra_args": []},
    {"script": "gl_dom.py",    "extra_args": []},
    {"script": "dom-g.py",     "extra_args": []},
    {"script": "text-g.py",    "extra_args": []},
    {"script": "jscall.py",    "extra_args": []},
    {"script": "clear.py",     "extra_args": []},
]


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("input", help="Input .graphml file")
    p.add_argument("output", help="Output .graphml file")

    p.add_argument(
        "--cache",
        action="store_true",
        help="Enable caching intermediate outputs into --workdir"
    )
    p.add_argument(
        "--workdir",
        default="data/_work",
        help="Where to store intermediate .graphml files when --cache is enabled"
    )
    return p.parse_args()


def run_cmd(script: Path, in_file: Path, out_file: Path, extra_args: list):
    cmd = [sys.executable, str(script), str(in_file), str(out_file), *extra_args]
    print("\n>>>", " ".join(cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
        raise SystemExit(f"❌ Failed: {script.name} (code={r.returncode})")


def main():
    args = parse_args()

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    if not input_path.exists():
        raise SystemExit(f"Input not found: {input_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # ----------------------------
    # 模式 1：cache 模式（保留每一步中间文件）
    #python run.py input.graphml output.graphml --cache --workdir _work

    # ----------------------------
    if args.cache:
        workdir = Path(args.workdir).resolve()
        workdir.mkdir(parents=True, exist_ok=True)

        current_input = input_path
        for i, step in enumerate(STEPS):
            script = BASE / step["script"]

            # 最后一步写到最终 output，其它写到 workdir
            if i == len(STEPS) - 1:
                current_output = output_path
            else:
                # 用脚本名做中间文件名，方便看
                stem = Path(step["script"]).stem  # dom-g / text-g 也能正常得到 stem
                current_output = workdir / f"{i+1:02d}_{stem}.graphml"

            run_cmd(script, current_input, current_output, step.get("extra_args", []))
            current_input = current_output

        print("\n✅ Done (cache mode). Output:", output_path)
        return

    # ----------------------------
    # 模式 2：默认原地覆盖（不缓存，不需要 workdir）
    # 第一步：input -> output
    # 后续：output -> tmp，再 replace 覆盖 output
    # ----------------------------
    for i, step in enumerate(STEPS):
        script = BASE / step["script"]
        extra = step.get("extra_args", [])

        if i == 0:
            run_cmd(script, input_path, output_path, extra)
        else:
            tmp_out = output_path.with_name(output_path.name + f".tmp_step_{i+1}")
            try:
                run_cmd(script, output_path, tmp_out, extra)
                tmp_out.replace(output_path)
            finally:
                if tmp_out.exists():
                    tmp_out.unlink(missing_ok=True)

    print("\n✅ Done (in-place mode). Output:", output_path)


if __name__ == "__main__":
    main()
