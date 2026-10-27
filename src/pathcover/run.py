#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PathCover — 关键路径提取（遮盖贡献法）

在模型预测为恶意的前提下，对网页样本的每条行为路径逐一遮盖：
    Δ_i = P(malicious | W) − P(malicious | W 去掉 p_i)
按 Δ_i 降序排序，取下降幅度最大的 Top-k 路径作为核心路径，供后续
取证分析（analyse）使用。Top-k 为可变参数（--topk，默认 3）。

输入与 predict.py 完全一致（保证遮盖前的基线概率与 prediction.json
相同），输出写入 检测结果包/pathcover/ 目录：
    result.json     完整结果（每条路径的遮盖明细 + Top-k 摘要）
    top_paths.json  机器可读的核心路径（含节点链与风险类别）
    top_paths.txt   人类可读报告

用法（由 app.py 流水线自动调用）：
    python run.py \
        --jsonl       <extract/webpage.jsonl> \
        --paths-dir   <extract/paths> \
        --prediction  <model/prediction.json> \
        --vocabs      <pro2/vocabs.json> \
        --num-stats   <pro2/num_stats.json> \
        --checkpoint  <best_model.pt> \
        --output-dir  <output/检测网址名/pathcover> \
        --topk        3
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import torch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src" / "extract"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "model"))

from dataset import WebPageSequenceDataset  # noqa: E402
from model import WebSeqModel  # noqa: E402
from process import (  # noqa: E402
    collect_json_files,
    extract_sequences_from_file,
    normalize_node,
)

# 与 predict.py 保持完全一致，保证基线概率与 prediction.json 相同
MAX_NUM_SEQUENCES = 8
MAX_SEQ_LEN = 64


# ─────────────────────── 模型加载与前向 ─────────────────────── #

def load_model(checkpoint_path: str, vocabs: Dict[str, Any]) -> WebSeqModel:
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    config = checkpoint.get("config", {})
    model = WebSeqModel(
        node_type_vocab_size=len(vocabs["node_type_vocab"]),
        api_name_vocab_size=len(vocabs["api_name_vocab"]),
        html_element_info_vocab_size=len(vocabs["html_element_info_vocab"]),
        calling_method_vocab_size=len(vocabs["calling_method_vocab"]),
        frame_owner_info_vocab_size=len(vocabs["frame_owner_info_vocab"]),
        emb_dim=config.get("emb_dim", 32),
        lstm_hidden_dim=config.get("lstm_hidden_dim", 128),
        dropout=config.get("dropout", 0.1),
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    return model


def to_single_batch(sample: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: (value.unsqueeze(0) if torch.is_tensor(value) else value)
        for key, value in sample.items()
    }


def clone_batch(batch: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: (value.clone() if torch.is_tensor(value) else value)
        for key, value in batch.items()
    }


@torch.no_grad()
def forward_malicious_prob(model: WebSeqModel, batch: Dict[str, Any]) -> Tuple[float, List[float]]:
    """返回 (P(malicious), 各序列注意力权重)。"""
    logits, attention = model(
        node_type_ids=batch["node_type_ids"],
        api_name_ids=batch["api_name_ids"],
        html_element_info_ids=batch["html_element_info_ids"],
        calling_method_ids=batch["calling_method_ids"],
        frame_owner_info_ids=batch["frame_owner_info_ids"],
        num_feats=batch["num_feats"],
        bin_feats=batch["bin_feats"],
        multi_feats=batch["multi_feats"],
        seq_mask=batch["seq_mask"],
        web_mask=batch["web_mask"],
    )
    probabilities = torch.softmax(logits, dim=-1)[0]
    valid_attention = attention[0][batch["web_mask"][0].bool()].tolist()
    return float(probabilities[1].item()), [float(v) for v in valid_attention]


def mask_sequences(batch: Dict[str, Any], seq_indices: List[int]) -> Dict[str, Any]:
    """遮盖若干条序列：web_mask/seq_mask 置 0，特征全部清零。"""
    masked = clone_batch(batch)
    for idx in seq_indices:
        masked["web_mask"][0, idx] = 0
        masked["seq_mask"][0, idx, :] = 0
        for key in (
            "node_type_ids",
            "api_name_ids",
            "html_element_info_ids",
            "calling_method_ids",
            "frame_owner_info_ids",
        ):
            masked[key][0, idx, :] = 0
        for key in ("num_feats", "bin_feats", "multi_feats"):
            masked[key][0, idx, :, :] = 0
    return masked


# ─────────────────────── 路径来源映射 ─────────────────────── #

def build_source_map(paths_dir: str) -> List[Dict[str, Any]]:
    """按 process.py 的相同顺序重建「样本序列 → 源文件/源序列」映射。

    process.py 将 paths 目录下所有 JSON 的序列按文件名排序拼接，
    这里复用其解析逻辑，保证第 k 条样本序列对得上源文件中的第 j 条原始序列。
    """
    mapping: List[Dict[str, Any]] = []
    for file_path in collect_json_files(Path(paths_dir)):
        try:
            data = json.loads(Path(file_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for seq_pos, raw_seq in enumerate(extract_sequences_from_file(data)):
            normalized = [normalize_node(n) for n in raw_seq if isinstance(n, dict)]
            if not normalized:
                continue
            mapping.append(
                {
                    "source_file": Path(file_path).name,
                    "source_seq_idx": seq_pos,
                    "raw_nodes": [n.get("node", "") for n in raw_seq],
                    "norm_len": len(normalized),
                }
            )
    return mapping


def resolve_source(source_map: List[Dict[str, Any]], seq_idx: int, seq_len: int) -> Dict[str, Any]:
    """把样本序列索引映射回源文件；对不上时降级为 unknown。"""
    if seq_idx < len(source_map) and source_map[seq_idx]["norm_len"] == seq_len:
        entry = source_map[seq_idx]
        return {
            "source_file": entry["source_file"],
            "source_seq_idx": entry["source_seq_idx"],
            "raw_nodes": entry["raw_nodes"],
        }
    return {"source_file": None, "source_seq_idx": None, "raw_nodes": []}


# ─────────────────────── 结果整理 ─────────────────────── #

def summarize_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """规范化节点 → 可读摘要（去掉 NONE 占位值）。"""
    summary = []
    for node in nodes:
        cat = node.get("cat", {})
        entry = {
            "node_type": node.get("node_type", "UNKNOWN"),
            "api_name": cat.get("api_name"),
            "calling_method": cat.get("calling_method"),
            "html_element_info": cat.get("html_element_info"),
            "frame_owner_info": cat.get("frame_owner_info"),
        }
        entry = {k: v for k, v in entry.items() if v not in (None, "", "NONE")}
        summary.append(entry)
    return summary


def path_risk_categories(nodes: List[Dict[str, Any]]) -> List[str]:
    """路径级风险类别：任一节点命中即计入（保持 process.py 的类别顺序）。"""
    risks: List[str] = []
    for node in nodes:
        for category, value in node.get("multi", {}).items():
            if value and category not in risks:
                risks.append(category)
    return risks


def write_report_text(result: Dict[str, Any], output_path: Path) -> None:
    """生成人类可读的 Top-k 报告。"""
    lines = [
        "PathCover 关键路径提取报告",
        "=" * 60,
        f"网页标识 : {result['webpage_id']}",
        f"模型判定 : {result['prediction']}"
        f"（P(恶意)={result['baseline']['malicious']:.4f}）",
        f"路径总数 : {result['num_extracted_sequences']}"
        f"（模型实际考虑 {result['num_paths_considered']} 条，"
        f"上限 {MAX_NUM_SEQUENCES}）",
        f"Top-k    : {result['top_k']}",
        "",
    ]

    for path in result["top_paths"]:
        source = path.get("source_file") or "未知来源"
        seq_note = (
            f"序列 #{path['source_seq_idx']}" if path.get("source_seq_idx") is not None else ""
        )
        lines.append(
            f"#贡献 {path['rank']}  样本序列 #{path['seq_idx']}"
            f"（来源: {source} {seq_note}）"
        )
        if path["delta"] is None:
            lines.append("  ΔP(恶意) = 无法评估（遮盖后无有效路径）")
        else:
            lines.append(
                f"  ΔP(恶意) = {path['delta']:.4f}"
                f"（遮盖后 {path['f_without']:.4f}，"
                f"相对下降 {path['delta_pct'] * 100:.1f}%）"
            )
        if path.get("raw_nodes"):
            chain = " → ".join(path["raw_nodes"])
            if len(chain) > 400:
                chain = chain[:400] + " …"
            lines.append(f"  节点链 : {chain}")
        if path.get("risk_categories"):
            lines.append(f"  风险类别 : {', '.join(path['risk_categories'])}")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


# ─────────────────────── 主流程 ─────────────────────── #

def run_pathcover(args: argparse.Namespace) -> int:
    prediction = json.loads(Path(args.prediction).read_text(encoding="utf-8"))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if prediction.get("class_id") != 1:
        skipped = {
            "status": "skipped",
            "webpage_id": prediction.get("webpage_id"),
            "prediction": prediction.get("prediction"),
            "reason": "模型预测为良性，未执行路径遮盖分析（仅对恶意结果提取核心路径）",
        }
        (output_dir / "result.json").write_text(
            json.dumps(skipped, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"[SKIP] 预测为{prediction.get('prediction')}，仅对恶意结果执行路径遮盖分析")
        return 0

    vocabs = json.loads(Path(args.vocabs).read_text(encoding="utf-8"))
    dataset = WebPageSequenceDataset(
        jsonl_path=args.jsonl,
        vocabs_path=args.vocabs,
        num_stats_path=args.num_stats,
        max_num_sequences=MAX_NUM_SEQUENCES,
        max_seq_len=MAX_SEQ_LEN,
    )
    if len(dataset) != 1:
        raise SystemExit(f"Expected one webpage sample; found {len(dataset)}")

    model = load_model(args.checkpoint, vocabs)
    sample = dataset[0]
    raw_sample = dataset.samples[0]
    raw_sequences = [
        seq for seq in raw_sample.get("sequences", []) if seq.get("nodes")
    ][:MAX_NUM_SEQUENCES]

    batch = to_single_batch(sample)
    f_full, attention = forward_malicious_prob(model, batch)

    valid_indices = [
        idx for idx in range(MAX_NUM_SEQUENCES) if batch["web_mask"][0, idx].item() > 0
    ]
    if not valid_indices:
        raise SystemExit("样本中没有有效路径，无法执行路径遮盖分析")

    # 逐路径遮盖，计算贡献 Δ_i
    path_deltas: List[Dict[str, Any]] = []
    for seq_idx in valid_indices:
        masked = mask_sequences(batch, [seq_idx])
        f_without, _ = forward_malicious_prob(model, masked)
        if math.isnan(f_without):
            # 遮盖后样本无任何有效序列，模型输出无意义
            delta: Optional[float] = None
            f_without_value: Optional[float] = None
        else:
            f_without_value = f_without
            delta = f_full - f_without
        path_deltas.append(
            {"seq_idx": seq_idx, "f_without": f_without_value, "delta": delta}
        )

    # 按 Δ 降序；无法评估的排最后
    ranked = sorted(
        path_deltas,
        key=lambda item: (item["delta"] is None, -(item["delta"] or 0.0)),
    )

    top_k = max(1, min(args.topk, len(ranked)))
    source_map = build_source_map(args.paths_dir)

    top_paths: List[Dict[str, Any]] = []
    for rank, item in enumerate(ranked[:top_k], start=1):
        seq_idx = item["seq_idx"]
        nodes = raw_sequences[seq_idx]["nodes"] if seq_idx < len(raw_sequences) else []
        source = resolve_source(source_map, seq_idx, len(nodes))
        delta = item["delta"]
        entry: Dict[str, Any] = {
            "rank": rank,
            "seq_idx": seq_idx,
            "seq_len": len(nodes),
            "delta": delta,
            "f_without": item["f_without"],
            "delta_pct": (delta / f_full) if (delta is not None and f_full > 1e-8) else None,
            "attention": attention[valid_indices.index(seq_idx)],
            "source_file": source["source_file"],
            "source_seq_idx": source["source_seq_idx"],
            "raw_nodes": source["raw_nodes"],
            "risk_categories": path_risk_categories(nodes),
            "nodes": summarize_nodes(nodes),
        }
        top_paths.append(entry)

    result = {
        "status": "ok",
        "webpage_id": prediction.get("webpage_id"),
        "prediction": prediction.get("prediction"),
        "baseline": {
            "benign": 1.0 - f_full,
            "malicious": f_full,
        },
        "num_extracted_sequences": len(raw_sample.get("sequences", [])),
        "num_paths_considered": len(valid_indices),
        "top_k": top_k,
        "top_paths": top_paths,
        "all_path_deltas": [
            {
                "seq_idx": item["seq_idx"],
                "delta": item["delta"],
                "f_without": item["f_without"],
            }
            for item in ranked
        ],
        "sequence_attention": attention,
        "checkpoint": str(Path(args.checkpoint).resolve()),
    }

    (output_dir / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output_dir / "top_paths.json").write_text(
        json.dumps(top_paths, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    write_report_text(result, output_dir / "top_paths.txt")

    print(f"[DONE] 基线 P(恶意)={f_full:.4f}，共评估 {len(valid_indices)} 条路径")
    for path in top_paths:
        delta_text = "N/A" if path["delta"] is None else f"{path['delta']:.4f}"
        print(
            f"[TOP{path['rank']}] 序列 #{path['seq_idx']}"
            f"（{path['source_file'] or '未知来源'}）"
            f" ΔP(恶意)={delta_text}"
        )
    print(f"[DONE] 结果已保存至 {output_dir}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="PathCover 关键路径提取（遮盖贡献法）")
    parser.add_argument("--jsonl", required=True, help="extract/webpage.jsonl 样本文件")
    parser.add_argument("--paths-dir", required=True, help="extract/paths 路径 JSON 目录")
    parser.add_argument("--prediction", required=True, help="model/prediction.json 预测结果")
    parser.add_argument("--vocabs", required=True, help="vocabs.json 词表")
    parser.add_argument("--num-stats", required=True, help="num_stats.json 数值统计")
    parser.add_argument("--checkpoint", required=True, help="模型权重文件")
    parser.add_argument("--output-dir", required=True, help="结果输出目录（检测包/pathcover）")
    parser.add_argument("--topk", type=int, default=3, help="选取贡献最大的前 k 条路径（默认 3）")
    args = parser.parse_args()
    raise SystemExit(run_pathcover(args))


if __name__ == "__main__":
    main()
