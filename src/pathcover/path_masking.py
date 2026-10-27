#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Path Masking Contribution Verification (可解释性核心实验)

For each malicious sample:
  1. Compute baseline P(malicious) = f(W)
  2. Rank paths by individual contribution Δ_i = f(W) - f(W \ p_i)
  3. Mask top-k paths together → f(W \ {p_top-k})
  4. Mask random-k paths (repeat R times) → avg f(W \ {p_random-k})
  5. Compare: top-k masking should cause larger score drop than random

Usage:
    python path_masking.py --data_dir ../pro2 --ckpt ../best_model.pt --out results/
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from tqdm import tqdm

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Add parent src/ to path for model/dataset imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from dataset import WebPageSequenceDataset
from model import WebSeqModel


# ─────────────────────── Helpers ─────────────────────── #

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_model(ckpt_path, data_dir, device):
    ckpt = torch.load(ckpt_path, map_location=device)
    config = ckpt["config"]
    vocabs = load_json(str(Path(data_dir) / "vocabs.json"))

    model = WebSeqModel(
        node_type_vocab_size=len(vocabs["node_type_vocab"]),
        api_name_vocab_size=len(vocabs["api_name_vocab"]),
        html_element_info_vocab_size=len(vocabs["html_element_info_vocab"]),
        calling_method_vocab_size=len(vocabs["calling_method_vocab"]),
        frame_owner_info_vocab_size=len(vocabs["frame_owner_info_vocab"]),
        num_dim=7, bin_dim=5, multi_dim=9,
        emb_dim=config["emb_dim"],
        lstm_hidden_dim=config["lstm_hidden_dim"],
        dropout=config["dropout"],
    ).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    return model, config


def load_dataset(split, data_dir, config):
    return WebPageSequenceDataset(
        jsonl_path=str(Path(data_dir) / f"{split}.jsonl"),
        vocabs_path=str(Path(data_dir) / "vocabs.json"),
        num_stats_path=str(Path(data_dir) / "num_stats.json"),
        max_num_sequences=config["max_num_sequences"],
        max_seq_len=config["max_seq_len"],
    )


def to_device(sample, device):
    return {k: v.to(device) if torch.is_tensor(v) else v for k, v in sample.items()}


def add_batch(sample):
    return {k: v.unsqueeze(0) if torch.is_tensor(v) else v for k, v in sample.items()}


def clone_batch(batch):
    return {k: v.clone() if torch.is_tensor(v) else v for k, v in batch.items()}


@torch.no_grad()
def predict_mal_prob(model, batch):
    """Return P(malicious) for a single sample."""
    output = model(
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
    # model returns (logits, attn_weights)
    if isinstance(output, tuple):
        logits = output[0]
    else:
        logits = output
    probs = F.softmax(logits, dim=-1)
    return probs[0, 1].item()


def get_valid_seq_indices(batch):
    web_mask = batch["web_mask"][0]
    valid = torch.nonzero(web_mask > 0, as_tuple=False).squeeze(-1).tolist()
    if isinstance(valid, int):
        valid = [valid]
    return valid


def mask_sequences(batch, seq_indices):
    """Mask multiple sequences at once (set their web_mask to 0)."""
    b = clone_batch(batch)
    for idx in seq_indices:
        b["web_mask"][0, idx] = 0
        b["seq_mask"][0, idx, :] = 0
        for k in ["node_type_ids", "api_name_ids", "html_element_info_ids",
                   "calling_method_ids", "frame_owner_info_ids"]:
            b[k][0, idx, :] = 0
        for k in ["num_feats", "bin_feats", "multi_feats"]:
            b[k][0, idx, :, :] = 0
    return b


# ─────────────────────── Core Experiment ─────────────────────── #

def run_experiment(model, dataset, device, n_random_trials=50):
    """
    For each malicious test sample:
      1. f(W): baseline prob
      2. Per-path contribution: Δ_i = f(W) - f(W \ p_i)
      3. Top-k masking: f(W \ {top-k})
      4. Random-k masking: avg over R trials
    """
    results = []

    for idx in tqdm(range(len(dataset)), desc="Samples"):
        sample = dataset[idx]
        label = sample["label"].item() if torch.is_tensor(sample["label"]) else sample["label"]
        if label != 1:
            continue

        batch = to_device(add_batch(sample), device)
        valid_seqs = get_valid_seq_indices(batch)
        n_paths = len(valid_seqs)

        if n_paths == 0:
            continue

        # 1. Baseline
        f_full = predict_mal_prob(model, batch)

        # 2. Per-path contribution
        path_deltas = []
        for si in valid_seqs:
            b_masked = mask_sequences(batch, [si])
            f_without = predict_mal_prob(model, b_masked)
            delta = f_full - f_without
            path_deltas.append({"seq_idx": si, "delta": delta, "f_without": f_without})

        # Sort by delta descending (most important first)
        path_deltas.sort(key=lambda x: x["delta"], reverse=True)
        ranked_indices = [p["seq_idx"] for p in path_deltas]

        # 3. Top-k masking
        topk_results = {}
        for k in [1, 3, 5]:
            if k > n_paths:
                continue
            topk_seqs = ranked_indices[:k]
            b_topk = mask_sequences(batch, topk_seqs)
            f_topk = predict_mal_prob(model, b_topk)
            topk_results[f"top{k}"] = {
                "f_after": f_topk,
                "drop": f_full - f_topk,
                "drop_pct": (f_full - f_topk) / max(f_full, 1e-8),
            }

        # 4. Random-k masking
        random_results = {}
        rng = np.random.RandomState(42)
        for k in [1, 3, 5]:
            if k > n_paths:
                continue
            drops = []
            for _ in range(n_random_trials):
                random_seqs = rng.choice(valid_seqs, size=k, replace=False).tolist()
                b_rand = mask_sequences(batch, random_seqs)
                f_rand = predict_mal_prob(model, b_rand)
                drops.append(f_full - f_rand)
            random_results[f"random{k}"] = {
                "mean_drop": float(np.mean(drops)),
                "std_drop": float(np.std(drops)),
                "drops": [float(d) for d in drops],
            }

        results.append({
            "sample_idx": idx,
            "n_paths": n_paths,
            "f_full": f_full,
            "path_ranking": path_deltas,
            "topk": topk_results,
            "random": random_results,
        })

    return results


# ─────────────────────── Analysis & Visualization ─────────────────────── #

def aggregate_and_plot(results, out_dir):
    """Aggregate results across samples and generate plots + tables."""
    os.makedirs(out_dir, exist_ok=True)

    # ── Table 1: Average drop comparison ──
    rows = []
    for k in [1, 3, 5]:
        key = f"top{k}"
        rkey = f"random{k}"

        top_drops = [r["topk"][key]["drop"] for r in results if key in r["topk"]]
        rand_drops = [r["random"][rkey]["mean_drop"] for r in results if rkey in r["random"]]

        if top_drops:
            rows.append({
                "mask_type": f"Top-{k}",
                "mean_drop": np.mean(top_drops),
                "std_drop": np.std(top_drops),
                "median_drop": np.median(top_drops),
                "n_samples": len(top_drops),
            })
        if rand_drops:
            rows.append({
                "mask_type": f"Random-{k}",
                "mean_drop": np.mean(rand_drops),
                "std_drop": np.std(rand_drops),
                "median_drop": np.median(rand_drops),
                "n_samples": len(rand_drops),
            })

    summary_df = pd.DataFrame(rows)
    summary_df.to_csv(os.path.join(out_dir, "drop_comparison.csv"), index=False)

    print("\n" + "=" * 70, flush=True)
    print("PATH MASKING RESULTS: Top-k vs Random-k", flush=True)
    print("=" * 70, flush=True)
    print(summary_df.to_string(index=False), flush=True)

    # ── Table 2: Per-sample detail ──
    detail_rows = []
    for r in results:
        row = {
            "sample_idx": r["sample_idx"],
            "n_paths": r["n_paths"],
            "f_full": r["f_full"],
        }
        for k in [1, 3, 5]:
            key = f"top{k}"
            rkey = f"random{k}"
            if key in r["topk"]:
                row[f"top{k}_drop"] = r["topk"][key]["drop"]
            if rkey in r["random"]:
                row[f"random{k}_mean_drop"] = r["random"][rkey]["mean_drop"]
        detail_rows.append(row)

    detail_df = pd.DataFrame(detail_rows)
    detail_df.to_csv(os.path.join(out_dir, "per_sample_detail.csv"), index=False)

    # ── Figure 1: Grouped bar chart ──
    fig, ax = plt.subplots(figsize=(10, 6))

    ks = [1, 3, 5]
    top_means = []
    top_stds = []
    rand_means = []
    rand_stds = []

    for k in ks:
        key = f"top{k}"
        rkey = f"random{k}"
        top_drops = [r["topk"][key]["drop"] for r in results if key in r["topk"]]
        rand_drops = [r["random"][rkey]["mean_drop"] for r in results if rkey in r["random"]]
        top_means.append(np.mean(top_drops) if top_drops else 0)
        top_stds.append(np.std(top_drops) if top_drops else 0)
        rand_means.append(np.mean(rand_drops) if rand_drops else 0)
        rand_stds.append(np.std(rand_drops) if rand_drops else 0)

    x = np.arange(len(ks))
    width = 0.35

    bars1 = ax.bar(x - width/2, top_means, width, yerr=top_stds, label="Top-k (Model-ranked)",
                   color="#e74c3c", capsize=5, alpha=0.85)
    bars2 = ax.bar(x + width/2, rand_means, width, yerr=rand_stds, label="Random-k",
                   color="#3498db", capsize=5, alpha=0.85)

    ax.set_xlabel("Number of Masked Paths (k)", fontsize=13)
    ax.set_ylabel("Mean P(malicious) Drop", fontsize=13)
    ax.set_title("Path Masking: Top-k vs Random-k", fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels([f"k={k}" for k in ks], fontsize=12)
    ax.legend(fontsize=12)
    ax.grid(axis="y", alpha=0.3)

    # Add value labels
    for bar in bars1:
        h = bar.get_height()
        ax.annotate(f"{h:.3f}", xy=(bar.get_x() + bar.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", fontsize=10)
    for bar in bars2:
        h = bar.get_height()
        ax.annotate(f"{h:.3f}", xy=(bar.get_x() + bar.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", fontsize=10)

    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "topk_vs_random.png"), dpi=200)
    plt.close()
    print(f"\nSaved: {out_dir}/topk_vs_random.png", flush=True)

    # ── Figure 2: Per-sample scatter ──
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))

    for i, k in enumerate([1, 3, 5]):
        ax = axes[i]
        key = f"top{k}"
        rkey = f"random{k}"

        top_d = [r["topk"][key]["drop"] for r in results if key in r["topk"]]
        rand_d = [r["random"][rkey]["mean_drop"] for r in results if rkey in r["random"]]

        if not top_d:
            continue

        n = min(len(top_d), len(rand_d))
        top_d = top_d[:n]
        rand_d = rand_d[:n]

        ax.scatter(rand_d, top_d, alpha=0.5, s=30, c="#e74c3c")
        max_val = max(max(top_d), max(rand_d), 0.01)
        ax.plot([0, max_val], [0, max_val], "k--", alpha=0.3, label="y=x")
        ax.set_xlabel(f"Random-{k} Drop", fontsize=12)
        ax.set_ylabel(f"Top-{k} Drop", fontsize=12)
        ax.set_title(f"k={k}", fontsize=13)
        ax.legend(fontsize=10)
        ax.grid(alpha=0.3)

    plt.suptitle("Per-Sample: Top-k Drop vs Random-k Drop", fontsize=14, y=1.02)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "per_sample_scatter.png"), dpi=200, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out_dir}/per_sample_scatter.png", flush=True)

    # ── Figure 3: Path count distribution ──
    fig, ax = plt.subplots(figsize=(8, 5))
    n_paths = [r["n_paths"] for r in results]
    ax.hist(n_paths, bins=range(1, max(n_paths)+2), color="#2ecc71", alpha=0.8, edgecolor="white")
    ax.set_xlabel("Number of Paths per Sample", fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("Distribution of Path Counts (Malicious Test Samples)", fontsize=13)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "path_count_dist.png"), dpi=200)
    plt.close()
    print(f"Saved: {out_dir}/path_count_dist.png", flush=True)

    # ── Figure 4: Delta distribution (first path contribution) ──
    fig, ax = plt.subplots(figsize=(8, 5))
    first_deltas = [r["path_ranking"][0]["delta"] for r in results if r["path_ranking"]]
    ax.hist(first_deltas, bins=30, color="#9b59b6", alpha=0.8, edgecolor="white")
    ax.axvline(np.mean(first_deltas), color="red", linestyle="--", label=f"Mean={np.mean(first_deltas):.4f}")
    ax.set_xlabel("ΔP(malicious) — Top-1 Path", fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("Distribution of Top-1 Path Contribution", fontsize=13)
    ax.legend(fontsize=11)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "top1_delta_dist.png"), dpi=200)
    plt.close()
    print(f"Saved: {out_dir}/top1_delta_dist.png", flush=True)

    return summary_df


# ─────────────────────── Main ─────────────────────── #

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", default="pro2")
    parser.add_argument("--ckpt", default="best_model.pt")
    parser.add_argument("--split", default="test")
    parser.add_argument("--out", default="kjs/results")
    parser.add_argument("--n_random", type=int, default=50, help="Random trials per sample")
    parser.add_argument("--device", default="auto")
    args = parser.parse_args()

    if args.device == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device = torch.device(args.device)

    print(f"Device: {device}", flush=True)

    model, config = build_model(args.ckpt, args.data_dir, device)
    dataset = load_dataset(args.split, args.data_dir, config)

    print(f"Dataset: {len(dataset)} samples", flush=True)

    results = run_experiment(model, dataset, device, n_random_trials=args.n_random)

    # Save raw results
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "raw_results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    summary = aggregate_and_plot(results, args.out)
    summary.to_csv(os.path.join(args.out, "summary.csv"), index=False)

    print(f"\nAll results saved to: {args.out}", flush=True)


if __name__ == "__main__":
    main()
