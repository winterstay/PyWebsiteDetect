#!/usr/bin/env python3
"""Run one-page inference using the training vocabularies and checkpoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src" / "extract"))
from dataset import WebPageSequenceDataset  # noqa: E402
from model import WebSeqModel  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jsonl", required=True)
    parser.add_argument("--vocabs", required=True)
    parser.add_argument("--num-stats", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    vocabs = json.loads(Path(args.vocabs).read_text(encoding="utf-8"))
    dataset = WebPageSequenceDataset(
        jsonl_path=args.jsonl,
        vocabs_path=args.vocabs,
        num_stats_path=args.num_stats,
        max_num_sequences=8,
        max_seq_len=64,
    )
    if len(dataset) != 1:
        raise SystemExit(f"Expected one webpage sample; found {len(dataset)}")

    checkpoint = torch.load(args.checkpoint, map_location="cpu", weights_only=False)
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

    sample = dataset[0]
    with torch.no_grad():
        logits, attention = model(
            node_type_ids=sample["node_type_ids"].unsqueeze(0),
            api_name_ids=sample["api_name_ids"].unsqueeze(0),
            html_element_info_ids=sample["html_element_info_ids"].unsqueeze(0),
            calling_method_ids=sample["calling_method_ids"].unsqueeze(0),
            frame_owner_info_ids=sample["frame_owner_info_ids"].unsqueeze(0),
            num_feats=sample["num_feats"].unsqueeze(0),
            bin_feats=sample["bin_feats"].unsqueeze(0),
            multi_feats=sample["multi_feats"].unsqueeze(0),
            seq_mask=sample["seq_mask"].unsqueeze(0),
            web_mask=sample["web_mask"].unsqueeze(0),
        )
        probabilities = torch.softmax(logits, dim=-1)[0]
        predicted = int(torch.argmax(probabilities).item())
        valid_attention = attention[0][sample["web_mask"].bool()].tolist()

    result = {
        "webpage_id": sample["webpage_id"],
        "prediction": "恶意" if predicted == 1 else "良性",
        "class_id": predicted,
        "probabilities": {
            "benign": float(probabilities[0].item()),
            "malicious": float(probabilities[1].item()),
        },
        "sequence_attention": [float(value) for value in valid_attention],
        "checkpoint": str(Path(args.checkpoint).resolve()),
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
