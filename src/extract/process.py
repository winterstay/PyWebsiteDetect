import os
import re
import json
import math
import random
import argparse
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, Dict, List, Tuple


RISK_CATEGORIES = [
    "dynamic_execution",
    "obfuscation_decode",
    "network_request",
    "storage_access",
    "sensitive_access",
    "dom_injection",
    "dynamic_resource_loading",
    "download_file_ops",
    "system_execution",
]

NUM_FIELDS = [
    "url_length",
    "url_entropy",
    "param_length",
    "entropy",
    "max_string_length",
    "special_char_count",
    "subdomain_levels",
]

BIN_FIELDS = [
    "has_eval_exec",
    "has_long_string",
    "has_string_concatenation",
    "has_parameters",
    "has_system_command",
]

CAT_FIELDS = [
    "api_name",
    "html_element_info",
    "calling_method",
    "frame_owner_info",
]

CLASS_MAP = {
    "benign": 0,
    "malicious": 1,
}


def safe_read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_write_json(obj: Any, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def write_jsonl(items: List[Dict[str, Any]], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def as_float(v: Any) -> float:
    try:
        x = float(v)
        if math.isnan(x) or math.isinf(x):
            return 0.0
        return x
    except Exception:
        return 0.0


def as_int_bool(v: Any) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return 1 if v != 0 else 0
    if isinstance(v, str):
        return 1 if v.strip().lower() in {"1", "true", "yes", "y"} else 0
    return 0


def parse_node_type(node_name: str) -> str:
    """
    e.g.
    'n173(script)' -> 'script'
    'n76(web API)' -> 'web API'
    """
    if not isinstance(node_name, str):
        return "UNKNOWN"
    m = re.search(r"\((.*?)\)", node_name)
    if m:
        return m.group(1).strip()
    return "UNKNOWN"


def is_node_dict(x: Any) -> bool:
    return isinstance(x, dict) and ("node" in x or any(key.endswith("_features") for key in x))


def collect_json_files(folder: Path) -> List[Path]:
    files = []
    for ext in ("*.json", "*.JSON"):
        files.extend(folder.rglob(ext))
    return sorted(files)


def extract_sequences_from_file(data: Any) -> List[List[Dict[str, Any]]]:
    """
    目标结构：
    一个文件 = 一个网页
    一个网页 = 多条序列
    每条序列 = 节点列表

    支持：
    1) 多序列:
       [
         [node, node, ...],
         [node, node, ...]
       ]

    2) 单序列:
       [node, node, node]

    3) 外包一层 dict:
       {"sequences": [[...], [...]]}
       {"nodes": [...]}  # 当成单序列
    """
    # case 1: dict wrapper
    if isinstance(data, dict):
        if "sequences" in data and isinstance(data["sequences"], list):
            sequences = []
            for seq in data["sequences"]:
                if isinstance(seq, list) and all(is_node_dict(n) for n in seq):
                    sequences.append(seq)
            return sequences

        if "nodes" in data and isinstance(data["nodes"], list):
            if all(is_node_dict(n) for n in data["nodes"]):
                return [data["nodes"]]

        return []

    # case 2: list
    if isinstance(data, list):
        if len(data) == 0:
            return []

        # 单序列：[node, node, ...]
        # 尝试提取有效的节点
        valid_nodes = [x for x in data if is_node_dict(x)]
        if valid_nodes:
            return [valid_nodes]

        # 多序列：[[node...], [node...]]
        sequences = []
        for item in data:
            if isinstance(item, list):
                # 尝试提取每个列表中的有效节点
                valid_items = [n for n in item if is_node_dict(n)]
                if valid_items:
                    sequences.append(valid_items)
        if sequences:
            return sequences

    return []


def normalize_node(raw_node: Dict[str, Any]) -> Dict[str, Any]:
    node_type = parse_node_type(raw_node.get("node", "UNKNOWN"))
    # 如果没有 node 字段，尝试从特征字段推断类型
    if node_type == "UNKNOWN":
        if "url_features" in raw_node:
            node_type = "resource"
        elif "script_features" in raw_node:
            node_type = "script"
        elif "webapi_features" in raw_node:
            node_type = "web API"
        elif "frame_owner_features" in raw_node:
            node_type = "frame owner"
        elif "html_element_features" in raw_node:
            node_type = "HTML element"
        elif "text_node_features" in raw_node:
            node_type = "text node"

    webapi = raw_node.get("webapi_features", {})
    html = raw_node.get("html_element_features", {})
    script = raw_node.get("script_features", {})
    urlf = raw_node.get("url_features", {})
    frame = raw_node.get("frame_owner_features", {})

    if not isinstance(webapi, dict):
        webapi = {}
    if not isinstance(html, dict):
        html = {}
    if not isinstance(script, dict):
        script = {}
    if not isinstance(urlf, dict):
        urlf = {}
    if not isinstance(frame, dict):
        frame = {}

    cat = {
        "api_name": str(webapi.get("api_name", "NONE")) if webapi.get("api_name") is not None else "NONE",
        "html_element_info": str(html.get("html_element_info", "NONE")) if html.get("html_element_info") is not None else "NONE",
        "calling_method": str(script.get("calling_method", "NONE")) if script.get("calling_method") is not None else "NONE",
        "frame_owner_info": str(frame.get("frame_owner_info", "NONE")) if frame.get("frame_owner_info") is not None else "NONE",
    }

    num = {
        "url_length": as_float(urlf.get("url_length", 0)),
        "url_entropy": as_float(urlf.get("url_entropy", 0)),
        "param_length": as_float(script.get("param_length", 0)),
        "entropy": as_float(script.get("entropy", 0)),
        "max_string_length": as_float(script.get("max_string_length", 0)),
        "special_char_count": as_float(urlf.get("special_char_count", 0)),
        "subdomain_levels": as_float(urlf.get("subdomain_levels", 0)),
    }

    binf = {
        "has_eval_exec": as_int_bool(script.get("has_eval_exec", 0)),
        "has_long_string": as_int_bool(script.get("has_long_string", 0)),
        "has_string_concatenation": as_int_bool(script.get("has_string_concatenation", 0)),
        "has_parameters": as_int_bool(urlf.get("has_parameters", 0)),
        "has_system_command": as_int_bool(script.get("has_system_command", 0)),
    }

    matched = script.get("matched_api_categories", {})
    if not isinstance(matched, dict):
        matched = {}

    multi = {}
    for c in RISK_CATEGORIES:
        value = matched.get(c, [])
        multi[c] = 1 if isinstance(value, list) and len(value) > 0 else 0

    return {
        "node_type": node_type,
        "cat": cat,
        "num": num,
        "bin": binf,
        "multi": multi,
    }


def normalize_sequence(raw_seq: List[Dict[str, Any]], seq_id: int) -> Dict[str, Any]:
    nodes = [normalize_node(n) for n in raw_seq if isinstance(n, dict)]
    return {
        "seq_id": seq_id,
        "seq_len": len(nodes),
        "nodes": nodes,
    }


def normalize_webpage(
    raw_sequences: List[List[Dict[str, Any]]],
    label: int,
    webpage_id: str,
    source_file: str,
) -> Dict[str, Any]:
    sequences = []
    for idx, raw_seq in enumerate(raw_sequences):
        seq = normalize_sequence(raw_seq, idx)
        if seq["seq_len"] > 0:
            sequences.append(seq)

    return {
        "webpage_id": webpage_id,
        "label": label,
        "source_file": source_file,
        "num_sequences": len(sequences),
        "sequences": sequences,
    }


def build_dataset(root_dir: Path, debug: bool = False) -> List[Dict[str, Any]]:
    webpages = []

    for class_name, label in CLASS_MAP.items():
        class_dir = root_dir / class_name
        if not class_dir.exists():
            print(f"[WARN] folder not found: {class_dir}")
            continue

        files = collect_json_files(class_dir)
        print(f"[INFO] {class_name}: found {len(files)} json files")

        for fp in files:
            try:
                data = safe_read_json(fp)
                raw_sequences = extract_sequences_from_file(data)

                if debug:
                    print(f"[DEBUG] file={fp}")
                    print(f"[DEBUG] type(data)={type(data).__name__}")
                    if isinstance(data, list):
                        print(f"[DEBUG] top-level list len={len(data)}")
                    print(f"[DEBUG] extracted_sequences={len(raw_sequences)}")

                if not raw_sequences:
                    print(f"[SKIP] unsupported format: {fp}")
                    continue

                webpage_id = f"{class_name}_{fp.stem}"
                webpage = normalize_webpage(
                    raw_sequences=raw_sequences,
                    label=label,
                    webpage_id=webpage_id,
                    source_file=str(fp.relative_to(root_dir)),
                )

                if webpage["num_sequences"] == 0:
                    print(f"[SKIP] no valid sequences after normalize: {fp}")
                    continue

                webpages.append(webpage)

            except Exception as e:
                print(f"[ERROR] file={fp} error={e}")

    return webpages


def stratified_split_webpages(
    webpages: List[Dict[str, Any]],
    train_ratio: float,
    valid_ratio: float,
    test_ratio: float,
    seed: int = 42,
) -> Dict[str, List[str]]:
    assert abs(train_ratio + valid_ratio + test_ratio - 1.0) < 1e-8

    rng = random.Random(seed)

    groups = {0: [], 1: []}
    for w in webpages:
        groups[w["label"]].append(w["webpage_id"])

    split = {"train": [], "valid": [], "test": []}

    for label, ids in groups.items():
        rng.shuffle(ids)
        n = len(ids)

        n_train = int(n * train_ratio)
        n_valid = int(n * valid_ratio)
        n_test = n - n_train - n_valid

        split["train"].extend(ids[:n_train])
        split["valid"].extend(ids[n_train:n_train + n_valid])
        split["test"].extend(ids[n_train + n_valid:])

    rng.shuffle(split["train"])
    rng.shuffle(split["valid"])
    rng.shuffle(split["test"])
    return split


def filter_by_ids(webpages: List[Dict[str, Any]], id_set: set) -> List[Dict[str, Any]]:
    return [w for w in webpages if w["webpage_id"] in id_set]


def build_vocab(values: List[str]) -> Dict[str, int]:
    uniq = sorted(set(values))
    vocab = {"PAD": 0, "UNK": 1}
    for v in uniq:
        if v not in vocab:
            vocab[v] = len(vocab)
    return vocab


def build_vocabs(webpages: List[Dict[str, Any]]) -> Dict[str, Any]:
    node_types = []
    api_names = []
    html_infos = []
    calling_methods = []
    frame_infos = []

    for webpage in webpages:
        for seq in webpage["sequences"]:
            for node in seq["nodes"]:
                node_types.append(node["node_type"])
                api_names.append(node["cat"]["api_name"])
                html_infos.append(node["cat"]["html_element_info"])
                calling_methods.append(node["cat"]["calling_method"])
                frame_infos.append(node["cat"]["frame_owner_info"])

    return {
        "node_type_vocab": build_vocab(node_types),
        "api_name_vocab": build_vocab(api_names),
        "html_element_info_vocab": build_vocab(html_infos),
        "calling_method_vocab": build_vocab(calling_methods),
        "frame_owner_info_vocab": build_vocab(frame_infos),
        "meta": {
            "num_fields": NUM_FIELDS,
            "bin_fields": BIN_FIELDS,
            "risk_categories": RISK_CATEGORIES,
            "cat_fields": CAT_FIELDS,
        }
    }


def collect_train_numeric_stats(train_webpages: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    values = {k: [] for k in NUM_FIELDS}

    for webpage in train_webpages:
        for seq in webpage["sequences"]:
            for node in seq["nodes"]:
                for k in NUM_FIELDS:
                    v = node["num"].get(k, 0.0)
                    vv = math.log1p(v) if v > 0 else 0.0
                    values[k].append(vv)

    stats = {}
    for k, arr in values.items():
        if not arr:
            stats[k] = {"mean": 0.0, "std": 1.0}
            continue
        mean = sum(arr) / len(arr)
        var = sum((x - mean) ** 2 for x in arr) / len(arr)
        std = math.sqrt(var) if var > 1e-12 else 1.0
        stats[k] = {"mean": mean, "std": std}

    return stats


def build_stats(webpages: List[Dict[str, Any]]) -> Dict[str, Any]:
    num_webpages = len(webpages)
    num_benign = sum(1 for w in webpages if w["label"] == 0)
    num_malicious = sum(1 for w in webpages if w["label"] == 1)

    seq_counts = [w["num_sequences"] for w in webpages]
    seq_lens = []
    for w in webpages:
        for seq in w["sequences"]:
            seq_lens.append(seq["seq_len"])

    def avg(xs: List[float]) -> float:
        return sum(xs) / len(xs) if xs else 0.0

    return {
        "num_webpages": num_webpages,
        "num_benign": num_benign,
        "num_malicious": num_malicious,
        "avg_sequences_per_webpage": avg(seq_counts),
        "max_sequences_per_webpage": max(seq_counts) if seq_counts else 0,
        "avg_nodes_per_sequence": avg(seq_lens),
        "max_nodes_per_sequence": max(seq_lens) if seq_lens else 0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root_dir", type=str, help="root dir containing benign/ and malicious/")
    parser.add_argument("--out_dir", type=str, help="output dir")
    parser.add_argument("--single-json-dir", type=str, help="path JSON directory for one-page inference")
    parser.add_argument("--url", type=str, help="URL associated with the one-page inference sample")
    parser.add_argument("--out-jsonl", type=str, help="output JSONL for one-page inference")
    parser.add_argument("--train_ratio", type=float, default=0.7)
    parser.add_argument("--valid_ratio", type=float, default=0.1)
    parser.add_argument("--test_ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--debug", action="store_true", help="print debug info")
    args = parser.parse_args()

    if args.single_json_dir:
        if not args.url or not args.out_jsonl:
            parser.error("--single-json-dir requires --url and --out-jsonl")
        json_dir = Path(args.single_json_dir)
        output_path = Path(args.out_jsonl)
        files = collect_json_files(json_dir)
        if not files:
            raise SystemExit(f"No extracted path JSON files found in {json_dir}")
        all_sequences = []
        for file_path in files:
            raw_sequences = extract_sequences_from_file(safe_read_json(file_path))
            all_sequences.extend(raw_sequences)
        if not all_sequences:
            raise SystemExit("No sink paths were extracted; cannot create a model sample")
        parsed = urlparse(args.url)
        webpage_id = parsed.netloc or parsed.path or "webpage"
        webpage = normalize_webpage(
            raw_sequences=all_sequences,
            label=0,
            webpage_id=webpage_id,
            source_file=", ".join(str(path.name) for path in files),
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        write_jsonl([webpage], output_path)
        print(f"[DONE] extracted {len(all_sequences)} paths into {output_path}")
        return

    if not args.root_dir or not args.out_dir:
        parser.error("--root_dir and --out_dir are required for dataset preprocessing")

    root_dir = Path(args.root_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    webpages = build_dataset(root_dir, debug=args.debug)

    if len(webpages) == 0:
        print("[ERROR] no valid webpages found.")
        return

    split = stratified_split_webpages(
        webpages=webpages,
        train_ratio=args.train_ratio,
        valid_ratio=args.valid_ratio,
        test_ratio=args.test_ratio,
        seed=args.seed,
    )

    train_ids = set(split["train"])
    valid_ids = set(split["valid"])
    test_ids = set(split["test"])

    train_webpages = filter_by_ids(webpages, train_ids)
    valid_webpages = filter_by_ids(webpages, valid_ids)
    test_webpages = filter_by_ids(webpages, test_ids)

    vocabs = build_vocabs(train_webpages)
    num_stats = collect_train_numeric_stats(train_webpages)
    stats = build_stats(webpages)

    write_jsonl(webpages, out_dir / "webpages.jsonl")
    write_jsonl(train_webpages, out_dir / "train.jsonl")
    write_jsonl(valid_webpages, out_dir / "valid.jsonl")
    write_jsonl(test_webpages, out_dir / "test.jsonl")

    safe_write_json(split, out_dir / "split.json")
    safe_write_json(vocabs, out_dir / "vocabs.json")
    safe_write_json(num_stats, out_dir / "num_stats.json")
    safe_write_json(stats, out_dir / "stats.json")

    print("[DONE] preprocessing finished")
    print(f"[DONE] total webpages: {len(webpages)}")
    print(f"[DONE] train/valid/test: {len(train_webpages)}/{len(valid_webpages)}/{len(test_webpages)}")
    print(f"[DONE] saved to: {out_dir}")


if __name__ == "__main__":
    main()
