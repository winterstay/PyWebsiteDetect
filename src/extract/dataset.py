import json
import math
from pathlib import Path
from typing import Dict, List, Any

import torch
from torch.utils.data import Dataset


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

CAT_FIELD_TO_VOCAB = {
    "node_type": "node_type_vocab",
    "api_name": "api_name_vocab",
    "html_element_info": "html_element_info_vocab",
    "calling_method": "calling_method_vocab",
    "frame_owner_info": "frame_owner_info_vocab",
}


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


class WebPageSequenceDataset(Dataset):
    """
    一个样本 = 一个网页
    一个网页 = 多条序列
    一条序列 = 多个节点
    """

    def __init__(
        self,
        jsonl_path: str,
        vocabs_path: str,
        num_stats_path: str,
        max_num_sequences: int = 8,
        max_seq_len: int = 64,
    ):
        self.samples = load_jsonl(jsonl_path)
        self.vocabs = load_json(vocabs_path)
        self.num_stats = load_json(num_stats_path)

        self.max_num_sequences = max_num_sequences
        self.max_seq_len = max_seq_len

        self.pad_id = 0
        self.unk_id = 1

    def __len__(self) -> int:
        return len(self.samples)

    def lookup_id(self, vocab_name: str, token: str) -> int:
        vocab = self.vocabs[vocab_name]
        return vocab.get(token, self.unk_id)

    def normalize_num(self, field_name: str, value: float) -> float:
        if value is None:
            value = 0.0
        value = float(value)

        # 与预处理统计保持一致：先 log1p，再 z-score
        value = math.log1p(value) if value > 0 else 0.0

        mean = self.num_stats[field_name]["mean"]
        std = self.num_stats[field_name]["std"]
        return (value - mean) / std

    def encode_node(self, node: Dict[str, Any]) -> Dict[str, Any]:
        cat = node.get("cat", {})
        num = node.get("num", {})
        binf = node.get("bin", {})
        multi = node.get("multi", {})

        node_type = node.get("node_type", "UNKNOWN")

        encoded = {
            "node_type_id": self.lookup_id("node_type_vocab", node_type),
            "api_name_id": self.lookup_id("api_name_vocab", cat.get("api_name", "NONE")),
            "html_element_info_id": self.lookup_id("html_element_info_vocab", cat.get("html_element_info", "NONE")),
            "calling_method_id": self.lookup_id("calling_method_vocab", cat.get("calling_method", "NONE")),
            "frame_owner_info_id": self.lookup_id("frame_owner_info_vocab", cat.get("frame_owner_info", "NONE")),
            "num_feats": [self.normalize_num(k, num.get(k, 0.0)) for k in NUM_FIELDS],
            "bin_feats": [float(int(binf.get(k, 0))) for k in BIN_FIELDS],
            "multi_feats": [float(int(multi.get(k, 0))) for k in RISK_CATEGORIES],
        }
        return encoded

    def pad_sequence_nodes(self, encoded_nodes: List[Dict[str, Any]]) -> Dict[str, torch.Tensor]:
        max_len = self.max_seq_len

        node_type_ids = []
        api_name_ids = []
        html_element_info_ids = []
        calling_method_ids = []
        frame_owner_info_ids = []
        num_feats = []
        bin_feats = []
        multi_feats = []
        seq_mask = []

        encoded_nodes = encoded_nodes[:max_len]

        for node in encoded_nodes:
            node_type_ids.append(node["node_type_id"])
            api_name_ids.append(node["api_name_id"])
            html_element_info_ids.append(node["html_element_info_id"])
            calling_method_ids.append(node["calling_method_id"])
            frame_owner_info_ids.append(node["frame_owner_info_id"])
            num_feats.append(node["num_feats"])
            bin_feats.append(node["bin_feats"])
            multi_feats.append(node["multi_feats"])
            seq_mask.append(1)

        pad_count = max_len - len(encoded_nodes)

        for _ in range(pad_count):
            node_type_ids.append(self.pad_id)
            api_name_ids.append(self.pad_id)
            html_element_info_ids.append(self.pad_id)
            calling_method_ids.append(self.pad_id)
            frame_owner_info_ids.append(self.pad_id)
            num_feats.append([0.0] * len(NUM_FIELDS))
            bin_feats.append([0.0] * len(BIN_FIELDS))
            multi_feats.append([0.0] * len(RISK_CATEGORIES))
            seq_mask.append(0)

        return {
            "node_type_ids": torch.tensor(node_type_ids, dtype=torch.long),
            "api_name_ids": torch.tensor(api_name_ids, dtype=torch.long),
            "html_element_info_ids": torch.tensor(html_element_info_ids, dtype=torch.long),
            "calling_method_ids": torch.tensor(calling_method_ids, dtype=torch.long),
            "frame_owner_info_ids": torch.tensor(frame_owner_info_ids, dtype=torch.long),
            "num_feats": torch.tensor(num_feats, dtype=torch.float),
            "bin_feats": torch.tensor(bin_feats, dtype=torch.float),
            "multi_feats": torch.tensor(multi_feats, dtype=torch.float),
            "seq_mask": torch.tensor(seq_mask, dtype=torch.float),
        }

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        sample = self.samples[idx]

        sequences = sample.get("sequences", [])
        sequences = sequences[:self.max_num_sequences]

        seq_outputs = []
        web_mask = []

        for seq in sequences:
            nodes = seq.get("nodes", [])
            encoded_nodes = [self.encode_node(n) for n in nodes]
            seq_tensor_dict = self.pad_sequence_nodes(encoded_nodes)
            seq_outputs.append(seq_tensor_dict)
            web_mask.append(1)

        pad_seq_count = self.max_num_sequences - len(seq_outputs)

        for _ in range(pad_seq_count):
            seq_outputs.append(
                self.pad_sequence_nodes([])
            )
            web_mask.append(0)

        batch_item = {
            "webpage_id": sample["webpage_id"],
            "label": torch.tensor(sample["label"], dtype=torch.long),
            "web_mask": torch.tensor(web_mask, dtype=torch.float),

            "node_type_ids": torch.stack([x["node_type_ids"] for x in seq_outputs], dim=0),
            "api_name_ids": torch.stack([x["api_name_ids"] for x in seq_outputs], dim=0),
            "html_element_info_ids": torch.stack([x["html_element_info_ids"] for x in seq_outputs], dim=0),
            "calling_method_ids": torch.stack([x["calling_method_ids"] for x in seq_outputs], dim=0),
            "frame_owner_info_ids": torch.stack([x["frame_owner_info_ids"] for x in seq_outputs], dim=0),

            "num_feats": torch.stack([x["num_feats"] for x in seq_outputs], dim=0),
            "bin_feats": torch.stack([x["bin_feats"] for x in seq_outputs], dim=0),
            "multi_feats": torch.stack([x["multi_feats"] for x in seq_outputs], dim=0),

            "seq_mask": torch.stack([x["seq_mask"] for x in seq_outputs], dim=0),
        }
        return batch_item
