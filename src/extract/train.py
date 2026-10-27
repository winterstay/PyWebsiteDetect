import json
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from dataset import WebPageSequenceDataset
from model import WebSeqModel

# Parameters
data_dir = "pro2/"
batch_size = 8
epochs = 10
lr = 1e-3
weight_decay = 1e-4
max_num_sequences = 8
max_seq_len = 64
emb_dim = 32
lstm_hidden_dim = 128
dropout = 0.1
num_workers = 0
save_path = "best_model.pt"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def move_batch_to_device(batch, device):
    out = {}
    for k, v in batch.items():
        if torch.is_tensor(v):
            out[k] = v.to(device)
        else:
            out[k] = v
    return out


@torch.no_grad()
def evaluate(model, loader, criterion, device):
    model.eval()

    total_loss = 0.0
    total = 0
    correct = 0

    tp = fp = tn = fn = 0

    fp_files = []
    fn_files = []

    for batch in loader:
        batch = move_batch_to_device(batch, device)

        logits, _ = model(
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

        labels = batch["label"]
        loss = criterion(logits, labels)

        total_loss += loss.item() * labels.size(0)

        preds = torch.argmax(logits, dim=1)

        total += labels.size(0)
        correct += (preds == labels).sum().item()

        tp += ((preds == 1) & (labels == 1)).sum().item()
        fp += ((preds == 1) & (labels == 0)).sum().item()
        tn += ((preds == 0) & (labels == 0)).sum().item()
        fn += ((preds == 0) & (labels == 1)).sum().item()

        for i in range(len(preds)):
            if preds[i] == 1 and labels[i] == 0:
                fp_files.append(batch["webpage_id"][i])
            elif preds[i] == 0 and labels[i] == 1:
                fn_files.append(batch["webpage_id"][i])

    avg_loss = total_loss / max(total, 1)
    acc = correct / max(total, 1)

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)

    return {
        "loss": avg_loss,
        "acc": acc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "fp_files": fp_files,
        "fn_files": fn_files,
    }


def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("device =", device)

    data_dir_path = Path(data_dir)

    train_dataset = WebPageSequenceDataset(
        jsonl_path=str(data_dir_path / "train.jsonl"),
        vocabs_path=str(data_dir_path / "vocabs.json"),
        num_stats_path=str(data_dir_path / "num_stats.json"),
        max_num_sequences=max_num_sequences,
        max_seq_len=max_seq_len,
    )
    valid_dataset = WebPageSequenceDataset(
        jsonl_path=str(data_dir_path / "valid.jsonl"),
        vocabs_path=str(data_dir_path / "vocabs.json"),
        num_stats_path=str(data_dir_path / "num_stats.json"),
        max_num_sequences=max_num_sequences,
        max_seq_len=max_seq_len,
    )
    test_dataset = WebPageSequenceDataset(
        jsonl_path=str(data_dir_path / "test.jsonl"),
        vocabs_path=str(data_dir_path / "vocabs.json"),
        num_stats_path=str(data_dir_path / "num_stats.json"),
        max_num_sequences=max_num_sequences,
        max_seq_len=max_seq_len,
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=num_workers,
    )
    valid_loader = DataLoader(
        valid_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
    )

    vocabs = load_json(str(data_dir_path / "vocabs.json"))

    model = WebSeqModel(
        node_type_vocab_size=len(vocabs["node_type_vocab"]),
        api_name_vocab_size=len(vocabs["api_name_vocab"]),
        html_element_info_vocab_size=len(vocabs["html_element_info_vocab"]),
        calling_method_vocab_size=len(vocabs["calling_method_vocab"]),
        frame_owner_info_vocab_size=len(vocabs["frame_owner_info_vocab"]),
        num_dim=7,
        bin_dim=5,
        multi_dim=9,
        emb_dim=emb_dim,
        lstm_hidden_dim=lstm_hidden_dim,
        dropout=dropout,
    ).to(device)

    # 类别不平衡时可加权
    train_labels = [sample["label"] for sample in train_dataset.samples]
    pos_count = sum(train_labels)
    neg_count = len(train_labels) - pos_count
    class_weights = torch.tensor(
        [
            len(train_labels) / max(neg_count, 1),
            len(train_labels) / max(pos_count, 1),
        ],
        dtype=torch.float,
        device=device,
    )

    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=lr,
        weight_decay=weight_decay,
    )

    best_valid_f1 = -1.0

    for epoch in range(1, epochs + 1):
        model.train()

        total_loss = 0.0
        total = 0
        correct = 0

        for batch in train_loader:
            batch = move_batch_to_device(batch, device)

            logits, _ = model(
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

            labels = batch["label"]
            loss = criterion(logits, labels)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * labels.size(0)
            preds = torch.argmax(logits, dim=1)
            total += labels.size(0)
            correct += (preds == labels).sum().item()

        train_loss = total_loss / max(total, 1)
        train_acc = correct / max(total, 1)

        valid_metrics = evaluate(model, valid_loader, criterion, device)

        print(
            f"Epoch {epoch:02d} | "
            f"train_loss={train_loss:.4f} train_acc={train_acc:.4f} | "
            f"valid_loss={valid_metrics['loss']:.4f} valid_acc={valid_metrics['acc']:.4f} "
            f"valid_precision={valid_metrics['precision']:.4f} "
            f"valid_recall={valid_metrics['recall']:.4f} "
            f"valid_f1={valid_metrics['f1']:.4f}"
        )

        # 只在最后一轮输出验证集的误报漏报
        if epoch == epochs:
            if valid_metrics['fp_files']:
                print(f"  [FP] {len(valid_metrics['fp_files'])} false positives: {valid_metrics['fp_files'][:3]}{'...' if len(valid_metrics['fp_files']) > 3 else ''}")
            if valid_metrics['fn_files']:
                print(f"  [FN] {len(valid_metrics['fn_files'])} false negatives: {valid_metrics['fn_files'][:3]}{'...' if len(valid_metrics['fn_files']) > 3 else ''}")

        if valid_metrics["f1"] > best_valid_f1:
            best_valid_f1 = valid_metrics["f1"]
            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "config": {
                        "data_dir": data_dir,
                        "batch_size": batch_size,
                        "epochs": epochs,
                        "lr": lr,
                        "weight_decay": weight_decay,
                        "max_num_sequences": max_num_sequences,
                        "max_seq_len": max_seq_len,
                        "emb_dim": emb_dim,
                        "lstm_hidden_dim": lstm_hidden_dim,
                        "dropout": dropout,
                        "num_workers": num_workers,
                        "save_path": save_path,
                    },
                    "best_valid_f1": best_valid_f1,
                },
                save_path,
            )
            print(f"[SAVE] best model saved to {save_path}")

    print("\nLoading best model for final test...")
    ckpt = torch.load(save_path, map_location=device)
    model.load_state_dict(ckpt["model_state_dict"])

    test_metrics = evaluate(model, test_loader, criterion, device)
    print(
        f"TEST | "
        f"loss={test_metrics['loss']:.4f} acc={test_metrics['acc']:.4f} "
        f"precision={test_metrics['precision']:.4f} "
        f"recall={test_metrics['recall']:.4f} "
        f"f1={test_metrics['f1']:.4f}"
    )
    print(
        f"CONFUSION | TP={test_metrics['tp']} FP={test_metrics['fp']} "
        f"TN={test_metrics['tn']} FN={test_metrics['fn']}"
    )

    if test_metrics['fp_files']:
        print(f"\n[FP - False Positives] {len(test_metrics['fp_files'])} files misclassified as malicious:")
        for f in test_metrics['fp_files']:
            print(f"  - {f}")

    if test_metrics['fn_files']:
        print(f"\n[FN - False Negatives] {len(test_metrics['fn_files'])} malicious files misclassified as benign:")
        for f in test_metrics['fn_files']:
            print(f"  - {f}")

    if not test_metrics['fp_files'] and not test_metrics['fn_files']:
        print("\n[PERFECT] No false positives or false negatives!")


if __name__ == "__main__":
    main()
