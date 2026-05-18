#!/usr/bin/env python3
"""Train and export a hybrid quantized BNN from PeerRush CSV."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


FEATURES = [
    "ip_len",
    "total_len",
    "proto",
    "tos",
    "tcp_offset",
    "max_packet_len",
    "min_packet_len",
    "max_ipd",
    "min_ipd",
    "last_ipd",
]

LABEL_ORDER = ["emule", "utorrent", "vuze"]
LABEL_MAP = {name: idx for idx, name in enumerate(LABEL_ORDER)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-csv", default="../PeerRush/PeerRush_train.csv")
    parser.add_argument("--test-csv", default="../PeerRush/PeerRush_test.csv")
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--batch-size", type=int, default=2048)
    parser.add_argument("--lr", type=float, default=0.03)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", default="generated/model.json")
    parser.add_argument("--metrics", default="generated/python_metrics.json")
    parser.add_argument("--metrics-md", default="generated/python_metrics.md")
    parser.add_argument("--predictions", default=None, help="Optional CSV path for per-row Python predictions.")
    return parser.parse_args()


def ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def load_csv(path: str) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(path)
    rename_map = {c: c.strip().lower().replace(" ", "_") for c in df.columns}
    df = df.rename(columns=rename_map)
    missing = [c for c in (["label"] + FEATURES) if c not in df.columns]
    if missing:
        raise ValueError(f"{path} missing columns: {missing}")
    x = df[FEATURES].to_numpy(dtype=np.float32, copy=True)
    y_col = df["label"]
    if y_col.dtype.kind in ("i", "u"):
        y = y_col.to_numpy(dtype=np.int64, copy=True)
    else:
        y = y_col.astype(str).map(LABEL_MAP).to_numpy(dtype=np.int64, copy=True)
    return x, y


def ternary_quantize(values: np.ndarray, delta: float = 0.5) -> np.ndarray:
    out = np.zeros_like(values, dtype=np.int8)
    out[values > delta] = 1
    out[values < -delta] = -1
    return out


def softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(shifted)
    return exp / np.sum(exp, axis=1, keepdims=True)


def forward_with_quantized(
    x: np.ndarray,
    w1_latent: np.ndarray,
    b1: np.ndarray,
    th1: np.ndarray,
    w2_latent: np.ndarray,
    b2: np.ndarray,
    delta: float = 0.5,
) -> dict[str, np.ndarray]:
    w1_q = ternary_quantize(w1_latent, delta=delta).astype(np.float32)
    w2_q = ternary_quantize(w2_latent, delta=delta).astype(np.float32)
    hidden_acc = x @ w1_q.T + b1[None, :]
    z = np.clip((hidden_acc - th1[None, :]) / 4.0, -40.0, 40.0)
    hidden_prob = 1.0 / (1.0 + np.exp(-z))
    hidden_bin = (hidden_acc > th1[None, :]).astype(np.float32)
    logits = hidden_bin @ w2_q.T + b2[None, :]
    return {
        "w1_q": w1_q,
        "w2_q": w2_q,
        "hidden_acc": hidden_acc,
        "hidden_prob": hidden_prob,
        "hidden_bin": hidden_bin,
        "logits": logits,
    }


def train_model(
    x_train: np.ndarray,
    y_train: np.ndarray,
    epochs: int,
    batch_size: int,
    lr: float,
    seed: int,
    n_hidden: int,
) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    n_features = x_train.shape[1]
    n_classes = 3

    w1_latent = rng.normal(0.0, 0.6, size=(n_hidden, n_features)).astype(np.float32)
    b1 = np.zeros((n_hidden,), dtype=np.float32)
    th1 = np.zeros((n_hidden,), dtype=np.float32)
    w2_latent = rng.normal(0.0, 0.6, size=(n_classes, n_hidden)).astype(np.float32)
    b2 = np.zeros((n_classes,), dtype=np.float32)

    n = x_train.shape[0]
    for _epoch in range(epochs):
        order = rng.permutation(n)
        for start in range(0, n, batch_size):
            idx = order[start:start + batch_size]
            xb = x_train[idx]
            yb = y_train[idx]
            bs = xb.shape[0]

            fwd = forward_with_quantized(xb, w1_latent, b1, th1, w2_latent, b2)
            probs = softmax(fwd["logits"])
            grad_logits = probs
            grad_logits[np.arange(bs), yb] -= 1.0
            grad_logits /= float(bs)

            grad_w2 = grad_logits.T @ fwd["hidden_bin"]
            grad_b2 = grad_logits.sum(axis=0)
            grad_hidden = grad_logits @ fwd["w2_q"]
            grad_hidden_acc = grad_hidden * (fwd["hidden_prob"] * (1.0 - fwd["hidden_prob"]))
            grad_w1 = grad_hidden_acc.T @ xb
            grad_b1 = grad_hidden_acc.sum(axis=0)
            grad_th1 = -grad_hidden_acc.sum(axis=0)

            w2_latent -= lr * grad_w2
            b2 -= lr * grad_b2
            w1_latent -= lr * grad_w1
            b1 -= lr * grad_b1
            th1 -= lr * grad_th1

    return {
        "w1_latent": w1_latent,
        "b1": b1,
        "th1": th1,
        "w2_latent": w2_latent,
        "b2": b2,
    }


def infer_quantized(x: np.ndarray, params: dict[str, np.ndarray]) -> tuple[np.ndarray, np.ndarray]:
    fwd = forward_with_quantized(
        x,
        params["w1_latent"],
        params["b1"],
        params["th1"],
        params["w2_latent"],
        params["b2"],
    )
    logits = fwd["logits"]
    pred = np.argmax(logits, axis=1)
    return pred, logits


def metrics_from_predictions(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    labels = [0, 1, 2]
    confusion = {str(t): {str(p): 0 for p in labels} for t in labels}
    for t, p in zip(y_true, y_pred):
        confusion[str(int(t))][str(int(p))] += 1
    per_class = {}
    host_accuracy_spread = {}
    macro_p = 0.0
    macro_r = 0.0
    macro_f1 = 0.0
    for cls in labels:
        tp = confusion[str(cls)][str(cls)]
        fp = sum(confusion[str(other)][str(cls)] for other in labels if other != cls)
        fn = sum(confusion[str(cls)][str(other)] for other in labels if other != cls)
        support = sum(confusion[str(cls)].values())
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        macro_p += p
        macro_r += r
        macro_f1 += f1
        per_class[str(cls)] = {
            "name": LABEL_ORDER[cls],
            "precision": p,
            "recall": r,
            "f1": f1,
            "support": support,
        }
        host_accuracy_spread[f"h{cls + 2}"] = {
            "class": cls,
            "name": LABEL_ORDER[cls],
            "correct": tp,
            "support": support,
            "accuracy": r,
            "packets_predicted_to_host": sum(confusion[str(other)][str(cls)] for other in labels),
        }
    total = int(y_true.shape[0])
    accuracy = float(np.sum(y_true == y_pred) / max(total, 1))
    return {
        "total": total,
        "accuracy": accuracy,
        "macro_precision": macro_p / 3.0,
        "macro_recall": macro_r / 3.0,
        "macro_f1": macro_f1 / 3.0,
        "confusion_matrix": confusion,
        "per_class": per_class,
        "host_accuracy_spread": host_accuracy_spread,
    }


def export_model(params: dict[str, np.ndarray], path: str) -> dict:
    w1_q = ternary_quantize(params["w1_latent"]).astype(np.int32)
    w2_q = ternary_quantize(params["w2_latent"]).astype(np.int32)
    n_hidden = int(w1_q.shape[0])
    model = {
        "model_type": f"hybrid_quantized_bnn_10x{n_hidden}x3",
        "deployment_profile": "p4_runtime",
        "hidden_units": n_hidden,
        "feature_order": FEATURES,
        "label_order": ["emule", "utorrent", "vuze"],
        "class_order": ["emule", "utorrent", "vuze"],
        "hidden_weights": w1_q.tolist(),
        "hidden_thresholds": np.rint(params["th1"]).astype(np.int32).tolist(),
        "hidden_biases": np.rint(params["b1"]).astype(np.int32).tolist(),
        "output_weights": w2_q.tolist(),
        "output_biases": np.rint(params["b2"]).astype(np.int32).tolist(),
        "encoding": {
            "ternary_weight_values": {"-1": -1, "0": 0, "+1": 1},
            "hidden_activation": "binary( acc > threshold )",
            "input_type": "raw_integer_features",
        },
    }
    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2)
        f.write("\n")
    return model


def write_metrics(path_json: str, path_md: str, metrics: dict) -> None:
    ensure_parent(path_json)
    with open(path_json, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
        f.write("\n")
    ensure_parent(path_md)
    lines = [
        "# Hybrid Quantized BNN Metrics",
        "",
        f"- Deployment Profile: {metrics.get('deployment_profile', 'unknown')}",
        f"- Hidden Units: {metrics.get('hidden_units', 'unknown')}",
        f"- Total: {metrics['total']}",
        f"- Accuracy: {metrics['accuracy']:.6f}",
        f"- Macro Precision: {metrics['macro_precision']:.6f}",
        f"- Macro Recall: {metrics['macro_recall']:.6f}",
        f"- Macro F1: {metrics['macro_f1']:.6f}",
        "",
        "## Per Class",
        "",
        "| Class | Name | Precision | Recall | F1 | Support |",
        "|---:|---|---:|---:|---:|---:|",
    ]
    for cls in ["0", "1", "2"]:
        c = metrics["per_class"][cls]
        lines.append(
            f"| {cls} | {c['name']} | {c['precision']:.6f} | "
            f"{c['recall']:.6f} | {c['f1']:.6f} | {c['support']} |"
        )
    lines.extend([
        "",
        "## Class-Port / Host Accuracy Spread",
        "",
        "| Host | Predicted Class | Name | Correct | Support | Accuracy | Packets Predicted To Host |",
        "|---|---:|---|---:|---:|---:|---:|",
    ])
    for host, row in sorted(metrics.get("host_accuracy_spread", {}).items()):
        lines.append(
            f"| {host} | {row['class']} | {row['name']} | {row['correct']} | "
            f"{row['support']} | {row['accuracy']:.6f} | {row['packets_predicted_to_host']} |"
        )
    lines.extend(["", "## Confusion Matrix", "", "```json", json.dumps(metrics["confusion_matrix"], indent=2), "```"])
    with open(path_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def write_predictions(path: str, y_true: np.ndarray, y_pred: np.ndarray, logits: np.ndarray) -> None:
    import csv
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["row_id", "true_label", "predicted_label", "score_0", "score_1", "score_2"])
        for i in range(y_true.shape[0]):
            writer.writerow([i, int(y_true[i]), int(y_pred[i]), float(logits[i, 0]), float(logits[i, 1]), float(logits[i, 2])])


def main() -> None:
    args = parse_args()
    n_hidden = 8
    x_train, y_train = load_csv(args.train_csv)
    x_test, y_test = load_csv(args.test_csv)
    params = train_model(x_train, y_train, args.epochs, args.batch_size, args.lr, args.seed, n_hidden)
    y_pred, logits = infer_quantized(x_test, params)
    metrics = metrics_from_predictions(y_test, y_pred)
    metrics["deployment_profile"] = "p4_runtime"
    metrics["hidden_units"] = n_hidden
    export_model(params, args.out)
    write_metrics(args.metrics, args.metrics_md, metrics)
    if args.predictions:
        write_predictions(args.predictions, y_test, y_pred, logits)
    print(f"model written: {args.out}")
    print(f"accuracy: {metrics['accuracy']:.6f}")
    print(f"macro_f1: {metrics['macro_f1']:.6f}")
    print("host_accuracy_spread:")
    for host, row in sorted(metrics.get("host_accuracy_spread", {}).items()):
        print(
            f"  {host}/class {row['class']} ({row['name']}): "
            f"accuracy={row['accuracy']:.6f}, "
            f"correct={row['correct']}/{row['support']}, "
            f"predicted_to_host={row['packets_predicted_to_host']}"
        )


if __name__ == "__main__":
    main()
