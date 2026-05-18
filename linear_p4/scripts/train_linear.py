#!/usr/bin/env python3
"""Train/export a fixed-point linear classifier and evaluate JSON replay state."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from common import (
    DEFAULT_LABEL_ORDER,
    FEATURES,
    canonical_flow_key,
    metric_summary,
    parse_flow_tuple,
    read_json,
    write_json,
    write_metrics_markdown,
    write_predictions_csv,
)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/peerrush_linear.json")
    parser.add_argument("--train-csv", default="../PeerRush/PeerRush_train.csv")
    parser.add_argument("--test-csv", default="../PeerRush/PeerRush_test.csv")
    parser.add_argument("--test-json", default="../PeerRush/redeal_test.json")
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--speedup", type=float, default=1000.0)
    parser.add_argument("--l2-reg", type=float, default=None)
    parser.add_argument("--quant-scale", type=int, default=None)
    parser.add_argument("--out", default="generated/linear_model.json")
    parser.add_argument("--metrics", default="generated/linear_python_metrics.json")
    parser.add_argument("--metrics-md", default="generated/linear_python_metrics.md")
    parser.add_argument("--predictions", default=None, help="Optional CSV path for per-row Python predictions.")
    return parser.parse_args()


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return (Path.cwd() / candidate).resolve()


def load_config(path: str) -> dict:
    cfg_path = resolve_path(path)
    if not cfg_path.exists():
        return {}
    return read_json(cfg_path)


def resolve_arg(arg_value, config: dict, key: str, default):
    if arg_value is not None:
        return arg_value
    return config.get(key, default)


def load_csv(path: str, feature_order: list[str], label_order: list[str]) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(path)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    missing = [c for c in (["label"] + feature_order) if c not in df.columns]
    if missing:
        raise ValueError(f"{path} missing columns: {missing}")

    x = df[feature_order].to_numpy(dtype=np.float64, copy=True)
    y_col = df["label"]
    if y_col.dtype.kind in ("i", "u"):
        y = y_col.to_numpy(dtype=np.int64, copy=True)
    else:
        label_map = {name: idx for idx, name in enumerate(label_order)}
        y = y_col.astype(str).str.strip().str.lower().map(label_map).to_numpy(dtype=np.int64, copy=True)
    return x, y


def fit_linear_model(x_train: np.ndarray, y_train: np.ndarray, class_count: int, l2_reg: float) -> dict[str, np.ndarray]:
    mean = x_train.mean(axis=0)
    std = x_train.std(axis=0)
    std[std < 1e-9] = 1.0

    x_norm = (x_train - mean) / std
    targets = -np.ones((x_train.shape[0], class_count), dtype=np.float64)
    targets[np.arange(x_train.shape[0]), y_train] = 1.0

    x_aug = np.concatenate([x_norm, np.ones((x_norm.shape[0], 1), dtype=np.float64)], axis=1)
    reg = np.eye(x_aug.shape[1], dtype=np.float64)
    reg[-1, -1] = 0.0

    theta = np.linalg.solve(x_aug.T @ x_aug + l2_reg * reg, x_aug.T @ targets)
    w_norm = theta[:-1, :]
    b_norm = theta[-1, :]

    alpha = w_norm / std[:, None]
    beta = b_norm - (mean / std) @ w_norm
    return {
        "mean": mean,
        "std": std,
        "w_norm": w_norm,
        "b_norm": b_norm,
        "alpha": alpha,
        "beta": beta,
    }


def quantize_model(alpha: np.ndarray, beta: np.ndarray, quant_scale: int) -> tuple[np.ndarray, np.ndarray]:
    weights = np.rint(alpha.T * quant_scale).astype(np.int64)
    biases = np.rint(beta * quant_scale).astype(np.int64)
    return weights, biases


def predict_float_raw(x_raw: np.ndarray, alpha: np.ndarray, beta: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    scores = x_raw @ alpha + beta[None, :]
    pred = np.argmax(scores, axis=1)
    return pred.astype(np.int64), scores


def predict_quantized_raw(x_raw: np.ndarray, weights: np.ndarray, biases: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    x_int = np.rint(x_raw).astype(np.int64)
    scores = x_int @ weights.T + biases[None, :]
    pred = np.argmax(scores, axis=1)
    return pred.astype(np.int64), scores


def predict_float_one(features: list[int], alpha: np.ndarray, beta: np.ndarray) -> tuple[int, list[float]]:
    x = np.asarray(features, dtype=np.float64)
    scores = (x @ alpha + beta).tolist()
    return int(np.argmax(scores)), scores


def predict_quantized_one(features: list[int], weights: np.ndarray, biases: np.ndarray) -> tuple[int, list[int]]:
    x = np.asarray(features, dtype=np.int64)
    scores = (x @ weights.T + biases).astype(np.int64).tolist()
    return int(np.argmax(scores)), scores


def rows_from_predictions(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray, variant: str) -> list[dict]:
    rows: list[dict] = []
    for idx in range(y_true.shape[0]):
        rows.append({
            "row_id": idx,
            "flow_id": -1,
            "packet_index": -1,
            "true_label": int(y_true[idx]),
            "predicted_label": int(y_pred[idx]),
            "score_0": int(scores[idx, 0]),
            "score_1": int(scores[idx, 1]),
            "score_2": int(scores[idx, 2]),
            "variant": variant,
        })
    return rows


def label_to_id(label, label_order: list[str]) -> int:
    if isinstance(label, (int, np.integer)):
        return int(label)
    label_map = {name: idx for idx, name in enumerate(label_order)}
    return label_map[str(label).strip().lower()]


def iter_replay_feature_rows(
    json_path: Path,
    label_order: list[str],
    start_index: int,
    count: int | None,
    speedup: float,
) -> list[dict]:
    records = read_json(json_path)
    selected = records[start_index:] if count is None else records[start_index:start_index + count]

    rows: list[dict] = []
    flow_state: dict[tuple[int, int, int, int, int], tuple[int, int, int, int, int]] = {}
    row_id = 0
    now_us_float = 0.0

    for flow_id, record in enumerate(selected, start=start_index):
        true_label = label_to_id(record["label"], label_order)
        flow = parse_flow_tuple(record["source"])
        flow_key = canonical_flow_key(flow)
        state = flow_state.get(flow_key)
        packet_num = int(record.get("packet_num", len(record.get("len_seq", []))))
        prev_ts: float | None = None

        for packet_index in range(packet_num):
            ts = float(record["ts_seq"][packet_index])
            if prev_ts is not None:
                delta = ts - prev_ts
                if delta > 0:
                    now_us_float += (delta * 1_000_000.0) / max(speedup, 1e-9)
            prev_ts = ts
            now_us = int(round(now_us_float))

            total_len = int(record["len_seq"][packet_index]) + 14
            if state is None:
                last_ipd = 0
                max_packet_len = total_len
                min_packet_len = total_len
                max_ipd = 0
                min_ipd = 0
            else:
                last_ts, max_packet_len, min_packet_len, max_ipd, min_ipd = state
                last_ipd = max(0, now_us - last_ts)
                max_packet_len = max(max_packet_len, total_len)
                min_packet_len = min(min_packet_len, total_len)
                max_ipd = max(max_ipd, last_ipd)
                min_ipd = last_ipd if min_ipd == 0 else min(min_ipd, last_ipd)

            proto = int(record["proto_seq"][packet_index])
            feature_values = {
                "ip_len": int(record["ip_hl_seq"][packet_index]),
                "total_len": total_len,
                "proto": proto,
                "tos": int(record["ip_tos_seq"][packet_index]),
                "tcp_offset": int(record["tcp_off_seq"][packet_index]) if proto == 6 else 0,
                "max_packet_len": max_packet_len,
                "min_packet_len": min_packet_len,
                "max_ipd": max_ipd,
                "min_ipd": min_ipd,
                "last_ipd": last_ipd,
            }
            rows.append({
                "row_id": row_id,
                "flow_id": flow_id,
                "packet_index": packet_index,
                "true_label": true_label,
                "features": feature_values,
            })
            row_id += 1
            state = (now_us, max_packet_len, min_packet_len, max_ipd, min_ipd)

        flow_state[flow_key] = state

    return rows


def replay_prediction_rows(
    replay_rows: list[dict],
    feature_order: list[str],
    weights: np.ndarray,
    biases: np.ndarray,
    alpha: np.ndarray,
    beta: np.ndarray,
) -> tuple[list[dict], list[dict], float]:
    quant_rows: list[dict] = []
    float_rows: list[dict] = []
    agreement = 0

    for row in replay_rows:
        features = [int(row["features"][name]) for name in feature_order]
        quant_pred, quant_scores = predict_quantized_one(features, weights, biases)
        float_pred, float_scores = predict_float_one(features, alpha, beta)
        agreement += int(quant_pred == float_pred)

        base = {
            "row_id": int(row["row_id"]),
            "flow_id": int(row["flow_id"]),
            "packet_index": int(row["packet_index"]),
            "true_label": int(row["true_label"]),
        }
        quant_rows.append({
            **base,
            "predicted_label": quant_pred,
            "score_0": int(quant_scores[0]),
            "score_1": int(quant_scores[1]),
            "score_2": int(quant_scores[2]),
            "variant": "json_replay_quantized",
        })
        float_rows.append({
            **base,
            "predicted_label": float_pred,
            "score_0": int(round(float_scores[0])),
            "score_1": int(round(float_scores[1])),
            "score_2": int(round(float_scores[2])),
            "variant": "json_replay_float",
        })

    return quant_rows, float_rows, agreement / len(replay_rows) if replay_rows else 0.0


def export_model(
    path: str,
    feature_order: list[str],
    label_order: list[str],
    quant_scale: int,
    fit: dict[str, np.ndarray],
    weights: np.ndarray,
    biases: np.ndarray,
    l2_reg: float,
    metrics: dict,
) -> dict:
    model = {
        "model_type": "fixed_point_linear_10x3_bmv2_mul",
        "feature_order": feature_order,
        "label_order": label_order,
        "class_order": label_order,
        "quant_scale": int(quant_scale),
        "weights": weights.tolist(),
        "biases": biases.tolist(),
        "tie_break": "lowest_class_id",
        "normalization": {
            feature_order[i]: {
                "mean": float(fit["mean"][i]),
                "std": float(fit["std"][i]),
            }
            for i in range(len(feature_order))
        },
        "float_reference": {
            "raw_weights": fit["alpha"].T.tolist(),
            "raw_biases": fit["beta"].tolist(),
        },
        "training": {
            "l2_reg": float(l2_reg),
        },
        "metrics": metrics,
    }
    write_json(path, model)
    return model


def main() -> None:
    args = parse_args()
    config = load_config(args.config)

    feature_order = config.get("features", FEATURES)
    label_order = config.get("label_order", DEFAULT_LABEL_ORDER)
    l2_reg = float(resolve_arg(args.l2_reg, config, "l2_reg", 1.0))
    quant_scale = int(resolve_arg(args.quant_scale, config, "quant_scale", 8192))

    x_train, y_train = load_csv(str(resolve_path(args.train_csv)), feature_order, label_order)
    x_test, y_test = load_csv(str(resolve_path(args.test_csv)), feature_order, label_order)

    fit = fit_linear_model(x_train, y_train, len(label_order), l2_reg)
    weights, biases = quantize_model(fit["alpha"], fit["beta"], quant_scale)

    float_pred, float_scores = predict_float_raw(x_test, fit["alpha"], fit["beta"])
    quant_pred, quant_scores = predict_quantized_raw(x_test, weights, biases)

    float_rows = rows_from_predictions(y_test, float_pred, np.rint(float_scores).astype(np.int64), "csv_float")
    quant_rows = rows_from_predictions(y_test, quant_pred, quant_scores, "csv_quantized")

    float_metrics = metric_summary(float_rows, label_order)
    csv_metrics = metric_summary(quant_rows, label_order)
    csv_metrics["quant_scale"] = quant_scale
    csv_metrics["l2_reg"] = l2_reg
    csv_metrics["float_reference_accuracy"] = float_metrics["accuracy"]
    csv_metrics["float_reference_macro_f1"] = float_metrics["macro_f1"]
    csv_metrics["float_quant_agreement"] = float(np.mean(float_pred == quant_pred))

    replay_rows = iter_replay_feature_rows(
        resolve_path(args.test_json),
        label_order,
        args.start_index,
        args.count,
        args.speedup,
    )
    replay_quant_rows, replay_float_rows, replay_agreement = replay_prediction_rows(
        replay_rows,
        feature_order,
        weights,
        biases,
        fit["alpha"],
        fit["beta"],
    )
    replay_float_metrics = metric_summary(replay_float_rows, label_order)
    metrics = metric_summary(replay_quant_rows, label_order)
    metrics["evaluation"] = "redeal_json_state_replay"
    metrics["test_json"] = args.test_json
    metrics["start_index"] = int(args.start_index)
    metrics["record_count"] = args.count
    metrics["speedup"] = float(args.speedup)
    metrics["quant_scale"] = quant_scale
    metrics["l2_reg"] = l2_reg
    metrics["csv_quantized_accuracy"] = csv_metrics["accuracy"]
    metrics["csv_quantized_macro_f1"] = csv_metrics["macro_f1"]
    metrics["csv_float_reference_accuracy"] = float_metrics["accuracy"]
    metrics["csv_float_reference_macro_f1"] = float_metrics["macro_f1"]
    metrics["replay_float_reference_accuracy"] = replay_float_metrics["accuracy"]
    metrics["replay_float_reference_macro_f1"] = replay_float_metrics["macro_f1"]
    metrics["replay_float_quant_agreement"] = replay_agreement

    export_model(
        str(resolve_path(args.out)),
        feature_order,
        label_order,
        quant_scale,
        fit,
        weights,
        biases,
        l2_reg,
        {
            "test_quantized_accuracy": csv_metrics["accuracy"],
            "test_quantized_macro_f1": csv_metrics["macro_f1"],
            "test_float_accuracy": float_metrics["accuracy"],
            "test_float_macro_f1": float_metrics["macro_f1"],
            "float_quant_agreement": csv_metrics["float_quant_agreement"],
            "json_replay_quantized_accuracy": metrics["accuracy"],
            "json_replay_quantized_macro_f1": metrics["macro_f1"],
            "json_replay_float_accuracy": replay_float_metrics["accuracy"],
            "json_replay_float_macro_f1": replay_float_metrics["macro_f1"],
            "json_replay_float_quant_agreement": replay_agreement,
            "json_replay_records": args.count,
            "json_replay_speedup": args.speedup,
        },
    )

    if args.predictions:
        write_predictions_csv(resolve_path(args.predictions), replay_quant_rows)
    write_json(resolve_path(args.metrics), metrics)
    write_metrics_markdown(resolve_path(args.metrics_md), metrics, "PeerRush Fixed-Point Linear JSON Replay Metrics")

    print(f"quant_scale: {quant_scale}")
    print(f"evaluation: redeal_json_state_replay")
    print(f"records: {args.count}")
    print(f"speedup: {args.speedup:g}")
    print(f"accuracy: {metrics['accuracy']:.6f}")
    print(f"macro_f1: {metrics['macro_f1']:.6f}")
    print(f"float_reference_accuracy: {replay_float_metrics['accuracy']:.6f}")
    print(f"float_quant_agreement: {metrics['replay_float_quant_agreement']:.6f}")
    print(f"csv_quantized_accuracy: {metrics['csv_quantized_accuracy']:.6f}")
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
