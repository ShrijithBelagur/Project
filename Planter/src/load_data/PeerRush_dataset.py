# Planter loader for the PeerRush P2P traffic-classification dataset.
#
# Header-only features (stateless, available in every packet at line rate):
#   ip_len, total_len, proto, tos, tcp_offset
#
# Planter's generated P4 has no flow-table or register state, so the stateful
# PeerRush features (max/min packet length, max/min/last IPD) cannot be
# populated on the switch. This loader only supports num_features <= 5; any
# higher value is rejected to prevent silently training on features the
# generated P4 pipeline cannot evaluate.
#
# Train data: full PeerRush_train.csv (one CSV row = one packet).
# Test  data: redeal_test.json, taking the first N records (flows)
# starting from `start_index`, expanded to per-packet rows. This matches the
# semantics of `run_benchmark.sh --count N --start-index S` in the sibling
# Project: records are taken sequentially (no shuffling), so the same N
# selects the same flows across Planter and the Project benchmark.

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder


FEATURE_ORDER = [
    "ip_len",
    "total_len",
    "proto",
    "tos",
    "tcp_offset",
]
MAX_FEATURES = len(FEATURE_ORDER)

# Canonical class ordering: matches the sibling Project (config/peerrush_linear.json
# label_order). Used to fit LabelEncoder up-front so transform() works whether the
# CSV stores labels as ints (0/1/2) or strings.
LABEL_ORDER = ["emule", "utorrent", "vuze"]


def _read_csv(path):
    df = pd.read_csv(path)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    return df


def _prompt_int(question, default):
    while True:
        raw = input(f"+ {question} (default = {default}) ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
            if value < 0:
                print("  Warning! Must be >= 0.")
                continue
            return value
        except ValueError:
            print("  Warning! Please enter an integer.")


def _packet_rows_from_records(records, label_encoder):
    rows = []
    labels = []
    for record in records:
        label_raw = record.get("label")
        if isinstance(label_raw, (int, np.integer)):
            label_id = int(label_raw)
        else:
            label_id = int(label_encoder.transform(
                [str(label_raw).strip().lower()]
            )[0])

        packet_num = int(record.get("packet_num", len(record.get("len_seq", []))))
        len_seq = record["len_seq"]
        ip_hl_seq = record["ip_hl_seq"]
        proto_seq = record["proto_seq"]
        ip_tos_seq = record["ip_tos_seq"]
        tcp_off_seq = record["tcp_off_seq"]

        for i in range(packet_num):
            proto = int(proto_seq[i])
            rows.append({
                "ip_len": int(ip_hl_seq[i]),
                "total_len": int(len_seq[i]) + 14,
                "proto": proto,
                "tos": int(ip_tos_seq[i]),
                "tcp_offset": int(tcp_off_seq[i]) if proto == 6 else 0,
            })
            labels.append(label_id)

    return pd.DataFrame(rows, columns=FEATURE_ORDER), np.asarray(labels, dtype=np.int64)


def load_data(num_features, data_dir):
    if num_features > MAX_FEATURES:
        raise ValueError(
            f"PeerRush Planter loader only supports up to {MAX_FEATURES} features "
            f"(header-only). Got num_features={num_features}. Stateful PeerRush "
            f"features cannot be evaluated by the Planter-generated P4 pipeline."
        )
    used_features = FEATURE_ORDER[:num_features]

    peerrush_dir = Path(data_dir) / "PeerRush"
    train_csv = peerrush_dir / "PeerRush_train.csv"
    test_json = peerrush_dir / "redeal_test.json"
    for path in (train_csv, test_json):
        if not path.exists():
            raise FileNotFoundError(
                f"Required PeerRush file missing: {path}. "
                f"Place PeerRush_train.csv and redeal_test.json under "
                f"{peerrush_dir} before running Planter."
            )

    train_df = _read_csv(train_csv)
    missing_train = [c for c in used_features + ["label"] if c not in train_df.columns]
    if missing_train:
        raise ValueError(f"PeerRush_train.csv missing columns: {missing_train}")

    encoder = LabelEncoder().fit(LABEL_ORDER)
    if train_df["label"].dtype.kind in ("i", "u"):
        y_train = train_df["label"].astype(int).to_numpy()
    else:
        y_train = encoder.transform(
            train_df["label"].astype(str).str.strip().str.lower()
        )
    X_train = train_df[used_features].astype(int).reset_index(drop=True)

    print(f"= PeerRush loader: train rows={len(X_train)} (full PeerRush_train.csv)")

    with open(test_json, "r", encoding="utf-8") as handle:
        all_records = json.load(handle)
    total_records = len(all_records)

    print(f"= PeerRush loader: redeal_test.json has {total_records} records (flows)")
    count = _prompt_int(
        f"How many test records (flows)? 0 = all, max {total_records}", 0,
    )
    start_index = _prompt_int("Test start index?", 0)
    if start_index >= total_records:
        raise ValueError(f"start_index {start_index} >= total records {total_records}")

    if count == 0:
        selected = all_records[start_index:]
    else:
        selected = all_records[start_index : start_index + count]

    X_test, y_test = _packet_rows_from_records(selected, encoder)
    X_test = X_test[used_features].astype(int).reset_index(drop=True)

    print(
        f"= PeerRush loader: test records={len(selected)} (start={start_index}), "
        f"expanded to {len(X_test)} packet rows"
    )

    return X_train, y_train, X_test, y_test, used_features
