import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TREE_DIR = PROJECT_ROOT / "tree_p4"
PEERRUSH_DIR = PROJECT_ROOT / "PeerRush"
GENERATED_DIR = TREE_DIR / "generated"
TRAIN_CSV = PEERRUSH_DIR / "PeerRush_train.csv"
TEST_CSV = PEERRUSH_DIR / "PeerRush_test.csv"
MODEL_PATH = GENERATED_DIR / "peerrush_model.joblib"
BINDINGS_PATH = GENERATED_DIR / "peerrush_bindings.json"

MAX_DEPTH = 5
RANDOM_STATE = 42


def build_bindings(feature_names: list[str]) -> dict:
    binding_specs = {
        "ip_len": {"p4_expr": "hdr.ipv4.ihl", "type": "bit<4>"},
        "total_len": {"p4_expr": "hdr.ipv4.totalLen", "type": "bit<16>"},
        "proto": {"p4_expr": "hdr.ipv4.protocol", "type": "bit<8>"},
        "tos": {"p4_expr": "hdr.ipv4.diffserv", "type": "bit<8>"},
        "tcp_offset": {"p4_expr": "hdr.tcp.dataOffset", "type": "bit<4>"},
        "max_packet_len": {"p4_expr": "meta.max_packet_len", "type": "bit<16>"},
        "min_packet_len": {"p4_expr": "meta.min_packet_len", "type": "bit<16>"},
        "max_ipd": {"p4_expr": "meta.max_ipd", "type": "bit<32>"},
        "min_ipd": {"p4_expr": "meta.min_ipd", "type": "bit<32>"},
        "last ipd": {"p4_expr": "meta.last_ipd", "type": "bit<32>"},
    }

    missing_features = [name for name in feature_names if name not in binding_specs]
    if missing_features:
        raise ValueError(f"Missing binding specs for features: {missing_features}")

    return {
        "features": [
            {
                "name": name,
                "p4_expr": binding_specs[name]["p4_expr"],
                "type": binding_specs[name]["type"],
            }
            for name in feature_names
        ]
    }


def load_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series]:
    dataset = pd.read_csv(path)
    if "label" not in dataset.columns:
        raise ValueError(f"Expected a 'label' column in {path}")

    features = dataset.drop(columns=["label"])
    labels = dataset["label"]
    return features, labels


def main() -> None:
    x_train, y_train = load_dataset(TRAIN_CSV)
    x_test, y_test = load_dataset(TEST_CSV)

    model = DecisionTreeClassifier(max_depth=MAX_DEPTH, random_state=RANDOM_STATE)
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)

    bindings = build_bindings(list(x_train.columns))

    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    BINDINGS_PATH.write_text(json.dumps(bindings, indent=2))

    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved bindings to {BINDINGS_PATH}")
    print(f"Feature order: {list(x_train.columns)}")
    print(f"Test accuracy: {accuracy:.6f}")
    print(f"Tree depth: {model.get_depth()}")
    print(f"Leaf count: {model.get_n_leaves()}")
    print(f"Classes: {list(model.classes_)}")


if __name__ == "__main__":
    main()
