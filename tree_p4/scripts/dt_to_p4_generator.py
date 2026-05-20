import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np


"""
Export a scikit-learn DecisionTreeClassifier to:
  1) JSON
  2) P4

The tree is traversed from root to leaf, and each packet follows exactly one path.
That avoids the earlier bug where unrelated comparisons were treated independently.

Expected bindings.json format:
{
  "features": [
    {"name": "protocol", "p4_expr": "hdr.ipv4.protocol", "type": "bit<8>"},
    {"name": "srcPort", "p4_expr": "hdr.tcp.srcPort", "type": "bit<16>"},
    {"name": "dstPort", "p4_expr": "hdr.tcp.dstPort", "type": "bit<16>"}
  ]
}
"""


@dataclass(frozen=True)
class FeatureBinding:
    name: str
    p4_expr: str
    type_str: str


@dataclass(frozen=True)
class TreeNodeInfo:
    node_id: int
    feature_index: int
    threshold: float
    left_child: int
    right_child: int
    is_leaf: bool
    prediction_class: int
    depth: int


def to_native(value: Any) -> Any:
    """Convert NumPy scalar types into regular Python values."""
    if isinstance(value, (np.bool_, bool)):
        return bool(value)
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    return value


def threshold_literal(value: Any) -> int:
    """
    Emit integer P4 split constants.

    sklearn stores thresholds as floats. For integer packet/header metadata,
    `field <= 3082.5` is equivalent to `field <= 3082`.
    """
    return int(np.floor(float(value)))


def load_bindings(path: Path) -> List[FeatureBinding]:
    data = json.loads(path.read_text())
    raw_features = data.get("features", [])
    if not raw_features:
        raise ValueError("bindings.json must contain a non-empty 'features' list")

    bindings: List[FeatureBinding] = []
    for item in raw_features:
        bindings.append(
            FeatureBinding(
                name=str(item["name"]),
                p4_expr=str(item["p4_expr"]),
                type_str=str(item.get("type", "bit<32>")),
            )
        )
    return bindings


def load_model(path: Path):
    model = joblib.load(path)
    if not hasattr(model, "tree_"):
        raise TypeError("Loaded object does not look like a scikit-learn decision tree model")
    return model


def majority_class(model, node_id: int) -> int:
    counts = model.tree_.value[node_id][0]
    return int(np.argmax(counts))


def traverse_tree(model) -> Tuple[List[TreeNodeInfo], Dict[int, str], int]:
    """
    Walk the sklearn tree and collect:
      - a flat list of node metadata
      - leaf node -> root-to-leaf bitstring
      - maximum depth
    """
    tree = model.tree_
    left_child = tree.children_left
    right_child = tree.children_right
    feature = tree.feature
    threshold = tree.threshold
    values = tree.value

    def node_class(node_id: int) -> int:
        return int(np.argmax(values[node_id][0]))

    node_infos: List[TreeNodeInfo] = []
    leaf_paths: Dict[int, str] = {}
    max_depth = 0

    def dfs(node_id: int, depth: int, bits: str) -> None:
        nonlocal max_depth
        max_depth = max(max_depth, depth)

        is_leaf = left_child[node_id] == right_child[node_id]
        node_infos.append(
            TreeNodeInfo(
                node_id=int(node_id),
                feature_index=int(feature[node_id]),
                threshold=float(threshold[node_id]),
                left_child=int(left_child[node_id]),
                right_child=int(right_child[node_id]),
                is_leaf=bool(is_leaf),
                prediction_class=node_class(node_id),
                depth=int(depth),
            )
        )

        if is_leaf:
            leaf_paths[int(node_id)] = bits
            return

        # sklearn convention:
        #   left  => feature <= threshold => bit 0
        #   right => feature > threshold  => bit 1
        dfs(int(left_child[node_id]), depth + 1, bits + "0")
        dfs(int(right_child[node_id]), depth + 1, bits + "1")

    dfs(0, 0, "")
    return node_infos, leaf_paths, max_depth


def export_tree_json(model, bindings: List[FeatureBinding]) -> Dict[str, Any]:
    node_infos, leaf_paths, max_depth = traverse_tree(model)

    used_features = sorted({n.feature_index for n in node_infos if not n.is_leaf})
    for feature_index in used_features:
        if feature_index < 0 or feature_index >= len(bindings):
            raise ValueError(f"No binding provided for feature index {feature_index}")

    nodes_json: List[Dict[str, Any]] = []
    for node in node_infos:
        entry: Dict[str, Any] = {
            "node_id": to_native(node.node_id),
            "depth": to_native(node.depth),
            "is_leaf": to_native(node.is_leaf),
            "prediction_class": to_native(node.prediction_class),
        }

        if not node.is_leaf:
            binding = bindings[node.feature_index]
            entry.update(
                {
                    "feature_index": to_native(node.feature_index),
                    "feature_name": binding.name,
                    "p4_expr": binding.p4_expr,
                    "type": binding.type_str,
                    "threshold": to_native(node.threshold),
                    "left_child": to_native(node.left_child),
                    "right_child": to_native(node.right_child),
                }
            )

        nodes_json.append(entry)

    leaf_map: Dict[str, int] = {}
    leaf_depths: Dict[str, int] = {}

    for leaf_id, path_bits in leaf_paths.items():
        leaf_map[path_bits] = majority_class(model, leaf_id)
        leaf_depths[path_bits] = len(path_bits)

    n_classes = int(model.n_classes_ if hasattr(model, "n_classes_") else len(model.classes_))

    return {
        "max_depth": to_native(max_depth),
        "n_classes": to_native(n_classes),
        "nodes": nodes_json,
        "leaf_map": leaf_map,
        "leaf_depths": leaf_depths,
    }


def emit_p4(tree_json: Dict[str, Any]) -> str:
    nodes = tree_json["nodes"]
    node_by_id = {int(node["node_id"]): node for node in nodes}
    children_by_id = {
        int(node["node_id"]): (int(node["left_child"]), int(node["right_child"]))
        for node in nodes
        if not node["is_leaf"]
    }

    def emit_subtree(node_id: int, indent: str) -> List[str]:
        node = node_by_id[node_id]

        if node["is_leaf"]:
            class_id = int(node["prediction_class"])
            return [f"{indent}meta.class_id = {class_id};"]

        p4_expr = node["p4_expr"]
        threshold = threshold_literal(node["threshold"])
        left_id, right_id = children_by_id[node_id]

        lines: List[str] = []
        lines.append(f"{indent}if ({p4_expr} <= {threshold}) {{")
        lines.extend(emit_subtree(left_id, indent + "    "))
        lines.append(f"{indent}}} else {{")
        lines.extend(emit_subtree(right_id, indent + "    "))
        lines.append(f"{indent}}}")
        return lines

    root = node_by_id[0]

    lines: List[str] = []
    lines.append("#include <core.p4>")
    lines.append("#include <v1model.p4>")
    lines.append("")
    lines.append("const bit<16> ETHERTYPE_IPV4 = 0x0800;")
    lines.append("const bit<32> FLOW_SLOTS = 65536;")
    lines.append("")
    lines.append("header ethernet_t {")
    lines.append("    bit<48> dstAddr;")
    lines.append("    bit<48> srcAddr;")
    lines.append("    bit<16> etherType;")
    lines.append("}")
    lines.append("")
    lines.append("header ipv4_t {")
    lines.append("    bit<4>  version;")
    lines.append("    bit<4>  ihl;")
    lines.append("    bit<8>  diffserv;")
    lines.append("    bit<16> totalLen;")
    lines.append("    bit<16> identification;")
    lines.append("    bit<3>  flags;")
    lines.append("    bit<13> fragOffset;")
    lines.append("    bit<8>  ttl;")
    lines.append("    bit<8>  protocol;")
    lines.append("    bit<16> hdrChecksum;")
    lines.append("    bit<32> srcAddr;")
    lines.append("    bit<32> dstAddr;")
    lines.append("}")
    lines.append("")
    lines.append("header tcp_t {")
    lines.append("    bit<16> srcPort;")
    lines.append("    bit<16> dstPort;")
    lines.append("    bit<32> seqNo;")
    lines.append("    bit<32> ackNo;")
    lines.append("    bit<4>  dataOffset;")
    lines.append("    bit<3>  reserved;")
    lines.append("    bit<9>  flags;")
    lines.append("    bit<16> window;")
    lines.append("    bit<16> checksum;")
    lines.append("    bit<16> urgentPtr;")
    lines.append("}")
    lines.append("")
    lines.append("struct headers_t {")
    lines.append("    ethernet_t ethernet;")
    lines.append("    ipv4_t ipv4;")
    lines.append("    tcp_t tcp;")
    lines.append("}")
    lines.append("")
    lines.append("struct metadata_t {")
    lines.append("    bit<8> class_id;")
    lines.append("")
    lines.append("    bit<32> ip_a;")
    lines.append("    bit<16> port_a;")
    lines.append("    bit<32> ip_b;")
    lines.append("    bit<16> port_b;")
    lines.append("    bit<32> idx0;")
    lines.append("    bit<32> tag;")
    lines.append("")
    lines.append("    bit<1> valid0;")
    lines.append("    bit<32> stored_tag0;")
    lines.append("    bit<32> stored_last_ts;")
    lines.append("    bit<16> stored_max_len;")
    lines.append("    bit<16> stored_min_len;")
    lines.append("    bit<32> stored_max_ipd;")
    lines.append("    bit<32> stored_min_ipd;")
    lines.append("")
    lines.append("    bit<8> ip_len;")
    lines.append("    bit<16> total_len;")
    lines.append("    bit<8> proto;")
    lines.append("    bit<8> tos;")
    lines.append("    bit<8> tcp_offset;")
    lines.append("    bit<32> now_ts;")
    lines.append("    ")
    lines.append("    bit<16> max_packet_len;")
    lines.append("    bit<16> min_packet_len;")
    lines.append("")
    lines.append("    bit<32> max_ipd;")
    lines.append("    bit<32> min_ipd;")
    lines.append("    bit<32> last_ipd;")
    lines.append("}")
    lines.append("")
    lines.append(
        "parser MyParser(packet_in packet, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {"
    )
    lines.append("    state start {")
    lines.append("        packet.extract(hdr.ethernet);")
    lines.append("        transition select(hdr.ethernet.etherType) {")
    lines.append("            ETHERTYPE_IPV4: parse_ipv4;")
    lines.append("            default: accept;")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    state parse_ipv4 {")
    lines.append("        packet.extract(hdr.ipv4);")
    lines.append("        transition select(hdr.ipv4.protocol) {")
    lines.append("            6: parse_tcp;")
    lines.append("            default: accept;")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    state parse_tcp {")
    lines.append("        packet.extract(hdr.tcp);")
    lines.append("        transition accept;")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    lines.append("control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) { apply { } }")
    lines.append("")
    lines.append("register<bit<1>>(65536) valid0_reg;")
    lines.append("register<bit<32>>(65536) tag0_reg;")
    lines.append("register<bit<32>>(65536) last_ts0_reg;")
    lines.append("register<bit<16>>(65536) max_len0_reg;")
    lines.append("register<bit<16>>(65536) min_len0_reg;")
    lines.append("register<bit<32>>(65536) max_ipd0_reg;")
    lines.append("register<bit<32>>(65536) min_ipd0_reg;")
    lines.append("")
    lines.append("")
    lines.append("control MyIngress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {")
    lines.append("    action drop() {")
    lines.append("        mark_to_drop(standard_metadata);")
    lines.append("    }")
    lines.append("")
    lines.append("    action forward(bit<9> port) {")
    lines.append("        standard_metadata.egress_spec = port;")
    lines.append("    }")
    lines.append("")
    lines.append("    action canonicalize() {")
    lines.append("        if ((hdr.ipv4.srcAddr < hdr.ipv4.dstAddr) || ((hdr.ipv4.srcAddr == hdr.ipv4.dstAddr) && (hdr.tcp.srcPort <= hdr.tcp.dstPort))) {")
    lines.append("            meta.ip_a = hdr.ipv4.srcAddr; meta.port_a = hdr.tcp.srcPort; meta.ip_b = hdr.ipv4.dstAddr; meta.port_b = hdr.tcp.dstPort;")
    lines.append("        } else {")
    lines.append("            meta.ip_a = hdr.ipv4.dstAddr; meta.port_a = hdr.tcp.dstPort; meta.ip_b = hdr.ipv4.srcAddr; meta.port_b = hdr.tcp.srcPort;")
    lines.append("        }")
    lines.append("    }")
    lines.append("    action compute_hashes() {")
    lines.append("        hash(meta.idx0, HashAlgorithm.crc16, 32w0, { hdr.ipv4.protocol, meta.ip_a, meta.port_a, meta.ip_b, meta.port_b }, FLOW_SLOTS);")
    lines.append("        hash(meta.tag, HashAlgorithm.crc32, 32w0, { hdr.ipv4.protocol, meta.ip_a, meta.port_a, meta.ip_b, meta.port_b }, 32w4294967295);")
    lines.append("    }")
    lines.append("    action load_raw_features() {")
    lines.append("        meta.ip_len = (bit<8>) hdr.ipv4.ihl;")
    lines.append("        meta.total_len = hdr.ipv4.totalLen + 16w14;")
    lines.append("        meta.proto = hdr.ipv4.protocol;")
    lines.append("        meta.tos = hdr.ipv4.diffserv;")
    lines.append("        meta.tcp_offset = (bit<8>) hdr.tcp.dataOffset;")
    lines.append("        meta.now_ts = (bit<32>) standard_metadata.ingress_global_timestamp;")
    lines.append("    }")
    lines.append("    action read_bank0() {")
    lines.append("        valid0_reg.read(meta.valid0, meta.idx0);")
    lines.append("        tag0_reg.read(meta.stored_tag0, meta.idx0);")
    lines.append("        last_ts0_reg.read(meta.stored_last_ts, meta.idx0);")
    lines.append("        max_len0_reg.read(meta.stored_max_len, meta.idx0);")
    lines.append("        min_len0_reg.read(meta.stored_min_len, meta.idx0);")
    lines.append("        max_ipd0_reg.read(meta.stored_max_ipd, meta.idx0);")
    lines.append("        min_ipd0_reg.read(meta.stored_min_ipd, meta.idx0);")
    lines.append("    }")
    lines.append("    action update_bank0() {")
    lines.append("        if ((meta.valid0 == 1w1) && (meta.stored_tag0 == meta.tag)) {")
    lines.append("            meta.last_ipd = (meta.now_ts >= meta.stored_last_ts) ? (meta.now_ts - meta.stored_last_ts) : 32w0;")
    lines.append("            meta.max_packet_len = meta.stored_max_len; if (meta.total_len > meta.max_packet_len) { meta.max_packet_len = meta.total_len; }")
    lines.append("            meta.min_packet_len = meta.stored_min_len; if (meta.total_len < meta.min_packet_len) { meta.min_packet_len = meta.total_len; }")
    lines.append("            meta.max_ipd = meta.stored_max_ipd; if (meta.last_ipd > meta.max_ipd) { meta.max_ipd = meta.last_ipd; }")
    lines.append("            meta.min_ipd = meta.stored_min_ipd; if (meta.last_ipd < meta.min_ipd) { meta.min_ipd = meta.last_ipd; }")
    lines.append("        } else {")
    lines.append("            meta.last_ipd = 32w0; meta.max_packet_len = meta.total_len; meta.min_packet_len = meta.total_len; meta.max_ipd = 32w0; meta.min_ipd = 32w0;")
    lines.append("        }")
    lines.append("        valid0_reg.write(meta.idx0, 1w1); tag0_reg.write(meta.idx0, meta.tag); last_ts0_reg.write(meta.idx0, meta.now_ts);")
    lines.append("        max_len0_reg.write(meta.idx0, meta.max_packet_len); min_len0_reg.write(meta.idx0, meta.min_packet_len);")
    lines.append("        max_ipd0_reg.write(meta.idx0, meta.max_ipd); min_ipd0_reg.write(meta.idx0, meta.min_ipd);")
    lines.append("    }")
    lines.append("")
    lines.append("    apply {")
    lines.append("        meta.class_id = 0;")
    lines.append("")
    lines.append("        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {")
    lines.append("            canonicalize(); compute_hashes(); load_raw_features(); read_bank0(); update_bank0();  ")
    lines.append("        } ")
    lines.append("        else {")
    lines.append("            drop(); ")
    lines.append("        }")
    lines.append("")
    lines.append("        if (hdr.ipv4.isValid()) {")
    if root["is_leaf"]:
        lines.append(f"            meta.class_id = {int(root['prediction_class'])};")
    else:
        lines.extend(emit_subtree(0, "            "))
    lines.append("        }")
    lines.append("")
    lines.append("        if (meta.class_id == 0) {")
    lines.append("            forward(1);")
    lines.append("        } ")
    lines.append("        else if (meta.class_id == 1) {")
    lines.append("            forward(2);")
    lines.append("        }")
    lines.append("        else if (meta.class_id == 2){")
    lines.append("            forward(3);")
    lines.append("        } ")
    lines.append("        else {")
    lines.append("            drop();")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    lines.append("control MyEgress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { apply { } }")
    lines.append("")
    lines.append("control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) { apply { } }")
    lines.append("")
    lines.append("control MyDeparser(packet_out packet, in headers_t hdr) {")
    lines.append("    apply {")
    lines.append("        packet.emit(hdr.ethernet);")
    lines.append("        packet.emit(hdr.ipv4);")
    lines.append("        packet.emit(hdr.tcp);")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    lines.append("V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;")
    lines.append("")

    return "\n".join(lines)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TREE_DIR = PROJECT_ROOT / "tree_p4"
GENERATED_DIR = TREE_DIR / "generated"
P4_GENERATED_DIR = TREE_DIR / "p4_generated"


def main() -> None:
    parser = argparse.ArgumentParser(description="Export sklearn decision tree to JSON and P4")
    parser.add_argument("--model", default=GENERATED_DIR / "peerrush_model.joblib", type=Path, help="Path to joblib/pickle sklearn DecisionTreeClassifier")
    parser.add_argument("--bindings", default=GENERATED_DIR / "peerrush_bindings.json", type=Path, help="JSON file mapping feature indices to P4 expressions")
    parser.add_argument("--out-json", default=GENERATED_DIR / "tree.json", type=Path, help="Output JSON path")
    parser.add_argument("--out-p4", default=P4_GENERATED_DIR / "generated_tree.p4", type=Path, help="Output P4 path")
    args = parser.parse_args()

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_p4.parent.mkdir(parents=True, exist_ok=True)

    model = load_model(args.model)
    bindings = load_bindings(args.bindings)
    tree_json = export_tree_json(model, bindings)

    args.out_json.write_text(json.dumps(tree_json, indent=2, default=to_native))
    args.out_p4.write_text(emit_p4(tree_json))

    print(f"Wrote {args.out_json}")
    print(f"Wrote {args.out_p4}")


if __name__ == "__main__":
    main()
