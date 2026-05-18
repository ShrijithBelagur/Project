#!/usr/bin/env python3
"""Shared helpers for the Mininet/BMv2 classification benchmark."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Dict, Iterable, List, Optional, Sequence

DEFAULT_HOST_CONFIG = {
    "sender": {"name": "h1", "ip": "10.0.4.1/24", "mac": "02:00:00:00:04:01"},
    0: {"name": "h2", "ip": "10.0.1.1/24", "mac": "02:00:00:00:01:01"},
    1: {"name": "h3", "ip": "10.0.2.1/24", "mac": "02:00:00:00:02:01"},
    2: {"name": "h4", "ip": "10.0.3.1/24", "mac": "02:00:00:00:03:01"},
}
DEFAULT_LABEL_MAP = {"emule": 0, "utorrent": 1, "vuze": 2}
SOURCE_RE = re.compile(
    r"(TCP|UDP)_([0-9-]+)_(\d+)_([0-9-]+)_(\d+)",
    re.IGNORECASE,
)


def parse_label_map(raw: Optional[str]) -> Dict[str, int]:
    if not raw:
        return dict(DEFAULT_LABEL_MAP)
    parsed = json.loads(raw)
    label_map = {}
    for key, value in parsed.items():
        label_map[str(key)] = int(value)
    return label_map


def parse_source_metadata(source: str) -> Dict[str, object]:
    match = SOURCE_RE.search(source)
    if not match:
        raise ValueError(f"Could not parse source metadata from {source!r}")
    transport, src_ip, src_port, dst_ip, dst_port = match.groups()
    return {
        "transport": transport.upper(),
        "src_ip": src_ip.replace("-", "."),
        "dst_ip": dst_ip.replace("-", "."),
        "src_port": int(src_port),
        "dst_port": int(dst_port),
    }


def build_payload_bytes(
    payload_sequences: Sequence[Sequence[int]],
    packet_index: int,
    payload_len: int,
) -> bytes:
    if payload_len <= 0:
        return b""

    seed = []
    for row in payload_sequences:
        if packet_index < len(row):
            seed.append(int(row[packet_index]) & 0xFF)

    if not seed:
        seed = [0]

    repeated = (seed * ((payload_len + len(seed) - 1) // len(seed)))[:payload_len]
    return bytes(repeated)


def load_records(
    json_path: str,
    start_index: int = 0,
    count: Optional[int] = None,
) -> List[dict]:
    with open(json_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if start_index < 0:
        raise ValueError("start_index must be >= 0")
    if count is None:
        return data[start_index:]
    return data[start_index : start_index + count]


def compute_percentiles(values_ms: Sequence[float], percentiles: Iterable[int]) -> Dict[str, float]:
    results: Dict[str, float] = {}
    if not values_ms:
        for percentile in percentiles:
            results[f"p{percentile}_ms"] = 0.0
        return results

    sorted_values = sorted(values_ms)
    last_index = len(sorted_values) - 1
    for percentile in percentiles:
        rank = (percentile / 100.0) * last_index
        lower = math.floor(rank)
        upper = math.ceil(rank)
        if lower == upper:
            value = sorted_values[lower]
        else:
            ratio = rank - lower
            value = sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * ratio
        results[f"p{percentile}_ms"] = float(value)
    return results


def summarize_latencies(latencies_ms: Sequence[float]) -> Dict[str, float]:
    if not latencies_ms:
        return {
            "mean_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
        }
    summary = {
        "mean_ms": float(mean(latencies_ms)),
        "min_ms": float(min(latencies_ms)),
        "max_ms": float(max(latencies_ms)),
    }
    summary.update(compute_percentiles(latencies_ms, (50, 95, 99)))
    return summary


def label_counts(records: Sequence[dict], label_map: Dict[str, int]) -> Counter:
    counts: Counter = Counter()
    for record in records:
        label = record.get("label")
        expected_class = label_map.get(label)
        if expected_class is not None:
            counts[expected_class] += int(record.get("packet_num", 0))
    return counts


def format_rate(bits_per_second: float) -> str:
    units = ["bps", "Kbps", "Mbps", "Gbps"]
    value = float(bits_per_second)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if abs(value) < 1000.0 or candidate == units[-1]:
            break
        value /= 1000.0
    return f"{value:.2f} {unit}"


def format_summary_lines(summary: Dict[str, object]) -> List[str]:
    lines = []
    lines.append("=== PeerRush BMv2 Classification Benchmark ===")
    lines.append(f"Total runtime: {summary['runtime_seconds']:.3f} s")
    lines.append(f"Total packets sent: {summary['total_packets_sent']}")
    lines.append(f"Total packets received: {summary['total_packets_received']}")
    lines.append(f"Total packets dropped: {summary['drop_count']}")
    lines.append(f"Drop rate: {summary['drop_rate']:.4%}")
    lines.append(f"Classification accuracy: {summary['classification_accuracy']:.4%}")
    lines.append(
        f"Aggregate throughput: {format_rate(summary['aggregate_throughput_bps'])}"
    )

    latency = summary["latency_summary"]
    lines.append(
        "Latency ms: "
        f"mean={latency['mean_ms']:.3f} "
        f"min={latency['min_ms']:.3f} "
        f"max={latency['max_ms']:.3f} "
        f"p50={latency['p50_ms']:.3f} "
        f"p95={latency['p95_ms']:.3f} "
        f"p99={latency['p99_ms']:.3f}"
    )

    lines.append("Per-class accuracy:")
    for class_id, accuracy in sorted(summary["per_class_accuracy"].items()):
        lines.append(f"  class {class_id}: {accuracy:.4%}")

    lines.append("Per-receiver throughput and mean latency:")
    for receiver_id, stats in sorted(summary["per_receiver"].items()):
        lines.append(
            f"  h{receiver_id + 2}/class {receiver_id}: "
            f"throughput={format_rate(stats['throughput_bps'])} "
            f"mean_latency={stats['mean_latency_ms']:.3f} ms "
            f"packets={stats['packets_received']}"
        )
    return lines


def write_json(path: str, payload: Dict[str, object]) -> None:
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
