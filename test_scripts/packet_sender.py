#!/usr/bin/env python3
"""Replay PeerRush JSON records as packets from a Mininet sender host."""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from typing import Dict, List

from scapy.all import Ether, IP, TCP, Raw, conf, get_if_hwaddr, sendp  # type: ignore

from benchmark_common import (
    build_payload_bytes,
    load_records,
    parse_label_map,
    parse_source_metadata,
    write_json,
)


def compute_payload_length(total_ip_len: int, ip_hl_words: int, tcp_off_words: int) -> int:
    ip_header_len = max(20, ip_hl_words * 4)
    tcp_header_len = max(20, tcp_off_words * 4)
    return max(0, int(total_ip_len) - ip_header_len - tcp_header_len)


def build_packet(
    record: dict,
    packet_index: int,
    packet_id: int,
    sender_mac: str,
    receiver_mac: str,
    expected_class: int,
    max_frame_size: int,
) -> tuple[Ether, bool]:
    source_meta = parse_source_metadata(record["source"])
    ip_hl_words = int(record["ip_hl_seq"][packet_index])
    tcp_off_words = int(record["tcp_off_seq"][packet_index])
    original_total_ip_len = int(record["len_seq"][packet_index])
    payload_len = compute_payload_length(
        original_total_ip_len,
        ip_hl_words,
        tcp_off_words,
    )
    ip_header_len = max(20, ip_hl_words * 4)
    tcp_header_len = max(20, tcp_off_words * 4)
    max_payload_len = max(0, max_frame_size - 14 - ip_header_len - tcp_header_len)

    payload = build_payload_bytes(record["payload_sequences"], packet_index, payload_len)
    actual_payload_len = min(payload_len, max_payload_len)
    payload = payload[:actual_payload_len]
    truncated = actual_payload_len < payload_len
    advertised_total_ip_len = original_total_ip_len

    packet = (
        Ether(src=sender_mac, dst=receiver_mac)
        / IP(
            src=str(source_meta["src_ip"]),
            dst=str(source_meta["dst_ip"]),
            ttl=int(record["ip_ttl_seq"][packet_index]),
            tos=int(record["ip_tos_seq"][packet_index]),
            ihl=ip_hl_words,
            proto=int(record["proto_seq"][packet_index]),
            len=advertised_total_ip_len,
        )
        / TCP(
            sport=int(source_meta["src_port"]),
            dport=int(source_meta["dst_port"]),
            seq=packet_id,
            dataofs=tcp_off_words,
            window=int(record["tcp_win_seq"][packet_index]),
        )
        / Raw(load=payload)
    )
    return packet, truncated


def replay_records(
    interface: str,
    records: List[dict],
    label_map: Dict[str, int],
    speedup: float,
    respect_timing: bool,
    max_frame_size: int,
) -> Dict[str, object]:
    sender_mac = get_if_hwaddr(interface)
    receiver_mac_by_class = {
        0: "02:00:00:00:01:01",  # h2
        1: "02:00:00:00:02:01",  # h3
        2: "02:00:00:00:03:01",  # h4
    }

    sent_by_class: Counter = Counter()
    skipped_by_reason: Counter = Counter()
    sent_packets = []
    truncated_packets = 0
    packet_id = 0
    start_monotonic = time.monotonic()

    conf.iface = interface

    for record_index, record in enumerate(records):
        label = record.get("label")
        expected_class = label_map.get(label)
        if expected_class not in (0, 1, 2):
            skipped_by_reason["unknown_label"] += int(record.get("packet_num", 0))
            continue

        packet_num = int(record.get("packet_num", 0))
        timestamps = record.get("ts_seq", [])
        if len(timestamps) < packet_num:
            skipped_by_reason["bad_timestamp_sequence"] += packet_num
            continue

        for packet_index in range(packet_num):
            if respect_timing and packet_index > 0:
                delta = float(timestamps[packet_index]) - float(timestamps[packet_index - 1])
                if delta > 0:
                    time.sleep(delta / max(speedup, 1e-9))

            try:
                packet, truncated = build_packet(
                    record=record,
                    packet_index=packet_index,
                    packet_id=packet_id,
                    sender_mac=sender_mac,
                    receiver_mac=receiver_mac_by_class[expected_class],
                    expected_class=expected_class,
                    max_frame_size=max_frame_size,
                )
            except Exception:
                skipped_by_reason["packet_build_error"] += 1
                packet_id += 1
                continue

            try:
                send_time_ns = time.time_ns()
                sendp(packet, iface=interface, verbose=False)
            except OSError:
                skipped_by_reason["send_error"] += 1
                packet_id += 1
                continue
            sent_by_class[expected_class] += 1
            sent_packets.append({
                "packet_id": packet_id,
                "expected_class": expected_class,
                "send_time_ns": send_time_ns,
                "packet_bytes": len(bytes(packet)),
                "record_index": record_index,
                "packet_index": packet_index,
            })
            if truncated:
                truncated_packets += 1
            packet_id += 1

        if record_index % 10 == 0 and record_index > 0:
            elapsed = time.monotonic() - start_monotonic
            print(
                f"[sender] replayed {record_index} records / {packet_id} packets in {elapsed:.1f}s",
                flush=True,
            )

    runtime_seconds = time.monotonic() - start_monotonic
    return {
        "sender_interface": interface,
        "runtime_seconds": runtime_seconds,
        "total_packets_sent": int(sum(sent_by_class.values())),
        "sent_by_class": {str(key): int(value) for key, value in sent_by_class.items()},
        "sent_packets": sent_packets,
        "skipped_by_reason": {str(key): int(value) for key, value in skipped_by_reason.items()},
        "truncated_packets": truncated_packets,
        "max_frame_size": max_frame_size,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-path", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--summary-path", required=True)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--count", type=int)
    parser.add_argument("--speedup", type=float, default=1.0)
    parser.add_argument("--label-map", default="")
    parser.add_argument("--no-timing", action="store_true")
    parser.add_argument("--max-frame-size", type=int, default=1500)
    args = parser.parse_args()

    records = load_records(args.json_path, start_index=args.start_index, count=args.count)
    label_map = parse_label_map(args.label_map)
    summary = replay_records(
        interface=args.interface,
        records=records,
        label_map=label_map,
        speedup=args.speedup,
        respect_timing=not args.no_timing,
        max_frame_size=args.max_frame_size,
    )
    write_json(args.summary_path, summary)
    printable = dict(summary)
    printable["sent_packets"] = f"{len(summary['sent_packets'])} packet rows"
    print(json.dumps(printable, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
