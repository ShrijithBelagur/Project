#!/usr/bin/env python3
"""Receiver-side aggregate metrics collector for benchmark packets."""

from __future__ import annotations

import argparse
import json
import signal
import time
from typing import Dict, List, Set

from scapy.all import TCP, sniff  # type: ignore

from benchmark_common import write_json


class ReceiverAggregator:
    def __init__(self, receiver_class: int) -> None:
        self.receiver_class = receiver_class
        self.start_ns = time.time_ns()
        self.stop_requested = False
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_ids: Set[int] = set()
        self.received_packets: List[Dict[str, int]] = []

    def handle_packet(self, packet) -> None:
        if TCP not in packet:
            return
        packet_id = int(packet[TCP].seq)
        if packet_id in self.packet_ids:
            return
        self.packet_ids.add(packet_id)

        recv_time_ns = time.time_ns()
        self.total_packets += 1
        self.total_bytes += len(bytes(packet))
        self.received_packets.append({
            "packet_id": packet_id,
            "receiver_class": self.receiver_class,
            "recv_time_ns": recv_time_ns,
            "packet_bytes": len(bytes(packet)),
        })

    def request_stop(self, *_args) -> None:
        self.stop_requested = True

    def summary(self) -> Dict[str, object]:
        runtime_seconds = max((time.time_ns() - self.start_ns) / 1_000_000_000.0, 1e-9)
        return {
            "receiver_class": self.receiver_class,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "runtime_seconds": runtime_seconds,
            "received_packets": self.received_packets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--receiver-class", type=int, required=True)
    parser.add_argument("--summary-path", required=True)
    args = parser.parse_args()

    aggregator = ReceiverAggregator(receiver_class=args.receiver_class)
    signal.signal(signal.SIGINT, aggregator.request_stop)
    signal.signal(signal.SIGTERM, aggregator.request_stop)

    while not aggregator.stop_requested:
        sniff(
            iface=args.interface,
            prn=aggregator.handle_packet,
            store=False,
            timeout=1,
        )

    summary = aggregator.summary()
    write_json(args.summary_path, summary)
    printable = dict(summary)
    printable["received_packets"] = f"{len(summary['received_packets'])} packet rows"
    print(json.dumps(printable, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
