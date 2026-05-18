#!/usr/bin/env python3
"""Launch a BMv2 Mininet topology and run the PeerRush benchmark."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, TextIO

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host, Switch
from mininet.topo import Topo

from benchmark_common import (
    DEFAULT_HOST_CONFIG,
    format_summary_lines,
    parse_label_map,
    summarize_latencies,
)

RECEIVER_LOG_TEMPLATE = "/tmp/{host}-receiver.log"
SENDER_LOG_TEMPLATE = "/tmp/{host}-sender.log"
CONTROL_PLANE_LOG = "/tmp/control-plane-loader.log"


class Bmv2Switch(Switch):
    device_id = 0

    def __init__(
        self,
        name: str,
        sw_path: str,
        json_path: str,
        thrift_port: int = 9090,
        log_console: bool = False,
        **kwargs,
    ) -> None:
        Switch.__init__(self, name, **kwargs)
        self.sw_path = sw_path
        self.json_path = json_path
        self.thrift_port = thrift_port
        self.log_console = log_console
        self.logfile = f"/tmp/{name}-bmv2.log"

    def start(self, _controllers) -> None:
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.name or intf.name == "lo":
                continue
            args.extend(["-i", f"{port}@{intf.name}"])

        args.extend(
            [
                "--device-id",
                str(self.device_id),
                "--thrift-port",
                str(self.thrift_port),
            ]
        )
        if self.log_console:
            args.append("--log-console")
        args.append(self.json_path)

        command = " ".join(shlex.quote(arg) for arg in args) + f" > {self.logfile} 2>&1 & echo $!"
        self.cmd(command)
        time.sleep(1)

    def stop(self, deleteIntfs: bool = True) -> None:
        self.cmd(f"pkill -f {shlex.quote(self.sw_path)}")
        Switch.stop(self, deleteIntfs)


class BenchmarkTopo(Topo):
    def build(self, sw_path: str, json_path: str, thrift_port: int) -> None:
        switch = self.addSwitch(
            "s1",
            cls=Bmv2Switch,
            sw_path=sw_path,
            json_path=json_path,
            thrift_port=thrift_port,
        )

        sender = self.addHost(
            DEFAULT_HOST_CONFIG["sender"]["name"],
            ip=DEFAULT_HOST_CONFIG["sender"]["ip"],
            mac=DEFAULT_HOST_CONFIG["sender"]["mac"],
        )
        receiver_1 = self.addHost(
            DEFAULT_HOST_CONFIG[0]["name"],
            ip=DEFAULT_HOST_CONFIG[0]["ip"],
            mac=DEFAULT_HOST_CONFIG[0]["mac"],
        )
        receiver_2 = self.addHost(
            DEFAULT_HOST_CONFIG[1]["name"],
            ip=DEFAULT_HOST_CONFIG[1]["ip"],
            mac=DEFAULT_HOST_CONFIG[1]["mac"],
        )
        receiver_3 = self.addHost(
            DEFAULT_HOST_CONFIG[2]["name"],
            ip=DEFAULT_HOST_CONFIG[2]["ip"],
            mac=DEFAULT_HOST_CONFIG[2]["mac"],
        )

        self.addLink(receiver_1, switch, port2=1)
        self.addLink(receiver_2, switch, port2=2)
        self.addLink(receiver_3, switch, port2=3)
        self.addLink(sender, switch, port2=4)


def host_ifname(host: Host) -> str:
    interfaces = [intf.name for intf in host.intfList() if intf.name != "lo"]
    if len(interfaces) != 1:
        raise RuntimeError(f"Expected one interface for {host.name}, found {interfaces}")
    return interfaces[0]


def disable_offloads(host: Host) -> None:
    intf = host_ifname(host)
    for feature in ("rx", "tx", "sg"):
        host.cmd(f"ethtool --offload {intf} {feature} off")


def compile_p4(p4_src: str, output_json: str, p4c_bin: str) -> None:
    cmd = [p4c_bin, "--target", "bmv2", "--arch", "v1model", "-o", output_json, p4_src]
    subprocess.check_call(cmd)


def wait_for_thrift(port: int, timeout_seconds: float = 10.0) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            sock.connect(("127.0.0.1", port))
            sock.close()
            return
        except OSError:
            sock.close()
            time.sleep(0.2)
    raise RuntimeError(f"thrift port {port} not ready within {timeout_seconds}s")


def load_control_plane(
    loader_script: str | None,
    control_plane_type: str,
    model_path: str | None,
    bmv2_json: str,
    thrift_port: int,
    cli_bin: str,
) -> str | None:
    if control_plane_type == "none":
        return None
    if not loader_script:
        raise RuntimeError("--control-plane-loader is required when control plane is enabled")
    if not model_path:
        raise RuntimeError("--model-path is required when control plane is enabled")

    command = [
        "python3",
        loader_script,
        "--model",
        model_path,
        "--thrift-port",
        str(thrift_port),
        "--cli-bin",
        cli_bin,
    ]
    if control_plane_type in ("bnn", "linear"):
        command.extend(["--bmv2-json", bmv2_json])

    with open(CONTROL_PLANE_LOG, "w", encoding="utf-8") as log_handle:
        print("[benchmark] loading control plane:", " ".join(shlex.quote(arg) for arg in command), flush=True)
        proc = subprocess.run(command, stdout=log_handle, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"control-plane loader exited with status {proc.returncode}")
    return CONTROL_PLANE_LOG


def start_receiver(
    host: Host,
    receiver_class: int,
    summary_path: str,
    project_dir: str,
) -> tuple[subprocess.Popen, str, TextIO]:
    interface = host_ifname(host)
    log_path = RECEIVER_LOG_TEMPLATE.format(host=host.name)
    log_handle = open(log_path, "w", encoding="utf-8")
    process = host.popen(
        [
            "python3",
            os.path.join(project_dir, "packet_receiver.py"),
            "--interface",
            interface,
            "--receiver-class",
            str(receiver_class),
            "--summary-path",
            summary_path,
        ],
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    return process, log_path, log_handle


def stop_receivers(receivers: List[tuple[subprocess.Popen, str, TextIO]]) -> None:
    for process, _log_path, _log_handle in receivers:
        if process.poll() is None:
            process.terminate()
    for process, _log_path, _log_handle in receivers:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    for _process, _log_path, log_handle in receivers:
        log_handle.close()


def run_sender(
    host: Host,
    json_path: str,
    summary_path: str,
    start_index: int,
    count: int | None,
    speedup: float,
    label_map_json: str,
    project_dir: str,
    respect_timing: bool,
    max_frame_size: int,
) -> tuple[subprocess.Popen, str, TextIO]:
    interface = host_ifname(host)
    log_path = SENDER_LOG_TEMPLATE.format(host=host.name)
    log_handle = open(log_path, "w", encoding="utf-8")
    command = [
        "python3",
        os.path.join(project_dir, "packet_sender.py"),
        "--json-path",
        json_path,
        "--interface",
        interface,
        "--summary-path",
        summary_path,
        "--start-index",
        str(start_index),
        "--speedup",
        str(speedup),
        "--label-map",
        label_map_json,
        "--max-frame-size",
        str(max_frame_size),
    ]
    if count is not None:
        command.extend(["--count", str(count)])
    if not respect_timing:
        command.append("--no-timing")
    process = host.popen(
        command,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    return process, log_path, log_handle


def read_json(path: str) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def wait_for_file(path: str, timeout_seconds: float) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return True
        time.sleep(0.25)
    return os.path.exists(path) and os.path.getsize(path) > 0


def read_tail(path: str, max_lines: int = 80) -> str:
    if not os.path.exists(path):
        return f"[missing file] {path}"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError as exc:
        return f"[failed to read {path}: {exc}]"
    return "".join(lines[-max_lines:]).strip() or f"[empty file] {path}"


def wait_for_process_with_progress(
    process: subprocess.Popen,
    log_path: str,
    progress_prefix: str,
    poll_seconds: float = 5.0,
) -> int:
    last_snapshot = ""
    while True:
        return_code = process.poll()
        snapshot = read_tail(log_path, max_lines=3)
        if snapshot and snapshot != last_snapshot:
            last_line = snapshot.splitlines()[-1]
            print(f"{progress_prefix} {last_line}", flush=True)
            last_snapshot = snapshot
        if return_code is not None:
            return return_code
        time.sleep(poll_seconds)


def fail_with_logs(message: str, log_paths: Dict[str, str]) -> None:
    parts = [message]
    for label, path in log_paths.items():
        parts.append(f"\n--- {label}: {path} ---")
        parts.append(read_tail(path))
    raise RuntimeError("\n".join(parts))


def aggregate_summary(
    sender_summary: Dict[str, object],
    receiver_summaries: List[Dict[str, object]],
    label_map: Dict[str, int],
) -> Dict[str, object]:
    sent_by_class = {int(key): int(value) for key, value in sender_summary["sent_by_class"].items()}
    total_packets_sent = int(sender_summary["total_packets_sent"])
    runtime_seconds = max(
        [float(sender_summary["runtime_seconds"])]
        + [float(item["runtime_seconds"]) for item in receiver_summaries]
    )

    sent_packets = {
        int(row["packet_id"]): row
        for row in sender_summary.get("sent_packets", [])
    }
    confusion = {cls: {pred: 0 for pred in (0, 1, 2)} for cls in (0, 1, 2)}
    aggregate_latencies: List[float] = []
    per_receiver = {}
    correct = 0
    matched_packet_ids = set()
    total_bytes_received = 0

    for receiver_summary in receiver_summaries:
        receiver_class = int(receiver_summary["receiver_class"])
        received_packets = receiver_summary.get("received_packets", [])
        receiver_latencies: List[float] = []
        receiver_bytes = 0
        receiver_matched = 0
        for packet in received_packets:
            packet_id = int(packet["packet_id"])
            if packet_id in matched_packet_ids:
                continue
            sent_packet = sent_packets.get(packet_id)
            if not sent_packet:
                continue
            matched_packet_ids.add(packet_id)
            expected_class = int(sent_packet["expected_class"])
            actual_class = int(packet["receiver_class"])
            latency_ms = max(0.0, (int(packet["recv_time_ns"]) - int(sent_packet["send_time_ns"])) / 1_000_000.0)
            packet_bytes = int(packet["packet_bytes"])
            confusion[expected_class][actual_class] += 1
            if expected_class == actual_class:
                correct += 1
            aggregate_latencies.append(latency_ms)
            receiver_latencies.append(latency_ms)
            receiver_bytes += packet_bytes
            total_bytes_received += packet_bytes
            receiver_matched += 1
        latency_summary = summarize_latencies(receiver_latencies)
        per_receiver[receiver_class] = {
            "packets_received": receiver_matched,
            "throughput_bps": (
                (receiver_bytes * 8.0)
                / max(float(receiver_summary["runtime_seconds"]), 1e-9)
            ),
            "mean_latency_ms": float(latency_summary["mean_ms"]),
        }

    total_packets_received = len(matched_packet_ids)
    drop_count = max(0, total_packets_sent - total_packets_received)
    per_class_accuracy = {}
    for class_id in (0, 1, 2):
        sent = sent_by_class.get(class_id, 0)
        correct_count = confusion[class_id][class_id]
        per_class_accuracy[class_id] = (correct_count / sent) if sent else 0.0

    aggregate_throughput_bps = (
        total_bytes_received * 8.0
    ) / max(runtime_seconds, 1e-9)

    return {
        "runtime_seconds": runtime_seconds,
        "total_packets_sent": total_packets_sent,
        "total_packets_received": total_packets_received,
        "drop_count": drop_count,
        "drop_rate": (drop_count / total_packets_sent) if total_packets_sent else 0.0,
        "classification_accuracy": (correct / total_packets_sent) if total_packets_sent else 0.0,
        "per_class_accuracy": per_class_accuracy,
        "aggregate_throughput_bps": aggregate_throughput_bps,
        "latency_summary": summarize_latencies(aggregate_latencies),
        "per_receiver": per_receiver,
        "sender_skipped_by_reason": sender_summary.get("skipped_by_reason", {}),
        "confusion_matrix": confusion,
        "label_map": label_map,
    }


def ensure_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("This script must be run with sudo/root inside the P4 VM.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bmv2-json", required=True, help="Path to compiled BMv2 JSON")
    parser.add_argument("--p4-src", help="Optional P4 source to compile before launch")
    parser.add_argument("--p4c-bin", default="p4c-bm2-ss")
    parser.add_argument("--simple-switch-bin", default="simple_switch")
    parser.add_argument("--json-path", default="PeerRush/redeal_test.json")
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--count", type=int)
    parser.add_argument("--speedup", type=float, default=1.0)
    parser.add_argument("--label-map", default="")
    parser.add_argument("--no-timing", action="store_true")
    parser.add_argument("--max-frame-size", type=int, default=1500)
    parser.add_argument("--thrift-port", type=int, default=9090)
    parser.add_argument("--cli-bin", default="simple_switch_CLI")
    parser.add_argument("--control-plane-type", choices=["none", "bnn", "linear", "custom"], default="none")
    parser.add_argument("--control-plane-loader", default=None)
    parser.add_argument("--model-path", default=None)
    args = parser.parse_args()

    ensure_root()
    setLogLevel("info")

    project_dir = str(Path(__file__).resolve().parent)
    bmv2_json = os.path.abspath(args.bmv2_json)
    if args.p4_src:
        compile_p4(os.path.abspath(args.p4_src), bmv2_json, args.p4c_bin)

    label_map = parse_label_map(args.label_map)

    topo = BenchmarkTopo(sw_path=args.simple_switch_bin, json_path=bmv2_json, thrift_port=args.thrift_port)
    net = Mininet(topo=topo, host=Host, switch=Bmv2Switch, controller=None, autoSetMacs=False)
    temp_dir = tempfile.mkdtemp(prefix="peerrush-benchmark-")

    sender_summary_path = os.path.join(temp_dir, "sender_summary.json")
    receiver_summary_paths = {
        0: os.path.join(temp_dir, "receiver_0_summary.json"),
        1: os.path.join(temp_dir, "receiver_1_summary.json"),
        2: os.path.join(temp_dir, "receiver_2_summary.json"),
    }
    log_paths: Dict[str, str] = {}
    receiver_processes: List[tuple[subprocess.Popen, str, TextIO]] = []
    sender_process: subprocess.Popen | None = None
    sender_log_handle: TextIO | None = None

    try:
        net.start()
        switch = net.get("s1")
        log_paths["switch"] = switch.logfile
        wait_for_thrift(args.thrift_port)
        if args.control_plane_type != "none":
            log_paths["control_plane"] = CONTROL_PLANE_LOG
            try:
                load_control_plane(
                    loader_script=args.control_plane_loader,
                    control_plane_type=args.control_plane_type,
                    model_path=args.model_path,
                    bmv2_json=bmv2_json,
                    thrift_port=args.thrift_port,
                    cli_bin=args.cli_bin,
                )
            except RuntimeError as exc:
                fail_with_logs(str(exc), log_paths)

        h1 = net.get("h1")
        h2 = net.get("h2")
        h3 = net.get("h3")
        h4 = net.get("h4")

        for host in (h1, h2, h3, h4):
            disable_offloads(host)

        receiver_processes = [
            start_receiver(h2, 0, receiver_summary_paths[0], project_dir),
            start_receiver(h3, 1, receiver_summary_paths[1], project_dir),
            start_receiver(h4, 2, receiver_summary_paths[2], project_dir),
        ]
        log_paths["receiver_h2"] = receiver_processes[0][1]
        log_paths["receiver_h3"] = receiver_processes[1][1]
        log_paths["receiver_h4"] = receiver_processes[2][1]
        time.sleep(2)

        sender_process, sender_log_path, sender_log_handle = run_sender(
            host=h1,
            json_path=os.path.abspath(args.json_path),
            summary_path=sender_summary_path,
            start_index=args.start_index,
            count=args.count,
            speedup=args.speedup,
            label_map_json=json.dumps(label_map),
            project_dir=project_dir,
            respect_timing=not args.no_timing,
            max_frame_size=args.max_frame_size,
        )
        log_paths["sender_h1"] = sender_log_path
        print("[benchmark] sender started", flush=True)
        sender_return_code = wait_for_process_with_progress(
            sender_process,
            sender_log_path,
            progress_prefix="[benchmark]",
        )
        sender_log_handle.close()
        if sender_return_code != 0:
            fail_with_logs(f"Sender exited with status {sender_return_code}.", log_paths)
        if not wait_for_file(sender_summary_path, timeout_seconds=5):
            fail_with_logs("Sender summary was not created.", log_paths)

        time.sleep(2)
        stop_receivers(receiver_processes)
        for summary_path in receiver_summary_paths.values():
            if not wait_for_file(summary_path, timeout_seconds=10):
                fail_with_logs("Receiver summary was not created.", log_paths)

        sender_summary = read_json(sender_summary_path)
        receiver_summaries = [read_json(receiver_summary_paths[idx]) for idx in (0, 1, 2)]
        summary = aggregate_summary(sender_summary, receiver_summaries, label_map)
        print("\n".join(format_summary_lines(summary)))
    finally:
        try:
            if sender_process is not None and sender_process.poll() is None:
                sender_process.terminate()
                sender_process.wait(timeout=5)
            if sender_log_handle is not None and not sender_log_handle.closed:
                sender_log_handle.close()
            if receiver_processes:
                stop_receivers(receiver_processes)
        except Exception:
            pass
        try:
            net.stop()
        except Exception:
            pass
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
