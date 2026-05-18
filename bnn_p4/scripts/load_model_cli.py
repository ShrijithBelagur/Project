#!/usr/bin/env python3
"""Load exported hybrid BNN model into BMv2 via simple_switch_CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="generated/model.json")
    parser.add_argument("--bmv2-json", default=None, help="Compiled BMv2 JSON for resolving table/action names.")
    parser.add_argument("--thrift-port", type=int, default=9090)
    parser.add_argument("--cli-bin", default="simple_switch_CLI")
    parser.add_argument("--connect-retries", type=int, default=30, help="CLI connection retry attempts.")
    parser.add_argument("--retry-delay", type=float, default=0.5, help="Delay between CLI connection retries (seconds).")
    parser.add_argument("--write-commands", default=None, help="If set, write CLI commands to this file.")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def encode_w(value: int) -> int:
    # 0 => -1, 1 => 0, 2 => +1
    if value == -1:
        return 0
    if value == 0:
        return 1
    if value == 1:
        return 2
    raise ValueError(f"invalid ternary weight value: {value}")


def choose_name(candidates: list[str], available: set[str], logical_name: str) -> str:
    for name in candidates:
        if name in available:
            return name
    suffix_hits = [name for name in available if name.endswith("." + logical_name)]
    if len(suffix_hits) == 1:
        return suffix_hits[0]
    raise ValueError(
        f"could not resolve '{logical_name}'. candidates={candidates}, "
        f"matches={sorted(suffix_hits)}"
    )


def resolve_cli_names(bmv2_json_path: str | None) -> dict[str, str]:
    # Default assumptions for most generated programs.
    names = {
        "nn_w1_reg": "nn_w1_reg",
        "nn_th1_reg": "nn_th1_reg",
        "nn_b1_reg": "nn_b1_reg",
        "nn_w2_reg": "nn_w2_reg",
        "nn_b2_reg": "nn_b2_reg",
        "class_fwd": "class_fwd",
        "set_class_port": "set_class_port",
    }
    if not bmv2_json_path:
        return names

    data = json.loads(Path(bmv2_json_path).read_text(encoding="utf-8"))
    regs = {row["name"] for row in data.get("register_arrays", [])}
    tables = {row["name"] for row in data.get("tables", [])}
    for pipe in data.get("pipelines", []):
        for table in pipe.get("tables", []):
            if "name" in table:
                tables.add(table["name"])
    actions = {row["name"] for row in data.get("actions", [])}

    names["nn_w1_reg"] = choose_name(["nn_w1_reg", "MyIngress.nn_w1_reg"], regs, "nn_w1_reg")
    names["nn_th1_reg"] = choose_name(["nn_th1_reg", "MyIngress.nn_th1_reg"], regs, "nn_th1_reg")
    names["nn_b1_reg"] = choose_name(["nn_b1_reg", "MyIngress.nn_b1_reg"], regs, "nn_b1_reg")
    names["nn_w2_reg"] = choose_name(["nn_w2_reg", "MyIngress.nn_w2_reg"], regs, "nn_w2_reg")
    names["nn_b2_reg"] = choose_name(["nn_b2_reg", "MyIngress.nn_b2_reg"], regs, "nn_b2_reg")
    names["class_fwd"] = choose_name(["class_fwd", "MyIngress.class_fwd"], tables, "class_fwd")
    names["set_class_port"] = choose_name(["set_class_port", "MyIngress.set_class_port"], actions, "set_class_port")
    return names


def build_commands(model: dict, names: dict[str, str]) -> list[str]:
    cmds: list[str] = []
    required = ["hidden_weights", "hidden_thresholds", "output_weights", "output_biases"]
    missing = [key for key in required if key not in model]
    if missing:
        raise ValueError(
            "model.json is not in hybrid BNN format; missing keys: "
            + ", ".join(missing)
            + ". Regenerate with scripts/train_bnn.py before running VM eval."
        )

    hidden_w = model["hidden_weights"]
    hidden_th = model["hidden_thresholds"]
    hidden_b = model.get("hidden_biases", [0] * len(hidden_th))
    out_w = model["output_weights"]
    out_b = model["output_biases"]

    if len(hidden_w) != 8 or any(len(row) != 10 for row in hidden_w):
        raise ValueError(
            "manual P4 BNN programs are constrained 10x8x3 dataplane models; "
            "hidden_weights must be 8x10. Regenerate the deployable model with "
            "scripts/train_bnn.py."
        )
    if len(out_w) != 3 or any(len(row) != 8 for row in out_w):
        raise ValueError(
            "manual P4 BNN programs are constrained 10x8x3 dataplane models; "
            "output_weights must be 3x8."
        )

    cmds.append(f"register_reset {names['nn_w1_reg']}")
    cmds.append(f"register_reset {names['nn_th1_reg']}")
    cmds.append(f"register_reset {names['nn_b1_reg']}")
    cmds.append(f"register_reset {names['nn_w2_reg']}")
    cmds.append(f"register_reset {names['nn_b2_reg']}")

    for h in range(8):
        for i in range(10):
            idx = h * 10 + i
            cmds.append(f"register_write {names['nn_w1_reg']} {idx} {encode_w(int(hidden_w[h][i]))}")
        cmds.append(f"register_write {names['nn_th1_reg']} {h} {int(hidden_th[h])}")
        cmds.append(f"register_write {names['nn_b1_reg']} {h} {int(hidden_b[h])}")

    for c in range(3):
        for h in range(8):
            idx = c * 8 + h
            cmds.append(f"register_write {names['nn_w2_reg']} {idx} {encode_w(int(out_w[c][h]))}")
        cmds.append(f"register_write {names['nn_b2_reg']} {c} {int(out_b[c])}")

    # runtime forwarding map
    cmds.append(f"table_clear {names['class_fwd']}")
    cmds.append(f"table_add {names['class_fwd']} {names['set_class_port']} 0 => 1")
    cmds.append(f"table_add {names['class_fwd']} {names['set_class_port']} 1 => 2")
    cmds.append(f"table_add {names['class_fwd']} {names['set_class_port']} 2 => 3")
    return cmds


def run_cli(cli_bin: str, thrift_port: int, commands: list[str], connect_retries: int, retry_delay: float) -> None:
    payload = "\n".join(commands) + "\n"
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as tf:
        tf.write(payload)
        tmp = tf.name
    attempts = max(1, int(connect_retries))
    last_proc = None
    for attempt in range(1, attempts + 1):
        with open(tmp, "r", encoding="utf-8") as fh:
            proc = subprocess.run(
                [cli_bin, "--thrift-port", str(thrift_port)],
                stdin=fh,
                capture_output=True,
                text=True,
            )
        last_proc = proc
        if proc.returncode == 0:
            return

        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        is_connect_error = (
            "Could not connect to thrift client" in combined
            or "Could not connect to any of" in combined
            or "Connection refused" in combined
        )
        if is_connect_error and attempt < attempts:
            time.sleep(max(0.0, float(retry_delay)))
            continue
        break

    raise RuntimeError(
        f"{cli_bin} failed with exit code {last_proc.returncode if last_proc else 'unknown'} "
        f"after {attempts} attempts\n"
        f"stdout:\n{(last_proc.stdout if last_proc else '')}\n"
        f"stderr:\n{(last_proc.stderr if last_proc else '')}"
    )


def main() -> None:
    args = parse_args()
    model = json.loads(Path(args.model).read_text(encoding="utf-8"))
    names = resolve_cli_names(args.bmv2_json)
    commands = build_commands(model, names)
    if args.write_commands:
        Path(args.write_commands).write_text("\n".join(commands) + "\n", encoding="utf-8")
        print(f"wrote commands: {args.write_commands}")
    if args.dry_run:
        print("\n".join(commands))
        return
    run_cli(args.cli_bin, args.thrift_port, commands, args.connect_retries, args.retry_delay)
    print(f"loaded model to thrift port {args.thrift_port}")


if __name__ == "__main__":
    main()
