#!/usr/bin/env python3
"""Load exported fixed-point linear model into BMv2 via simple_switch_CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="generated/linear_model.json")
    parser.add_argument("--bmv2-json", default=None, help="Compiled BMv2 JSON for resolving table/action names.")
    parser.add_argument("--thrift-port", type=int, default=9090)
    parser.add_argument("--cli-bin", default="simple_switch_CLI")
    parser.add_argument("--connect-retries", type=int, default=30)
    parser.add_argument("--retry-delay", type=float, default=0.5)
    parser.add_argument("--write-commands", default=None)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


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
    names = {
        "lin_w_reg": "lin_w_reg",
        "lin_b_reg": "lin_b_reg",
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

    names["lin_w_reg"] = choose_name(["lin_w_reg", "MyIngress.lin_w_reg"], regs, "lin_w_reg")
    names["lin_b_reg"] = choose_name(["lin_b_reg", "MyIngress.lin_b_reg"], regs, "lin_b_reg")
    names["class_fwd"] = choose_name(["class_fwd", "MyIngress.class_fwd"], tables, "class_fwd")
    names["set_class_port"] = choose_name(["set_class_port", "MyIngress.set_class_port"], actions, "set_class_port")
    return names


def build_commands(model: dict, names: dict[str, str]) -> list[str]:
    weights = model["weights"]
    biases = model["biases"]

    if len(weights) != 3 or any(len(row) != 10 for row in weights):
        raise ValueError("weights must be 3x10")
    if len(biases) != 3:
        raise ValueError("biases must have length 3")

    cmds: list[str] = []
    cmds.append(f"register_reset {names['lin_w_reg']}")
    cmds.append(f"register_reset {names['lin_b_reg']}")

    for cls in range(3):
        for feat in range(10):
            idx = cls * 10 + feat
            cmds.append(f"register_write {names['lin_w_reg']} {idx} {int(weights[cls][feat])}")
        cmds.append(f"register_write {names['lin_b_reg']} {cls} {int(biases[cls])}")

    cmds.append(f"table_clear {names['class_fwd']}")
    cmds.append(f"table_add {names['class_fwd']} {names['set_class_port']} 0 => 1")
    cmds.append(f"table_add {names['class_fwd']} {names['set_class_port']} 1 => 2")
    cmds.append(f"table_add {names['class_fwd']} {names['set_class_port']} 2 => 3")
    return cmds


def run_cli(cli_bin: str, thrift_port: int, commands: list[str], connect_retries: int, retry_delay: float) -> None:
    payload = "\n".join(commands) + "\n"
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as tf:
        tf.write(payload)
        temp_path = tf.name
    attempts = max(1, int(connect_retries))
    last_proc = None
    for attempt in range(1, attempts + 1):
        with open(temp_path, "r", encoding="utf-8") as fh:
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
    print(f"loaded linear model to thrift port {args.thrift_port}")


if __name__ == "__main__":
    main()
