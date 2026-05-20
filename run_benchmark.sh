#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_SCRIPTS_DIR="${SCRIPT_DIR}/test_scripts"
DEFAULT_P4_SRC="${SCRIPT_DIR}/bnn_p4/p4/peerrush_bnn_constrained.p4"
DEFAULT_DATASET="${SCRIPT_DIR}/PeerRush/redeal_test.json"
BUILD_DIR="${SCRIPT_DIR}/build"
BMV2_JSON="${BUILD_DIR}/classifier.json"

P4_SRC="$DEFAULT_P4_SRC"
DATASET_PATH="$DEFAULT_DATASET"
SPEEDUP="${SPEEDUP:-1.0}"
START_INDEX="${START_INDEX:-0}"
COUNT="${COUNT:-}"
NO_TIMING=0
MAX_FRAME_SIZE="${MAX_FRAME_SIZE:-1500}"
P4C_BIN="${P4C_BIN:-p4c-bm2-ss}"
SIMPLE_SWITCH_BIN="${SIMPLE_SWITCH_BIN:-simple_switch}"
THRIFT_PORT="${THRIFT_PORT:-9090}"
CLI_BIN="${CLI_BIN:-simple_switch_CLI}"
LABEL_MAP="${LABEL_MAP:-}"
CONTROL_PLANE="${CONTROL_PLANE:-auto}"
MODEL_PATH="${MODEL_PATH:-}"
CONTROL_PLANE_LOADER="${CONTROL_PLANE_LOADER:-}"

run_as_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

usage() {
  cat <<EOF
Usage:
  ./run_benchmark.sh [options] [P4_SOURCE] [DATASET_JSON]

Examples:
  ./run_benchmark.sh
  ./run_benchmark.sh --count 1 --speedup 1000
  ./run_benchmark.sh bnn_p4/p4/peerrush_bnn_bmv2_relaxed.p4
  ./run_benchmark.sh linear_p4/p4/linear_bmv2_relaxed.p4
  ./run_benchmark.sh linear_p4/p4/linear_realswitch_constrained.p4
  ./run_benchmark.sh tree_p4/p4_generated/generated_tree.p4

Options:
  --count N               Limit replay to N records
  --speedup X             Replay timing multiplier
  --start-index N         First JSON record to replay
  --label-map JSON        Override label mapping
  --control-plane MODE    one of auto, none, bnn, linear, custom
  --model-path PATH       Runtime model JSON for BNN/linear/custom loader
  --control-plane-loader PATH
                          Custom loader script, or override inferred loader
  --no-timing             Ignore packet timestamps and send as fast as possible
  --max-frame-size N      Cap transmitted Ethernet frame size in bytes
  -h, --help              Show this help

Optional environment variables:
  P4C_BIN=p4c-bm2-ss      P4 compiler binary
  SIMPLE_SWITCH_BIN=simple_switch
  CLI_BIN=simple_switch_CLI
  THRIFT_PORT=9090
  CONTROL_PLANE=auto
  MODEL_PATH=/path/to/model.json
EOF
}

POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --count)
      COUNT="${2:?missing value for --count}"
      shift 2
      ;;
    --speedup)
      SPEEDUP="${2:?missing value for --speedup}"
      shift 2
      ;;
    --start-index)
      START_INDEX="${2:?missing value for --start-index}"
      shift 2
      ;;
    --label-map)
      LABEL_MAP="${2:?missing value for --label-map}"
      shift 2
      ;;
    --control-plane)
      CONTROL_PLANE="${2:?missing value for --control-plane}"
      shift 2
      ;;
    --model-path)
      MODEL_PATH="${2:?missing value for --model-path}"
      shift 2
      ;;
    --control-plane-loader)
      CONTROL_PLANE_LOADER="${2:?missing value for --control-plane-loader}"
      shift 2
      ;;
    --no-timing)
      NO_TIMING=1
      shift
      ;;
    --max-frame-size)
      MAX_FRAME_SIZE="${2:?missing value for --max-frame-size}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        POSITIONAL_ARGS+=("$1")
        shift
      done
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL_ARGS[@]} -ge 1 ]]; then
  P4_SRC="${POSITIONAL_ARGS[0]}"
fi

if [[ ${#POSITIONAL_ARGS[@]} -ge 2 ]]; then
  DATASET_PATH="${POSITIONAL_ARGS[1]}"
fi

if [[ ${#POSITIONAL_ARGS[@]} -gt 2 ]]; then
  echo "Too many positional arguments." >&2
  usage
  exit 1
fi

if [[ ! -f "$P4_SRC" ]]; then
  echo "P4 source not found: $P4_SRC" >&2
  exit 1
fi

if [[ ! -f "$DATASET_PATH" ]]; then
  echo "Dataset JSON not found: $DATASET_PATH" >&2
  exit 1
fi

if [[ ! -f "${TEST_SCRIPTS_DIR}/mininet_benchmark.py" ]]; then
  echo "Launcher script not found: ${TEST_SCRIPTS_DIR}/mininet_benchmark.py" >&2
  exit 1
fi

case "$CONTROL_PLANE" in
  auto)
    p4_base="$(basename "$P4_SRC")"
    if [[ "$p4_base" == peerrush_bnn_constrained.p4 || "$p4_base" == peerrush_bnn_bmv2_relaxed.p4 ]]; then
      CONTROL_PLANE="bnn"
    elif [[ "$p4_base" == *linear_bmv2_relaxed* ]]; then
      CONTROL_PLANE="linear"
    else
      CONTROL_PLANE="none"
    fi
    ;;
  none|bnn|linear|custom)
    ;;
  *)
    echo "Invalid --control-plane value: $CONTROL_PLANE" >&2
    exit 1
    ;;
esac

if [[ "$CONTROL_PLANE" == "bnn" ]]; then
  CONTROL_PLANE_LOADER="${CONTROL_PLANE_LOADER:-${SCRIPT_DIR}/bnn_p4/scripts/load_model_cli.py}"
  MODEL_PATH="${MODEL_PATH:-${SCRIPT_DIR}/bnn_p4/generated/model.json}"
elif [[ "$CONTROL_PLANE" == "linear" ]]; then
  CONTROL_PLANE_LOADER="${CONTROL_PLANE_LOADER:-${SCRIPT_DIR}/linear_p4/scripts/load_linear_model_cli.py}"
  MODEL_PATH="${MODEL_PATH:-${SCRIPT_DIR}/linear_p4/generated/linear_model.json}"
fi

if [[ "$CONTROL_PLANE" != "none" ]]; then
  if [[ -z "$CONTROL_PLANE_LOADER" ]]; then
    echo "Control-plane loader is required for mode: $CONTROL_PLANE" >&2
    exit 1
  fi
  if [[ -z "$MODEL_PATH" ]]; then
    echo "Model path is required for mode: $CONTROL_PLANE" >&2
    exit 1
  fi
  if [[ ! -f "$CONTROL_PLANE_LOADER" ]]; then
    echo "Control-plane loader not found: $CONTROL_PLANE_LOADER" >&2
    exit 1
  fi
  if [[ ! -f "$MODEL_PATH" ]]; then
    echo "Model JSON not found: $MODEL_PATH" >&2
    exit 1
  fi
fi

mkdir -p "$BUILD_DIR"

cleanup() {
  run_as_root mn -c >/dev/null 2>&1 || true
  run_as_root pkill -f packet_receiver.py >/dev/null 2>&1 || true
  run_as_root pkill -f simple_switch >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "[1/3] Cleaning any stale Mininet state"
cleanup

echo "[2/3] Compiling $(basename "$P4_SRC") -> ${BMV2_JSON}"
"$P4C_BIN" --target bmv2 --arch v1model -o "$BMV2_JSON" "$P4_SRC"

echo "[3/3] Starting BMv2 Mininet benchmark"
CMD=(
  python3 "${TEST_SCRIPTS_DIR}/mininet_benchmark.py"
  --bmv2-json "$BMV2_JSON"
  --json-path "$DATASET_PATH"
  --simple-switch-bin "$SIMPLE_SWITCH_BIN"
  --thrift-port "$THRIFT_PORT"
  --cli-bin "$CLI_BIN"
  --speedup "$SPEEDUP"
  --start-index "$START_INDEX"
  --max-frame-size "$MAX_FRAME_SIZE"
)

if [[ "$CONTROL_PLANE" != "none" ]]; then
  CMD+=(
    --control-plane-type "$CONTROL_PLANE"
    --control-plane-loader "$CONTROL_PLANE_LOADER"
    --model-path "$MODEL_PATH"
  )
fi

if [[ -n "$COUNT" ]]; then
  CMD+=(--count "$COUNT")
fi

if [[ -n "$LABEL_MAP" ]]; then
  CMD+=(--label-map "$LABEL_MAP")
fi

if [[ "$NO_TIMING" -eq 1 ]]; then
  CMD+=(--no-timing)
fi

printf 'Running command:'
for arg in "${CMD[@]}"; do
  printf ' %q' "$arg"
done
printf '\n'

run_as_root "${CMD[@]}"
