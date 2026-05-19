# Machine Learning Inference in the Programmable Data Plane

This repository contains the source code and scripts for PeerRush traffic classification in
BMv2/Mininet using P4.
The benchmark topology uses one switch and four hosts:

- `h1`: sender
- `h2`: class 0 sink, `emule`
- `h3`: class 1 sink, `utorrent`
- `h4`: class 2 sink, `vuze`


## Environment

Run the P4 benchmarks inside the P4 VM (download from p4lang github) with:

- Python 3
- Scapy available to root/Mininet host commands
- BMv2 `simple_switch`
- `simple_switch_CLI`
- `p4c-bm2-ss`
- Mininet

The Python training/evaluation scripts use `numpy` and `pandas`.

## Generate Python Baselines and Model Files

From the repository root:

```bash
cd Project

cd linear_p4
python3 scripts/train_linear.py --count 500 --speedup 1000
cd ..

cd bnn_p4
python3 scripts/train_bnn.py --count 500 --speedup 1000
cd ..
```

Expected outputs:

- `linear_p4/generated/linear_model.json`
- `linear_p4/generated/linear_python_metrics.json`
- `linear_p4/generated/linear_python_metrics.md`
- `bnn_p4/generated/model.json`
- `bnn_p4/generated/python_metrics.json`
- `bnn_p4/generated/python_metrics.md`

Expected runtime: about 1 minute for the linear script and about 1-2 minutes for
the BNN script on the P4 VM, depending on CPU speed.

Expected current baseline highlights:

- Linear replay Python baseline: about `54.35%` accuracy on 500 replay records.
- BNN replay Python baseline: about `37.90%` accuracy on 500 replay records.

## Run P4 Benchmarks

The benchmark compiles the P4 program, starts Mininet/BMv2, starts receivers,
loads runtime model parameters when needed, sends PeerRush replay packets from
`h1`, and reports accuracy, throughput, drop rate, and latency.

Linear relaxed, no speedup:

```bash
cd Project
sudo bash run_benchmark.sh --count 500 \
  linear_p4/p4/linear_bmv2_relaxed.p4
```

Linear relaxed, 1000x speedup:

```bash
cd Project
sudo bash run_benchmark.sh --count 500 --speedup 1000 \
  linear_p4/p4/linear_bmv2_relaxed.p4
```

Linear constrained, 1000x speedup:

```bash
cd Project
sudo bash run_benchmark.sh --count 500 --speedup 1000 \
  linear_p4/p4/linear_realswitch_constrained.p4
```

BNN constrained, 1000x speedup:

```bash
cd Project
sudo bash run_benchmark.sh --count 500 --speedup 1000 \
  bnn_p4/p4/peerrush_bnn_constrained.p4
```

BNN BMv2-relaxed, 1000x speedup:

```bash
cd Project
sudo bash run_benchmark.sh --count 500 --speedup 1000 \
  bnn_p4/p4/peerrush_bnn_bmv2_relaxed.p4
```

Expected runtime:

- No-speedup 500-record replay: roughly 17-25 minutes.
- 1000x speedup 500-record replay: roughly 8-12 minutes per P4 run.

Expected outputs:

- BMv2 JSON build output under `build/`.
- Sender, receiver, control-plane, and switch logs under the generated/log
  paths printed by the benchmark.
- Terminal summary with packets sent/received, packet loss, throughput, latency,
  classification accuracy, and per-class behavior.

For runtime-programmable models, `run_benchmark.sh` automatically chooses the
control-plane loader:

- `linear_bmv2_relaxed.p4` loads `linear_p4/generated/linear_model.json`.
- BNN P4 files load `bnn_p4/generated/model.json`.
- The constrained linear P4 program has its shift/add coefficients in source
  and does not require runtime model loading.

## Notes

The report PDF discusses the scientific setup, model design, results, and
interpretation.
