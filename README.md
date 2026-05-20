# Machine Learning Inference in the Programmable Data Plane

This repository contains the source code and scripts for PeerRush traffic classification in
BMv2/Mininet using P4.
The benchmark topology uses one switch and four hosts:

- `h1`: sender
- `h2`: class 0 sink, `emule`
- `h3`: class 1 sink, `utorrent`
- `h4`: class 2 sink, `vuze`


## Environment

Run the P4 benchmarks inside the P4 VM [link](https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md) with:

- Python 3
- Scapy available to root/Mininet host commands
- BMv2 `simple_switch`
- `simple_switch_CLI`
- `p4c-bm2-ss`
- Mininet
- scikit-learn

The Python training/evaluation scripts use `numpy` and `pandas`.

## Dataset

The PeerRush dataset is not committed to git (the replay JSONs are too large
for GitHub's 100 MB limit). Download it from
[this Google Drive link](https://drive.google.com/file/d/1JY_UcLr_ZrIfzYLEmCVPn3LMza_b_bhH/view)
and place the `.csv` and `.json` files in `PeerRush/`. See
[`PeerRush/README.md`](PeerRush/README.md). The training/evaluation
scripts expect:

- `PeerRush/PeerRush_train.csv`
- `PeerRush/PeerRush_test.csv`
- `PeerRush/redeal_train.json`
- `PeerRush/redeal_test.json`

## Generate Python Baselines and Model Files

From the repository root:

```bash
cd Project

cd tree_p4
python3 scripts/train_peerrush_decision_tree.py
python3 scripts/dt_to_p4_generator.py
cd ..

cd linear_p4
python3 scripts/train_linear.py --count 500 --speedup 1000
cd ..

cd bnn_p4
python3 scripts/train_bnn.py --count 500 --speedup 1000
cd ..
```

`dt_to_p4_generator.py` reads from `tree_p4/generated/` and writes the P4
program to `tree_p4/p4_generated/`. Override with `--model`, `--bindings`,
`--out-json`, `--out-p4` if needed.

Expected outputs:

- `tree_p4/generated/peerrush_model.joblib`
- `tree_p4/generated/peerrush_bindings.json`
- `tree_p4/generated/tree.json`
- `tree_p4/p4_generated/generated_tree.p4`
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
- Python/sklearn test accuracy: about `86.007%` accuracy on 300 replay records.


## Run P4 Benchmarks

The benchmark compiles the P4 program, starts Mininet/BMv2, starts receivers,
loads runtime model parameters when needed, sends PeerRush replay packets from
`h1`, and reports accuracy, throughput, drop rate, and latency.

Decision tree, 300-record replay, no speedup:

```bash
cd Project
sudo bash run_benchmark.sh --count 300 tree_p4/p4_generated/generated_tree.p4 PeerRush/redeal_test.json
```

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

- Decision-tree 300-record replay with normal timing: about 15-20 minutes
  (`1000.732 s` in the recorded run).
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
- The generated decision-tree P4 program has all split thresholds and leaf
  predictions in source code and does not require runtime model loading.
- The constrained linear P4 program has its shift/add coefficients in source
  and does not require runtime model loading.

Expected decision-tree benchmark summary for the recorded 300-record run:

- `300` records replayed as `11,957` packets.
- `82.9807%` classification accuracy.
- `2.0072%` drop rate.
- `53.94 Kbps` aggregate throughput.
- `15.755 ms` mean latency.
- Per-class accuracy: class 0 `73.7981%`, class 1 `96.7475%`, class 2 `61.7712%`.

Expected linear results for the recorded 500-record runs:

- Python replay baseline: `19,068` packets, `54.3476%` accuracy,
  `49.5886%` macro-F1.
- Relaxed BMv2, no speedup: `43.0302%` accuracy, `2.1240%` drop rate,
  `49.16 Kbps` throughput, `22.871 ms` mean latency, `1750.254 s` runtime.
- Relaxed BMv2, 1000x speedup: `42.9358%` accuracy, `2.1135%` drop rate,
  `140.21 Kbps` throughput, `24.021 ms` mean latency, `613.100 s` runtime.
- Constrained P4, 1000x speedup: `39.7944%` accuracy, `2.0820%` drop rate,
  `151.07 Kbps` throughput, `21.262 ms` mean latency.
- Per-class accuracy, relaxed BMv2 1000x: class 0 `32.8536%`,
  class 1 `60.8341%`, class 2 `28.9383%`.
- Per-class accuracy, constrained P4 1000x: class 0 `24.7025%`,
  class 1 `77.5698%`, class 2 `0.0000%`.

Expected BNN results for the recorded 500-record runs:

- Python replay baseline: `19,068` packets, `37.8960%` accuracy,
  `18.3210%` macro-F1.
- Constrained P4, 1000x speedup: `38.5620%` accuracy, `1.7359%` drop rate,
  `181.81 Kbps` throughput, `23.098 ms` mean latency.
- BMv2-relaxed P4, 1000x speedup: `38.5410%` accuracy, `1.6834%` drop rate,
  `188.13 Kbps` throughput, `21.490 ms` mean latency.
- Per-class accuracy, constrained P4: class 0 `0.0000%`,
  class 1 `98.2390%`, class 2 `0.0000%`.
- Per-class accuracy, BMv2-relaxed P4: class 0 `0.0000%`,
  class 1 `98.2355%`, class 2 `0.0000%`.

## Latency baseline comparison

`simple_p4/p4/simple_forward.p4` is a minimal "null classifier" pipeline.

The metric of interest here is **per-packet latency**, not throughput.

Run the baseline and each classifier pipeline **without `--no-timing` and
without `--speedup`** — i.e. natural trace pacing.

We baseline the pipelines for 30 records which contain a total of 642 packets.
```bash
# Baseline: minimal-work pipeline
sudo bash run_benchmark.sh --count 30 simple_p4/p4/simple_forward.p4

# Classifier pipelines (same --count across all, natural pacing)
sudo bash run_benchmark.sh --count 30 tree_p4/p4_generated/generated_tree.p4
sudo bash run_benchmark.sh --count 30 linear_p4/p4/linear_bmv2_relaxed.p4
sudo bash run_benchmark.sh --count 30 linear_p4/p4/linear_realswitch_constrained.p4
sudo bash run_benchmark.sh --count 30 bnn_p4/p4/peerrush_bnn_bmv2_relaxed.p4
sudo bash run_benchmark.sh --count 30 bnn_p4/p4/peerrush_bnn_constrained.p4
```

Expect roughly 2 minutes for the each 30-record run at
natural pacing.

### Recorded latency results (30 records, 652 packets sent, natural pacing)

All values in milliseconds. `Δ mean` is mean latency minus the simple_p4
baseline mean. `Drop` is the drop rate during the run.

| Pipeline | mean | min | max | p50 | p95 | p99 | Δ mean | Drop |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `simple_p4/simple_forward.p4` (baseline) | 19.915 | 3.349 | 276.188 | 12.362 | 71.330 | 103.374 | — | 4.29% |
| `linear_p4/linear_bmv2_relaxed.p4` | 30.762 | 5.577 | 1408.229 | 16.483 | 87.063 | 184.930 | +10.847 | 4.14% |
| `linear_p4/linear_realswitch_constrained.p4` | 21.318 | 5.634 | 568.899 | 13.738 | 67.752 | 104.834 | +1.403 | 2.45% |
| `tree_p4/generated_tree.p4` | 27.136 | 4.126 | 2017.625 | 14.607 | 76.186 | 134.932 | +7.221 | 2.91% |
| `bnn_p4/peerrush_bnn_bmv2_relaxed.p4` | 20.982 | 6.880 | 267.298 | 15.067 | 60.602 | 96.925 | +1.067 | 1.84% |
| `bnn_p4/peerrush_bnn_constrained.p4` | 24.479 | 7.833 | 223.404 | 17.726 | 71.329 | 122.615 | +4.564 | 3.83% |

Caveats:

- BMv2 is a software simulator. Absolute latency numbers reflect BMv2-on-your-VM
  per-packet cost, not real hardware switch latency.

## Planter comparison
https://github.com/In-Network-Machine-Learning/Planter/

We compare Planter's decision tree model with the decision tree model implemented in this project.

For a direct comparison against the [Planter](Planter/) in-network ML
framework on the same PeerRush dataset, see [PlanterRun.md](PlanterRun.md).
It documents the patches we applied to make Planter run on our P4 dev
VM (Python 3.12), the PeerRush dataset plugin we added, the 5-feature
header-only configuration we use for a fair benchmark, and step-by-step
instructions for launching and running Planter for a comparison.

- The expected runtime is 15-30 minutes for the specifications provided in the PlanterRun.md file.

## Pegasus Run (For fun)
https://github.com/afireswallow/Pegasus

The [Pegasus](Pegasus/) directory contains the code from its repository with our patches.

For step-by - step instructions on running Pegasus on the P4 dev VM - see [PegasusRun.md](PegasusRun.md).

## Notes

The report PDF discusses the scientific setup, model design, results, and
interpretation.
