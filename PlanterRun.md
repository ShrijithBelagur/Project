# Running Planter on PeerRush

This document records the changes made to upstream Planter to run on a modern
P4 dev VM (Python 3.12, externally-managed pip) with the PeerRush P2P
traffic-classification dataset, plus the full step-by-step run instructions.

## Changes made

### 1. PeerRush dataset plugin

- Created `src/load_data/PeerRush_dataset.py` — implements
  `load_data(num_features, data_dir)` returning
  `(X_train, y_train, X_test, y_test, used_features)`.
- The data is read from the Project/PeerRush directory. Ensure to download the files here before running Planter.

The loader exposes 5 header-only PeerRush columns:
`ip_len`, `total_len`, `proto`, `tos`, `tcp_offset`. Stateful features
(`max_ipd`, `min_ipd`, `last_ipd`, `max_packet_len`, `min_packet_len`) are
deliberately not supported — Planter's generated P4 has no flow-table or
register state and cannot evaluate them. The loader raises an error if
`num_features > 5`.

Train data: full `PeerRush_train.csv` (one CSV row = one packet).

Test data: `redeal_test.json`, taking the first N records (flows) starting
from `start_index`, expanded to one row per packet. This matches the
semantics of `run_benchmark.sh --count N --start-index S` in the our Project: records are taken sequentially, no shuffling, so the same N
selects the same test flows across Planter and the Project benchmark results
are comparable.

At runtime the loader prompts:

```
+ How many test records (flows)? 0 = all, max <N> (default = 0)
+ Test start index? (default = 0)
```

The expansion factor is ~40 packets per record (300 records ≈ 11,957 packet
rows on PeerRush).

### 2. Modified Python requirements for Python 3.12

Planter's python requirements file
`src/configs/requirements_pip3.txt` is modified as the original one does not build for python 3.12.

We also adds `multiprocess` (previously only in
the sudo requirements file).

### 3. Use the venv Python under sudo (no `--break-system-packages`)

Planter spawns sub-processes via `sudo python3` to run Mininet/BMv2 as root.
On a venv-based setup, `sudo python3` resolves to the system Python and can't
see venv-installed packages. PEP 668 also blocks `sudo pip3 install` outside
a venv.

Fixed by routing every privileged Python invocation through the venv
interpreter's absolute path (`sys.executable`).

**6 Makefiles** under `src/targets/bmv2/` get two small edits each:

```makefile
PYTHON_BIN ?= python3                                   # added
...
sudo $(PYTHON_BIN) $(RUN_SCRIPT) -t $(TOPO) $(run_args)  # was: sudo python3 ...
```

Files:
- `src/targets/bmv2/software/utils/Makefile`
- `src/targets/bmv2/software/utils/architecture/v1model/Makefile`
- `src/targets/bmv2/software/utils/architecture/psa/Makefile`
- `src/targets/bmv2/compile/utils/Makefile`
- `src/targets/bmv2/compile/utils/architecture/v1model/Makefile`
- `src/targets/bmv2/compile/utils/architecture/psa/Makefile`

**2 `run_model.py` files** patched to embed `sys.executable` in the in-Mininet
test command and pass `PYTHON_BIN=<sys.executable>` to make:

- `src/targets/bmv2/software/run_model.py`
- `src/targets/bmv2/compile/run_model.py`

With these changes, all root-side Python work uses the same venv interpreter as the parent Planter process, so the venv's installed packages are sufficient.
`requirements_sudo_pip3.txt` is no longer needed.

### 4. Matplotlib 3.6+ seaborn-style rename

Matplotlib 3.6 renamed the `seaborn` style to `seaborn-v0_8` (because seaborn
0.12 broke the API). Planter's model `table_generator.py` files use the old
name. Replaced `plt.style.use('seaborn')` with `plt.style.use('seaborn-v0_8')`
in several files under `src/models/.

## Instructions to run

Assuming the p4dev-python-venv is active (from the VM).

### 1. Enter Planter

```bash
cd Planter
```

### 2. Install Python dependencies (venv only — no sudo install)

```bash
pip3 install -r src/configs/requirements_pip3.txt
```

<!-- Verify everything imports:

```bash
python3 -c "import numpy, pandas, sklearn, scipy, scapy; print('ok')"
```

Confirm the venv interpreter is reachable under sudo too:

```bash
sudo /home/p4/src/p4dev-python-venv/bin/python3 -c "import scapy, sklearn; print('ok')"
``` -->

### 3. Dataset requirements.

The loader requires
`PeerRush_train.csv` and `redeal_test.json`. These should be in ../Project/PeerRush directory.

### 4. Launch Planter interactively

```bash
python3 Planter.py -m
```

Answer the prompts as follows:

| # | Prompt | Answer |
|---|---|---|
| 1 | Where is your data folder? | `<REPO_PATH>/Project/` |
| 2 | Where is your Planter folder? | Enter (default `/media/sf_Project/Planter`) |
| 3 | Which model do you want to plant? | `DT` (or `RF`, `XGB`, `SVM`, `NB`) |
| 4 | Which type (variation) of model? | `1` (default) or `EB` |
| 5 | Which dataset? | `PeerRush` |
| 6 | Where is the number of features? | `5` (hard cap; loader rejects higher) |
| 7 | Use the testing mode or not? | `n` |
| 8 | **How many test records (flows)?** | e.g. `300` (matches `run_benchmark.sh --count 300`) or `0` for all |
| 9 | **Test start index?** | `0` (default) |
| 10 | (DT-only) Number of depth? | `5` |
| 11 | (DT-only) Number of leaf nodes? | `1000` |
| 12 | Test the table or not? | `n` |
| 13 | Which architecture do you use? | `v1model` |
| 14 | Which is the use case? | `standard_classification` |
| 15 | Which target? | `bmv2` |
| 16 | Software or compile mode? (if asked) | `software` |
| 17 | Send packets to which port? | Enter (default `eth0`) |
| 18 | Sudo password? | your sudo password |

Prompts 8 and 9 are emitted by the PeerRush loader itself, immediately after
Planter's "testing mode" question. The selection is deterministic: the same
`(start_index, count)` always picks the same flows, matching the project's
`run_benchmark.sh` behavior for decision trees.

Planter then prints three accuracy matrices:

1. **sklearn baseline** — pure-Python model accuracy on the test CSV.
2. **Table-entry replay** — what the generated M/A tables predict in Python (theoretical pipeline accuracy) This is output if the tables are tested.
3. **BMv2 test result** — actual on-switch classification accuracy via Mininet.

### 5. Trying different models

Rerun `python3 Planter.py -m` and pick a different model at prompt #3. Go through planter's README's and docs to know more.

### 6. Where outputs land

- `src/scripts/` — generated P4 source and per-run shell scripts.
- `src/temp/` — intermediate table entries and configs.
- `src/logs/` — accuracy matrices and timing logs.

## Notes on fair comparison with the P4 hand-rolled pipelines

Planter's stock P4 reads features from packet headers only — there is no
flow-state machinery. The PeerRush stateful features (`max_ipd`, `min_ipd`,
`last_ipd`, `max_packet_len`, `min_packet_len`) require per-flow registers
and a flow-table hashing scheme that Planter does not generate. The accurate
comparison is therefore:

- **Planter, 5 header-only features** vs.
- **`linear_p4` / `tree_p4` / `bnn_p4`, 10 features including stateful ones**

The gap between these two configurations quantifies the value of the per-flow
state added in the hand-rolled pipelines.
