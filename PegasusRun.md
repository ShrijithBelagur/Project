# Running Pegasus on BMv2 (CICIOT2022 use case)

This document records the practical steps to bring up the Pegasus MLP-B
reference implementation on a P4 dev VM and replay the CICIOT2022 test set
through the BMv2 switch. Pegasus is **not** used as a quantitative baseline
in this project - upstream only ships an MLP-B BMv2 deployment, and only
the CICIOT2022 / ISCX / PeerRush splits the Pegasus authors prepared are
supported. The steps below are the minimum recipe to reproduce one of
their published runs end-to-end so the framework can be studied alongside
our PeerRush pipelines.

- Repository: <https://github.com/afireswallow/Pegasus>
- We have cloned the repository into our Project and minor changes have been made to ensure that it runs.
- Tested on: Ubuntu 24.04 VirtualBox image referenced at
  [P4 tutorials](https://github.com/p4lang/tutorials), and 
  [VMs](https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md).

## 1. Environment

- Use the P4 dev VM's default Python virtual environment
  (`p4dev-python-venv`, activated automatically by the VM's `bashrc`).
- Install Pegasus's Python dependencies into that venv:

  ```bash
  pip install -r Pegasus/bmv2/requirements.txt
  ```

  The requirements.txt was modified slightly to ensure it works with the VM's venv python version.

## 2. Dataset focus

Pegasus ships preprocessed CSV splits for three datasets. These live under `Pegasus/software/dataset/`. The instructions below cover
**CICIOT2022** specifically. ISCX and PeerRush share the similar feature
layout, so swapping is straightforward - substitute the dataset name in
the paths and commands below.

## 3. Pretrained artifacts

Pegasus's BMv2 deployment relies on three artifacts under
`Pegasus/bmv2/make_dataset/mlp/CICIOT2022/`:

- **`mlp_CICIOT2022_0.8563548831138729.pt`** - trained MLP-B PyTorch
  `state_dict` (weights, biases, BN parameters). The numeric suffix is the
  held-out test accuracy of the checkpoint (~85.6%).
- **`mlp_CICIOT.pkl`** - output of `convert_pkl_mlp.py`: fuzzy clustering
  thresholds, centroid-to-output mappings, and fused
  BN → FC → ReLU results, serialised for the control plane to install as
  match-action entries.
- **`CICIOT2022_dataset.pkl`** - processed test set in per-packet form.
  Used downstream to generate the replay pcap.

If the `.pkl` files are missing or stale, regenerate them with the
conversion step in Section 4.1.

## 4. BMv2 pipeline - step by step

All paths below are relative to the `Pegasus/` directory unless otherwise
stated. Run each block in its own terminal where indicated.

### 4.1 Regenerate the table and dataset pickles (sanity check)

This step can be skipped if the distributed `.pkl` files are already in
place.

```bash
cd bmv2/make_dataset

python convert_pkl_mlp.py \
    --model_path mlp/CICIOT2022/mlp_CICIOT2022_0.8563548831138729.pt \
    --test_data_path ../../dataset/CICIOT2022_test.csv \
    --dataset_type CICIOT2022 \
    --output_pkl_path mlp/CICIOT2022/output.pkl \
    --dataset_pkl_path mlp/CICIOT2022/dataset.pkl
```

### 4.2 Bring up the BMv2 veth pair

```bash
cd Pegasus/bmv2
bash start_veth.sh
```

### 4.3 Compile the P4 program and start the switch (terminal A)

```bash
cd Pegasus/bmv2
./p4_CICIOT2022/start_switch.sh
```

This invokes `p4c` on `basic.p4 + headers.p4 + parsers.p4` under
`p4_CICIOT2022/` and starts `simple_switch` listening on the veth pair
created in Section 4.2.

### 4.4 Populate match-action tables via the control plane (terminal B)

```bash
cd Pegasus/bmv2/p4_CICIOT2022/control/
python mlp32_control.py
```

> Some fixes done by us:
>
> 1. The Pegasus README suggests running
>    `python p4_CICIOT2022/control/mlp32_control.py` from `Pegasus/bmv2/`.
>    Several paths inside the script are hard-coded relative to the
>    script's own directory, so launching from any other cwd raises
>    `FileNotFoundError`. With our fixes you should`cd` into `p4_CICIOT2022/control/` first
>    and run `python mlp32_control.py`.
>
> 2. **Hard-coded model pickle path.** The path to `mlp_CICIOT.pkl` (or
>    your regenerated `output.pkl`) is hard-coded inside
>    `mlp32_control.py`. That line is editted so that it points to the correct file.

## 5. Traffic replay

Helpers for replaying the test set through the switch live in
`Pegasus/bmv2/send_recieve/`.

### 5.1 Generate the replay pcap

```bash
cd Pegasus/bmv2/send_recieve
python gen_pcap.py
```

`gen_pcap.py` is hard-coded for CICIOT2022 but works unmodified for ISCX
and PeerRush because they share the same feature layout. The output is
`ciciot_dataset.pcap` in the same directory.

### 5.2 Start the listener (terminal C)

```bash
sudo /home/p4/src/p4dev-python-venv/bin/python listen_veth.py
# When the listener prompts for a port number, type 1 and press Enter.
```

> `sudo python listen_veth.py` fails as it uses the system python

### 5.3 Replay the pcap into the switch (terminal D)

```bash
sudo tcpreplay --pps=100 -i veth0 ciciot_dataset.pcap
```

`--pps=100` paces replay at 100 packets/second

## 7. Caveats and scope

- Only the **MLP-B** model is provided as a BMv2 deployment by Pegasus.
  The other Pegasus model families (RNN, CNN, autoencoder) are not present
  in the software / BMv2 tree, so they cannot be reproduced from this
  repository alone.
- Pegasus is treated in our project as **background context, not as a
  quantitative baseline**. The published checkpoints and table-entry
  formats are not directly comparable to our PeerRush flow-feature
  pipelines (linear, BNN, decision tree), because Pegasus moves feature
  preparation largely off-switch and relies on per-feature fuzzy
  clustering that our pipelines do not implement.
- The two fixes called out in Section 4.4 (control-plane working
  directory, hard-coded pickle path) are mandatory on the P4 dev VM image;
  without them the control plane silently fails before any packets
  traverse the switch.
- Use the absolute venv python (`/home/p4/src/p4dev-python-venv/bin/python`)
  wherever a Python script is launched under `sudo`. This is the same
  pattern used in Planter (see [PlanterRun.md](PlanterRun.md)) and is
  documented here separately so Pegasus's quirks are self-contained.
