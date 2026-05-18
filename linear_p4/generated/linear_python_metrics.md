# PeerRush Fixed-Point Linear JSON Replay Metrics

- Total packets: 19068
- Accuracy: 0.543476
- Macro precision: 0.712275
- Macro recall: 0.502481
- Macro F1: 0.495886

## Per-Class Metrics

| Class | Name | Support | Precision | Recall | F1 |
|---:|---|---:|---:|---:|---:|
| 0 | emule | 7226 | 0.715613 | 0.330473 | 0.452144 |
| 1 | utorrent | 7481 | 0.469611 | 0.910974 | 0.619743 |
| 2 | vuze | 4361 | 0.951600 | 0.265994 | 0.415771 |

## Class-Port / Host Accuracy Spread

| Host | Predicted Class | Name | Correct | Support | Accuracy | Packets Predicted To Host |
|---|---:|---|---:|---:|---:|---:|
| h2 | 0 | emule | 2388 | 7226 | 0.330473 | 3337 |
| h3 | 1 | utorrent | 6815 | 7481 | 0.910974 | 14512 |
| h4 | 2 | vuze | 1160 | 4361 | 0.265994 | 1219 |

## Confusion Matrix

{
  "0": {
    "0": 2388,
    "1": 4809,
    "2": 29
  },
  "1": {
    "0": 636,
    "1": 6815,
    "2": 30
  },
  "2": {
    "0": 313,
    "1": 2888,
    "2": 1160
  }
}
