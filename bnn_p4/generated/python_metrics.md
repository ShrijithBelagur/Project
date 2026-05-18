# Hybrid Quantized BNN Metrics

- Deployment Profile: p4_runtime
- Hidden Units: 8
- Total: 194661
- Accuracy: 0.351627
- Macro Precision: 0.117209
- Macro Recall: 0.333333
- Macro F1: 0.173434

## Per Class

| Class | Name | Precision | Recall | F1 | Support |
|---:|---|---:|---:|---:|---:|
| 0 | emule | 0.000000 | 0.000000 | 0.000000 | 54256 |
| 1 | utorrent | 0.000000 | 0.000000 | 0.000000 | 71957 |
| 2 | vuze | 0.351627 | 1.000000 | 0.520301 | 68448 |

## Class-Port / Host Accuracy Spread

| Host | Predicted Class | Name | Correct | Support | Accuracy | Packets Predicted To Host |
|---|---:|---|---:|---:|---:|---:|
| h2 | 0 | emule | 0 | 54256 | 0.000000 | 0 |
| h3 | 1 | utorrent | 0 | 71957 | 0.000000 | 0 |
| h4 | 2 | vuze | 68448 | 68448 | 1.000000 | 194661 |

## Confusion Matrix

```json
{
  "0": {
    "0": 0,
    "1": 0,
    "2": 54256
  },
  "1": {
    "0": 0,
    "1": 0,
    "2": 71957
  },
  "2": {
    "0": 0,
    "1": 0,
    "2": 68448
  }
}
```
