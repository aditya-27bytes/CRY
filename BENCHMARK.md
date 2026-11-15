# CRY AI Security Model Benchmark Report

> Ground-truth evaluation testing accuracy, precision, recall, and token costs.

| Model | Precision | Recall (Sensitivity) | F1 Score | False Negatives | Latency | Total Cost ($) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`Offline Heuristic (No AI)`** | `100.00%` | `100.00%` | `100.00%` | **`0`** | `0.0s` | `$0.0000` |

### Metric Definitions:
- **Recall (Sensitivity)**: Percentage of real vulnerabilities successfully detected. (Target: > 95%)
- **False Negatives**: Real vulnerabilities that were completely missed. (**Must be 0**)
- **Precision**: Percentage of flagged issues that are genuinely dangerous. (Target: > 85%)
- **F1 Score**: Harmonic mean balancing precision and recall.