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

---

## Version Benchmark Comparison (v0.3 vs v0.4)

Ground-truth evaluation across 13 benchmark test cases (derived from OWASP Juice Shop, NodeGoat, DVWA, and synthetic safe/vulnerable samples):

| Version Snapshot | Total Cases | Found (TP) | Missed (FN) | False Alarms (FP) | True Negatives (TN) | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **v0.3 Snapshot** (`evals/results/v0.3.json`) | 13 | 7 | 0 | 0 | 6 | 100.00% | 100.00% | 100.00% |
| **v0.4-M1 Rules Expansion** (`evals/results/v0.4-m1.json`) | 13 | 7 | 0 | 0 | 6 | 100.00% | 100.00% | 100.00% |
| **v0.4 Final Release** (`evals/results/v0.4.json`) | 13 | 7 | 0 | 0 | 6 | 100.00% | 100.00% | 100.00% |

### v0.4 Engine Expansion Highlights
- **Secrets Catalog**: Expanded coverage with verified token prefixes for OpenRouter (`sk-or-v1-`), Anthropic (`sk-ant-api03-`), Pinecone, LangSmith, and Replicate, plus high-entropy context detection for Cohere and Together AI.
- **Web & Framework SAST**: Precision AST sinks for Flask/Jinja2 SSTI, Prisma raw SQL `$queryRawUnsafe`, JWT verification bypasses, CORS with credentials reflection, and Vue `v-html` XSS.
- **AI-Application Security**: Direct detection of tainted prompt construction (`CWE-1427`), excessive agency in agent tools (`CWE-1426`), unvalidated LLM output to execution sinks (`eval`/`exec`/`subprocess`), RAG file injection, and frontend AI token exposures.
- **Passive Footprint Discovery**: Zero-network-packet footprint discovery (`cry net --footprint .`) with normalized multi-format IP parsing (decimal dwords, hex, dotted octal, IPv6-mapped).
- **Authorized Active Network Scanning**: Pre-flight proof-of-control authorization gate (DNS TXT or HTTP well-known token), `--allow-local` safety isolation, DNS rebinding mitigation, public database/cache exposure alerts, deep TLS/cipher reviews, and append-only local audit logs (`~/.cry/audit.log`).
