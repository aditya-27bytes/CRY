# CRY AI Security Model Benchmark Report

> Ground-truth evaluation testing accuracy, precision, recall, and token costs across synthetic regression cases and real open-source benchmark applications.

| Model | Precision | Recall (Sensitivity) | F1 Score | False Negatives | Latency | Total Cost ($) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`Offline Heuristic (No AI)`** | `100.00%` | `100.00%` | `100.00%` | **`0`** | `0.0s` | `$0.0000` |

### Metric Definitions:
- **Recall (Sensitivity)**: Percentage of real vulnerabilities successfully detected. (Target: > 95%)
- **False Negatives**: Real vulnerabilities that were completely missed. (**Must be 0**)
- **Precision**: Percentage of flagged issues that are genuinely dangerous. (Target: > 85%)
- **F1 Score**: Harmonic mean balancing precision and recall.

---

## Real-Application Benchmark: OWASP NodeGoat

Ground-truth benchmark executed directly against the full codebase of **OWASP NodeGoat** (pinned commit `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`), tracked in `evals/real_apps/manifest.json` and verifiable via `cry eval --real-apps`.

### Scan Command & Execution
```bash
cry scan <nodegoat_path> --no-ai
# or via real-apps evaluation harness:
cry eval --real-apps
```

### Verification & Accuracy Metrics
| Metric | Count | Details |
| :--- | :---: | :--- |
| **Total Blockers** | **7** | Production critical security blockers |
| **Total Warnings** | **4** | Non-blocking security advisories and downgraded test/build findings |
| **Caught Vulnerabilities** | **7** | 1 Private key, 2 NoSQL injections, 3 dynamic code execution (`eval`), 1 SSRF |
| **Missed Vulnerabilities** | **0** | No critical production vulnerabilities missed |
| **Noisy Non-Production Blockers** | **0** | Documentation and test/build findings cleanly downgraded or excluded |
| **Excluded Files** | **42** | 15 vendor, 1 lockfile, 4 docs, 21 test/fixture, 1 build config |

### Real NodeGoat Findings Breakdown

#### Confirmed Blockers (7 issues)
1. **`artifacts/cert/server.key`** (Line 1): Private Key (RSA/EC/DSA/SSH) (`CWE-321`, tool: `cry-secrets`)
2. **`app/data/allocations-dao.js`** (Line 73): NoSQL Injection via `$where` Clause (`CWE-943`, tool: `cry-sast`)
3. **`app/data/allocations-dao.js`** (Line 78): NoSQL Injection via `$where` Clause (`CWE-943`, tool: `cry-sast`)
4. **`app/routes/contributions.js`** (Line 32): Use of `eval()` on Dynamic Input (`CWE-95`, tool: `cry-sast`)
5. **`app/routes/contributions.js`** (Line 33): Use of `eval()` on Dynamic Input (`CWE-95`, tool: `cry-sast`)
6. **`app/routes/contributions.js`** (Line 34): Use of `eval()` on Dynamic Input (`CWE-95`, tool: `cry-sast`)
7. **`app/routes/research.js`** (Line 16): Server-Side Request Forgery (SSRF) via Dynamic HTTP Client (`CWE-918`, tool: `cry-sast`)

#### Warnings & Non-Blocking Advisories (4 issues)
1. **`app/views/tutorial/a1.html`** (Line 220): Hardcoded Password Assignment (`CWE-798`, tool: `cry-secrets`)
2. **`Gruntfile.js`** (Line 165): `[Test/Build Fixture] Use of eval() or exec() on Dynamic Input` (`CWE-95`, downgraded from blocker to warning)
3. **`test/e2e/support/commands.js`** (Line 30): `[Test/Build Fixture] Use of eval() or exec() on Dynamic Input` (`CWE-95`, downgraded from blocker to warning)
4. **`app/routes/index.js`** (Line 72): Potential Open Redirect (`CWE-601`, tool: `cry-sast`)

### Verifiable Output Log
```text
Target: C:\Users\adity\AppData\Local\Temp\nodegoat
Triage Engine: Offline Heuristic Engine
Summary: 🚨 DEPLOYMENT BLOCKED: Discovered 7 critical production security blocker(s) and 4 warning(s). Your application contains active vulnerabilities that expose credentials or allow arbitrary command/database execution. Review the replacement code in the Blockers table below and resolve them before shipping. [Excluded: 42 files skipped (vendor: 15, lockfile: 1, docs: 4, test_or_fixture: 21, build_config: 1).]
```

---

## Synthetic Regression Suite (13 Curated Samples)

Regression testing across 13 self-written synthetic test cases (7 vulnerable code patterns, 6 safe negative traps) verifying basic SAST and secret rules:

| Version Snapshot | Total Cases | Found (TP) | Missed (FN) | False Alarms (FP) | True Negatives (TN) | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **v0.3 Synthetic Baseline** (`evals/results/v0.3.json`) | 13 | 7 | 0 | 0 | 6 | 100.00% | 100.00% | 100.00% |
| **v0.4 Synthetic Baseline** (`evals/results/v0.4.json`) | 13 | 7 | 0 | 0 | 6 | 100.00% | 100.00% | 100.00% |

### Engine Expansion Highlights
- **Secrets Catalog**: Expanded coverage with verified token prefixes for OpenRouter (`sk-or-v1-`), Anthropic (`sk-ant-api03-`), Pinecone, LangSmith, and Replicate, plus high-entropy context detection for Cohere and Together AI.
- **Web & Framework SAST**: Precision AST sinks for Flask/Jinja2 SSTI, Prisma raw SQL `$queryRawUnsafe`, JWT verification bypasses, CORS with credentials reflection, and Vue `v-html` XSS.
- **AI-Application Security**: Direct detection of tainted prompt construction (`CWE-1427`), excessive agency in agent tools (`CWE-1426`), unvalidated LLM output to execution sinks (`eval`/`exec`/`subprocess`), RAG file injection, and frontend AI token exposures.
- **Passive Footprint Discovery**: Zero-network-packet footprint discovery (`cry net --footprint .`) with normalized multi-format IP parsing (decimal dwords, hex, dotted octal, IPv6-mapped).
- **Authorized Active Network Scanning**: Pre-flight proof-of-control authorization gate (DNS TXT or HTTP well-known token), `--allow-local` safety isolation, DNS rebinding mitigation, public database/cache exposure alerts, deep TLS/cipher reviews, and append-only local audit logs (`~/.cry/audit.log`).
