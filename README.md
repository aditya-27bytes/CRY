# ⚡ CRY Security Platform

> **"Know if you're safe to ship."**  
> An open-source application and network security testing & triage platform for indie developers, solo founders, and fast-moving teams. CRY combines multi-engine static scanning, AST taint dataflow tracking, zero-dependency declarative rules, BYOM AI model benchmarking, and automated project network footprint discovery to deliver plain-English verdicts (`SHIP`, `FIX_FIRST`, `DONT_SHIP`) with exact copy-paste replacement code diffs.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-101%20passed-brightgreen.svg)]()
[![Code Style](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked](https://img.shields.io/badge/types-mypy-blue.svg)](http://mypy-lang.org/)

---

## 🎯 Why CRY?

AI coding assistants and high-velocity workflows help developers ship faster than ever, but developers without dedicated security operations teams are left unprotected. Traditional security tools flood terminals with 400+ noisy warnings without stating what is actually exploitable, while enterprise penetration testing costs thousands of dollars.

CRY bridges this gap:

1. **Multi-Engine Static & Network Scanning**:
   - **Secrets Detection**: 32+ verified regex signatures + Shannon entropy analysis (OpenRouter, Anthropic, Pinecone, LangSmith, Replicate, Cohere, Together AI, Stripe, AWS, GitHub, Supabase, Hugging Face, Slack, Twilio, SendGrid, database URIs).
   - **SAST Vulnerability Scanning**: SQL injection, command injection, dynamic `eval()`, path traversal, prototype pollution, broken crypto, insecure deserialization, Flask/Jinja2 SSTI, Prisma raw queries (`$queryRawUnsafe`), disabled JWT verification, CORS reflection with credentials, and Vue `v-html` XSS.
   - **AI-Application Security**: Direct detection of tainted prompt construction (`CWE-1427`), excessive agency in agent tools (`CWE-1426`), unvalidated LLM output to execution sinks (`eval`/`exec`/`subprocess`), RAG file injection, and frontend AI token exposures.
   - **Supply-Chain SCA**: Dependency manifest auditing (`package.json`, `requirements.txt`) flagging malicious lifecycle scripts and vulnerable packages.
   - **Config & Git Hygiene**: Unprotected `.env` files, `.gitignore` coverage gaps, exposed Docker sockets, and debug mode leaks.
   - **Network & SSRF Intelligence**: Detection of Server-Side Request Forgery sinks, Cloud Metadata leaks (AWS/GCP/Azure IMDS `169.254.169.254`), and cleartext HTTP APIs.

2. **AST Taint Dataflow Analysis & Context Graph**:
   - Source-to-sink dataflow tracking in Python (`ast.NodeVisitor`) and JavaScript/TypeScript.
   - Traces untrusted user inputs (`request.args`, `req.query`, `sys.argv`) through variable assignments and sanitization boundaries (`int()`, `shlex.quote()`, `DOMPurify.sanitize()`) into execution sinks (`cursor.execute()`, `os.system()`, `open()`, `fetch()`).
   - Structural context graphs capture enclosing function boundaries, decorators, and security middleware to eliminate false alarms.

3. **Zero-Dependency Declarative Rules Engine**:
   - Load and extend rules from `.cryrules.toml`, `.cryrules.yaml`, or `.cryrules.json`.
   - 17+ embedded high-signal rules curated from Gitleaks and Semgrep/OWASP standards.
   - Fast built-in rule validation and testing (`cry rules test`).

4. **Bring Your Own Model (BYOM) & AI Benchmarking**:
   - Test, benchmark, and compare AI models (Groq, Ollama, vLLM, OpenAI, Hugging Face) side-by-side on 13 ground-truth security evaluation cases.
   - Automated recommendation engine mathematically identifies the optimal model balancing 0 False Negatives, accuracy (F1), latency, and token cost.

5. **Passive Project Footprint & Authorized Network Scanning (`cry net`)**:
   - **Passive Footprint (Default)**: Running `cry net` or `cry net --footprint .` discovers every declared URL, host, and IP in your codebase without dispatching any network packets. Normalizes integer dword, hex, octal, and IPv6-mapped IP formats to catch obfuscated SSRF attempts.
   - **Target Authorization Gate**: Mandatory proof of control (DNS TXT record or HTTP well-known file) before active probes against public hosts.
   - **Safety & Isolation**: Explicit `--allow-local` required for local development targets; permanent blocking of cloud metadata; real-time DNS rebinding defense; and public database/cache exposure alerts.

6. **100% Offline Heuristic Fallback**:
   - Zero external API calls, zero latency, and zero token costs with `cry scan --no-ai` or `cry eval --no-ai`.
   - 100% private security analysis ensuring no proprietary source code ever leaves your machine.

7. **Smart Noise Reduction & Heuristic Exclusions**:
   - Automatically filters out noisy vendor directories (`node_modules`, `vendor/`, `dist/`, `.next/`, `coverage/`, `.venv`), lockfiles, and minified bundles (`*.min.js`, `*.min.css`).
   - Line-length and source map heuristics flag minified and bundled artifacts even without standard extensions.
   - Respects `.gitignore` rules out-of-the-box and displays full exclusion telemetry in terminal and report outputs.
   - Deep inspection available on demand via `--include-vendor`.

8. **Multi-Model Resilience & Strict Privacy Guard**:
   - Graceful fallback across primary and secondary backup LLM providers when API rate limits (HTTP 429) or transient provider outages occur during triage.
   - **Privacy Guard Guarantee**: Prevents code targeted at local models (`localhost`, `127.0.0.1`, `ollama`) from ever failing over to remote cloud APIs.

---

## 🚀 Quickstart

### 1. Prerequisites & Virtual Environment Setup

Ensure Python 3.11+ and Git are installed. Clone or navigate to your repository:

```bash
git clone https://github.com/aditya-27bytes/CRY.git
cd CRY
python -m venv .venv
```

#### Activate the Virtual Environment:

* **Windows PowerShell:**
  ```powershell
  .\.venv\Scripts\Activate.ps1
  ```
  *(If PowerShell displays an execution policy restriction, run once: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`)*

* **Windows Command Prompt (CMD):**
  ```cmd
  .\.venv\Scripts\activate.bat
  ```

* **macOS / Linux:**
  ```bash
  source .venv/bin/activate
  ```

---

### 2. Install CRY

With your `.venv` activated, install CRY in editable development mode:

```bash
pip install --upgrade pip
pip install -e ".[dev]"
```

Verify the installation:
```bash
cry version
# or: python -m cry version
```

---

### 3. Configure AI Engine (Groq or Local Ollama)

CRY supports any OpenAI-compatible API endpoint:

1. Copy the example configuration template:
   ```bash
   cp .env.example .env
   # On Windows PowerShell: Copy-Item .env.example .env
   ```

2. Open `.env` (or run `cry configure`) to set up your provider:

   **Option A: Cloud API via Groq (Fastest & Deepest Reasoning)**
   ```ini
   CRY_LLM_BASE_URL=https://api.groq.com/openai/v1
   CRY_LLM_API_KEY=gsk_your_groq_api_key_here
   CRY_LLM_MODEL=openai/gpt-oss-120b
   ```
   *(Get your free API key at [console.groq.com](https://console.groq.com). Models supported: `openai/gpt-oss-120b`, `llama-3.3-70b-versatile`, `qwen/qwen3.8-27b`).*

   **Option B: 100% Private Offline via Ollama (Zero data leaves your machine)**
   ```ini
   CRY_LLM_BASE_URL=http://localhost:11434/v1
   CRY_LLM_API_KEY=ollama
   CRY_LLM_MODEL=llama3.3:70b
   ```

3. Verify your configuration:
   ```bash
   cry check
   ```

---

## 🛠️ CLI Usage Guide

Every command in CRY works as a **seamless, single-line command** with intelligent defaults:

### 1. Launch the Interactive Welcome Menu
```bash
cry
```
Features an interactive terminal menu to scan code, run health checks, execute benchmarks, configure LLMs, and inspect rules.

### 2. Full Project Audit (All 5 Scanner Engines)
Scans the entire project end-to-end across **Secrets**, **SAST**, **Supply-Chain Dependencies (SCA)**, **Configuration & Git Hygiene**, and **Network & SSRF Security**:
```bash
# Deep full-project audit:
cry full

# Or equivalent alias:
cry scan full

# Run 100% offline without LLM:
cry full --no-ai
```

### 3. Network Security & IP Host Intelligence
CRY provides passive footprint analysis by default and strictly authorized active network scanning:

```bash
# 1. Passive Project Network Footprint (Default — zero network packets dispatched):
cry net --footprint .
cry net .

# 2. Scan Local Development Service (--allow-local required for localhost / RFC-1918):
cry net localhost:8000 --allow-local
cry net 127.0.0.1:3000 --allow-local

# 3. Prove Ownership of Public Host (Required before probing public targets):
cry net myapp.com --authorize

# 4. Authorized Active Network Audit (Probes ports, database exposures, TLS, and headers):
cry net myapp.com
cry net myapp.com --deep --ports 80,443,5432,6379,8080 -y

# 5. Export network intelligence audit to Markdown:
cry net . -m NET_REPORT.md
```

> See [docs/NETWORK.md](docs/NETWORK.md) for complete details on the target authorization gate, proof of control methods (DNS TXT & HTTP well-known), DNS rebinding defense, and legal use policy.

### 4. Scan Codebases & Single Files
```bash
# Scan current directory with intelligent defaults (auto-skips vendor, minified, and gitignored files):
cry scan

# Scan specific local path:
cry scan ./my-project
cry scan ./src/routes/auth.py

# Include third-party vendor directories, minified bundles, and lockfiles:
cry scan --include-vendor
cry full --include-vendor
```

### 5. Scan a Public Git Repository
Shallow-clones into a temporary sandbox, executes scanners and AI triage, outputs the audit report, and cleans up automatically:
```bash
cry scan https://github.com/OWASP/NodeGoat
```

### 6. Fast Deterministic Offline Mode (No LLM Required)
```bash
cry scan --no-ai
cry full --no-ai
```

### 7. Export Audit Reports (Markdown & JSON)
```bash
# Export GitHub/GitLab PR-ready Markdown audit:
cry scan full -m AUDIT.md

# Export machine-readable JSON for CI/CD pipelines:
cry scan full -o report.json
```

### 8. Bring Your Own Model (BYOM) & AI Benchmarking
Test your own custom models (Groq, Ollama, vLLM, OpenAI, Hugging Face) on 13 ground-truth security evaluation cases:
```bash
# Benchmark your active configured model or offline baseline:
cry eval
cry eval --no-ai

# Benchmark a specific model with report export:
cry eval --model llama3.3:70b -m BENCHMARK.md

# Compare multiple AI models side-by-side with automated recommendation:
cry eval --compare "openai/gpt-oss-120b,llama-3.3-70b-versatile"
```

### 9. Declarative Rules Catalog & Testing
Inspect and validate the embedded Semgrep/Gitleaks catalog or your custom `.cryrules.yaml`:
```bash
# View all active security rules directly:
cry rules

# Filter rules by category:
cry rules -c SECRET_EXPOSURE
cry rules -c INJECTION

# Validate all regexes for syntax errors and ReDoS risks:
cry rules test
```

### 10. Interactive Configuration Wizard
Configure or switch your LLM provider (Groq, Ollama, Custom API) at any time:
```bash
cry configure
```

### 11. 🐧 Host & Linux System Health Monitor
Inspect real-time system metrics, resource utilization, and proactive health alerts:
```bash
# View scanner readiness and live host telemetry
cry check

# Generate a timestamped system health report in reports/
cry check --report
```
Or run the standalone Ubuntu Linux Bash monitor:
```bash
bash scripts/system_health.sh
```
Monitors: Hostname, active user, date/time, system uptime, load averages, CPU cores & load %, RAM & disk capacity %, process count, network connectivity, and threshold alerts.

---

## 📊 Ground-Truth Evaluation Suite

CRY includes a ground-truth benchmark suite of 13 paired vulnerability & safe-trap test cases scored across the OWASP Top 10:

```bash
# Run baseline evaluation
cry eval --no-ai
```

Current baseline metrics:
* **Precision**: `100.00%` (0 noisy false alarms on safe traps)
* **Recall (Sensitivity)**: `100.00%` (0 missed vulnerabilities)
* **F1 Score**: `100.00%`
* **Actionable Patch Rate**: `100.00%` (syntax-valid replacement code diff provided for all blockers)
* **Inference Latency**: `0.00s` (offline heuristic) / `~3.8s` (Groq Llama 3.3 70B)

---

## 🧪 Running Automated Tests

```bash
# Run full pytest test suite (94 passing unit tests)
pytest -v

# Run linter and type checker
ruff check .
ruff format --check .
mypy cry
```

---

## 🛡️ Known Limitations & Design Constraints

1. **Host Platform OpenSSL Security Level (`SECLEVEL`)**:
   - Detection of legacy TLS 1.0 and TLS 1.1 protocol support via `--deep` depends on the host system's OpenSSL configuration. If the client platform enforces OpenSSL `SECLEVEL >= 2` (standard on modern Linux distributions and modern OpenSSL builds), the local client runtime prohibits initiating legacy handshakes.
2. **Prompt Injection & LLM Defenses (`CWE-1427`)**:
   - CRY flags dynamic request input interpolated into prompt templates. While structural role separation (system vs. user messages) and delimiters significantly reduce injection risk, no prompt architecture mathematically eliminates prompt injection. AI output must always be treated as untrusted.
3. **Network Probing Observability Assurance**:
   - Active network audits report observed technical indicators (open ports, header configurations, certificate attributes) at scan time only. CRY explicitly never certifies a host or web application as "secure" or free of vulnerabilities.
4. **Privacy Guard Boundary**:
   - When the primary LLM is configured to a local endpoint (`localhost`, `127.0.0.1`, `ollama`), CRY's Privacy Guard strictly blocks failing over to cloud APIs (e.g. OpenRouter). This prevents inadvertent transmission of confidential code to external servers.
5. **Static Analysis Scope**:
   - SAST taint analysis covers Python, JavaScript, and TypeScript dataflows. Highly obfuscated runtime reflection or dynamic code loading (`importlib.import_module(dynamic)`) may require human code audit.

---

## 📄 License
Apache 2.0. See [LICENSE](LICENSE) for details.
