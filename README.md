# ⚡ CRY Security Platform

> **"Know if you're safe to ship."**  
> An open-source application and network security testing & triage platform for indie developers, solo founders, and fast-moving teams. CRY combines multi-engine static scanning, AST taint dataflow tracking, zero-dependency declarative rules, BYOM AI model benchmarking, and automated project network footprint discovery to deliver plain-English verdicts (`SHIP`, `FIX_FIRST`, `DONT_SHIP`) with exact copy-paste replacement code diffs.

[![Release](https://img.shields.io/badge/release-v0.4.1-blueviolet.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Code Style](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked](https://img.shields.io/badge/types-mypy-blue.svg)](http://mypy-lang.org/)

> [!NOTE]
> ### 🚀 Release v0.4.1 Highlights
> * **🎯 Accuracy & Noise Reduction**: Filtered false positive credentials in documentation and test/build artifacts; added `--include-tests-and-docs`; fixed `.gitignore` exclusions accounting.
> * **🖥️ Terminal UI/UX Overhaul**: High-density warning table (2–3 lines per row), automated category aggregation for > 10 warnings, blocker separation, and actionable sticky bottom verdict card (`SHIP` / `FIX_FIRST` / `DONT_SHIP`).
> * **🔍 Full Display Option**: Added `--all` (`-a`) flag to `cry scan` and `cry full` to disable truncation whenever deep inspection is required.
> * **🧬 Enhanced AST Taint Tracking**: Intra-file taint propagation across string concatenation, f-strings, format strings, dictionary lookups, list indexes, and allowlist guards.
> * **⚡ NoSQL & SSRF Detection**: Flagging unvalidated MongoDB `$where` and operator injection (`CWE-943`) and dynamic HTTP clients (`CWE-918`).
> * **📊 Authentic Real-App Benchmarks**: Added OWASP NodeGoat real-app benchmark harness (`cry eval --real-apps`) with pinned commit ground truth.
>
> See full details in [CHANGELOG.md](CHANGELOG.md).

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
   - Benchmark candidate AI models (Groq, Ollama, vLLM, OpenAI, Hugging Face) using synthetic regression test cases or real applications (`cry eval`).
   - Side-by-side multi-model comparison (`cry eval --compare model1,model2`) evaluates recall, precision, latency, and token cost across models.

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
Features an interactive terminal menu to scan code, run configuration checks, execute benchmarks, configure LLMs, and inspect rules.

### 2. Full Project Audit (All 5 Scanner Engines)
Scans the entire project end-to-end across **Secrets**, **SAST**, **Supply-Chain Dependencies (SCA)**, **Configuration & Git Hygiene**, and **Network & SSRF Security**:
```bash
# Deep full-project audit:
cry full

# Or equivalent alias:
cry scan full

# Run 100% offline without LLM:
cry full --no-ai

# Display all findings in the terminal without truncation:
cry full --all
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

# Include test fixtures, build configs (e.g. Gruntfile), and documentation at full blocker severity:
cry scan --include-tests-and-docs
cry full --include-tests-and-docs

# Display all findings in the terminal without compacting or truncation:
cry scan --all
cry full --all
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

### 11. Configuration & Readiness Check
Inspect scanner readiness, provider reachability, model availability, and API key presence:
```bash
# Validate scanners, provider reachability, and model availability
cry check
```

---

## 📊 Benchmark Evaluation Suites

CRY includes two benchmark evaluation suites:

### 1. Real-App Benchmark (OWASP NodeGoat)
Runs an offline audit against the pinned OWASP NodeGoat benchmark commit (`c5cb68a7084e4ae7dcc60e6a98768720a81841e8`):
```bash
# Run real-app benchmark against pinned NodeGoat commit
cry eval --real-apps
```
Confirmed ground truth from local benchmark run:
* **Known Blockers Found**: `7 / 7`
* **Known Warnings Found**: `4 / 4`
* **Known Bugs Missed**: `0`
* **Noisy Blockers**: `0`

### 2. Synthetic Regression Suite
A 13-sample regression suite (`evals/results/v0.4.json`) covering standard vulnerability patterns and safe traps:
```bash
# Run regression suite with heuristic fallback
cry eval --no-ai
```
See [BENCHMARK.md](BENCHMARK.md) for full execution logs, methodology, and version comparisons.

---

## 🧪 Running Automated Tests

```bash
# Run full pytest test suite (126 passing unit tests)
pytest -v

# Run linter and type checker
ruff check .
ruff format --check .
mypy cry
```

---

## 🛡️ Known Limitations & Security Model

### 1. What Is NOT Detected
Based on static analysis constraints and confirmed during the OWASP NodeGoat real-app benchmark:
* **Inter-file & Inter-procedural Taint Flow**: Taint dataflow tracking operates within individual files. Tainted values passed across module imports, callbacks across distant files, or global event buses are not tracked.
* **Second-Order Vulnerabilities**: Untrusted input stored in a database, cache, or filesystem and retrieved in a separate request cycle is not traced.
* **Template-Based XSS in Custom Engines**: Template injection or DOM XSS where output is rendered through custom template filters outside standard DOM insertion sinks.
* **Business Logic & Access Control Flaws**: Broken Object Level Authorization (IDORs where entity ownership is not validated), workflow bypasses, and privilege escalation logic.
* **Session Lifecycle & Server CSRF State**: Server-side session expiration policies, token revocation state machines, and cookie security flags handled by external reverse proxies.
* **Runtime-Only Vulnerabilities**: Race conditions, thread-safety bugs, memory leaks, and timing side-channels that require active program execution to detect.

### 2. Languages Actually Supported
* **First-Class AST Taint Tracking & Syntax Analysis**: **Python** (`.py`), **JavaScript** (`.js`, `.jsx`, `.mjs`, `.cjs`), and **TypeScript** (`.ts`, `.tsx`, `.vue`).
* **Pattern & Manifest Auditing**: **JSON**, **YAML**, **TOML**, **Dockerfile**, `package.json`, `requirements.txt`.
* **Plaintext Secret Scanning**: All UTF-8 text files across the repository (excluding binary files, vendor directories, and minified bundles).

### 3. Active Network Scanning Authorization Gate
* **Mandatory Pre-flight Proof of Control**: Active probing (`cry net TARGET`) strictly requires verified proof of target ownership before probing (DNS TXT verification token `cry-verify-...` or HTTP `/.well-known/cry-challenge.txt`).
* **Local Network Safety**: Probing loopback (`127.0.0.1`, `localhost`) or private RFC-1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) requires explicit `--allow-local`.
* **Permanent Cloud Metadata Protection**: Cloud metadata IP addresses (`169.254.169.254`, `fd00:ec2::254`) are permanently blocked from active probing under all circumstances.
* **Observability Assurance**: CRY reports technical observations at scan time only (open ports, TLS attributes, HTTP headers) and never certifies a host as "secure".

### 4. Data Privacy & Egress Disclosure (What Leaves Your Machine)
* **Offline Mode (`cry scan --no-ai`)**: **Sends nothing.** 0 bytes and zero network packets leave your machine. All scanning and heuristic triage are 100% local.
* **Hosted AI Triage (`--ai`)**: When AI triage is configured and enabled with a cloud provider (e.g., Groq, OpenRouter), CRY transmits code snippets and file context of flagged potential vulnerabilities to the provider's API endpoint (`CRY_LLM_BASE_URL`). Never configure a public cloud API key if your repository policy forbids sending source code to third-party model providers.
* **Local Inference (Ollama / vLLM)**: When using a local inference endpoint (`localhost` / `127.0.0.1`), model inference remains strictly local on your machine.
* **Multi-Model Failover Boundaries**: Model failover (`CRY_FAILOVER=on`) only activates when explicitly enabled in `.env`, and strictly operates cloud-to-cloud. If your primary LLM is configured as a local endpoint, CRY's Privacy Guard permanently enforces isolation and will **never fail over from a local endpoint to a cloud endpoint**.
* **DNS Ownership Verification**: Running `cry net TARGET --authorize` sends DNS-over-HTTPS (DoH) queries to **Cloudflare's public DNS service** (`https://cloudflare-dns.com/dns-query`) containing `name={hostname}&type=TXT`. No source code, project files, or credentials are ever sent to Cloudflare; only the target hostname being authorized is queried.

---

## 📄 License
Apache 2.0. See [LICENSE](LICENSE) for details.
