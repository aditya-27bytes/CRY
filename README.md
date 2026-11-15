# ⚡ CRY Security Platform

> **"Know if you're safe to ship."**  
> An open-source application and network security testing & triage platform for indie developers, solo founders, and fast-moving teams. CRY combines multi-engine static scanning, AST taint dataflow tracking, zero-dependency declarative rules, BYOM AI model benchmarking, and automated project network footprint discovery to deliver plain-English verdicts (`SHIP`, `FIX_FIRST`, `DONT_SHIP`) with exact copy-paste replacement code diffs.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-48%20passed-brightgreen.svg)]()
[![Code Style](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked](https://img.shields.io/badge/types-mypy-blue.svg)](http://mypy-lang.org/)

---

## 🎯 Why CRY?

AI coding assistants and high-velocity workflows help developers ship faster than ever, but developers without dedicated security operations teams are left unprotected. Traditional security tools flood terminals with 400+ noisy warnings without stating what is actually exploitable, while enterprise penetration testing costs thousands of dollars.

CRY bridges this gap:

1. **Multi-Engine Static & Network Scanning**:
   - **Secrets Detection**: 25+ high-entropy regex signatures + Shannon entropy analysis (Stripe, AWS, GitHub, Supabase, Hugging Face, Slack, Twilio, SendGrid, database URIs).
   - **SAST Vulnerability Scanning**: SQL injection, command injection, dynamic `eval()`, path traversal, prototype pollution, broken crypto, insecure deserialization, and CORS wildcarding.
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

5. **Automated Project Network & IP Intelligence (`cry net`)**:
   - Running `cry net` with zero arguments automatically discovers every network endpoint, API URL, and IP address declared in your codebase.
   - Resolves live DNS records (IPv4, IPv6, PTR), maps local host topology, and alerts on dangerous SSRF and Cloud Metadata leaks.

6. **100% Offline Heuristic Fallback**:
   - Zero external API calls, zero latency, and zero token costs with `cry scan --no-ai` or `cry eval --no-ai`.
   - 100% private security analysis ensuring no proprietary source code ever leaves your machine.

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
```bash
# Automated project network footprint discovery (finds and resolves all URLs/IPs in code):
cry net

# Audit a specific live remote host, domain, or IP:
cry net api.example.com
cry net 1.1.1.1

# Export network intelligence audit to Markdown:
cry net -m NET_REPORT.md
```

### 4. Scan Codebases & Single Files
```bash
# Scan current directory with intelligent defaults:
cry scan

# Scan specific local path:
cry scan ./my-project
cry scan ./src/routes/auth.py
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
# Run full pytest test suite (48 passing unit tests)
pytest -v

# Run linter and type checker
ruff check .
mypy cry
```

---

## 📄 License
Apache 2.0. See [LICENSE](LICENSE) for details.
