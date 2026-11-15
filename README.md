# CRY Platform

> **"Know if you're safe to ship."**  
> An open-source security testing and triage platform for indie developers and small teams. CRY delivers plain-English verdicts (`SHIP`, `FIX_FIRST`, `DONT_SHIP`) with deep threat analysis and exact, copy-paste replacement code diffs.

---

## 🎯 Why CRY?
AI coding assistants and high-velocity workflows help developers ship fast, but developers without dedicated security teams are left unprotected. Existing open-source tools produce 400+ noisy warnings without stating what is actually exploitable, while enterprise penetration testing costs thousands of dollars.

CRY bridges this gap:
1. **Multi-Engine Static & Network Scanning**: Dual-engine secrets detection (25+ regex signatures + Shannon entropy analysis), SAST vulnerability scanning (SQLi, command injection, eval, cookies, CSRF, SSL, CORS, open redirect), Supply-Chain SCA (`package.json`, `requirements.txt`), Config & Git hygiene (`.gitignore`, Docker, `.env`), and Network/SSRF intelligence.
2. **Context-Aware AI Triage**: Evaluates surrounding code context (+/- 10 lines) using fast reasoning models (Groq `openai/gpt-oss-120b`, `qwen/qwen3.8-27b`) or 100% private local models (Ollama `llama3.3:70b`).
3. **High-Matrix Heuristic Offline Mode**: Runs 100% locally with `--no-ai` without network latency, providing rule-specific attack vectors, threat mechanics, and actionable replacement code diffs.
4. **Live Network & IP Defense Auditing**: Live DNS resolution (IPv4, IPv6, reverse PTR), SSRF & Cloud Metadata (IMDS `169.254.169.254`) detection, TLS/SSL certificate lifecycle tracking, and HTTP defense header scorecards (`cry net`).
5. **Transparent False Positives**: Safe test fixtures and mock credentials are never silently dropped; they are clearly explained and preserved in a transparent review section.
6. **Universal Target Support**: Scans local folders, individual files, live network endpoints, and public Git repositories directly via shallow clone.

---

## 🚀 Quickstart

### 1. Prerequisites & Virtual Environment Activation

Make sure Python 3.11+ and Git are installed. Clone or navigate to your CRY repository:

```bash
git clone https://github.com/your-username/cry.git
cd cry
python -m venv .venv
```

#### Activate the Virtual Environment:

* **Windows PowerShell:**
  ```powershell
  .\.venv\Scripts\Activate.ps1
  ```
  *(If PowerShell displays an `Execution_Policies` restriction error, run once: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`)*

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

2. Open `.env` and configure your preferred provider:

   **Option A: Cloud API via Groq (Fastest & Deepest Reasoning)**
   ```ini
   CRY_LLM_BASE_URL=https://api.groq.com/openai/v1
   CRY_LLM_API_KEY=gsk_your_groq_api_key_here
   CRY_LLM_MODEL=openai/gpt-oss-120b
   ```
   *(Get your free API key at [console.groq.com](https://console.groq.com). Models supported: `openai/gpt-oss-120b`, `qwen/qwen3.8-27b`).*

   **Option B: 100% Private Offline via Ollama (Zero data leaves your machine)**
   ```ini
   CRY_LLM_BASE_URL=http://localhost:11434/v1
   CRY_LLM_API_KEY=ollama
   CRY_LLM_MODEL=llama3.3:70b
   ```

Verify your setup with the built-in health check:
```bash
cry check
```

---

## 🛠️ CLI Usage Guide

### 1. Launch the Interactive Welcome Menu
```bash
cry
# or: python -m cry
```
Features an interactive terminal menu to scan code, run health checks, execute benchmarks, and configure API keys.

### 2. Full Project Audit (All 5 Engines)
Scans the entire project end-to-end across **Secrets**, **SAST**, **Supply-Chain Dependencies (SCA)**, **Configuration & Git Hygiene**, and **Network & SSRF Security**:
```bash
cry scan full
# or alias:
cry full
# or with offline heuristic mode:
cry scan full --no-ai
```

### 3. Network Security & IP Host Intelligence
Performs live DNS resolution, reverse PTR lookup, SSRF/private IP alerts, Cloud IMDS (`169.254.169.254`) detection, TLS/SSL certificate validation & cipher analysis, and HTTP defense header grading:
```bash
# Scan a live host or IP:
cry net api.example.com
# or inspect local SSRF risk:
cry net 127.0.0.1
# or export to Markdown:
cry net api.example.com -m NET_AUDIT.md
```

### 4. Scan a Specific Local Directory or File
```bash
cry scan ./my-project
# or single file:
cry scan ./src/routes/auth.py
```

### 5. Scan a Public Git Repository
Shallow-clones into a temporary sandbox, executes scanners and AI triage, outputs the audit report, and cleans up automatically:
```bash
cry scan https://github.com/OWASP/NodeGoat
```

### 6. Fast Deterministic Offline Mode (No LLM Required)
```bash
cry scan ./my-project --no-ai
```

### 7. Export Audit Reports (Markdown & JSON)
```bash
# Export GitHub/GitLab PR-ready Markdown audit:
cry scan full -m AUDIT.md

# Export machine-readable JSON for CI/CD pipelines:
cry scan full -o report.json
```

---

## 📊 Accuracy & Evaluation Harness

CRY includes a ground-truth benchmark harness scored against vulnerable applications (OWASP Juice Shop & NodeGoat samples):

```bash
# Run accuracy evaluation
python evals/runner.py --no-ai
```
Current baseline metrics:
* **Precision**: `100.00%` (0 noisy false alarms)
* **Recall (Sensitivity)**: `100.00%` (0 missed vulnerabilities)
* **F1 Score**: `100.00%`

---

## 🧪 Running Automated Tests

```bash
# Run pytest unit tests (36 passing unit tests)
pytest

# Run linter and type checker
ruff check .
mypy cry
```

---

## 🗺️ Roadmap & Live Website Scanning
* **v0.1.0 (Current)**: Local file/folder scanning, public Git repository scanning, high-precision regex + Shannon entropy secrets detection, SAST vulnerability patterns, OpenAI-compatible AI triage with batching, and Rich terminal / Markdown / JSON reporting.
* **v0.2.0 (Phase 2)**: Containerized DAST (Dynamic Application Security Testing) with automated domain-ownership verification for live hosted websites (`https://mywebsite.com`), dependency vulnerability scanning (SCA), and Next.js developer dashboard.

---

## 📄 License
Apache 2.0. See `LICENSE` for details.
