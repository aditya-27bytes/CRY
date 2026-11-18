# Changelog

All notable changes to the CRY project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.0] - 2026-11-18

### Added
- **Rules Catalog Expansion**:
  - **Secrets Catalog (`secrets.toml`)**: Added verified prefix-based patterns for OpenRouter (`sk-or-v1-`), Anthropic (`sk-ant-api03-`), Pinecone (`pcsk_`), LangSmith (`lsv2_pt_`), and Replicate (`r8_`). Added context-aware, Shannon-entropy rules for Cohere and Together AI API keys.
  - **Web & Framework SAST (`sast.toml`)**: Added precision sink rules for Flask/Jinja2 SSTI (`render_template_string`), Prisma raw SQL injection (`$queryRawUnsafe`, `$executeRawUnsafe`), disabled JWT verification (`verify=False`, `ignoreExpiration: true`, `algorithm: 'none'`), CORS reflection with credentials (`Access-Control-Allow-Credentials: true`), and Vue `v-html` non-constant binding without sanitizer.
  - **AI-Application Rules (`sast.toml`)**: Added detection for prompt construction taking untrusted tainted inputs (`CWE-1427`), excessive agency in agent tools (`CWE-1426`), unvalidated LLM output passed to execution sinks (`eval`, `exec`, `subprocess.Popen`), RAG file ingestion, and frontend exposures of server-side AI API tokens.
- **Multi-Model Failover & Privacy Guard**:
  - Opt-in automatic failover (`CRY_FAILOVER=on`) across primary and secondary inference providers on HTTP 429 rate limits or 5xx server errors.
  - **Privacy Guard**: Hard boundary preventing source code targeted at local inference endpoints (`localhost`, `127.0.0.1`, `ollama`) from ever failing over to remote cloud APIs.
  - Provider model validation (`cry check`) querying provider `/models` endpoints.
  - Comprehensive documentation in `docs/MODELS.md` covering model selection, latency, accuracy, cost, and privacy.
  - Interactive configuration wizard in `cry configure` with hidden password prompts (`password=True`).
- **Passive Network Footprint Analysis (`cry net --footprint .`)**:
  - Multi-format IP normalization engine (`cry/network_ip.py`) canonicalizing dword decimal integers (`2130706433`), hex (`0x7f000001`), dotted octal (`0177.0.0.1`), IPv6-mapped IPv4 (`::ffff:127.0.0.1`), AWS IMDSv2 IPv6 (`fd00:ec2::254`), and shortened BSD notation.
  - SSRF obfuscation detection flagging non-standard IP representations designed to bypass regex blocklists.
  - Hardcoded Cloud Metadata and Link-Local address detection in source code and configurations.
  - Passive project footprint mode discovering all declared endpoints without transmitting a single network packet.
- **Authorized Active Network Probing (`cry net TARGET`)**:
  - **Pre-flight Target Authorization Gate**: Mandatory proof of control (DNS TXT record `cry-verification=<token>` or HTTP `/.well-known/cry-challenge.txt`) before probing public hosts.
  - Verification CLI workflow: `cry net TARGET --authorize`.
  - Local scanning safety: Probing loopback or private RFC-1918 subnets requires explicit `--allow-local`.
  - Permanent Cloud Metadata Protection: `169.254.169.254` is strictly prohibited from active probing under all circumstances.
  - **DNS Rebinding Defense**: Real-time IP re-resolution before socket connections aborts if a public domain shifts to internal subnets.
  - **Active TCP Reachability**: Probing default top 15 ports or user-supplied `--ports` (capped at 100 ports max) with short 1.5s timeouts and rate limiting.
  - **Public Database Exposure Alerts**: High/Critical severity alerts when PostgreSQL, MySQL, Redis, MongoDB, or Elasticsearch are exposed on public IPs.
  - **Deep TLS & Cipher Review**: Certificate validity, expiration alerts (< 30 days), weak cipher detection (RC4, 3DES, CBC), and legacy protocol probes (TLS 1.0/1.1) with honest platform OpenSSL limitation documentation.
  - **Edge CDN / WAF Detection**: Informational identification of Cloudflare, CloudFront, Fastly, Akamai, Vercel, Netlify, and Imperva.
  - **Service Offline Detection**: Automatically detects when a target service is offline (`FILTERED`/`CLOSED`) and gracefully skips HTTP security header evaluation, rendering a dedicated `STATUS: SERVICE OFFLINE` indicator.
  - **Audit Logging**: Immutable local scan records written to `~/.cry/audit.log` (with automatic fallback to `.cry/audit.log`).
  - **Non-Certifying Observability Assurance**: Strict policy stating CRY reports technical observations and never claims a host is "secure".
- **🐧 Host & Linux System Health Monitor (`cry check`)**:
  - Live host telemetry table integrated into `cry check` and interactive menu: Hostname, active session user, OS platform, synchronized UTC date & time, system uptime, and Unix load averages.
  - Host computing metrics: CPU core count and utilization %, RAM memory usage and capacity %, and filesystem disk usage.
  - Process and connectivity monitoring: Active process count and TCP network/DNS reachability checks.
  - Proactive system health alerts for critical disk capacity (>90%), elevated memory (>90%), and peak CPU load (>95%).
  - Timestamped health report generation: Exporting structured plain-text health reports via `cry check --report`.
  - Standalone Ubuntu Linux Bash script (`scripts/system_health.sh`) providing identical native Linux command-line monitoring.

### Changed
- Bumped version to `0.4.0`.
- Expanded interactive CLI menu Option `[3]` into a guided sub-menu with 4 network actions.
- Updated `BENCHMARK.md` with v0.3 vs v0.4 ground-truth metrics.
- Updated `README.md` with modern rules, failover, passive footprinting, and active network authorization guides.

---

## [0.3.0] - 2026-11-17
- Stable finding fingerprints resilient to line shifts.
- Baseline support (`cry baseline create`, `cry scan --baseline`).
- Inline suppressions with mandatory reasons (`cry-ignore: <rule-id> reason: <text>`).
- Path exclusions with `.cryignore`.
- SARIF 2.1.0 output export (`cry scan --format sarif -o results.sarif`).
- Deterministic exit codes (0 = SHIP, 1 = FIX_FIRST, 2 = DONT_SHIP, 3 = Tool Error).
- GitHub Action (`action.yml`), PR comments, and pre-commit hook.
- Automated code fix suggestions (`cry fix`).

---

## [0.2.0] - 2026-11-15
- AST taint dataflow analysis for Python and JavaScript/TypeScript.
- Default exclusions for vendor directories, lockfiles, and minified bundles.
- Supply-chain SCA scanner and config audit engines.
- Compact Rich terminal output and interactive welcome menu.
- Real-app evals suite against OWASP Juice Shop, NodeGoat, and DVWA.

---

## [0.1.0] - 2026-11-13
- Initial release of CRY CLI security scanner.
- Regex-based Secrets and SAST scanners.
- LLM-assisted context triage and risk reasoning engine.
