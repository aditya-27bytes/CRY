# Changelog

All notable changes to the CRY project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.1] - 2026-11-19

### Fixed
- **CLI Architecture & Terminal UX**:
  - Restructured monolithic `cry/cli.py` and `cry/scanners/network.py` into modular command submodules (`cry/commands/`) and network engines (`cry/scanners/network_*.py`).
  - Implemented smart terminal table rollup: displays the top 10 actionable warnings in terminal with categorized summaries for remaining items to eliminate terminal overflow, while preserving full vulnerability details in Markdown (`-m`) and JSON (`-o`) exports. Added `--all` (`-a`) to inspect all items in terminal.
- **Network & Host Intelligence**:
  - Added IPv6 dual-stack socket probing (`AF_INET6` fallback) for `localhost` to reliably probe modern dev servers binding to `::1` (e.g. Vite on Node 18+).
  - Excluded internal security engines, rule catalogs, and benchmark datasets (`evals/datasets`) from self-flagging in network scans.
- **Multi-Model Triage Resilience**:
  - Added automatic JSON salvage from `failed_generation` and constraint-free fallback retry when LLM providers (e.g. Groq) return `HTTP 400 json_validate_failed`.
  - Added resilient JSON cleanup (`_clean_and_parse_json`) supporting markdown fences, trailing commas, and truncated bracket recovery.
  - Sanitized verdict summary banners to prevent raw API error dumps.
- **Accuracy & Noise Reduction**:
  - Filtered false positive credential alarms in documentation files (`.md`, `.rst`, `.txt`, `docs/`) and obvious placeholder examples (`user:password`, `<PASSWORD>`, `xxxx`, `changeme`).
  - Downgraded findings in test, mock, fixture, and build configuration files (`Gruntfile.js`, `webpack.config.js`) from blockers to non-blocking warnings (`TriageStatus.WARNING`) and tagged with file provenance.
  - Added CLI flag `--include-tests-and-docs` to restore full blocker severity when auditing test suites or documentation.
  - Fixed `.gitignore` directory and file exclusion accounting in `cry/exclusions.py` so ignored file counts and reason statistics are accurately recorded in scan summaries.
- **Taint Analysis**:
  - Closed confirmed taint tracking gaps in Python (`ast.NodeVisitor`) and JavaScript/TypeScript: propagated taint across string concatenation, f-strings, `str.format`, `%` formatting, `.join()`, and template literals.
  - Propagated taint across dictionary subscripting (`d["k"]`), list indexing, and attribute access.
  - Integrated sanitizers and allowlist guard checks (`int()`, `float()`, `shlex.quote()`, `DOMPurify.sanitize()`, and domain/path allowlist validation).
- **Vulnerability Detection**:
  - Added detection for NoSQL Injection: MongoDB `$where` clauses with string concatenation or template interpolation (`CRY-NOSQL-001`, Critical, CWE-943) and unvalidated query operator injection (`CRY-NOSQL-002`, High, CWE-943).
  - Added detection for Server-Side Request Forgery (`CRY-SSRF-001`, Critical, CWE-918) flagging dynamic outbound HTTP requests (`needle`, `axios`, `fetch`, `requests`, `httpx`) lacking strict allowlists or normalized IP verification.
- **Real-App Benchmark Harness**:
  - Replaced misleading claims regarding Juice Shop, NodeGoat, and DVWA with an authentic real-app benchmark harness (`cry eval --real-apps`) backed by `evals/real_apps/manifest.json`.
  - Pinned OWASP NodeGoat to commit `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` with verified ground truth (7 blockers, 4 warnings).
  - Relabeled synthetic test samples as "synthetic regression suite" across all code, datasets, and documentation.
  - Rewrote `BENCHMARK.md` to display actual execution outputs, timestamps, and verifiable commit hashes.

### Removed
- Removed off-mission host telemetry and Linux system health monitoring (`cry/system_health.py`, `scripts/system_health.sh`, and `cry check --report`) to focus exclusively on application and network security scanning.

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

### Changed
- Bumped version to `0.4.0`.
- Expanded interactive CLI menu Option `[3]` into a guided sub-menu with 4 network actions.
- Updated `BENCHMARK.md` with v0.3 vs v0.4 ground-truth metrics.
- Updated `README.md` with modern rules, failover, passive footprinting, and active network authorization guides.

---

## [0.3.0] - 2026-11-17

### Added
- Multi-model evaluation and side-by-side comparison command (`cry eval --compare`).
- Structured JSON and Markdown export for evaluation reports.
- Initial declarative rules engine structure.

### Planned (Not shipped in this release)
- Adoption features planned for future releases:
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

### Added
- Initial AST taint dataflow visitor for Python and regex pattern matcher for JavaScript/TypeScript.
- Default exclusions for vendor directories (`node_modules`, `vendor/`), lockfiles, and minified bundles.
- Supply-chain SCA scanner and config audit engines.
- Rich terminal output and interactive welcome menu.
- Synthetic regression evaluation suite of 13 paired test cases scored across OWASP Top 10 categories (derived from synthetic mock test cases, not real-app clones).

---

## [0.1.0] - 2026-11-13
- Initial release of CRY CLI security scanner.
- Regex-based Secrets and SAST scanners.
- LLM-assisted context triage and risk reasoning engine.
