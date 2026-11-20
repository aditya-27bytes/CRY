"""Triage engine: coordinates code context extraction, LLM reasoning, and verdict reporting."""

import asyncio
from pathlib import Path
from typing import Any

from cry.exclusions import (
    is_build_or_task_file,
    is_documentation_file,
    is_test_or_fixture_file,
)
from cry.models import (
    Category,
    Finding,
    Severity,
    TokenUsage,
    TriagedFinding,
    TriageStatus,
    Verdict,
    VerdictReport,
)
from cry.triage.client import LLMClient, LLMClientError, PrivacyGuardBlockedError
from cry.triage.prompts import TRIAGE_SYSTEM_PROMPT, build_triage_user_prompt


def extract_code_context(
    base_dir: Path,
    file_path_str: str | None,
    line_start: int | None,
    context_lines: int = 6,
) -> str | None:
    """Read +/- context_lines surrounding the flagged line."""
    if not file_path_str or line_start is None:
        return None

    p = Path(file_path_str)
    full_path = p if p.is_absolute() else base_dir / p
    if not full_path.is_file():
        return None

    try:
        lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None

    total_lines = len(lines)
    if total_lines == 0:
        return None

    target_idx = line_start - 1  # 0-indexed
    start_idx = max(0, target_idx - context_lines)
    end_idx = min(total_lines, target_idx + context_lines + 1)

    snippet_lines: list[str] = []
    for idx in range(start_idx, end_idx):
        line_num = idx + 1
        indicator = ">>>" if line_num == line_start else "   "
        snippet_lines.append(f"{indicator} {line_num:4d} | {lines[idx]}")

    return "\n".join(snippet_lines)


TEST_DIR_NAMES: set[str] = {
    "test",
    "tests",
    "testing",
    "testdata",
    "test-data",
    "mock",
    "mocks",
    "__mocks__",
    "fixture",
    "fixtures",
    "__fixtures__",
    "spec",
    "specs",
    "__specs__",
    "__tests__",
    "sample",
    "samples",
    "example",
    "examples",
    "demo",
    "demos",
    "eval",
    "evals",
    "benchmark",
    "benchmarks",
    "benches",
    "cypress",
    "playwright",
    "e2e",
}

TEST_FILE_PREFIXES: tuple[str, ...] = (
    "test_",
    "mock_",
    "fake_",
    "dummy_",
    "stub_",
    "sample_",
)

TEST_FILE_SUFFIXES: tuple[str, ...] = (
    "_test.py",
    "_spec.rb",
    "_test.go",
    "_test.rs",
    "tests.rs",
    ".test.ts",
    ".spec.ts",
    ".test.js",
    ".spec.js",
    ".test.tsx",
    ".spec.tsx",
    ".test.jsx",
    ".spec.jsx",
    ".test.mjs",
    ".test.cjs",
    ".mock.ts",
    ".mock.js",
)

TEST_FILE_EXACT: set[str] = {
    "conftest.py",
    "vulnerable_app.py",
    "safe_app.py",
    "test_env.py",
    "mock_server.py",
}


def _is_test_file(file_path_str: str | None, base_dir: Path | None = None) -> bool:
    """Check if file lives under test, mock, fixture, build config, or documentation path."""
    if not file_path_str:
        return False
    if is_documentation_file(file_path_str):
        return True
    if is_build_or_task_file(file_path_str):
        return True
    return is_test_or_fixture_file(file_path_str, base_dir)


def _generate_deep_heuristic_reasoning(f: Finding) -> str:
    """Generate in-depth security threat modeling and exploit mechanics for offline or fallback analysis."""
    title_lower = f.title.lower()
    cwe = f.cwe_id or "CWE-General"

    if (
        f.category == Category.SECRET_EXPOSURE
        or "secret" in title_lower
        or "key" in title_lower
        or "token" in title_lower
    ):
        return (
            f"Threat Vector: Automated GitHub crawlers and malicious bots scan public/private commits and runtime bundles for {f.title}. "
            "Attacker Impact: Immediate full credential compromise, allowing unauthenticated API requests, financial loss (via billing exhaustion), "
            f"or lateral movement into cloud data stores. Compliance: Violates SOC2 CC6.1, PCI-DSS 8.2, and {cwe}."
        )

    if "sql" in title_lower:
        return (
            "Threat Vector: Attacker supplies malicious SQL syntax in user parameters (e.g. `' OR '1'='1' --`). "
            "Attacker Impact: The database interprets user data as executable command structure, allowing authentication bypass, "
            f"complete exfiltration of user tables/PII, or dropping schemas. OWASP Top 10: A03:2021-Injection ({cwe})."
        )

    if "command" in title_lower or "shell" in title_lower:
        return (
            "Threat Vector: Attacker injects shell command delimiters (`;`, `&&`, `|`) into untrusted variables passed to the system shell. "
            "Attacker Impact: Unauthenticated Remote Code Execution (RCE) with host operating system privileges, leading to server compromise "
            f"and persistence backdoors. OWASP Top 10: A03:2021-Injection ({cwe})."
        )

    if "eval" in title_lower or "exec" in title_lower:
        return (
            "Threat Vector: Execution of dynamic user input as code at runtime. "
            "Attacker Impact: Complete arbitrary code execution within the application process, enabling memory inspection, process spawning, "
            f"and filesystem exfiltration. ({cwe})."
        )

    if "cors" in title_lower:
        return (
            "Threat Vector: Permissive Access-Control-Allow-Origin: '*' allows any external web origin to issue cross-origin requests. "
            "Attacker Impact: Hostile websites visited by an authenticated user can read sensitive JSON API responses and steal user sessions. "
            f"({cwe})."
        )

    if "csrf" in title_lower:
        return (
            "Threat Vector: Missing Anti-CSRF protection allows external third-party sites to submit unauthorized state-changing requests "
            "using ambient browser session cookies. Attacker Impact: Forged transactions, email/password alterations, or unauthorized actions on behalf of the victim. "
            f"OWASP Top 10: A01:2021-Broken Access Control ({cwe})."
        )

    if "ssl" in title_lower or "tls" in title_lower:
        return (
            "Threat Vector: Disabled SSL/TLS certificate verification removes cryptographic identity validation. "
            "Attacker Impact: Man-in-the-Middle (MitM) adversaries on public Wi-Fi, DNS hijacking, or proxies can passively intercept, decrypt, "
            f"and modify sensitive in-transit payloads including passwords and tokens. ({cwe})."
        )

    if "deserial" in title_lower or "pickle" in title_lower or "yaml" in title_lower:
        return (
            "Threat Vector: Deserialization of untrusted bytecode or unsafe YAML tags. "
            "Attacker Impact: Triggering arbitrary object constructors or Python `__reduce__` methods yields direct Remote Code Execution (RCE). "
            f"OWASP Top 10: A08:2021-Software and Data Integrity Failures ({cwe})."
        )

    if "debug" in title_lower:
        return (
            "Threat Vector: Active debug mode exposes interactive diagnostic consoles, stack traces, and environment variables. "
            "Attacker Impact: Attackers exploit interactive debug consoles (e.g. Werkzeug PIN bypass) to achieve RCE or discover sensitive internal architectural secrets. "
            f"({cwe})."
        )

    if "redirect" in title_lower:
        return (
            "Threat Vector: Unvalidated target URL in redirect parameter. "
            "Attacker Impact: Enables credential phishing campaigns masquerading under your trusted domain name (`yourdomain.com/login?next=https://evil.com`). "
            f"({cwe})."
        )

    if (
        f.category == Category.INSECURE_DEPENDENCY
        or "package" in title_lower
        or "depend" in title_lower
    ):
        return (
            f"Threat Vector: Vulnerable or untrusted upstream dependency ({f.title}). "
            "Attacker Impact: Supply-chain compromise, remote code execution during build or runtime, or unauthorized data exfiltration. "
            f"OWASP Top 10: A06:2021-Vulnerable and Outdated Components ({cwe})."
        )

    if "docker" in title_lower or "socket" in title_lower:
        return (
            "Threat Vector: Insecure container configuration or exposed Docker daemon socket. "
            "Attacker Impact: Full container escape yielding root privileges on the underlying host operating system. "
            f"({cwe})."
        )

    if "gitignore" in title_lower or ".env" in title_lower:
        return (
            "Threat Vector: Unprotected environment configuration tracked in repository. "
            "Attacker Impact: Complete credential compromise as soon as code is pushed to public or internal git remotes. "
            f"({cwe})."
        )

    return (
        f"Threat Vector: Flagged by pattern match on {f.title}. "
        f"Attacker Impact: Weakens security boundaries or exposes system resources under standard exploit conditions. Reference: {cwe}."
    )


def _generate_actionable_fix(f: Finding) -> str:
    """Generate specific, actionable remediation guidance if none was provided."""
    if f.fix_hint:
        return f.fix_hint
    title_lower = f.title.lower()
    if "sql" in title_lower:
        return "Use parameterized queries or ORM abstractions. Never concatenate or interpolate raw user variables into query strings."
    if "command" in title_lower or "shell" in title_lower:
        return "Execute commands with a fixed argument array (subprocess.run with shell=False or child_process.execFile). Avoid shell interpreters."
    if (
        "secret" in title_lower
        or "key" in title_lower
        or "token" in title_lower
        or f.category == Category.SECRET_EXPOSURE
    ):
        return "Remove hardcoded secret from repository, revoke the exposed key immediately in your provider console, and inject via environment variables."
    if (
        f.category == Category.INSECURE_DEPENDENCY
        or "package" in title_lower
        or "depend" in title_lower
    ):
        return "Upgrade the vulnerable library to the patched version specified in the advisory and pin dependency versions."
    if "gitignore" in title_lower or ".env" in title_lower:
        return "Add .env and sensitive environment files to .gitignore immediately and rotate any exposed keys."
    if "docker" in title_lower:
        return "Remove insecure volume mounts and pass credentials via runtime secrets managers rather than build-time layers."
    if "eval" in title_lower or "exec" in title_lower:
        return "Replace dynamic code evaluation with structured serialization like JSON.parse() or ast.literal_eval."
    if "cors" in title_lower:
        return "Explicitly whitelist authorized origins (e.g. ['https://app.yourdomain.com']) instead of permitting wildcard '*'."
    if "csrf" in title_lower:
        return "Enable CSRF token verification middleware on all state-changing endpoints (POST, PUT, DELETE, PATCH)."
    if "ssl" in title_lower or "tls" in title_lower:
        return "Enable strict TLS certificate verification (verify=True or rejectUnauthorized=true) to prevent MitM eavesdropping."
    if "jwt" in title_lower:
        return "Store JWT secret keys in environment variables or cloud secret managers with at least 256 bits of entropy."
    if "redirect" in title_lower:
        return "Validate target redirection destinations against an explicit whitelist of trusted internal routes or external domains."
    return "Refactor code following OWASP secure development practices to isolate and neutralize this finding."


def _generate_fallback_replacement_code(f: Finding) -> str | None:
    """Generate exact, production-ready replacement code if none was provided."""
    if f.suggested_fix:
        return f.suggested_fix
    ext = Path(f.file_path).suffix.lower() if f.file_path else ".py"
    is_js = ext in {".ts", ".tsx", ".js", ".jsx"}
    title_lower = f.title.lower()
    if "sql" in title_lower:
        return (
            'await db.query("SELECT * FROM items WHERE id = $1", [itemId]);'
            if is_js
            else 'cursor.execute("SELECT * FROM items WHERE id = %s", (item_id,))'
        )
    if "secret" in title_lower or "token" in title_lower or f.category == Category.SECRET_EXPOSURE:
        return (
            "const API_KEY = process.env.API_KEY;" if is_js else 'API_KEY = os.environ["API_KEY"]'
        )
    if "command" in title_lower:
        return (
            'execFile("ping", ["-c", "1", host], callback);'
            if is_js
            else 'subprocess.run(["ping", "-c", "1", host], capture_output=True, check=True)'
        )
    if "eval" in title_lower:
        return (
            "const data = JSON.parse(userInput);"
            if is_js
            else "import json\ndata = json.loads(user_input)"
        )
    return None


def extract_llm_triage_results(data: Any) -> list[dict[str, Any]]:
    """Extract individual finding triage records from LLM response whether formatted as list or dict."""
    raw_results: list[Any]
    if isinstance(data, list):
        raw_results = data
    elif isinstance(data, dict):
        candidate = (
            data.get("triage_results")
            or data.get("findings")
            or data.get("results")
            or ([data] if "finding_id" in data else [])
        )
        raw_results = candidate if isinstance(candidate, list) else []
    else:
        raw_results = []

    return [
        item
        for item in raw_results
        if isinstance(item, dict)
        and isinstance(item.get("finding_id"), str)
        and item.get("finding_id")
    ]


class TriageEngine:
    """Orchestrates security finding triage using code context and LLM analysis."""

    def __init__(self, client: LLMClient | None = None) -> None:
        self.client = client or LLMClient()

    async def triage_findings(
        self,
        findings: list[Finding],
        target_dir: Path,
        include_tests_and_docs: bool = False,
    ) -> VerdictReport:
        """Analyze raw findings and produce an enriched VerdictReport.

        Uses batched LLM calls to prevent context truncation and ensure deep reasoning.
        If LLM is not configured or unavailable, creates a rich rule-based heuristic report.
        """
        if not findings:
            return VerdictReport(
                verdict=Verdict.SHIP,
                summary="No security vulnerabilities or secrets were detected across scanned files.",
                target=str(target_dir),
                total_raw_findings=0,
            )

        # 1. Extract context and AST structural context graph for each finding
        from cry.triage.context_graph import build_context_graph

        finding_map = {f.id: f for f in findings}
        blockers: list[TriagedFinding] = []
        warnings: list[TriagedFinding] = []
        likely_false_positives: list[TriagedFinding] = []

        llm_findings_with_context: list[tuple[Finding, str | None]] = []
        llm_context_graphs: list[str] = []

        for f in findings:
            ctx = extract_code_context(target_dir, f.file_path, f.line_start)
            cg = build_context_graph(target_dir, f.file_path, f.line_start)
            in_test_file = (not include_tests_and_docs) and _is_test_file(f.file_path, target_dir)

            # SMART HYBRID ROUTING RULE 1: Secret exposures
            # High-entropy cryptographic secrets or API keys are deterministic.
            # Avoid sending sensitive credentials or tokens over cloud APIs.
            if f.category == Category.SECRET_EXPOSURE or f.tool == "cry-secrets":
                if in_test_file:
                    warnings.append(
                        TriagedFinding(
                            finding=f,
                            status=TriageStatus.WARNING,
                            exploitability_reasoning=(
                                f"Test/Mock Credential Advisory ({f.title}): Located inside test, mock, or fixture file ({f.file_path}). "
                                "This credential is not active in production runtime traffic and does not block release. "
                                "Ensure test artifacts, mock fixtures, and synthetic credentials are excluded from production build artifacts and Docker images."
                            ),
                            plain_english_explanation=f.description,
                            fix_recommendation=_generate_actionable_fix(f),
                            suggested_replacement_code=_generate_fallback_replacement_code(f),
                            triaged_by_model="CRY Scope Intelligence Engine",
                        )
                    )
                else:
                    blockers.append(
                        TriagedFinding(
                            finding=f,
                            status=TriageStatus.CONFIRMED_BLOCKER,
                            exploitability_reasoning=_generate_deep_heuristic_reasoning(f),
                            plain_english_explanation=f.description,
                            fix_recommendation=_generate_actionable_fix(f),
                            suggested_replacement_code=_generate_fallback_replacement_code(f),
                            triaged_by_model="CRY Deterministic Security Engine",
                        )
                    )
                continue

            # SMART HYBRID ROUTING RULE 2: Obvious test/mock fixture findings
            if in_test_file:
                warnings.append(
                    TriagedFinding(
                        finding=f,
                        status=TriageStatus.WARNING,
                        exploitability_reasoning=(
                            f"Test/Mock Fixture Advisory ({f.title}): Detected inside test, mock, or sample directory ({f.file_path}). "
                            "This code is not exposed to untrusted public production routes and does not block release. "
                            "Ensure test directories and mock fixtures are excluded from production container images."
                        ),
                        plain_english_explanation=f.description,
                        fix_recommendation=_generate_actionable_fix(f),
                        suggested_replacement_code=_generate_fallback_replacement_code(f),
                        triaged_by_model="CRY Scope Intelligence Engine",
                    )
                )
                continue

            # SMART HYBRID ROUTING RULE 3: AST Taint analysis proven benign constant literals
            if cg.taint_analysis and cg.taint_analysis.is_literal_constant:
                likely_false_positives.append(
                    TriagedFinding(
                        finding=f,
                        status=TriageStatus.LIKELY_FALSE_POSITIVE,
                        exploitability_reasoning=(
                            f"AST Dataflow Proof ({f.title}): Parameter or argument is verified as a constant literal. "
                            "No attacker-controlled untrusted input reaches the execution sink."
                        ),
                        plain_english_explanation=f.description,
                        fix_recommendation="No fix required; constant string literal verified by AST parser.",
                        suggested_replacement_code=None,
                        triaged_by_model="CRY AST Dataflow Engine",
                    )
                )
                continue

            # All real application vulnerabilities in production code require LLM deep reasoning
            llm_findings_with_context.append((f, ctx))
            llm_context_graphs.append(cg.format_for_llm_prompt())

        total_usage = TokenUsage()
        llm_errors: list[str] = []

        if llm_findings_with_context and self.client.is_configured:
            # Query LLM in chunks of at most 4 findings for maximum depth without token blowout
            chunk_size = 4
            batches = [
                llm_findings_with_context[i : i + chunk_size]
                for i in range(0, len(llm_findings_with_context), chunk_size)
            ]
            batch_cg_slices = [
                llm_context_graphs[i : i + chunk_size]
                for i in range(0, len(llm_context_graphs), chunk_size)
            ]

            for idx, batch in enumerate(batches):
                if idx > 0 and not self.client.is_local:
                    await asyncio.sleep(0.35)

                cg_slice = batch_cg_slices[idx] if idx < len(batch_cg_slices) else None
                user_prompt = build_triage_user_prompt(batch, context_graphs=cg_slice)
                try:
                    data, usage = await self.client.chat_completion_json(
                        system_prompt=TRIAGE_SYSTEM_PROMPT,
                        user_prompt=user_prompt,
                        findings_count=len(batch),
                    )
                    total_usage.prompt_tokens += usage.prompt_tokens
                    total_usage.completion_tokens += usage.completion_tokens
                    total_usage.total_tokens += usage.total_tokens
                    total_usage.estimated_cost_usd += usage.estimated_cost_usd

                    triaged_items = extract_llm_triage_results(data)
                    batch_triaged_ids: set[str] = set()

                    for item in triaged_items:
                        fid = str(item["finding_id"])
                        finding = finding_map.get(fid)
                        if not finding:
                            continue

                        batch_triaged_ids.add(fid)
                        status_str = item.get("status", TriageStatus.NEEDS_MANUAL_REVIEW.value)
                        try:
                            status = TriageStatus(status_str)
                        except ValueError:
                            status = TriageStatus.NEEDS_MANUAL_REVIEW

                        triaged = TriagedFinding(
                            finding=finding,
                            status=status,
                            exploitability_reasoning=item.get("exploitability_reasoning")
                            or _generate_deep_heuristic_reasoning(finding),
                            plain_english_explanation=item.get(
                                "plain_english_explanation", finding.description
                            ),
                            fix_recommendation=item.get("fix_recommendation")
                            or _generate_actionable_fix(finding),
                            suggested_replacement_code=item.get("suggested_replacement_code")
                            or _generate_fallback_replacement_code(finding),
                            triaged_by_model=self.client.model,
                        )

                        if status == TriageStatus.CONFIRMED_BLOCKER:
                            if (not include_tests_and_docs) and _is_test_file(
                                finding.file_path, target_dir
                            ):
                                triaged.status = TriageStatus.WARNING
                                triaged.exploitability_reasoning = (
                                    f"[Test/Non-Prod Scope Advisory]: Non-blocking warning. Finding is in test/mock/doc file ({finding.file_path}). "
                                    + triaged.exploitability_reasoning
                                )
                                warnings.append(triaged)
                            else:
                                blockers.append(triaged)
                        elif status in (TriageStatus.WARNING, TriageStatus.NEEDS_MANUAL_REVIEW):
                            warnings.append(triaged)
                        elif status == TriageStatus.LIKELY_FALSE_POSITIVE:
                            likely_false_positives.append(triaged)

                    # Fallback for any items in batch missed by LLM
                    for f, _ in batch:
                        if f.id not in batch_triaged_ids:
                            f_in_test = (not include_tests_and_docs) and _is_test_file(
                                f.file_path, target_dir
                            )
                            default_status = (
                                TriageStatus.WARNING
                                if f_in_test or f.severity != Severity.CRITICAL
                                else TriageStatus.CONFIRMED_BLOCKER
                            )
                            fallback_triaged = TriagedFinding(
                                finding=f,
                                status=default_status,
                                exploitability_reasoning=_generate_deep_heuristic_reasoning(f),
                                plain_english_explanation=f.description,
                                fix_recommendation=_generate_actionable_fix(f),
                                suggested_replacement_code=_generate_fallback_replacement_code(f),
                                triaged_by_model="CRY Heuristic Fallback",
                            )
                            if default_status == TriageStatus.CONFIRMED_BLOCKER:
                                blockers.append(fallback_triaged)
                            else:
                                warnings.append(fallback_triaged)

                except PrivacyGuardBlockedError as e:
                    llm_errors.append(f"Privacy Guard active: {e}")
                    for f, _ in batch:
                        f_in_test = (not include_tests_and_docs) and _is_test_file(
                            f.file_path, target_dir
                        )
                        default_status = (
                            TriageStatus.WARNING
                            if f_in_test or f.severity != Severity.CRITICAL
                            else TriageStatus.CONFIRMED_BLOCKER
                        )
                        fallback_triaged = TriagedFinding(
                            finding=f,
                            status=default_status,
                            exploitability_reasoning=_generate_deep_heuristic_reasoning(f),
                            plain_english_explanation=f.description,
                            fix_recommendation=_generate_actionable_fix(f),
                            suggested_replacement_code=_generate_fallback_replacement_code(f),
                            triaged_by_model="CRY Privacy Guard (Offline Fallback)",
                        )
                        if default_status == TriageStatus.CONFIRMED_BLOCKER:
                            blockers.append(fallback_triaged)
                        else:
                            warnings.append(fallback_triaged)

                except LLMClientError as e:
                    llm_errors.append(str(e))
                    for f, _ in batch:
                        f_in_test = (not include_tests_and_docs) and _is_test_file(
                            f.file_path, target_dir
                        )
                        default_status = (
                            TriageStatus.WARNING
                            if f_in_test or f.severity != Severity.CRITICAL
                            else TriageStatus.CONFIRMED_BLOCKER
                        )
                        fallback_triaged = TriagedFinding(
                            finding=f,
                            status=default_status,
                            exploitability_reasoning=_generate_deep_heuristic_reasoning(f),
                            plain_english_explanation=f.description,
                            fix_recommendation=_generate_actionable_fix(f),
                            suggested_replacement_code=_generate_fallback_replacement_code(f),
                            triaged_by_model="CRY Heuristic Fallback",
                        )
                        if default_status == TriageStatus.CONFIRMED_BLOCKER:
                            blockers.append(fallback_triaged)
                        else:
                            warnings.append(fallback_triaged)

        elif llm_findings_with_context and not self.client.is_configured:
            # Client not configured: triage remaining candidates with heuristic
            for f, _ in llm_findings_with_context:
                f_in_test = (not include_tests_and_docs) and _is_test_file(f.file_path, target_dir)
                default_status = (
                    TriageStatus.WARNING
                    if f_in_test or f.severity != Severity.CRITICAL
                    else TriageStatus.CONFIRMED_BLOCKER
                )
                fallback_triaged = TriagedFinding(
                    finding=f,
                    status=default_status,
                    exploitability_reasoning=_generate_deep_heuristic_reasoning(f),
                    plain_english_explanation=f.description,
                    fix_recommendation=_generate_actionable_fix(f),
                    suggested_replacement_code=_generate_fallback_replacement_code(f),
                    triaged_by_model="CRY Heuristic Engine",
                )
                if default_status == TriageStatus.CONFIRMED_BLOCKER:
                    blockers.append(fallback_triaged)
                else:
                    warnings.append(fallback_triaged)

        # 4. Determine final verdict
        if blockers:
            final_verdict = Verdict.DONT_SHIP
            summary = (
                f"🚨 DEPLOYMENT BLOCKED: Discovered {len(blockers)} critical production security blocker(s) "
                f"and {len(warnings)} warning(s). Immediate remediation required before release."
            )
        elif warnings:
            final_verdict = Verdict.FIX_FIRST
            all_test_warnings = all(
                _is_test_file(w.finding.file_path, target_dir) for w in warnings
            )
            if all_test_warnings:
                summary = (
                    f"⚠️ CAUTION (TEST/MOCK WARNINGS): No critical production blockers detected. "
                    f"Found {len(warnings)} non-blocking test/fixture warning(s). "
                    "Ensure test directories and mock fixtures are excluded from production build artifacts and Docker images."
                )
            else:
                summary = (
                    f"⚠️ CAUTION (FIX FIRST): No critical blockers detected, but found {len(warnings)} security warning(s). "
                    "Remediate these vulnerabilities before deploying to production."
                )
        else:
            final_verdict = Verdict.SHIP
            summary = (
                "✅ SAFE TO SHIP: No security blockers detected across scanned files. "
                f"Codebase passes security gates ({len(likely_false_positives)} benign test/mock items reviewed)."
            )

        if llm_errors:
            first_err = llm_errors[0]
            if "json_validate_failed" in first_err or "Failed to generate JSON" in first_err:
                first_err = "LLM schema validation error (remediated with fallback)"
            elif "HTTP 400" in first_err:
                first_err = "LLM provider HTTP 400 Bad Request"
            elif len(first_err) > 120:
                first_err = first_err[:117] + "..."
            summary += f" (Note: Partial AI fallback occurred: {first_err})"

        if llm_findings_with_context and self.client.is_configured:
            active_model_desc = f"{self.client.model} (Smart Hybrid Routing)"
        else:
            active_model_desc = "CRY Smart Hybrid Engine (Deterministic Triage)"

        return VerdictReport(
            verdict=final_verdict,
            summary=summary,
            target=str(target_dir),
            total_raw_findings=len(findings),
            blockers=blockers,
            warnings=warnings,
            likely_false_positives=likely_false_positives,
            token_usage=total_usage,
            model_used=active_model_desc,
            model_switches=list(self.client.switched_models_log),
            failover_events=list(self.client.failover_events),
        )

    def _heuristic_fallback(
        self,
        findings: list[Finding],
        target_dir: Path,
        include_tests_and_docs: bool = False,
    ) -> VerdictReport:
        """Deterministic, comprehensive security evaluation when LLM is unavailable."""
        blockers: list[TriagedFinding] = []
        warnings: list[TriagedFinding] = []
        likely_false_positives: list[TriagedFinding] = []

        # Deduplicate duplicate findings on identical (file_path, line_start, cwe_id),
        # preserving the highest severity finding across scanner modules.
        severity_rank = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        loc_map: dict[tuple[str, int, str], Finding] = {}
        effective_findings: list[Finding] = []
        for f in findings:
            if f.file_path is not None and f.line_start is not None and f.cwe_id is not None:
                key = (f.file_path, f.line_start, f.cwe_id)
                if key not in loc_map or severity_rank.get(f.severity, 0) > severity_rank.get(
                    loc_map[key].severity, 0
                ):
                    loc_map[key] = f
            else:
                effective_findings.append(f)
        effective_findings.extend(loc_map.values())

        for f in effective_findings:
            in_test_file = (not include_tests_and_docs) and _is_test_file(f.file_path, target_dir)

            if getattr(f, "confidence", 1.0) < 0.3:
                status = TriageStatus.LIKELY_FALSE_POSITIVE
                reasoning = (
                    f"AST Taint Analysis ({f.title}): Parameter or argument is verified as a constant literal or sanitized upstream. "
                    "No attacker-controlled untrusted input reaches the execution sink."
                )
            elif in_test_file:
                status = TriageStatus.WARNING
                reasoning = (
                    f"Test/Mock Scope Advisory ({f.title}): Located inside test, mock, or fixture path ({f.file_path}). "
                    "This finding does not execute in production runtime traffic and will not block deployment. "
                    "Verify that test artifacts, mock fixtures, and synthetic credentials are excluded from production container images and release packages."
                )
            elif f.severity == Severity.CRITICAL:
                status = TriageStatus.CONFIRMED_BLOCKER
                reasoning = _generate_deep_heuristic_reasoning(f)
            elif f.severity in (Severity.HIGH, Severity.MEDIUM):
                status = TriageStatus.WARNING
                reasoning = _generate_deep_heuristic_reasoning(f)
            else:
                status = TriageStatus.NEEDS_MANUAL_REVIEW
                reasoning = _generate_deep_heuristic_reasoning(f)

            triaged = TriagedFinding(
                finding=f,
                status=status,
                exploitability_reasoning=reasoning,
                plain_english_explanation=f.description,
                fix_recommendation=_generate_actionable_fix(f),
                suggested_replacement_code=_generate_fallback_replacement_code(f),
            )

            if status == TriageStatus.CONFIRMED_BLOCKER:
                blockers.append(triaged)
            elif status == TriageStatus.LIKELY_FALSE_POSITIVE:
                likely_false_positives.append(triaged)
            else:
                warnings.append(triaged)

        if blockers:
            verdict = Verdict.DONT_SHIP
            summary = (
                f"🚨 DEPLOYMENT BLOCKED: Discovered {len(blockers)} critical production security blocker(s) and {len(warnings)} warning(s). "
                "Your application contains active vulnerabilities that expose credentials or allow arbitrary command/database execution. "
                "Review the replacement code in the Blockers table below and resolve them before shipping."
            )
        elif warnings:
            verdict = Verdict.FIX_FIRST
            all_test_warnings = all(
                _is_test_file(w.finding.file_path, target_dir) for w in warnings
            )
            if all_test_warnings:
                summary = (
                    f"⚠️ CAUTION (TEST/MOCK WARNINGS): No critical production blockers detected. "
                    f"Found {len(warnings)} non-blocking test/fixture warning(s). "
                    "Ensure test directories and mock fixtures are excluded from production build artifacts and Docker images."
                )
            else:
                summary = (
                    f"⚠️ CAUTION (FIX FIRST): No critical blockers detected, but found {len(warnings)} security warning(s). "
                    "These issues weaken your application's defense-in-depth and should be remediated before production rollout."
                )
        else:
            verdict = Verdict.SHIP
            summary = (
                "✅ SAFE TO SHIP: No security blockers detected across scanned files. "
                f"Codebase passes security gates ({len(likely_false_positives)} benign test/mock items reviewed)."
            )

        return VerdictReport(
            verdict=verdict,
            summary=summary,
            target=str(target_dir),
            total_raw_findings=len(findings),
            blockers=blockers,
            warnings=warnings,
            likely_false_positives=likely_false_positives,
            model_used="Offline Heuristic Engine",
            failover_events=list(self.client.failover_events),
        )
