"""Triage engine: coordinates code context extraction, LLM reasoning, and verdict reporting."""

from pathlib import Path

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
from cry.triage.client import LLMClient, LLMClientError
from cry.triage.prompts import TRIAGE_SYSTEM_PROMPT, build_triage_user_prompt


def extract_code_context(
    base_dir: Path,
    file_path_str: str | None,
    line_start: int | None,
    context_lines: int = 10,
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


def _is_test_file(file_path_str: str | None, base_dir: Path | None = None) -> bool:
    """Check if file lives under a test, mock, fixture, or sample directory."""
    if not file_path_str:
        return False
    p = Path(file_path_str)
    full_path = (base_dir / p) if (base_dir and not p.is_absolute()) else p
    parts = {part.lower() for part in full_path.parts}
    return bool(parts & {"test", "tests", "mock", "mocks", "fixture", "fixtures", "evals", "samples"})


def _generate_deep_heuristic_reasoning(f: Finding) -> str:
    """Generate in-depth security threat modeling and exploit mechanics for offline or fallback analysis."""
    title_lower = f.title.lower()
    cwe = f.cwe_id or "CWE-General"

    if f.category == Category.SECRET_EXPOSURE or "secret" in title_lower or "key" in title_lower or "token" in title_lower:
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

    if f.category == Category.INSECURE_DEPENDENCY or "package" in title_lower or "depend" in title_lower:
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
    if "secret" in title_lower or "key" in title_lower or "token" in title_lower or f.category == Category.SECRET_EXPOSURE:
        return "Remove hardcoded secret from repository, revoke the exposed key immediately in your provider console, and inject via environment variables."
    if f.category == Category.INSECURE_DEPENDENCY or "package" in title_lower or "depend" in title_lower:
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
        return 'await db.query("SELECT * FROM items WHERE id = $1", [itemId]);' if is_js else 'cursor.execute("SELECT * FROM items WHERE id = %s", (item_id,))'
    if "secret" in title_lower or "token" in title_lower or f.category == Category.SECRET_EXPOSURE:
        return 'const API_KEY = process.env.API_KEY;' if is_js else 'API_KEY = os.environ["API_KEY"]'
    if "command" in title_lower:
        return 'execFile("ping", ["-c", "1", host], callback);' if is_js else 'subprocess.run(["ping", "-c", "1", host], capture_output=True, check=True)'
    if "eval" in title_lower:
        return 'const data = JSON.parse(userInput);' if is_js else 'import json\ndata = json.loads(user_input)'
    return None


class TriageEngine:
    """Orchestrates security finding triage using code context and LLM analysis."""

    def __init__(self, client: LLMClient | None = None) -> None:
        self.client = client or LLMClient()

    async def triage_findings(
        self,
        findings: list[Finding],
        target_dir: Path,
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

        # 1. Extract context for each finding
        findings_with_context: list[tuple[Finding, str | None]] = []
        for f in findings:
            ctx = extract_code_context(target_dir, f.file_path, f.line_start)
            findings_with_context.append((f, ctx))

        # 2. If client is not configured, fall back to heuristic baseline
        if not self.client.is_configured:
            return self._heuristic_fallback(findings, target_dir)

        # 3. Query LLM in chunks of at most 5 findings to guarantee maximum depth
        chunk_size = 5
        batches = [
            findings_with_context[i : i + chunk_size]
            for i in range(0, len(findings_with_context), chunk_size)
        ]

        finding_map = {f.id: f for f in findings}
        blockers: list[TriagedFinding] = []
        warnings: list[TriagedFinding] = []
        likely_false_positives: list[TriagedFinding] = []
        total_usage = TokenUsage()
        llm_errors: list[str] = []

        for batch in batches:
            user_prompt = build_triage_user_prompt(batch)
            try:
                data, usage = await self.client.chat_completion_json(
                    system_prompt=TRIAGE_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                )
                total_usage.prompt_tokens += usage.prompt_tokens
                total_usage.completion_tokens += usage.completion_tokens
                total_usage.total_tokens += usage.total_tokens
                total_usage.estimated_cost_usd += usage.estimated_cost_usd

                raw_results = data.get("triage_results", [])
                batch_triaged_ids = set()

                for item in raw_results:
                    fid = item.get("finding_id")
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
                    )

                    if status == TriageStatus.CONFIRMED_BLOCKER:
                        blockers.append(triaged)
                    elif status in (TriageStatus.WARNING, TriageStatus.NEEDS_MANUAL_REVIEW):
                        warnings.append(triaged)
                    elif status == TriageStatus.LIKELY_FALSE_POSITIVE:
                        likely_false_positives.append(triaged)

                # Fallback for any items in batch missed by LLM
                for f, _ in batch:
                    if f.id not in batch_triaged_ids:
                        default_status = (
                            TriageStatus.CONFIRMED_BLOCKER
                            if f.severity == Severity.CRITICAL
                            else TriageStatus.WARNING
                        )
                        fallback_triaged = TriagedFinding(
                            finding=f,
                            status=default_status,
                            exploitability_reasoning=_generate_deep_heuristic_reasoning(f),
                            plain_english_explanation=f.description,
                            fix_recommendation=_generate_actionable_fix(f),
                            suggested_replacement_code=_generate_fallback_replacement_code(f),
                        )
                        if default_status == TriageStatus.CONFIRMED_BLOCKER:
                            blockers.append(fallback_triaged)
                        else:
                            warnings.append(fallback_triaged)

            except LLMClientError as e:
                llm_errors.append(str(e))
                # Fall back to heuristic for this batch
                for f, _ in batch:
                    default_status = (
                        TriageStatus.CONFIRMED_BLOCKER
                        if f.severity == Severity.CRITICAL
                        else TriageStatus.WARNING
                    )
                    fallback_triaged = TriagedFinding(
                        finding=f,
                        status=default_status,
                        exploitability_reasoning=_generate_deep_heuristic_reasoning(f),
                        plain_english_explanation=f.description,
                        fix_recommendation=_generate_actionable_fix(f),
                        suggested_replacement_code=_generate_fallback_replacement_code(f),
                    )
                    if default_status == TriageStatus.CONFIRMED_BLOCKER:
                        blockers.append(fallback_triaged)
                    else:
                        warnings.append(fallback_triaged)

        # 4. Determine final verdict
        if blockers:
            final_verdict = Verdict.DONT_SHIP
            summary = (
                f"🚨 DEPLOYMENT BLOCKED: Discovered {len(blockers)} critical security blocker(s) "
                f"and {len(warnings)} warning(s). Immediate remediation required before release."
            )
        elif warnings:
            final_verdict = Verdict.FIX_FIRST
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
            summary += f" (Note: Partial AI fallback occurred: {llm_errors[0]})"

        return VerdictReport(
            verdict=final_verdict,
            summary=summary,
            target=str(target_dir),
            total_raw_findings=len(findings),
            blockers=blockers,
            warnings=warnings,
            likely_false_positives=likely_false_positives,
            token_usage=total_usage,
        )

    def _heuristic_fallback(self, findings: list[Finding], target_dir: Path) -> VerdictReport:
        """Deterministic, comprehensive security evaluation when LLM is unavailable."""
        blockers: list[TriagedFinding] = []
        warnings: list[TriagedFinding] = []
        likely_false_positives: list[TriagedFinding] = []

        for f in findings:
            in_test_file = _is_test_file(f.file_path, target_dir)

            if f.category == Category.SECRET_EXPOSURE and in_test_file:
                status = TriageStatus.LIKELY_FALSE_POSITIVE
                reasoning = (
                    f"Test/Mock Credential ({f.title}): Located inside a test or fixture directory ({f.file_path}). "
                    "This is not active in production runtime traffic, but should still be verified and excluded from build artifacts."
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
                f"🚨 DEPLOYMENT BLOCKED: Discovered {len(blockers)} critical security blocker(s) and {len(warnings)} warning(s). "
                "Your application contains active vulnerabilities that expose credentials or allow arbitrary command/database execution. "
                "Review the replacement code in the Blockers table below and resolve them before shipping."
            )
        elif warnings:
            verdict = Verdict.FIX_FIRST
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
        )
