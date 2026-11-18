"""Secrets scanner: detects leaked API keys, tokens, passwords, and private keys in source code.

Uses a combination of high-precision regex signatures for known credential formats
and Shannon entropy analysis for detecting unknown high-randomness tokens.
Runs 100% in native Python — no external binaries required.
"""

import math
import re
import uuid
from pathlib import Path
from typing import Any

from cry.exclusions import ExclusionStats, GitIgnoreMatcher, should_skip_path
from cry.models import Category, Finding, Severity
from cry.scanners.base import BaseScanner

# ---------------------------------------------------------------------------
# Directories and extensions to skip
# ---------------------------------------------------------------------------
SKIP_DIRS: set[str] = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    ".next",
    ".nuxt",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
    ".egg-info",
}

SKIP_EXTENSIONS: set[str] = {
    ".pyc",
    ".pyo",
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".dat",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".lock",
    ".min.js",
    ".min.css",
    ".map",
}

# ---------------------------------------------------------------------------
# Credential signatures: (name, pattern, severity, CWE)
# Each pattern is compiled with IGNORECASE off unless specified.
# ---------------------------------------------------------------------------
SECRET_RULES: list[tuple[str, re.Pattern[str], Severity, str]] = [
    # ── Cloud Provider Keys ──
    (
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "AWS Secret Access Key",
        re.compile(
            r"""(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""
        ),
        Severity.CRITICAL,
        "CWE-798",
    ),
    # ── Stripe ──
    (
        "Stripe Live Secret Key",
        re.compile(r"""(sk_live_[0-9a-zA-Z]{24,})"""),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "Stripe Live Restricted Key",
        re.compile(r"""(rk_live_[0-9a-zA-Z]{24,})"""),
        Severity.CRITICAL,
        "CWE-798",
    ),
    # ── OpenAI ──
    (
        "OpenAI API Key",
        re.compile(r"""(sk-[A-Za-z0-9]{20,})"""),
        Severity.CRITICAL,
        "CWE-798",
    ),
    # ── Google ──
    (
        "Google API Key",
        re.compile(r"""(AIza[0-9A-Za-z\-_]{35})"""),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "Google OAuth Client Secret",
        re.compile(r"""client_secret['":\s]+([A-Za-z0-9_\-]{24,})"""),
        Severity.HIGH,
        "CWE-798",
    ),
    # ── GitHub ──
    (
        "GitHub Personal Access Token",
        re.compile(r"""(ghp_[A-Za-z0-9]{36,})"""),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "GitHub Fine-Grained PAT",
        re.compile(r"""(github_pat_[A-Za-z0-9_]{22,})"""),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "GitHub OAuth Access Token",
        re.compile(r"""(gho_[A-Za-z0-9]{36,})"""),
        Severity.CRITICAL,
        "CWE-798",
    ),
    # ── Supabase ──
    (
        "Supabase Service Role Key",
        re.compile(r"""(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"""),
        Severity.HIGH,
        "CWE-798",
    ),
    # ── Database Connection Strings ──
    (
        "Database Connection String with Password",
        re.compile(
            r"""((?:postgres|mysql|mongodb|redis|mssql)(?:ql)?://[^:]+:[^@\s'"]{4,}@[^\s'"]+)""",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "CWE-798",
    ),
    # ── Private Keys ──
    (
        "Private Key (RSA/EC/DSA/SSH)",
        re.compile(r"""(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"""),
        Severity.CRITICAL,
        "CWE-321",
    ),
    # ── Generic Patterns ──
    (
        "Hardcoded Password Assignment",
        re.compile(
            r"""(?:password|passwd|pwd|secret|token|api_key|apikey|api_secret|access_token)\s*[=:]\s*['"]([^'"]{8,})['"]""",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "CWE-798",
    ),
    # ── Slack / Discord / Twilio ──
    (
        "Slack Bot Token",
        re.compile(r"""(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})"""),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "Discord Bot Token",
        re.compile(r"""([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})"""),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "Twilio Auth Token",
        re.compile(
            r"""(?:twilio[_\s]*auth[_\s]*token)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""", re.IGNORECASE
        ),
        Severity.HIGH,
        "CWE-798",
    ),
    # ── SendGrid / Mailgun ──
    (
        "SendGrid API Key",
        re.compile(r"""(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"""),
        Severity.HIGH,
        "CWE-798",
    ),
]

# ---------------------------------------------------------------------------
# Files that commonly hold example/mock credentials (lower confidence)
# ---------------------------------------------------------------------------
LIKELY_SAFE_PATHS: set[str] = {
    "test",
    "tests",
    "spec",
    "mock",
    "fixture",
    "fixtures",
    "example",
    "examples",
    "sample",
    "samples",
    "__tests__",
    "__mocks__",
}


# ---------------------------------------------------------------------------
# Known test & mock placeholder tokens to ignore
# ---------------------------------------------------------------------------
PLACEHOLDER_KEYWORDS: tuple[str, ...] = (
    "placeholder",
    "changeme",
    "your_password",
    "your_secret",
    "your_key",
    "your_token",
    "insert_",
    "replace_",
    "dummy_secret",
    "dummy",
    "mock",
    "not_real",
    "fake",
    "test_token",
    "00000000",
)


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    length = len(data)
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_in_safe_path(file_path: Path) -> bool:
    """Check if file lives under a test/mock/fixture directory."""
    parts = {p.lower() for p in file_path.parts}
    return not parts.isdisjoint(LIKELY_SAFE_PATHS)


_CACHED_CATALOG_RULES: list[Any] | None = None


def _get_catalog_secret_rules(base_dir: Path) -> list[Any]:
    """Load and cache external catalog secret rules."""
    global _CACHED_CATALOG_RULES
    if _CACHED_CATALOG_RULES is None:
        try:
            from cry.rules.manager import RuleManager

            mgr = RuleManager(workspace_dir=base_dir)
            _CACHED_CATALOG_RULES = mgr.get_secret_rules()
        except Exception:
            _CACHED_CATALOG_RULES = []
    return _CACHED_CATALOG_RULES


def _should_skip_file(
    file_path: Path,
    max_size_mb: int = 5,
    base_dir: Path | None = None,
    include_vendor: bool = False,
    gitignore: GitIgnoreMatcher | None = None,
) -> bool:
    """Determine if a file should be skipped based on directory, extension, or size."""
    b_dir = base_dir or file_path.parent
    decision = should_skip_path(
        file_path,
        b_dir,
        include_vendor=include_vendor,
        gitignore=gitignore,
        max_file_size_mb=max_size_mb,
    )
    if decision.skip:
        return True

    # Skip by extension
    suffix = file_path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return True

    # Skip unit test implementation files (containing assertions/mock test data)
    name_lower = file_path.name.lower()
    if name_lower.startswith("test_") and name_lower.endswith(".py"):
        return True
    return name_lower.endswith(("_test.py", ".spec.ts", ".test.ts", ".spec.js", ".test.js"))


def scan_file(file_path: Path, base_dir: Path) -> list[Finding]:
    """Scan a single file for leaked secrets."""
    findings: list[Finding] = []
    relative_path = str(file_path.relative_to(base_dir))

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    # Skip self-flagging of scanner rules or catalog definitions
    if (
        file_path.name in ("secrets.py", "secrets.toml", "sast.toml", "sast.py")
        and "cry" in file_path.parts
    ):
        return findings

    lines = content.splitlines()

    ext = file_path.suffix.lower()
    is_js = ext in {".ts", ".tsx", ".js", ".jsx"}

    for line_num, line in enumerate(lines, start=1):
        # Skip comment-only lines that are documentation references
        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*", "<!--")) and not any(
            kw in stripped.lower() for kw in ("sk_live", "sk-", "akia", "ghp_", "password")
        ):
            continue

        # Skip test assertions checking strings (e.g. assert "sk_live" not in ...)
        if stripped.startswith(("assert ", "assert(", "expect(")):
            continue

        for rule_name, pattern, severity, cwe_id in SECRET_RULES:
            match = pattern.search(line)
            if match:
                secret_value = match.group(1) if match.lastindex else match.group(0)

                # Skip very short matches (likely false positives)
                if len(secret_value) < 8:
                    continue

                # Check for obviously fake / placeholder values
                lower_val = secret_value.lower()

                # For DB URLs, only check the password portion for placeholders
                if "://" in secret_value and "@" in secret_value:
                    pw_part = re.search(r":([^:@\s]+)@", secret_value)
                    val_to_check = pw_part.group(1).lower() if pw_part else lower_val
                else:
                    val_to_check = lower_val

                if any(placeholder in val_to_check for placeholder in PLACEHOLDER_KEYWORDS):
                    continue

                env_name = rule_name.upper().replace(" ", "_").replace("-", "_")
                if is_js:
                    fix_hint = (
                        f"Load credential from environment variables via process.env.{env_name}."
                    )
                    suggested_fix = f"const API_KEY = process.env.{env_name};"
                else:
                    fix_hint = (
                        f"Load credential from environment variables via os.environ['{env_name}']."
                    )
                    suggested_fix = f'API_KEY = os.environ["{env_name}"]'

                # Build the finding
                finding = Finding(
                    id=f"secret-{uuid.uuid4().hex[:12]}",
                    tool="cry-secrets",
                    title=rule_name,
                    description=f"Detected {rule_name} in source code. "
                    f"{'This file is in a test/mock directory — verify if this is a real credential.' if _is_in_safe_path(file_path) else 'This appears to be a live credential that should be removed immediately.'}",
                    category=Category.SECRET_EXPOSURE,
                    severity=severity,
                    file_path=relative_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=_redact_line(line.strip(), secret_value),
                    cwe_id=cwe_id,
                    fix_hint=fix_hint,
                    suggested_fix=suggested_fix,
                    raw_evidence=f"Matched rule: {rule_name}",
                )
                findings.append(finding)

        # Check external declarative secret rules (Supabase, HuggingFace, Slack, Twilio, etc.)
        for ext_rule in _get_catalog_secret_rules(base_dir):
            if any(f.line_start == line_num for f in findings):
                break
            for pat in ext_rule.compile_patterns():
                ext_match = pat.search(line)
                if ext_match:
                    secret_val = ext_match.group(1) if ext_match.groups() else ext_match.group(0)
                    if any(p in secret_val.lower() for p in PLACEHOLDER_KEYWORDS):
                        continue
                    if (
                        ext_rule.entropy_min is not None
                        and _shannon_entropy(secret_val) < ext_rule.entropy_min
                    ):
                        continue
                    env_var = ext_rule.name.upper().replace(" ", "_").replace("-", "_")
                    fix = (
                        f"const KEY = process.env.{env_var};"
                        if is_js
                        else f'KEY = os.environ["{env_var}"]'
                    )
                    findings.append(
                        Finding(
                            id=f"secret-{uuid.uuid4().hex[:12]}",
                            tool="cry-secrets",
                            title=ext_rule.name,
                            description=f"{ext_rule.description} {'(In test/mock directory).' if _is_in_safe_path(file_path) else ''}",
                            category=Category.SECRET_EXPOSURE,
                            severity=ext_rule.severity,
                            file_path=relative_path,
                            line_start=line_num,
                            line_end=line_num,
                            code_snippet=_redact_line(line.strip(), secret_val),
                            cwe_id=ext_rule.cwe_id,
                            fix_hint=ext_rule.fix_hint,
                            suggested_fix=ext_rule.suggested_fix or fix,
                            raw_evidence=f"Matched external rule: {ext_rule.rule_id}",
                            confidence=ext_rule.confidence,
                        )
                    )
                    break

        # Check for unclassified high-entropy tokens
        entropy_match = re.search(
            r"""(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[=:]\s*['"]([A-Za-z0-9_\-+/=]{20,})['"]""",
            line,
            re.IGNORECASE,
        )
        if entropy_match:
            candidate = entropy_match.group(1)
            lower_candidate = candidate.lower()
            if any(p in lower_candidate for p in PLACEHOLDER_KEYWORDS):
                continue

            entropy = _shannon_entropy(candidate)
            if entropy >= 3.8 and not any(f.line_start == line_num for f in findings):
                if is_js:
                    token_hint = "Store token in environment variables (.env) and access via process.env.SECRET_TOKEN."
                    token_fix = "const SECRET_TOKEN = process.env.SECRET_TOKEN;"
                else:
                    token_hint = "Store token in environment variables (.env) and access via os.environ['SECRET_TOKEN']."
                    token_fix = 'SECRET_TOKEN = os.environ["SECRET_TOKEN"]'

                findings.append(
                    Finding(
                        id=f"secret-{uuid.uuid4().hex[:12]}",
                        tool="cry-secrets",
                        title="High-Entropy Secret / Token",
                        description=f"Detected high-entropy token (entropy: {entropy:.2f}) assigned to sensitive variable.",
                        category=Category.SECRET_EXPOSURE,
                        severity=Severity.HIGH,
                        file_path=relative_path,
                        line_start=line_num,
                        line_end=line_num,
                        code_snippet=_redact_line(line.strip(), candidate),
                        cwe_id="CWE-798",
                        fix_hint=token_hint,
                        suggested_fix=token_fix,
                        raw_evidence=f"Entropy score: {entropy:.2f}",
                    )
                )

    return findings


def _redact_line(line: str, secret: str) -> str:
    """Partially redact the secret value in the code snippet for safe display."""
    if len(secret) <= 8:
        return line.replace(secret, "****")
    visible_prefix = secret[:4]
    visible_suffix = secret[-4:]
    redacted = f"{visible_prefix}...{visible_suffix}"
    return line.replace(secret, redacted)


def scan_directory(
    target_dir: Path,
    max_file_size_mb: int = 5,
    include_vendor: bool = False,
    stats: ExclusionStats | None = None,
) -> list[Finding]:
    """Scan an entire directory tree for leaked secrets.

    Args:
        target_dir: Root directory to scan.
        max_file_size_mb: Skip files larger than this.
        include_vendor: Whether to include vendor/minified/gitignored files.
        stats: Optional ExclusionStats instance to track skipped files.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    if not target_dir.is_dir():
        return findings

    gitignore = GitIgnoreMatcher(target_dir) if not include_vendor else None

    for file_path in target_dir.rglob("*"):
        if not file_path.is_file():
            continue
        decision = should_skip_path(
            file_path,
            target_dir,
            include_vendor=include_vendor,
            gitignore=gitignore,
            max_file_size_mb=max_file_size_mb,
        )
        if decision.skip:
            if stats and decision.reason:
                stats.record_skip(file_path, decision.reason)
            continue
        suffix = file_path.suffix.lower()
        if suffix in SKIP_EXTENSIONS:
            continue
        name_lower = file_path.name.lower()
        if name_lower.startswith("test_") and name_lower.endswith(".py"):
            continue
        if name_lower.endswith(("_test.py", ".spec.ts", ".test.ts", ".spec.js", ".test.js")):
            continue
        findings.extend(scan_file(file_path, target_dir))

    return findings


class SecretsScanner(BaseScanner):
    """Secrets scanner adapter conforming to BaseScanner."""

    @property
    def name(self) -> str:
        return "cry-secrets"

    @property
    def description(self) -> str:
        return "Scans files for hardcoded secrets, API tokens, and credentials using regex and entropy."

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path, base_dir: Path) -> list[Finding]:
        """Scan a single file directly."""
        return scan_file(file_path, base_dir)

    async def scan(
        self,
        target: Path | str,
        include_vendor: bool = False,
        stats: ExclusionStats | None = None,
    ) -> list[Finding]:
        target_path = Path(target)
        if target_path.is_file():
            return scan_file(target_path, target_path.parent)
        if target_path.is_dir():
            return scan_directory(
                target_path,
                include_vendor=include_vendor,
                stats=stats,
            )
        return []
