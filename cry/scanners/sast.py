"""SAST scanner: detects dangerous code patterns common in AI-generated and indie web apps.

Scans source files (Python, JavaScript, TypeScript) for high-risk patterns including:
- SQL injection via string concatenation/interpolation
- Command injection via os.system / exec / eval
- Hardcoded CORS wildcards
- Disabled security features (CSRF, SSL verification)
- Dangerous deserialization (pickle.loads on untrusted data)
- Missing authentication/authorization indicators

Runs 100% in native Python using regex pattern matching — no external binaries required.
"""

import ast
import re
import uuid
from pathlib import Path

from cry.models import Category, Finding, Severity
from cry.scanners.base import BaseScanner

# ---------------------------------------------------------------------------
# Directories and safe paths to skip/annotate
# ---------------------------------------------------------------------------
LIKELY_SAFE_PATHS: set[str] = {
    "test",
    "tests",
    "testing",
    "mock",
    "mocks",
    "fixture",
    "fixtures",
    "example",
    "examples",
    "sample",
    "samples",
    "spec",
    "specs",
}


def _is_in_safe_path(file_path: Path) -> bool:
    """Check if file lives under a test/mock/fixture directory."""
    parts = {p.lower() for p in file_path.parts}
    return bool(parts & LIKELY_SAFE_PATHS)

# ---------------------------------------------------------------------------
# File extensions this scanner handles
# ---------------------------------------------------------------------------
SCANNABLE_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".mjs",
    ".cjs",
}

# ---------------------------------------------------------------------------
# Directories to skip (same as secrets scanner)
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


class SASTRule:
    """A single static analysis detection rule."""

    def __init__(
        self,
        rule_id: str,
        title: str,
        description: str,
        pattern: re.Pattern[str],
        category: Category,
        severity: Severity,
        cwe_id: str,
        languages: set[str],
        fix_hint: str,
        suggested_fix: str = "",
        language_fixes: dict[str, tuple[str, str]] | None = None,
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.pattern = pattern
        self.category = category
        self.severity = severity
        self.cwe_id = cwe_id
        self.languages = languages  # file extensions this rule applies to
        self.fix_hint = fix_hint
        self.suggested_fix = suggested_fix
        self.language_fixes = language_fixes or {}

    def get_fix(self, file_ext: str) -> tuple[str, str]:
        """Return (fix_hint, suggested_fix) tailored to the target file's language."""
        if file_ext in self.language_fixes:
            return self.language_fixes[file_ext]
        return self.fix_hint, self.suggested_fix


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
SAST_RULES: list[SASTRule] = [
    # ── SQL Injection ──
    SASTRule(
        rule_id="CRY-SQLI-001",
        title="SQL Injection via String Concatenation",
        description="User input is concatenated directly into an SQL query string. "
        "An attacker can inject arbitrary SQL to read, modify, or delete database contents.",
        pattern=re.compile(
            r"""(?:execute|query|raw|run)\s*\(\s*(?:['"][^'"]*['"]\s*\+\s*|f['"][^'"]*\{|`[^`]*\$\{|['"][^'"]*['"]\s*%\s*)""",
            re.IGNORECASE,
        ),
        category=Category.INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-89",
        languages={".py", ".js", ".ts", ".jsx", ".tsx"},
        fix_hint="Use parameterized queries with placeholders instead of string concatenation.",
        suggested_fix='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        language_fixes={
            ".py": (
                "Pass query parameters as a tuple to the DB-API execute method.",
                'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            ),
            ".js": (
                "Use parameterized query placeholders ($1, $2 or ?) in db.query().",
                'await db.query("SELECT * FROM users WHERE id = $1", [userId]);',
            ),
            ".ts": (
                "Use parameterized query placeholders ($1, $2 or ?) in db.query().",
                'await db.query("SELECT * FROM users WHERE id = $1", [userId]);',
            ),
            ".jsx": (
                "Use parameterized query placeholders ($1, $2 or ?) in db.query().",
                'await db.query("SELECT * FROM users WHERE id = $1", [userId]);',
            ),
            ".tsx": (
                "Use parameterized query placeholders ($1, $2 or ?) in db.query().",
                'await db.query("SELECT * FROM users WHERE id = $1", [userId]);',
            ),
        },
    ),
    SASTRule(
        rule_id="CRY-SQLI-002",
        title="SQL Injection via f-string / Template Literal",
        description="An f-string or template literal constructs an SQL query with embedded variables.",
        pattern=re.compile(
            r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.+(?:\{[a-zA-Z_]|` ?\$\{|\+\s*\w+\s*\+)""",
            re.IGNORECASE,
        ),
        category=Category.INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-89",
        languages={".py", ".js", ".ts", ".jsx", ".tsx"},
        fix_hint="Pass user variables as query parameters instead of embedding them in the SQL string.",
        suggested_fix='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        language_fixes={
            ".py": (
                "Pass user variables as query parameters instead of embedding them in the SQL string.",
                'cursor.execute("SELECT * FROM users WHERE name LIKE %s", (f"%{search_term}%",))',
            ),
            ".js": (
                "Pass user variables as query parameters ($1, $2) instead of template literals.",
                'await db.query("SELECT * FROM products WHERE name LIKE $1", [`%${searchTerm}%`]);',
            ),
            ".ts": (
                "Pass user variables as query parameters ($1, $2) instead of template literals.",
                'await db.query("SELECT * FROM products WHERE name LIKE $1", [`%${searchTerm}%`]);',
            ),
            ".jsx": (
                "Pass user variables as query parameters ($1, $2) instead of template literals.",
                'await db.query("SELECT * FROM products WHERE name LIKE $1", [`%${searchTerm}%`]);',
            ),
            ".tsx": (
                "Pass user variables as query parameters ($1, $2) instead of template literals.",
                'await db.query("SELECT * FROM products WHERE name LIKE $1", [`%${searchTerm}%`]);',
            ),
        },
    ),
    # ── Command Injection ──
    SASTRule(
        rule_id="CRY-CMDI-001",
        title="Command Injection via os.system or subprocess with shell=True",
        description="User-controlled input may be passed to a system shell command, "
        "allowing arbitrary command execution on the server.",
        pattern=re.compile(
            r"""(?:os\.(?:system|popen)\s*\(|subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True)""",
        ),
        category=Category.INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-78",
        languages={".py"},
        fix_hint="Use subprocess.run() with a list of arguments and shell=False.",
        suggested_fix='subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, check=True)',
    ),
    # ── Dangerous eval/exec ──
    SASTRule(
        rule_id="CRY-EVAL-001",
        title="Use of eval() or exec() on Dynamic Input",
        description="eval() or exec() executes arbitrary code. If the input comes from a user, "
        "this is a remote code execution vulnerability.",
        pattern=re.compile(
            r"""\b(?:eval|exec)\s*\(\s*(?!['"](?:true|false|null|undefined)['"]\s*\))""",
        ),
        category=Category.INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-95",
        languages={".py", ".js", ".ts", ".jsx", ".tsx"},
        fix_hint="Replace eval/exec with a safe parser (e.g. json.loads, ast.literal_eval).",
        suggested_fix="import json\ndata = json.loads(user_input)",
        language_fixes={
            ".py": (
                "Replace eval/exec with a safe parser (e.g. json.loads, ast.literal_eval).",
                "import json\ndata = json.loads(user_input)",
            ),
            ".js": (
                "Replace eval() with JSON.parse() or a safe expression parser.",
                "const data = JSON.parse(userInput);",
            ),
            ".ts": (
                "Replace eval() with JSON.parse() or a safe expression parser.",
                "const data: unknown = JSON.parse(userInput);",
            ),
            ".jsx": (
                "Replace eval() with JSON.parse().",
                "const data = JSON.parse(userInput);",
            ),
            ".tsx": (
                "Replace eval() with JSON.parse().",
                "const data: unknown = JSON.parse(userInput);",
            ),
        },
    ),
    # ── CORS Wildcard ──
    SASTRule(
        rule_id="CRY-CORS-001",
        title="CORS Allows All Origins (Wildcard *)",
        description="Access-Control-Allow-Origin is set to '*', allowing any website to make "
        "authenticated requests to your API if credentials are also allowed.",
        pattern=re.compile(
            r"""(?:Access-Control-Allow-Origin|cors.*origin|allow_origin)\s*[=:]\s*['"]?\*['"]?""",
            re.IGNORECASE,
        ),
        category=Category.MISCONFIGURATION,
        severity=Severity.MEDIUM,
        cwe_id="CWE-942",
        languages={".py", ".js", ".ts", ".jsx", ".tsx"},
        fix_hint="Restrict CORS to specific trusted origins instead of '*'.",
        suggested_fix='allow_origins=["https://yourdomain.com", "https://app.yourdomain.com"]',
        language_fixes={
            ".py": (
                "Restrict CORS to specific trusted origins instead of '*'.",
                'allow_origins=["https://yourdomain.com", "https://app.yourdomain.com"]',
            ),
            ".js": (
                "Restrict CORS origins in middleware instead of allowing wildcard '*'.",
                'app.use(cors({ origin: ["https://yourdomain.com"], credentials: true }));',
            ),
            ".ts": (
                "Restrict CORS origins in middleware instead of allowing wildcard '*'.",
                'app.use(cors({ origin: ["https://yourdomain.com"], credentials: true }));',
            ),
        },
    ),
    # ── Disabled CSRF Protection ──
    SASTRule(
        rule_id="CRY-CSRF-001",
        title="CSRF Protection Disabled",
        description="CSRF middleware or protection appears to be explicitly disabled.",
        pattern=re.compile(
            r"""(?:(?:csrf|enable_csrf|csrf_enabled|WTF_CSRF_ENABLED)\s*[=:]\s*(?:false|False|0)|csrf\.disable\s*\(\))""",
            re.IGNORECASE,
        ),
        category=Category.MISCONFIGURATION,
        severity=Severity.HIGH,
        cwe_id="CWE-352",
        languages={".py", ".js", ".ts", ".jsx", ".tsx"},
        fix_hint="Enable CSRF protection. Use built-in middleware (e.g. csurf, Django CSRF).",
        suggested_fix="WTF_CSRF_ENABLED = True  # Always enable CSRF in production",
        language_fixes={
            ".py": (
                "Enable CSRF protection. Use built-in middleware (e.g. csurf, Django CSRF).",
                "WTF_CSRF_ENABLED = True  # Always enable CSRF in production",
            ),
            ".js": (
                "Enable CSRF protection middleware on mutating HTTP methods.",
                'const csrf = require("csurf");\napp.use(csrf({ cookie: true }));',
            ),
            ".ts": (
                "Enable CSRF protection middleware on mutating HTTP methods.",
                'import csrf from "csurf";\napp.use(csrf({ cookie: true }));',
            ),
        },
    ),
    # ── Disabled SSL Verification ──
    SASTRule(
        rule_id="CRY-SSL-001",
        title="SSL/TLS Certificate Verification Disabled",
        description="SSL certificate verification is disabled, making the connection "
        "vulnerable to man-in-the-middle attacks.",
        pattern=re.compile(
            r"""(?:verify\s*=\s*False|rejectUnauthorized\s*[=:]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)""",
        ),
        category=Category.MISCONFIGURATION,
        severity=Severity.HIGH,
        cwe_id="CWE-295",
        languages={".py", ".js", ".ts", ".jsx", ".tsx"},
        fix_hint="Always verify SSL certificates in production. Remove verify=False.",
        suggested_fix="response = requests.get(url, verify=True)",
        language_fixes={
            ".py": (
                "Always verify SSL certificates in production. Remove verify=False.",
                "response = requests.get(url, verify=True)",
            ),
            ".js": (
                "Always verify SSL certificates in production. Remove rejectUnauthorized: false.",
                "const res = await fetch(url); // Standard fetch validates TLS certificates",
            ),
            ".ts": (
                "Always verify SSL certificates in production. Remove rejectUnauthorized: false.",
                "const res = await fetch(url); // Standard fetch validates TLS certificates",
            ),
        },
    ),
    # ── Dangerous Deserialization ──
    SASTRule(
        rule_id="CRY-DESER-001",
        title="Unsafe Deserialization (pickle / yaml.load)",
        description="pickle.loads() or yaml.load() without SafeLoader can execute arbitrary code "
        "when deserializing untrusted data.",
        pattern=re.compile(
            r"""(?:pickle\.loads?\s*\(|yaml\.load\s*\([^)]*(?:Loader\s*=\s*(?!yaml\.SafeLoader|SafeLoader)))""",
        ),
        category=Category.INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-502",
        languages={".py"},
        fix_hint="Use json instead of pickle, or yaml.safe_load() instead of yaml.load().",
        suggested_fix="data = yaml.safe_load(content)  # or json.loads(content)",
    ),
    # ── Debug Mode in Production ──
    SASTRule(
        rule_id="CRY-DEBUG-001",
        title="Debug Mode Enabled",
        description="Application debug mode is enabled. This can leak stack traces, "
        "environment variables, and internal paths to attackers.",
        pattern=re.compile(
            r"""(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|\.run\s*\([^)]*debug\s*=\s*True)""",
        ),
        category=Category.MISCONFIGURATION,
        severity=Severity.MEDIUM,
        cwe_id="CWE-215",
        languages={".py"},
        fix_hint="Set DEBUG=False in production. Use environment variables to toggle debug mode.",
        suggested_fix='DEBUG = os.environ.get("DEBUG", "0") == "1"',
    ),
    # ── Hardcoded JWT Secret ──
    SASTRule(
        rule_id="CRY-JWT-001",
        title="Hardcoded JWT Secret Key",
        description="JWT signing secret is hardcoded in source code rather than loaded from "
        "a secure environment variable.",
        pattern=re.compile(
            r"""(?:jwt_secret|JWT_SECRET|SECRET_KEY|secret_key)\s*[=:]\s*['"][^'"]{8,}['"]""",
            re.IGNORECASE,
        ),
        category=Category.AUTHENTICATION,
        severity=Severity.HIGH,
        cwe_id="CWE-798",
        languages={".py", ".js", ".ts", ".jsx", ".tsx"},
        fix_hint="Load secrets from environment variables: os.environ['JWT_SECRET']",
        suggested_fix='JWT_SECRET = os.environ["JWT_SECRET"]',
        language_fixes={
            ".py": (
                "Load secrets from environment variables: os.environ['JWT_SECRET']",
                'JWT_SECRET = os.environ["JWT_SECRET"]',
            ),
            ".js": (
                "Load secrets from environment variables: process.env.JWT_SECRET",
                'const JWT_SECRET = process.env.JWT_SECRET;',
            ),
            ".ts": (
                "Load secrets from environment variables: process.env.JWT_SECRET",
                'const JWT_SECRET: string = process.env.JWT_SECRET!;',
            ),
        },
    ),
    # ── Open Redirect ──
    SASTRule(
        rule_id="CRY-REDIR-001",
        title="Potential Open Redirect",
        description="A redirect destination is taken directly from user input (query parameter) "
        "without validation, enabling phishing attacks.",
        pattern=re.compile(
            r"""(?:\bres\.)?\bredirect\s*\([^)]*(?:req|request|url|target|dest|next|return|to)""",
            re.IGNORECASE,
        ),
        category=Category.MISCONFIGURATION,
        severity=Severity.MEDIUM,
        cwe_id="CWE-601",
        languages={".py", ".js", ".ts", ".jsx", ".tsx"},
        fix_hint="Validate redirect URLs against an allowlist of trusted domains.",
        suggested_fix="if target_url in ALLOWED_DOMAINS:\n    redirect(target_url)",
        language_fixes={
            ".py": (
                "Validate redirect URLs against an allowlist of trusted domains.",
                "if target_url in ALLOWED_DOMAINS:\n    redirect(target_url)",
            ),
            ".js": (
                "Validate redirect URLs against an allowlist of trusted domains.",
                "if (ALLOWED_DOMAINS.includes(targetUrl)) res.redirect(targetUrl);",
            ),
            ".ts": (
                "Validate redirect URLs against an allowlist of trusted domains.",
                "if (ALLOWED_DOMAINS.includes(targetUrl)) res.redirect(targetUrl);",
            ),
        },
    ),
]


def _should_skip_file(file_path: Path, max_size_mb: int = 5) -> bool:
    """Determine if a file should be skipped."""
    for part in file_path.parts:
        if part in SKIP_DIRS:
            return True

    if file_path.suffix.lower() not in SCANNABLE_EXTENSIONS:
        return True

    # Skip unit test implementation files (containing assertions/mock test data)
    name_lower = file_path.name.lower()
    if name_lower.startswith("test_") and name_lower.endswith(".py"):
        return True
    if name_lower.endswith(("_test.py", ".spec.ts", ".test.ts", ".spec.js", ".test.js")):
        return True

    try:
        if file_path.stat().st_size > max_size_mb * 1024 * 1024:
            return True
    except OSError:
        return True

    return False


def _extract_non_code_lines(source_text: str, extension: str) -> set[int]:
    """Find line numbers that are docstrings, multi-line string constants, or block comments."""
    non_code_lines: set[int] = set()
    if extension == ".py":
        try:
            tree = ast.parse(source_text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    if (
                        node.body
                        and isinstance(node.body[0], ast.Expr)
                        and isinstance(node.body[0].value, ast.Constant)
                        and isinstance(node.body[0].value.value, str)
                    ):
                        doc = node.body[0]
                        for line_no in range(doc.lineno, (doc.end_lineno or doc.lineno) + 1):
                            non_code_lines.add(line_no)
                elif (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and node.lineno
                    and node.end_lineno
                    and node.end_lineno > node.lineno
                ):
                    for line_no in range(node.lineno, node.end_lineno + 1):
                        non_code_lines.add(line_no)
        except Exception:
            pass
    return non_code_lines


def scan_file(file_path: Path, base_dir: Path) -> list[Finding]:
    """Scan a single source file for dangerous code patterns."""
    findings: list[Finding] = []
    relative_path = str(file_path.relative_to(base_dir))
    extension = file_path.suffix.lower()

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    # Avoid self-flagging of the rule definitions inside this scanner itself
    if file_path.name == "sast.py" and "scanners" in file_path.parts:
        return findings

    non_code_lines = _extract_non_code_lines(content, extension)
    in_safe_path = _is_in_safe_path(file_path)
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        if line_num in non_code_lines:
            continue

        stripped = line.strip()

        # Skip empty lines, pure comments, and rule metadata assignments
        if not stripped or stripped.startswith((
            "#",
            "//",
            "/*",
            "*",
            "<!--",
            "title=",
            "description=",
            "fix_hint=",
            "suggested_fix=",
            "pattern=",
            'r"""',
            "r'''",
            '"""',
            "'''",
        )):
            continue

        for rule in SAST_RULES:
            # Only apply rules relevant to this file type
            if extension not in rule.languages:
                continue

            if rule.pattern.search(line):
                description = rule.description
                if in_safe_path:
                    description += " (This file is in a test/mock directory — verify if this file is deployed to production)."

                rule_fix_hint, rule_suggested_fix = rule.get_fix(extension)
                finding = Finding(
                    id=f"sast-{uuid.uuid4().hex[:12]}",
                    tool="cry-sast",
                    title=rule.title,
                    description=description,
                    category=rule.category,
                    severity=rule.severity,
                    file_path=relative_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=stripped[:200],
                    cwe_id=rule.cwe_id,
                    fix_hint=rule_fix_hint,
                    suggested_fix=rule_suggested_fix,
                    raw_evidence=f"Rule: {rule.rule_id} | Fix: {rule_fix_hint}",
                )
                findings.append(finding)

    return findings


def scan_directory(target_dir: Path, max_file_size_mb: int = 5) -> list[Finding]:
    """Scan an entire directory tree for dangerous code patterns.

    Args:
        target_dir: Root directory to scan.
        max_file_size_mb: Skip files larger than this.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    if not target_dir.is_dir():
        return findings

    for file_path in target_dir.rglob("*"):
        if not file_path.is_file():
            continue
        if _should_skip_file(file_path, max_file_size_mb):
            continue
        findings.extend(scan_file(file_path, target_dir))

    return findings


class SASTScanner(BaseScanner):
    """SAST scanner adapter conforming to BaseScanner."""

    @property
    def name(self) -> str:
        return "cry-sast"

    @property
    def description(self) -> str:
        return "Static analysis scanner for dangerous code patterns and OWASP vulnerabilities."

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path, base_dir: Path) -> list[Finding]:
        """Scan a single file directly."""
        return scan_file(file_path, base_dir)

    async def scan(self, target: Path | str) -> list[Finding]:
        target_path = Path(target)
        if target_path.is_file():
            return scan_file(target_path, target_path.parent)
        if target_path.is_dir():
            return scan_directory(target_path)
        return []
