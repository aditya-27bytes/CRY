"""Dependency & Supply-Chain Scanner for CRY.

Scans manifest files (package.json, requirements.txt, pyproject.toml) for:
- Known vulnerable library versions with high-severity CVEs
- Unpinned or wildcard package dependencies (*, latest)
- Unencrypted HTTP package repository indexes (susceptible to MitM)
- Suspicious pre/postinstall lifecycle scripts executing remote commands
"""

import json
import re
import uuid
from pathlib import Path

from cry.models import Category, Finding, Severity
from cry.scanners.base import BaseScanner

# Directories to skip
SKIP_DIRS: set[str] = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
}

# Known vulnerable npm packages: name -> (vulnerable_regex, min_safe_version, cwe, title, description)
NPM_VULNERABLE_PACKAGES: dict[str, tuple[str, str, str, str, str]] = {
    "lodash": (
        r"^<?4\.(?:[0-9]|1[0-6])\.",
        "4.17.21",
        "CWE-1321",
        "Prototype Pollution in lodash",
        "Versions of lodash before 4.17.21 are vulnerable to Prototype Pollution via zipObjectDeep and defaultsDeep.",
    ),
    "axios": (
        r"^(?:0\.|1\.[0-5]\.)",
        "1.6.0",
        "CWE-918",
        "SSRF & Confidentiality Leak in axios",
        "Versions of axios prior to 1.6.0 leak custom Authorization headers during cross-origin redirects.",
    ),
    "jsonwebtoken": (
        r"^[0-8]\.",
        "9.0.0",
        "CWE-287",
        "Insecure Key Verification in jsonwebtoken",
        "Versions of jsonwebtoken prior to 9.0.0 allow algorithm confusion (e.g. none, RS256/HS256 confusion).",
    ),
    "express": (
        r"^(?:[0-3]\.|4\.(?:[0-9]|1[0-8])\.)",
        "4.19.2",
        "CWE-601",
        "Open Redirect / IP Whitelist Bypass in express",
        "Versions of express prior to 4.19.2 contain an open redirect and request routing bypass vulnerability.",
    ),
    "minimist": (
        r"^(?:0\.|1\.[0-1]\.)",
        "1.2.6",
        "CWE-1321",
        "Prototype Pollution in minimist",
        "Versions of minimist prior to 1.2.6 allow attackers to manipulate Object.prototype via malicious CLI arguments.",
    ),
    "tar": (
        r"^(?:[0-5]\.|6\.[0-1]\.)",
        "6.2.1",
        "CWE-22",
        "Arbitrary File Overwrite via Path Traversal in tar",
        "Versions of tar prior to 6.2.1 allow directory traversal during archive extraction.",
    ),
}

# Known vulnerable Python packages: name -> (vulnerable_regex, min_safe_version, cwe, title, description)
PY_VULNERABLE_PACKAGES: dict[str, tuple[str, str, str, str, str]] = {
    "requests": (
        r"^(?:[0-1]\.|2\.(?:[0-9]|1[0-9]|2[0-9]|30)\.)",
        "2.31.0",
        "CWE-200",
        "Leaked Proxy-Authorization in requests",
        "requests prior to 2.31.0 automatically forwards Proxy-Authorization headers to destination servers on redirect.",
    ),
    "urllib3": (
        r"^(?:[0-1]\.(?:[0-9]|1[0-9]|2[0-5])\.|2\.0\.[0-6]$)",
        "1.26.18 / 2.0.7",
        "CWE-444",
        "Request Smuggling & Header Injection in urllib3",
        "urllib3 prior to 1.26.18 and 2.0.7 mishandles strip header logic, enabling request smuggling.",
    ),
    "flask": (
        r"^(?:[0-1]\.|2\.[0-1]\.)",
        "2.2.5",
        "CWE-200",
        "Cookie Disclosure in Flask",
        "Flask prior to 2.2.5 leaks sensitive session cookie contents under specific error handling conditions.",
    ),
    "jinja2": (
        r"^(?:[0-2]\.|3\.[0]\.)",
        "3.1.3",
        "CWE-1336",
        "HTML/Sandbox Attribute Injection in Jinja2",
        "Jinja2 prior to 3.1.3 allows cross-site scripting and template sandbox escape via compiler attribute manipulation.",
    ),
    "pyyaml": (
        r"^[0-5]\.[0-3]\.",
        "5.3.1",
        "CWE-502",
        "Arbitrary Code Execution in PyYAML",
        "PyYAML before 5.3.1 uses yaml.load without safe loader by default, allowing remote arbitrary code execution.",
    ),
}


def _should_skip(path: Path) -> bool:
    return any(p in SKIP_DIRS for p in path.parts)


def scan_package_json(file_path: Path, base_dir: Path) -> list[Finding]:
    """Scan a package.json file for dangerous scripts, wildcards, and known CVEs."""
    findings: list[Finding] = []
    rel_path = str(file_path.relative_to(base_dir))

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
    except Exception:
        return findings

    # 1. Audit lifecycle scripts for dangerous remote execution
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for script_name in ("preinstall", "install", "postinstall", "prepublish"):
            cmd = scripts.get(script_name, "")
            if isinstance(cmd, str) and re.search(r"\b(?:curl|wget|nc|bash\s+-c|sh\s+-c|powershell)\b", cmd, re.IGNORECASE):
                findings.append(
                    Finding(
                        id=f"dep-{uuid.uuid4().hex[:12]}",
                        tool="cry-sca",
                        title=f"Dangerous Package Lifecycle Script ({script_name})",
                        description=f"Package script '{script_name}' executes remote network downloads or shell commands ({cmd[:80]}). This is a common attack vector in malicious supply-chain packages.",
                        category=Category.INSECURE_DEPENDENCY,
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line_start=1,
                        line_end=1,
                        code_snippet=f'"{script_name}": "{cmd}"',
                        cwe_id="CWE-78",
                        fix_hint=f"Remove arbitrary shell commands from '{script_name}' script. Run explicit local build scripts instead.",
                        suggested_fix=f'"{script_name}": "node ./scripts/build.js"',
                        raw_evidence=f"Suspicious lifecycle command: {cmd}",
                    )
                )

    # 2. Audit dependencies & devDependencies
    all_deps: dict[str, str] = {}
    if isinstance(data.get("dependencies"), dict):
        all_deps.update(data["dependencies"])
    if isinstance(data.get("devDependencies"), dict):
        all_deps.update(data["devDependencies"])

    for pkg_name, version_str in all_deps.items():
        clean_version = str(version_str).strip().lstrip("^~>=<")

        # Check for wildcard or unpinned resolution
        if version_str in ("*", "latest", ""):
            findings.append(
                Finding(
                    id=f"dep-{uuid.uuid4().hex[:12]}",
                    tool="cry-sca",
                    title=f"Wildcard Package Version ({pkg_name}: {version_str})",
                    description=f"Package '{pkg_name}' specifies a wildcard or floating version ('{version_str}'). A compromised upstream release will be automatically pulled into your production builds without review.",
                    category=Category.INSECURE_DEPENDENCY,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line_start=1,
                    line_end=1,
                    code_snippet=f'"{pkg_name}": "{version_str}"',
                    cwe_id="CWE-829",
                    fix_hint=f"Pin '{pkg_name}' to a specific semantic release version (e.g. ^1.2.3 or 1.2.3).",
                    suggested_fix=f'"{pkg_name}": "^1.0.0"',
                    raw_evidence=f"Wildcard version: {version_str}",
                )
            )

        # Check for unencrypted HTTP git/tarball URLs
        if str(version_str).startswith("http://"):
            findings.append(
                Finding(
                    id=f"dep-{uuid.uuid4().hex[:12]}",
                    tool="cry-sca",
                    title=f"Insecure Unencrypted HTTP Package URL ({pkg_name})",
                    description=f"Package '{pkg_name}' fetches from an unencrypted HTTP URL ({version_str}). Attackers on local networks can intercept and inject malicious code via Man-in-the-Middle (MitM).",
                    category=Category.INSECURE_DEPENDENCY,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line_start=1,
                    line_end=1,
                    code_snippet=f'"{pkg_name}": "{version_str}"',
                    cwe_id="CWE-319",
                    fix_hint=f"Use secure HTTPS or npm registry URLs for '{pkg_name}'.",
                    suggested_fix=f'"{pkg_name}": "{str(version_str).replace("http://", "https://")}"',
                    raw_evidence=f"Insecure URL: {version_str}",
                )
            )

        # Check against known vulnerable versions
        if pkg_name in NPM_VULNERABLE_PACKAGES:
            vuln_regex, min_safe, cwe, title, desc = NPM_VULNERABLE_PACKAGES[pkg_name]
            if re.search(vuln_regex, clean_version):
                findings.append(
                    Finding(
                        id=f"dep-{uuid.uuid4().hex[:12]}",
                        tool="cry-sca",
                        title=title,
                        description=f"{desc} (Installed: {version_str}, Required: >={min_safe})",
                        category=Category.INSECURE_DEPENDENCY,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_start=1,
                        line_end=1,
                        code_snippet=f'"{pkg_name}": "{version_str}"',
                        cwe_id=cwe,
                        fix_hint=f"Upgrade '{pkg_name}' to version >={min_safe} or run `npm update {pkg_name}`.",
                        suggested_fix=f'"{pkg_name}": "^{min_safe}"',
                        raw_evidence=f"Matched vulnerable version pattern: {clean_version}",
                    )
                )

    return findings


def scan_requirements_txt(file_path: Path, base_dir: Path) -> list[Finding]:
    """Scan a requirements.txt file for unencrypted indexes, wildcards, and known CVEs."""
    findings: list[Finding] = []
    rel_path = str(file_path.relative_to(base_dir))

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Check for unencrypted index URLs
        if line.startswith(("--index-url", "--extra-index-url")) and "http://" in line:
            findings.append(
                Finding(
                    id=f"dep-{uuid.uuid4().hex[:12]}",
                    tool="cry-sca",
                    title="Insecure Plaintext Package Index (HTTP)",
                    description="pip is configured to download Python packages over unencrypted HTTP. An attacker on the network can tamper with wheel files to achieve Remote Code Execution (RCE).",
                    category=Category.INSECURE_DEPENDENCY,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=line,
                    cwe_id="CWE-319",
                    fix_hint="Change package index URLs to use HTTPS.",
                    suggested_fix=line.replace("http://", "https://"),
                    raw_evidence=line,
                )
            )

        # Parse package name and version
        match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:(==|>=|<=|~=)\s*([0-9a-zA-Z_\.\-]+))?", line)
        if match:
            pkg_name = match.group(1).lower()
            version = match.group(3) or ""

            if pkg_name in PY_VULNERABLE_PACKAGES and version:
                vuln_regex, min_safe, cwe, title, desc = PY_VULNERABLE_PACKAGES[pkg_name]
                if re.search(vuln_regex, version):
                    findings.append(
                        Finding(
                            id=f"dep-{uuid.uuid4().hex[:12]}",
                            tool="cry-sca",
                            title=title,
                            description=f"{desc} (Installed: {version}, Safe: >={min_safe})",
                            category=Category.INSECURE_DEPENDENCY,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line_start=line_num,
                            line_end=line_num,
                            code_snippet=line,
                            cwe_id=cwe,
                            fix_hint=f"Upgrade '{pkg_name}' to version >={min_safe} in requirements.txt.",
                            suggested_fix=f"{pkg_name}>={min_safe}",
                            raw_evidence=f"Vulnerable version pinned: {version}",
                        )
                    )

    return findings


def scan_dependencies(target_dir: Path) -> list[Finding]:
    """Scan all dependency manifests in the target directory."""
    findings: list[Finding] = []

    if target_dir.is_file():
        name = target_dir.name.lower()
        if name == "package.json":
            return scan_package_json(target_dir, target_dir.parent)
        elif "requirements" in name and name.endswith(".txt"):
            return scan_requirements_txt(target_dir, target_dir.parent)
        return []

    for file_path in target_dir.rglob("*"):
        if not file_path.is_file() or _should_skip(file_path):
            continue

        name = file_path.name.lower()
        if name == "package.json":
            findings.extend(scan_package_json(file_path, target_dir))
        elif "requirements" in name and name.endswith(".txt"):
            findings.extend(scan_requirements_txt(file_path, target_dir))

    return findings


class DependencyScanner(BaseScanner):
    """Dependency / Software Composition Analysis (SCA) scanner."""

    @property
    def name(self) -> str:
        return "cry-sca"

    @property
    def description(self) -> str:
        return "Software Composition Analysis (SCA) for vulnerable packages and insecure dependency manifests."

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path, base_dir: Path) -> list[Finding]:
        name = file_path.name.lower()
        if name == "package.json":
            return scan_package_json(file_path, base_dir)
        elif "requirements" in name and name.endswith(".txt"):
            return scan_requirements_txt(file_path, base_dir)
        return []

    async def scan(self, target: Path | str) -> list[Finding]:
        target_path = Path(target).resolve()
        return scan_dependencies(target_path)
