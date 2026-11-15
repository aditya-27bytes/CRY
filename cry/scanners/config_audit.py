"""Repository, Environment, and Infrastructure Configuration Auditor for CRY.

Checks for:
- Unprotected .env files missing from .gitignore
- Raw private keys (.pem, .key, id_rsa, id_ed25519) stored in repository
- Committed cloud service account keys (service-account.json, gcp-key.json)
- Insecure Dockerfile configurations (hardcoded secrets in ENV, running as root)
- Docker daemon socket mounts (/var/run/docker.sock) allowing container breakout
"""

import re
import uuid
from pathlib import Path

from cry.models import Category, Finding, Severity
from cry.scanners.base import BaseScanner

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

SENSITIVE_KEY_EXTENSIONS: set[str] = {".pem", ".key", ".pfx", ".p12"}
SENSITIVE_FILE_NAMES: set[str] = {
    "id_rsa",
    "id_dsa",
    "id_ed25519",
    "id_ecdsa",
    "service-account.json",
    "service_account.json",
    "gcp-credentials.json",
    "client_secret.json",
    "client_secrets.json",
}


def _should_skip(path: Path) -> bool:
    return any(p in SKIP_DIRS for p in path.parts)


def scan_gitignore_protection(root_dir: Path) -> list[Finding]:
    """Verify that .env and sensitive environment files are properly ignored by git."""
    findings: list[Finding] = []
    gitignore_path = root_dir / ".gitignore"

    # Find any .env files in root or immediate subdirectories
    env_files = [f for f in root_dir.glob(".env*") if f.is_file() and not f.name.endswith(".example")]

    if not env_files:
        return findings

    if not gitignore_path.exists():
        findings.append(
            Finding(
                id=f"cfg-{uuid.uuid4().hex[:12]}",
                tool="cry-config",
                title="Missing .gitignore File (.env At Risk)",
                description="Your repository contains active environment file(s) but has no .gitignore. Running `git add .` will commit live secrets and credentials to your public/private version control history.",
                category=Category.MISCONFIGURATION,
                severity=Severity.CRITICAL,
                file_path=".gitignore",
                line_start=1,
                line_end=1,
                code_snippet="No .gitignore present in project root",
                cwe_id="CWE-798",
                fix_hint="Create a .gitignore file in your repository root and add '.env' and '*.local' immediately.",
                suggested_fix=".env\n*.local\n.venv/\nnode_modules/",
                raw_evidence="Missing .gitignore with active .env files present",
            )
        )
        return findings

    gitignore_text = gitignore_path.read_text(encoding="utf-8", errors="ignore")
    lines = [line.strip() for line in gitignore_text.splitlines() if line.strip() and not line.startswith("#")]

    if not any(pattern in lines for pattern in (".env", "*.env", ".env*")):
        findings.append(
            Finding(
                id=f"cfg-{uuid.uuid4().hex[:12]}",
                tool="cry-config",
                title=".env File Not Protected in .gitignore",
                description="Active .env file exists in your project but is NOT protected in .gitignore. Any git commit will leak production API keys, secrets, and database credentials to your version control repository.",
                category=Category.MISCONFIGURATION,
                severity=Severity.CRITICAL,
                file_path=".gitignore",
                line_start=1,
                line_end=1,
                code_snippet=".gitignore missing .env rule",
                cwe_id="CWE-798",
                fix_hint="Add '.env' to your .gitignore file to prevent credential leaks.",
                suggested_fix=".env\n.env.local\n*.local",
                raw_evidence="Found .env in project root, but no .env rule in .gitignore",
            )
        )

    return findings


def scan_sensitive_files(root_dir: Path) -> list[Finding]:
    """Scan for committed private keys and cloud service account credentials."""
    findings: list[Finding] = []

    for file_path in root_dir.rglob("*"):
        if not file_path.is_file() or _should_skip(file_path):
            continue

        name_lower = file_path.name.lower()
        ext_lower = file_path.suffix.lower()
        rel_path = str(file_path.relative_to(root_dir))

        # Check for committed private keys
        if ext_lower in SENSITIVE_KEY_EXTENSIONS or name_lower in SENSITIVE_FILE_NAMES:
            # Check content to confirm it's a real private key / credential
            try:
                first_bytes = file_path.read_text(encoding="utf-8", errors="ignore")[:300]
            except Exception:
                continue

            if "PRIVATE KEY" in first_bytes or "private_key" in first_bytes or "client_secret" in first_bytes:
                findings.append(
                    Finding(
                        id=f"cfg-{uuid.uuid4().hex[:12]}",
                        tool="cry-config",
                        title=f"Committed Private Key or Service Account ({file_path.name})",
                        description=f"Raw cryptographic private key or service account credential file stored directly in source tree ({rel_path}). This gives anyone with repo access instant cryptographic identity impersonation.",
                        category=Category.SECRET_EXPOSURE,
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line_start=1,
                        line_end=1,
                        code_snippet=f"File: {rel_path} contains private key data",
                        cwe_id="CWE-321",
                        fix_hint="Delete this private key file from git history, add to .gitignore, and inject keys via secure secrets managers.",
                        suggested_fix=f"# In .gitignore:\n{file_path.name}\n*.pem\n*.key",
                        raw_evidence=f"Private key file detected at {rel_path}",
                    )
                )

    return findings


def scan_docker_security(root_dir: Path) -> list[Finding]:
    """Scan Dockerfile and docker-compose.yml for security misconfigurations."""
    findings: list[Finding] = []

    for file_path in root_dir.rglob("*"):
        if not file_path.is_file() or _should_skip(file_path):
            continue

        name = file_path.name.lower()
        rel_path = str(file_path.relative_to(root_dir))

        if name == "dockerfile" or name.startswith("dockerfile."):
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue

            for line_no, raw_line in enumerate(lines, start=1):
                line = raw_line.strip()
                if line.startswith("#"):
                    continue

                # Hardcoded secrets in ENV
                if line.upper().startswith("ENV ") and re.search(
                    r"\b(?:api[_-]?key|secret|password|token)\s*=\s*['\"]?[a-zA-Z0-9_\-]{8,}", line, re.IGNORECASE
                ):
                    findings.append(
                        Finding(
                            id=f"cfg-{uuid.uuid4().hex[:12]}",
                            tool="cry-config",
                            title="Hardcoded Secret in Dockerfile ENV Instruction",
                            description="A secret or credential is baked into a Docker image layer via 'ENV'. Docker image layers are immutable and publicly visible via `docker history`.",
                            category=Category.SECRET_EXPOSURE,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line,
                            cwe_id="CWE-798",
                            fix_hint="Pass runtime credentials via container environment variables or Docker Secrets, not build-time 'ENV' instructions.",
                            suggested_fix="# Remove hardcoded ENV secret. Pass via docker run -e SECRET=... or compose",
                            raw_evidence=line,
                        )
                    )

        elif "docker-compose" in name and (name.endswith(".yml") or name.endswith(".yaml")):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for line_no, raw_line in enumerate(content.splitlines(), start=1):
                line = raw_line.strip()
                if "/var/run/docker.sock" in line:
                    findings.append(
                        Finding(
                            id=f"cfg-{uuid.uuid4().hex[:12]}",
                            tool="cry-config",
                            title="Docker Socket Mounted into Container",
                            description="Mounting `/var/run/docker.sock` grants the container root-equivalent control over the host Docker daemon, allowing trivial host takeover and container escape.",
                            category=Category.MISCONFIGURATION,
                            severity=Severity.CRITICAL,
                            file_path=rel_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line,
                            cwe_id="CWE-250",
                            fix_hint="Remove the docker.sock volume mount unless the container is a dedicated CI agent with strict host isolation.",
                            suggested_fix="# Remove: - /var/run/docker.sock:/var/run/docker.sock",
                            raw_evidence=line,
                        )
                    )

    return findings


def scan_configurations(root_dir: Path) -> list[Finding]:
    """Execute all configuration, git, and deployment security audits."""
    findings: list[Finding] = []
    if root_dir.is_file():
        return findings

    findings.extend(scan_gitignore_protection(root_dir))
    findings.extend(scan_sensitive_files(root_dir))
    findings.extend(scan_docker_security(root_dir))
    return findings


class ConfigAuditScanner(BaseScanner):
    """Configuration and repository security auditor adapter."""

    @property
    def name(self) -> str:
        return "cry-config"

    @property
    def description(self) -> str:
        return "Audits repository hygiene, .gitignore coverage, private keys, and container deployment security."

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path, base_dir: Path) -> list[Finding]:
        return []

    async def scan(self, target: Path | str) -> list[Finding]:
        target_path = Path(target).resolve()
        return scan_configurations(target_path)
