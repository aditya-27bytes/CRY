"""Static code analysis for network vulnerabilities and project IP footprint."""

from __future__ import annotations

import re
import socket
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cry.exclusions import (
    ExclusionStats,
    GitIgnoreMatcher,
    is_build_or_task_file,
    is_documentation_file,
    is_test_or_fixture_file,
    should_skip_path,
)
from cry.models import Category, Finding, Severity
from cry.network_ip import (
    detect_ip_obfuscation,
    get_ip_classification,
    is_cloud_metadata,
    is_internal,
    is_loopback,
    is_private_rfc1918,
    normalize_ip,
)
from cry.scanners.base import BaseScanner
from cry.scanners.taint import analyze_taint_in_javascript, analyze_taint_in_python

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

SCANNABLE_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".conf",
    ".config",
}

# Regex to detect Cloud Instance Metadata IPs (IPv4 169.254.169.254, AWS IPv6 fd00:ec2::254, Azure wire server)
METADATA_IP_PATTERN = re.compile(
    r"""\b(?:169\.254\.169\.254|169\.254\.169\.253|fd00:ec2::254)\b""", re.IGNORECASE
)

# Regex to detect generic Link-Local IPv4 addresses (169.254.x.x)
LINK_LOCAL_PATTERN = re.compile(r"""\b169\.254\.(?:[0-9]{1,3})\.(?:[0-9]{1,3})\b""")

# Regex to detect unencrypted HTTP remote API calls (excluding localhost, 127.0.0.1, example.com, test domains)
PLAINTEXT_HTTP_PATTERN = re.compile(
    r"""['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|test|example\.com|schemas\.)([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(?::\d+)?[^'"]*)['"]""",
    re.IGNORECASE,
)

# Regex to detect private RFC-1918 IPs in source code
PRIVATE_IP_PATTERN = re.compile(
    r"""\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"""
)

# SSRF sink patterns: client request using unvalidated query / request parameters or dynamic URLs
SSRF_SINK_PATTERN = re.compile(
    r"""\b(?:needle\.(?:get|post|put|delete|request)|needle|axios\.(?:get|post|put|delete|request)|axios|fetch|requests\.(?:get|post|put|delete|request)|httpx\.(?:get|post|put|delete|request|Client)|http\.(?:get|request))\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:args|GET|POST|values)|url_param|user_url|target_url|\burl\b)""",
    re.IGNORECASE,
)

# URL / endpoint matching regex in source files
URL_PATTERN = re.compile(
    r"""(?:https?|postgres|postgresql|mysql|redis|mongodb|amqp|wss?)://([^\s/'"?#]+)""",
    re.IGNORECASE,
)


def _should_skip(file_path: Path) -> bool:
    return any(p in SKIP_DIRS for p in file_path.parts)


@dataclass
class DiscoveredEndpoint:
    """A network endpoint or IP discovered within codebase or configuration files."""

    raw_reference: str
    host: str
    source_file: str
    line_number: int
    resolved_ips: list[str] = field(default_factory=list)
    normalized_ip: str | None = None
    reverse_dns: str | None = None
    is_private: bool = False
    is_metadata: bool = False
    is_internal: bool = False
    security_scope: str = "Public Routable"
    ssrf_warning: str | None = None
    obfuscation_note: str | None = None


@dataclass
class ProjectNetworkReport:
    """Network intelligence and IP footprint audit across an entire project directory."""

    project_dir: str
    local_hostname: str
    local_outbound_ip: str
    discovered_endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    internal_endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    external_endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    total_endpoints_found: int = 0
    ssrf_risks_count: int = 0
    private_ips_count: int = 0
    is_passive: bool = True
    scan_timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


def scan_file_network(file_path: Path, base_dir: Path) -> list[Finding]:
    """Scan a single source or config file for network security flaws."""
    findings: list[Finding] = []
    rel_path = str(file_path.relative_to(base_dir))
    ext = file_path.suffix.lower()

    if ext not in SCANNABLE_EXTENSIONS or _should_skip(file_path):
        return findings

    # Avoid self-flagging of scanner rules and security engine definitions
    if (
        ("scanners" in file_path.parts)
        or file_path.name in ("network_ip.py", "network_auth.py", "network.py", "taint.py")
        or ("rules" in file_path.parts and "catalog" in file_path.parts)
    ):
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()

    for line_num, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", "/*", "*", "<!--")):
            continue

        # 1. Check for Cloud Metadata Service IP (IMDS)
        meta_match = METADATA_IP_PATTERN.search(line)
        if meta_match:
            matched_ip = meta_match.group(0)
            findings.append(
                Finding(
                    id=f"net-{uuid.uuid4().hex[:12]}",
                    tool="cry-network",
                    title=f"Hardcoded Cloud Metadata IP ({matched_ip})",
                    description=(
                        f"Detected cloud instance metadata service (IMDS) IP address ({matched_ip}). "
                        "If an attacker can control or influence this HTTP call via SSRF, they can steal IAM role credentials, "
                        "service tokens, and full cloud instance environment variables."
                    ),
                    category=Category.INJECTION,
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=line[:200],
                    cwe_id="CWE-918",
                    fix_hint="Enforce IMDSv2 with token hops restricted to 1, or block outbound access to metadata services via network security groups.",
                    suggested_fix=f"# Avoid hardcoding {matched_ip}. Use cloud SDK IAM credential providers instead.",
                    raw_evidence=f"Matched {matched_ip} Cloud Metadata IMDS IP",
                )
            )

        # 2. Check for Generic Link-Local IPs (169.254.x.x excluding IMDS)
        ll_match = LINK_LOCAL_PATTERN.search(line)
        if ll_match and not meta_match:
            ll_ip = ll_match.group(0)
            findings.append(
                Finding(
                    id=f"net-{uuid.uuid4().hex[:12]}",
                    tool="cry-network",
                    title=f"Hardcoded Link-Local IP ({ll_ip})",
                    description=(
                        f"Detected link-local IP address ({ll_ip}) hardcoded in source code. "
                        "Link-local addresses (169.254.0.0/16) are typically assigned dynamically via autoconfiguration or point to host hypervisor services."
                    ),
                    category=Category.MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    file_path=rel_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=line[:200],
                    cwe_id="CWE-200",
                    fix_hint="Replace hardcoded link-local address with configuration parameter or DNS hostname.",
                    suggested_fix=line.replace(ll_ip, "service.internal"),
                    raw_evidence=f"Matched link-local IP {ll_ip}",
                )
            )

        # 3. Check for Obfuscated IP SSRF Bypasses in URLs
        for match in URL_PATTERN.finditer(line):
            raw_url = match.group(0)
            netloc = match.group(1).split("@")[-1]
            host_cand = netloc.split("/")[0].split(":")[0].strip("[]")
            is_obf, norm_ip, evasion_desc = detect_ip_obfuscation(host_cand)
            if is_obf and norm_ip and (is_internal(norm_ip) or is_cloud_metadata(norm_ip)):
                sev = (
                    Severity.CRITICAL
                    if (is_cloud_metadata(norm_ip) or is_loopback(norm_ip))
                    else Severity.HIGH
                )
                findings.append(
                    Finding(
                        id=f"net-{uuid.uuid4().hex[:12]}",
                        tool="cry-network",
                        title=f"Obfuscated IP SSRF Bypass ({evasion_desc})",
                        description=(
                            f"Detected obfuscated IP representation '{host_cand}' in URL ({raw_url}) which normalizes to internal address '{norm_ip}'. "
                            f"Adversaries employ {evasion_desc} to evade naive string-matching SSRF defenses and reach internal microservices or cloud metadata."
                        ),
                        category=Category.INJECTION,
                        severity=sev,
                        file_path=rel_path,
                        line_start=line_num,
                        line_end=line_num,
                        code_snippet=line[:200],
                        cwe_id="CWE-918",
                        fix_hint="Replace obfuscated IP with an authorized public domain or validate URLs using normalized IP addresses against an allowlist.",
                        suggested_fix=line.replace(host_cand, "api.trusted-domain.com"),
                        raw_evidence=f"Obfuscated candidate: {host_cand} -> Normalized: {norm_ip}",
                    )
                )

        # 4. Check for Plaintext HTTP External API Calls
        http_match = PLAINTEXT_HTTP_PATTERN.search(line)
        if http_match:
            endpoint = http_match.group(1)
            # Skip documentation links or schema URIs
            if not any(
                skip_kw in line.lower()
                for skip_kw in ("doc", "xml", "w3.org", "json-schema", "xmlns")
            ):
                findings.append(
                    Finding(
                        id=f"net-{uuid.uuid4().hex[:12]}",
                        tool="cry-network",
                        title=f"Insecure Plaintext HTTP Endpoint (http://{endpoint[:35]})",
                        description=(
                            f"Remote service or API URL is configured over unencrypted HTTP (http://{endpoint}). "
                            "Sensitive request payloads, headers, tokens, and response bodies are vulnerable to interception "
                            "and active tampering by Man-in-the-Middle (MitM) adversaries on transit networks."
                        ),
                        category=Category.MISCONFIGURATION,
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line_start=line_num,
                        line_end=line_num,
                        code_snippet=line[:200],
                        cwe_id="CWE-319",
                        fix_hint=f"Upgrade remote endpoint from HTTP to HTTPS: https://{endpoint}",
                        suggested_fix=line.replace("http://", "https://"),
                        raw_evidence=f"Plaintext URL: http://{endpoint}",
                    )
                )

        # 5. Check for SSRF Sinks
        if SSRF_SINK_PATTERN.search(line):
            taint = None
            if ext == ".py":
                taint = analyze_taint_in_python(file_path, line_num)
            elif ext in {".ts", ".tsx", ".js", ".jsx"}:
                taint = analyze_taint_in_javascript(content, line_num)

            if taint and not taint.is_tainted:
                pass
            else:
                findings.append(
                    Finding(
                        id=f"net-{uuid.uuid4().hex[:12]}",
                        tool="cry-network",
                        title="Potential Server-Side Request Forgery (SSRF) Sink",
                        description=(
                            "An outbound HTTP client request takes the destination URL directly from untrusted user request parameters. "
                            "An attacker can supply internal hostnames (e.g. `http://169.254.169.254` or `http://localhost:6379`) "
                            "to probe private VPC microservices and dump instance credentials."
                        ),
                        category=Category.INJECTION,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_start=line_num,
                        line_end=line_num,
                        code_snippet=line[:200],
                        cwe_id="CWE-918",
                        fix_hint="Validate destination URLs against an allowlist of trusted domains and resolve IPs to verify they are not in private subnets.",
                        suggested_fix="if is_safe_external_url(target_url):\n    response = requests.get(target_url)",
                        raw_evidence="HTTP client invoked directly on request parameter",
                    )
                )

    return findings


def scan_network_code_patterns(
    target_dir: Path,
    include_vendor: bool = False,
    stats: ExclusionStats | None = None,
    include_tests_and_docs: bool = False,
) -> list[Finding]:
    """Scan all files in directory for network security anti-patterns."""
    findings: list[Finding] = []

    if target_dir.is_file():
        file_findings = scan_file_network(target_dir, target_dir.parent)
        if not include_tests_and_docs:
            if is_documentation_file(target_dir):
                return []
            if is_test_or_fixture_file(target_dir) or is_build_or_task_file(target_dir):
                for f in file_findings:
                    f.severity = Severity.LOW
                    if not f.title.startswith("[Test/Build Fixture]"):
                        f.title = f"[Test/Build Fixture] {f.title}"
        return file_findings

    gitignore = GitIgnoreMatcher(target_dir) if not include_vendor else None

    for file_path in target_dir.rglob("*"):
        if not file_path.is_file():
            continue
        decision = should_skip_path(
            file_path,
            target_dir,
            include_vendor=include_vendor,
            gitignore=gitignore,
        )
        if decision.skip:
            if stats and decision.reason:
                stats.record_skip(file_path, decision.reason)
            continue
        if _should_skip(file_path):
            continue
        if not include_tests_and_docs and is_documentation_file(file_path):
            continue

        file_findings = scan_file_network(file_path, target_dir)
        if not include_tests_and_docs and (
            is_test_or_fixture_file(file_path, target_dir) or is_build_or_task_file(file_path)
        ):
            for f in file_findings:
                f.severity = Severity.LOW
                if not f.title.startswith("[Test/Build Fixture]"):
                    f.title = f"[Test/Build Fixture] {f.title}"
        findings.extend(file_findings)

    return findings


def audit_project_network(
    project_dir: Path,
    passive: bool = True,
    include_vendor: bool = False,
    stats: ExclusionStats | None = None,
) -> ProjectNetworkReport:
    """Scan project files to discover all declared network endpoints and analyze footprint."""
    from cry.scanners import network as net_mod

    p = project_dir.resolve()
    local_hostname = socket.gethostname()
    if passive:
        local_outbound_ip = "Offline / Passive (No traffic dispatched)"
    else:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_outbound_ip = str(s.getsockname()[0])
        except Exception:
            local_outbound_ip = "127.0.0.1"

    report = ProjectNetworkReport(
        project_dir=str(p),
        local_hostname=local_hostname,
        local_outbound_ip=local_outbound_ip,
        is_passive=passive,
    )

    if not p.is_dir():
        return report

    gitignore = GitIgnoreMatcher(p) if not include_vendor else None

    ip_raw_regex = re.compile(
        r"""\b(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|0x[0-9a-fA-F]{1,8}|2130706433|2852039166|fd00:ec2::254)\b"""
    )

    seen_refs: set[str] = set()

    for file_path in p.rglob("*"):
        if not file_path.is_file():
            continue
        decision = should_skip_path(
            file_path,
            p,
            include_vendor=include_vendor,
            gitignore=gitignore,
        )
        if decision.skip:
            if stats and decision.reason:
                stats.record_skip(file_path, decision.reason)
            continue
        if _should_skip(file_path):
            continue

        rel_path = str(file_path.relative_to(p))
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith(("#", "//", "/*", "*")):
                continue

            extracted_items: list[tuple[str, str]] = []

            # 1. Discover URLs
            for match in URL_PATTERN.finditer(line_str):
                raw_ref = match.group(0)
                netloc = match.group(1).split("@")[-1]
                host = netloc.split("/")[0].split(":")[0].strip(" ./:;'\"`()[]{}<>").lower()
                if (
                    host
                    and len(host) >= 3
                    and not host.startswith(".")
                    and not host.endswith(".")
                    and ".." not in host
                    and raw_ref not in seen_refs
                ):
                    extracted_items.append((raw_ref, host))
                    seen_refs.add(raw_ref)

            # 2. Discover Raw IPs & Obfuscated Candidates
            for match in ip_raw_regex.finditer(line_str):
                cand = match.group(0).strip()
                if cand not in seen_refs and cand not in {"0.0.0.0", "255.255.255.255"}:
                    norm = normalize_ip(cand)
                    if norm:
                        extracted_items.append((cand, cand))
                        seen_refs.add(cand)

            for raw_ref, host in extracted_items:
                is_obf, obf_norm, obf_desc = detect_ip_obfuscation(host)
                norm_ip = obf_norm or normalize_ip(host)

                if passive:
                    target_for_scope = norm_ip or host
                    scope = get_ip_classification(target_for_scope)
                    is_priv = is_private_rfc1918(target_for_scope)
                    is_meta = is_cloud_metadata(target_for_scope)
                    is_intern = is_internal(target_for_scope)

                    ssrf_warn: str | None = None
                    if is_obf and obf_norm:
                        ssrf_warn = f"Obfuscated IP SSRF Bypass ({obf_desc})"
                    elif is_meta:
                        ssrf_warn = "Cloud IMDS Exfiltration Risk (CWE-918)"
                    elif is_priv:
                        ssrf_warn = "Internal RFC-1918 Network Topology Disclosure"
                    elif is_intern:
                        ssrf_warn = f"Internal Scope Access ({scope})"

                    endpoint = DiscoveredEndpoint(
                        raw_reference=raw_ref,
                        host=host,
                        source_file=rel_path,
                        line_number=line_num,
                        resolved_ips=[norm_ip] if norm_ip else [],
                        normalized_ip=norm_ip,
                        reverse_dns=None,
                        is_private=is_priv,
                        is_metadata=is_meta,
                        is_internal=is_intern,
                        security_scope=scope,
                        ssrf_warning=ssrf_warn,
                        obfuscation_note=obf_desc,
                    )
                else:
                    ipv4_list, _, reverse_dns, is_priv, is_meta, ssrf_warn = (
                        net_mod.resolve_ip_and_dns(host)
                    )
                    is_intern = is_priv or is_meta or is_internal(host)
                    scope = get_ip_classification(ipv4_list[0] if ipv4_list else host)
                    endpoint = DiscoveredEndpoint(
                        raw_reference=raw_ref,
                        host=host,
                        source_file=rel_path,
                        line_number=line_num,
                        resolved_ips=ipv4_list,
                        normalized_ip=norm_ip,
                        reverse_dns=reverse_dns,
                        is_private=is_priv,
                        is_metadata=is_meta,
                        is_internal=is_intern,
                        security_scope=scope,
                        ssrf_warning=ssrf_warn,
                        obfuscation_note=obf_desc,
                    )

                report.discovered_endpoints.append(endpoint)
                if endpoint.is_internal:
                    report.internal_endpoints.append(endpoint)
                    report.private_ips_count += 1
                else:
                    report.external_endpoints.append(endpoint)

                if endpoint.ssrf_warning or endpoint.is_metadata:
                    report.ssrf_risks_count += 1

    report.total_endpoints_found = len(report.discovered_endpoints)
    return report


class NetworkScanner(BaseScanner):
    """Network security static scanner adapter."""

    @property
    def name(self) -> str:
        return "cry-network"

    @property
    def description(self) -> str:
        return "Scans code and configurations for IMDS metadata leaks, cleartext HTTP APIs, and SSRF attack vectors."

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path, base_dir: Path) -> list[Finding]:
        return scan_file_network(file_path, base_dir)

    async def scan(self, target: Path | str) -> list[Finding]:
        target_path = Path(target).resolve()
        return scan_network_code_patterns(target_path)
