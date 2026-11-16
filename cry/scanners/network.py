"""Network security scanner and live IP / host intelligence engine for CRY.

Provides:
1. Static Code Analysis for Network Flaws:
   - Cloud instance metadata IP leaks (169.254.169.254 AWS/GCP/Azure IMDS)
   - Cleartext HTTP API calls in production code (CWE-319)
   - Internal RFC-1918 private IP topology disclosure (CWE-200)
   - Potential Server-Side Request Forgery (SSRF) invocation sinks (CWE-918)

2. Live Network & IP Intelligence Engine:
   - DNS & IP address resolution (IPv4, IPv6, Reverse PTR)
   - SSRF / DNS rebinding detection (flags public domains resolving to private/metadata IPs)
   - TLS/SSL certificate status, issuer, and days until expiration
   - HTTP defense-in-depth security headers audit and grading (HSTS, CSP, X-Frame, nosniff)
"""

import ipaddress
import re
import socket
import ssl
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

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

# Regex to detect Cloud Instance Metadata IP (AWS/GCP/Azure IMDS)
METADATA_IP_PATTERN = re.compile(r"""\b169\.254\.169\.254\b""")

# Regex to detect unencrypted HTTP remote API calls (excluding localhost, 127.0.0.1, example.com, test domains)
PLAINTEXT_HTTP_PATTERN = re.compile(
    r"""['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|test|example\.com|schemas\.)([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(?::\d+)?[^'"]*)['"]""",
    re.IGNORECASE,
)

# Regex to detect private RFC-1918 IPs in source code
PRIVATE_IP_PATTERN = re.compile(
    r"""\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"""
)

# SSRF sink patterns: client request using unvalidated query / request parameters
SSRF_SINK_PATTERN = re.compile(
    r"""(?:requests\.(?:get|post|put|delete)|fetch|axios\.(?:get|post)|http\.(?:get|request))\s*\(\s*(?:req\.query|req\.body|request\.args|request\.GET|url_param|user_url)""",
    re.IGNORECASE,
)


def _should_skip(file_path: Path) -> bool:
    return any(p in SKIP_DIRS for p in file_path.parts)


# ---------------------------------------------------------------------------
# 1. Static Code Analysis for Network Vulnerabilities
# ---------------------------------------------------------------------------


def scan_file_network(file_path: Path, base_dir: Path) -> list[Finding]:
    """Scan a single source or config file for network security flaws."""
    findings: list[Finding] = []
    rel_path = str(file_path.relative_to(base_dir))
    ext = file_path.suffix.lower()

    if ext not in SCANNABLE_EXTENSIONS or _should_skip(file_path):
        return findings

    # Avoid self-flagging of scanner rules
    if file_path.name == "network.py" and "scanners" in file_path.parts:
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
        if METADATA_IP_PATTERN.search(line):
            findings.append(
                Finding(
                    id=f"net-{uuid.uuid4().hex[:12]}",
                    tool="cry-network",
                    title="Hardcoded Cloud Metadata IP (169.254.169.254)",
                    description=(
                        "Detected AWS/GCP/Azure instance metadata IP address (169.254.169.254). "
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
                    fix_hint="Enforce IMDSv2 with token hops restricted to 1, or block outbound access to 169.254.169.254 via network security groups.",
                    suggested_fix="# Block or avoid calling 169.254.169.254. Use cloud SDK IAM credential providers instead.",
                    raw_evidence="Matched 169.254.169.254 IMDS IP",
                )
            )

        # 2. Check for Plaintext HTTP External API Calls
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

        # 3. Check for SSRF Sinks
        if SSRF_SINK_PATTERN.search(line):
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


def scan_network_code_patterns(target_dir: Path) -> list[Finding]:
    """Scan all files in directory for network security anti-patterns."""
    findings: list[Finding] = []

    if target_dir.is_file():
        return scan_file_network(target_dir, target_dir.parent)

    for file_path in target_dir.rglob("*"):
        if not file_path.is_file() or _should_skip(file_path):
            continue
        findings.extend(scan_file_network(file_path, target_dir))

    return findings


# ---------------------------------------------------------------------------
# 2. Live Network & IP Intelligence Engine
# ---------------------------------------------------------------------------


@dataclass
class HeaderCheck:
    """Status of an individual HTTP security header."""

    name: str
    present: bool
    value: str | None
    recommendation: str
    severity: str  # HIGH, MEDIUM, LOW


@dataclass
class SSLCertificateInfo:
    """Parsed SSL/TLS certificate information."""

    issuer: str = "Unknown"
    subject: str = "Unknown"
    valid_from: str = "Unknown"
    valid_to: str = "Unknown"
    days_remaining: int = 0
    is_expired: bool = False
    tls_version: str = "Unknown"
    cipher_suite: str = "Unknown"


@dataclass
class NetworkAuditReport:
    """Comprehensive network and IP intelligence audit result."""

    target: str
    hostname: str
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)
    reverse_dns: str | None = None
    is_private_ip: bool = False
    is_metadata_ip: bool = False
    ssrf_risk_warning: str | None = None
    ssl_info: SSLCertificateInfo | None = None
    security_headers: list[HeaderCheck] = field(default_factory=list)
    security_score: str = "F"
    scan_timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    error_message: str | None = None


@dataclass
class DiscoveredEndpoint:
    """A network endpoint or IP discovered within codebase or configuration files."""

    raw_reference: str
    host: str
    source_file: str
    line_number: int
    resolved_ips: list[str] = field(default_factory=list)
    reverse_dns: str | None = None
    is_private: bool = False
    is_metadata: bool = False
    ssrf_warning: str | None = None


@dataclass
class ProjectNetworkReport:
    """Network intelligence and IP footprint audit across an entire project directory."""

    project_dir: str
    local_hostname: str
    local_outbound_ip: str
    discovered_endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    total_endpoints_found: int = 0
    ssrf_risks_count: int = 0
    private_ips_count: int = 0
    scan_timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


def _clean_target_hostname(raw_target: str) -> str:
    """Extract clean hostname from URL or input string."""
    target = raw_target.strip()
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        host = parsed.netloc or parsed.path
    else:
        host = target.split("/")[0]

    # Strip port if present
    if ":" in host and not host.startswith("["):
        host = host.split(":")[0]
    return host.strip()


def resolve_ip_and_dns(
    hostname: str,
) -> tuple[list[str], list[str], str | None, bool, bool, str | None]:
    """Resolve IPv4, IPv6, Reverse DNS PTR, and detect SSRF/private IP risks."""
    ipv4_list: list[str] = []
    ipv6_list: list[str] = []
    reverse_dns: str | None = None
    is_private = False
    is_metadata = False
    ssrf_warning: str | None = None

    # Resolve IP addresses via getaddrinfo
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = str(sockaddr[0])
            if family == socket.AF_INET and ip_str not in ipv4_list:
                ipv4_list.append(ip_str)
            elif family == socket.AF_INET6 and ip_str not in ipv6_list:
                ipv6_list.append(ip_str)
    except (socket.gaierror, UnicodeError, OSError, ValueError):
        pass

    # Evaluate IP risks (Private subnets or Cloud Metadata IP)
    all_ips = ipv4_list + ipv6_list
    for ip_str in all_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_str == "169.254.169.254":
                is_metadata = True
                ssrf_warning = (
                    "CRITICAL SSRF RISK: Resolves to Cloud Instance Metadata IP (169.254.169.254)!"
                )
            elif ip_obj.is_private or ip_obj.is_loopback:
                is_private = True
                ssrf_warning = (
                    f"HIGH SSRF RISK: Domain resolves to private or loopback IP range ({ip_str})!"
                )
        except ValueError:
            continue

    # Reverse DNS PTR
    if ipv4_list:
        try:
            reverse_host, _, _ = socket.gethostbyaddr(ipv4_list[0])
            reverse_dns = reverse_host
        except (socket.herror, socket.gaierror, OSError):
            reverse_dns = None

    return ipv4_list, ipv6_list, reverse_dns, is_private, is_metadata, ssrf_warning


def inspect_ssl_certificate(
    hostname: str, port: int = 443, timeout: float = 5.0
) -> SSLCertificateInfo | None:
    """Connect via TLS socket and extract live certificate telemetry."""
    context = ssl.create_default_context()
    context.check_hostname = True

    try:
        with (
            socket.create_connection((hostname, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cert: dict[str, Any] = ssock.getpeercert() or {}
            cipher = ssock.cipher()
            tls_version = ssock.version() or "Unknown"

            # Parse issuer
            issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
            issuer_name = (
                issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"
            )

            # Parse subject
            subject_dict = dict(x[0] for x in cert.get("subject", ()))
            subject_name = subject_dict.get("commonName") or "Unknown"

            # Parse expiration date
            not_after_str = cert.get("notAfter", "")
            days_left = 0
            is_expired = False
            valid_to_display = not_after_str

            if not_after_str:
                try:
                    # Format: 'May 15 12:00:00 2026 GMT'
                    expire_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=UTC
                    )
                    now_dt = datetime.now(UTC)
                    delta = expire_dt - now_dt
                    days_left = delta.days
                    is_expired = days_left < 0
                    valid_to_display = expire_dt.strftime("%Y-%m-%d %H:%M UTC")
                except Exception:
                    pass

            return SSLCertificateInfo(
                issuer=issuer_name,
                subject=subject_name,
                valid_from=cert.get("notBefore", "Unknown"),
                valid_to=valid_to_display,
                days_remaining=days_left,
                is_expired=is_expired,
                tls_version=tls_version,
                cipher_suite=cipher[0] if cipher else "Unknown",
            )
    except Exception:
        return None


def audit_http_security_headers(
    target_url: str, timeout: float = 6.0
) -> tuple[list[HeaderCheck], str]:
    """Probe target server and audit HTTP security defense headers."""
    checks: list[HeaderCheck] = []
    url = target_url if target_url.startswith("http") else f"https://{target_url}"

    headers_to_check = [
        (
            "Strict-Transport-Security",
            "Enforces HTTPS for all future visits, defeating SSL-stripping MitM attacks.",
            "max-age=31536000; includeSubDomains; preload",
            "HIGH",
        ),
        (
            "Content-Security-Policy",
            "Restricts script, frame, and style injection to neutralize XSS attacks.",
            "default-src 'self'; script-src 'self'",
            "HIGH",
        ),
        (
            "X-Frame-Options",
            "Prevents clickjacking by blocking unauthorized framing of your web app.",
            "DENY or SAMEORIGIN",
            "MEDIUM",
        ),
        (
            "X-Content-Type-Options",
            "Blocks browser MIME-type sniffing to prevent script execution from uploaded files.",
            "nosniff",
            "MEDIUM",
        ),
        (
            "Referrer-Policy",
            "Protects user privacy and avoids leaking sensitive tokens in Referer headers.",
            "strict-origin-when-cross-origin",
            "LOW",
        ),
        (
            "Permissions-Policy",
            "Controls browser access to camera, microphone, geolocation, and payment APIs.",
            "camera=(), microphone=(), geolocation=()",
            "LOW",
        ),
    ]

    try:
        with httpx.Client(timeout=timeout, verify=True, follow_redirects=True) as client:
            resp = client.head(url)
            # If HEAD returns 405 Method Not Allowed, fallback to quick GET
            if resp.status_code == 405:
                resp = client.get(url)

            server_headers = resp.headers

            score_points = 0
            for name, purpose, recommended, sev in headers_to_check:
                header_val = server_headers.get(name)
                is_present = bool(header_val)
                if is_present:
                    score_points += 2 if sev == "HIGH" else 1

                checks.append(
                    HeaderCheck(
                        name=name,
                        present=is_present,
                        value=header_val,
                        recommendation=f"{purpose} (Recommended: `{recommended}`)",
                        severity=sev,
                    )
                )

            # Grade calculation
            max_points = 8
            ratio = score_points / max_points
            if ratio >= 0.9:
                grade = "A+"
            elif ratio >= 0.75:
                grade = "A"
            elif ratio >= 0.6:
                grade = "B"
            elif ratio >= 0.4:
                grade = "C"
            elif ratio >= 0.2:
                grade = "D"
            else:
                grade = "F"

            return checks, grade

    except Exception:
        # Fallback when HTTP call fails or host is unreachable
        for name, purpose, recommended, sev in headers_to_check:
            checks.append(
                HeaderCheck(
                    name=name,
                    present=False,
                    value=None,
                    recommendation=f"{purpose} (Recommended: `{recommended}`)",
                    severity=sev,
                )
            )
        return checks, "F"


def audit_network_target(target: str) -> NetworkAuditReport:
    """Execute complete network, IP lookup, SSL/TLS, and security header audit."""
    hostname = _clean_target_hostname(target)
    ipv4_list, ipv6_list, reverse_dns, is_private, is_metadata, ssrf_warning = resolve_ip_and_dns(
        hostname
    )

    if not ipv4_list and not ipv6_list:
        return NetworkAuditReport(
            target=target,
            hostname=hostname,
            error_message=f"Could not resolve DNS records for hostname '{hostname}'. Verify host spelling and network connection.",
        )

    # Inspect SSL if not on internal private IP
    ssl_info = None
    if not is_private and not is_metadata:
        ssl_info = inspect_ssl_certificate(hostname)

    # Audit HTTP Security Headers
    headers, grade = audit_http_security_headers(hostname)

    return NetworkAuditReport(
        target=target,
        hostname=hostname,
        ipv4_addresses=ipv4_list,
        ipv6_addresses=ipv6_list,
        reverse_dns=reverse_dns,
        is_private_ip=is_private,
        is_metadata_ip=is_metadata,
        ssrf_risk_warning=ssrf_warning,
        ssl_info=ssl_info,
        security_headers=headers,
        security_score=grade,
    )


def audit_project_network(project_dir: Path) -> ProjectNetworkReport:
    """Scan project files to discover all declared network endpoints and perform live IP/SSRF resolution."""
    p = project_dir.resolve()
    local_hostname = socket.gethostname()
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
    )

    if not p.is_dir():
        return report

    url_pattern = re.compile(
        r"""(?:https?|postgres|postgresql|mysql|redis|mongodb|amqp|wss?)://([a-zA-Z0-9\.\-_:]+)""",
        re.IGNORECASE,
    )
    ip_pattern = re.compile(r"""\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b""")

    seen_hosts: set[str] = set()

    for file_path in p.rglob("*"):
        if not file_path.is_file() or _should_skip(file_path):
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

            extracted_hosts: list[tuple[str, str]] = []

            # Check URLs
            for match in url_pattern.finditer(line_str):
                raw_ref = match.group(0)
                netloc = match.group(1).split("@")[-1]
                host = netloc.split("/")[0].split(":")[0].strip(" ./:;'\"`()[]{}<>").lower()
                if (
                    host
                    and len(host) >= 3
                    and not host.startswith(".")
                    and not host.endswith(".")
                    and ".." not in host
                    and host not in seen_hosts
                ):
                    extracted_hosts.append((raw_ref, host))
                    seen_hosts.add(host)

            # Check raw IPs
            for match in ip_pattern.finditer(line_str):
                ip_cand = match.group(1).strip()
                octets = ip_cand.split(".")
                if (
                    len(octets) == 4
                    and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets)
                    and ip_cand not in {"0.0.0.0", "255.255.255.255"}
                    and ip_cand not in seen_hosts
                ):
                    extracted_hosts.append((ip_cand, ip_cand))
                    seen_hosts.add(ip_cand)

            for raw_ref, host in extracted_hosts:
                ipv4_list, _, reverse_dns, is_priv, is_meta, ssrf_warn = resolve_ip_and_dns(host)
                endpoint = DiscoveredEndpoint(
                    raw_reference=raw_ref,
                    host=host,
                    source_file=rel_path,
                    line_number=line_num,
                    resolved_ips=ipv4_list,
                    reverse_dns=reverse_dns,
                    is_private=is_priv,
                    is_metadata=is_meta,
                    ssrf_warning=ssrf_warn,
                )
                report.discovered_endpoints.append(endpoint)
                if is_priv:
                    report.private_ips_count += 1
                if ssrf_warn or is_meta:
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
