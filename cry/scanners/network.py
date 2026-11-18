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
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from cry.exclusions import ExclusionStats, GitIgnoreMatcher, should_skip_path
from cry.models import Category, Finding, Severity
from cry.network_auth import (
    check_target_permission,
    log_network_scan_audit,
)
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

# SSRF sink patterns: client request using unvalidated query / request parameters
SSRF_SINK_PATTERN = re.compile(
    r"""(?:requests\.(?:get|post|put|delete)|fetch|axios\.(?:get|post)|http\.(?:get|request))\s*\(\s*(?:req\.query|req\.body|request\.args|request\.GET|url_param|user_url)""",
    re.IGNORECASE,
)

# URL / endpoint matching regex in source files
URL_PATTERN = re.compile(
    r"""(?:https?|postgres|postgresql|mysql|redis|mongodb|amqp|wss?)://([^\s/'"?#]+)""",
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


def scan_network_code_patterns(
    target_dir: Path,
    include_vendor: bool = False,
    stats: ExclusionStats | None = None,
) -> list[Finding]:
    """Scan all files in directory for network security anti-patterns."""
    findings: list[Finding] = []

    if target_dir.is_file():
        return scan_file_network(target_dir, target_dir.parent)

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
    weak_ciphers: list[str] = field(default_factory=list)
    legacy_protocols_supported: list[str] = field(default_factory=list)
    platform_limitation_note: str | None = None


@dataclass
class PortCheckResult:
    """Result of an individual TCP port reachability probe."""

    port: int
    service: str
    status: str  # "OPEN", "CLOSED", "FILTERED"
    is_database: bool = False
    severity: str | None = None  # "CRITICAL", "HIGH", None
    note: str | None = None


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
    authorization_status: str = "UNCHECKED"
    authorization_token: str | None = None
    ports_checked: list[PortCheckResult] = field(default_factory=list)
    database_exposures_count: int = 0
    waf_or_cdn: str | None = None
    is_deep: bool = False
    audit_logged: bool = False
    service_offline: bool = False
    service_offline_message: str | None = None
    disclaimer: str = (
        "Reported observations reflect only active technical probes at scan time. "
        "No claim is made that the target host is secure or free of vulnerabilities."
    )


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


def extract_host_and_port(raw_target: str) -> tuple[str, int | None]:
    """Extract clean hostname and optional port from URL or target string."""
    target = raw_target.strip()
    port: int | None = None
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or parsed.netloc.split(":")[0]
        port = parsed.port
    else:
        part0 = target.split("/")[0]
        if part0.startswith("[") and "]" in part0:
            host = part0[1:].split("]")[0]
            rem = part0.split("]")[1]
            if rem.startswith(":") and rem[1:].isdigit():
                port = int(rem[1:])
        elif ":" in part0 and not part0.count(":") > 1:
            sub = part0.split(":")
            host = sub[0]
            if sub[1].isdigit():
                port = int(sub[1])
        else:
            host = part0

    return host.strip(), port


def _clean_target_hostname(raw_target: str) -> str:
    """Extract clean hostname from URL or input string."""
    host, _ = extract_host_and_port(raw_target)
    return host


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


# ---------------------------------------------------------------------------
# Active Network Probing Constants & Port Catalogs
# ---------------------------------------------------------------------------

DATABASE_CACHE_PORTS: dict[int, str] = {
    5432: "PostgreSQL",
    3306: "MySQL/MariaDB",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    8500: "Consul Agent/API",
    2379: "etcd Client API",
}

COMMON_SERVICE_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    3000: "Node.js/Dev Web",
    5000: "Flask/Dev Web",
    8000: "Django/Dev Web",
    8080: "HTTP Alt/Proxy",
    8443: "HTTPS Alt",
    **DATABASE_CACHE_PORTS,
}

DEFAULT_PROBE_PORTS: list[int] = [
    80,
    443,
    8080,
    8443,
    22,
    21,
    25,
    3000,
    5000,
    8000,
    3306,
    5432,
    6379,
    27017,
    9200,
]

EXTENDED_PROBE_PORTS: list[int] = DEFAULT_PROBE_PORTS + [
    53,
    110,
    143,
    465,
    993,
    995,
    1433,
    1521,
    2379,
    8500,
    11211,
]

WEAK_CIPHER_REGEX = re.compile(
    r"""\b(?:RC4|3DES|DES|MD5|NULL|EXPORT|CBC)\b""",
    re.IGNORECASE,
)


class DNSRebindingError(Exception):
    """Raised when host re-resolves to forbidden/internal IP right before socket connect."""

    pass


def parse_port_list(ports_spec: str | None) -> list[int]:
    """Parse comma-separated port numbers and ranges, capping at 100 ports."""
    if not ports_spec:
        return DEFAULT_PROBE_PORTS.copy()
    ports: set[int] = set()
    parts = ports_spec.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            sub = part.split("-")
            if len(sub) == 2 and sub[0].isdigit() and sub[1].isdigit():
                start_p, end_p = int(sub[0]), int(sub[1])
                if 1 <= start_p <= 65535 and 1 <= end_p <= 65535:
                    for p in range(min(start_p, end_p), max(start_p, end_p) + 1):
                        ports.add(p)
                        if len(ports) >= 100:
                            break
        elif part.isdigit():
            p_val = int(part)
            if 1 <= p_val <= 65535:
                ports.add(p_val)
        if len(ports) >= 100:
            break
    result = sorted(ports)[:100]
    return result or DEFAULT_PROBE_PORTS.copy()


def probe_tcp_port(
    ip: str,
    port: int,
    timeout: float = 1.5,
    rate_delay: float = 0.03,
) -> tuple[str, str | None]:
    """Probe TCP reachability of a single port with rate limiting.

    Returns (status, error_note) where status in ('OPEN', 'CLOSED', 'FILTERED').
    """
    if rate_delay > 0:
        time.sleep(rate_delay)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res = sock.connect_ex((ip, port))
        sock.close()
        if res == 0:
            return "OPEN", None
        elif res in (10061, 111):
            return "CLOSED", None
        else:
            return "FILTERED", f"Code {res}"
    except TimeoutError:
        return "FILTERED", "Timeout"
    except Exception as e:
        return "FILTERED", str(e)


def verify_ip_before_connect(
    hostname: str,
    expected_ip: str,
    allow_local: bool = False,
) -> str:
    """Re-resolve hostname immediately prior to socket connect to mitigate DNS rebinding."""
    if normalize_ip(hostname):
        return expected_ip

    fresh_ipv4, fresh_ipv6, _, _, _, _ = resolve_ip_and_dns(hostname)
    fresh_ips = fresh_ipv4 + fresh_ipv6
    if not fresh_ips:
        return expected_ip

    for ip in fresh_ips:
        if is_cloud_metadata(ip):
            raise DNSRebindingError(
                f"DNS Rebinding detected: Host '{hostname}' re-resolved to cloud metadata IP ({ip})!"
            )
        if not allow_local and is_internal(ip):
            raise DNSRebindingError(
                f"DNS Rebinding detected: Host '{hostname}' re-resolved to internal IP ({ip}) without --allow-local!"
            )

    return fresh_ips[0]


def detect_waf_or_cdn(headers: dict[str, str] | httpx.Headers) -> str | None:
    """Identify Edge CDN or WAF from response headers (Informational only)."""
    normalized = {k.lower(): v.lower() for k, v in headers.items()}
    server = normalized.get("server", "")
    via = normalized.get("via", "")

    if "cf-ray" in normalized or "cloudflare" in server or "cf-cache-status" in normalized:
        return "Cloudflare Edge / WAF"
    if "x-amz-cf-id" in normalized or "x-amz-cf-pop" in normalized or "cloudfront" in via:
        return "AWS CloudFront CDN"
    if "x-fastly-request-id" in normalized or "fastly" in via:
        return "Fastly Edge CDN"
    if "x-akamai-transformed" in normalized or "akamai" in server:
        return "Akamai Edge Platform"
    if "x-vercel-id" in normalized or "vercel" in server:
        return "Vercel Edge Platform"
    if "x-nf-request-id" in normalized or "netlify" in server:
        return "Netlify CDN"
    if "x-iinfo" in normalized or "incapsula" in server or "x-cdn" in normalized:
        return "Imperva / Incapsula WAF"
    if "x-sucuri-id" in normalized or "sucuri" in server:
        return "Sucuri Cloud WAF"
    if "envoy" in server or "x-envoy-upstream-service-time" in normalized:
        return "Envoy Proxy / Edge Ingress"
    if "nginx" in server:
        return "Nginx Web Server / Reverse Proxy"
    if "caddy" in server:
        return "Caddy Web Server"

    return None


def inspect_ssl_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    connect_host: str | None = None,
    check_legacy: bool = False,
) -> SSLCertificateInfo | None:
    """Connect via TLS socket and extract live certificate telemetry and cipher review."""
    context = ssl.create_default_context()
    context.check_hostname = True
    dest = connect_host or hostname

    try:
        with (
            socket.create_connection((dest, port), timeout=timeout) as sock,
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

            cipher_name = cipher[0] if cipher else "Unknown"
            weak_ciphers: list[str] = []
            if cipher_name != "Unknown" and WEAK_CIPHER_REGEX.search(cipher_name):
                weak_ciphers.append(cipher_name)

            legacy_protocols: list[str] = []
            platform_note: str | None = None
            if check_legacy:
                platform_note = (
                    "Probing legacy protocols (TLS 1.0/1.1) depends on host platform OpenSSL security level. "
                    "If system OpenSSL enforces SECLEVEL >= 2, legacy handshakes are refused by local crypto runtime."
                )
                for ver_name, ver_enum in [
                    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
                ]:
                    if ver_enum is None:
                        continue
                    try:
                        leg_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        leg_ctx.check_hostname = False
                        leg_ctx.verify_mode = ssl.CERT_NONE
                        leg_ctx.minimum_version = ver_enum
                        leg_ctx.maximum_version = ver_enum
                        with (
                            socket.create_connection((dest, port), timeout=timeout) as lsock,
                            leg_ctx.wrap_socket(lsock, server_hostname=hostname),
                        ):
                            legacy_protocols.append(ver_name)
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
                cipher_suite=cipher_name,
                weak_ciphers=weak_ciphers,
                legacy_protocols_supported=legacy_protocols,
                platform_limitation_note=platform_note,
            )
    except Exception:
        return None


def audit_http_security_headers_and_waf(
    target_url: str, timeout: float = 6.0
) -> tuple[list[HeaderCheck], str, str | None]:
    """Probe target server and audit HTTP security defense headers and detect WAF/CDN."""
    checks: list[HeaderCheck] = []
    url = target_url if target_url.startswith("http") else f"https://{target_url}"
    waf_cdn: str | None = None

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
            waf_cdn = detect_waf_or_cdn(server_headers)

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

            return checks, grade, waf_cdn

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
        return checks, "F", None


def audit_http_security_headers(
    target_url: str, timeout: float = 6.0
) -> tuple[list[HeaderCheck], str]:
    """Probe target server and audit HTTP security defense headers."""
    checks, grade, _ = audit_http_security_headers_and_waf(target_url, timeout=timeout)
    return checks, grade


def audit_network_target(
    target: str,
    allow_local: bool = False,
    deep: bool = False,
    ports: list[int] | None = None,
) -> NetworkAuditReport:
    """Execute complete authorized network, IP lookup, port exposure, SSL/TLS, and header audit."""
    target_host, target_port = extract_host_and_port(target)
    hostname = target_host
    ipv4_list, ipv6_list, reverse_dns, is_private, is_metadata, ssrf_warning = resolve_ip_and_dns(
        hostname
    )

    if not ipv4_list and not ipv6_list:
        return NetworkAuditReport(
            target=target,
            hostname=hostname,
            error_message=f"Could not resolve DNS records for hostname '{hostname}'. Verify host spelling and network connection.",
        )

    primary_ip = ipv4_list[0] if ipv4_list else ipv6_list[0]

    # 1. Target Authorization Gate
    is_allowed, auth_reason, token = check_target_permission(
        hostname,
        allow_local=allow_local,
        pre_resolved_ip=primary_ip,
    )
    if not is_allowed:
        return NetworkAuditReport(
            target=target,
            hostname=hostname,
            ipv4_addresses=ipv4_list,
            ipv6_addresses=ipv6_list,
            reverse_dns=reverse_dns,
            is_private_ip=is_private,
            is_metadata_ip=is_metadata,
            authorization_status="UNAUTHORIZED",
            authorization_token=token,
            error_message=auth_reason,
        )

    auth_status = (
        "AUTHORIZED_LOCAL"
        if (is_private or is_metadata or is_internal(hostname))
        else "AUTHORIZED_PUBLIC"
    )

    # 2. DNS Rebinding Pre-connect Check
    try:
        connect_ip = verify_ip_before_connect(hostname, primary_ip, allow_local=allow_local)
    except DNSRebindingError as e:
        return NetworkAuditReport(
            target=target,
            hostname=hostname,
            ipv4_addresses=ipv4_list,
            ipv6_addresses=ipv6_list,
            authorization_status=auth_status,
            error_message=f"SECURITY ABORT: {e}",
        )

    # 3. Determine Ports to Probe (Hard Cap 100)
    if ports:
        ports_to_probe = ports[:100]
    elif deep:
        ports_to_probe = EXTENDED_PROBE_PORTS[:100]
    else:
        ports_to_probe = DEFAULT_PROBE_PORTS[:100]

    # Ensure custom target port (e.g. 3001 in http://localhost:3001/) is probed
    if target_port and target_port not in ports_to_probe:
        ports_to_probe = [target_port] + ports_to_probe

    # 4. Port Reachability & Database Exposure Probe
    port_results: list[PortCheckResult] = []
    database_exposures = 0

    for p in ports_to_probe:
        status, err_note = probe_tcp_port(connect_ip, p, timeout=1.5, rate_delay=0.03)
        service_name = COMMON_SERVICE_PORTS.get(p, f"Port {p}")
        is_db = p in DATABASE_CACHE_PORTS and status == "OPEN"
        sev: str | None = None
        note = err_note

        if is_db:
            if not is_private and not is_metadata:
                sev = "CRITICAL" if p in (6379, 27017) else "HIGH"
                database_exposures += 1
                note = f"EXPOSURE RISK: {service_name} database directly reachable on public IP!"
            else:
                note = f"Local/internal {service_name} instance"

        port_results.append(
            PortCheckResult(
                port=p,
                service=service_name,
                status=status,
                is_database=p in DATABASE_CACHE_PORTS,
                severity=sev,
                note=note,
            )
        )

    # 5. Determine Target Service Reachability (Service Offline Check)
    service_offline = False
    service_offline_message: str | None = None

    if target_port:
        web_ports = [target_port]
    elif target.startswith("https://"):
        web_ports = [443]
    elif target.startswith("http://"):
        web_ports = [80]
    else:
        web_ports = [80, 443]

    probed_web_results = [pr for pr in port_results if pr.port in web_ports]
    if probed_web_results and all(pr.status != "OPEN" for pr in probed_web_results):
        service_offline = True
        if target_port:
            status_str = probed_web_results[0].status.lower()
            service_offline_message = (
                f"Target port {target_port} is {status_str} (service offline). "
                "HTTP security header evaluation skipped."
            )
        else:
            ports_str = ", ".join(str(p) for p in web_ports)
            service_offline_message = (
                f"Designated web port(s) ({ports_str}) are unreachable or closed. "
                "HTTP security header evaluation skipped."
            )

    # 6. Inspect SSL/TLS Certificate & Cipher Review
    ssl_info = None
    tls_port = target_port if (target_port and target_port in (443, 8443)) else 443
    if (
        not service_offline
        and any(pr.port == tls_port and pr.status == "OPEN" for pr in port_results)
        and not is_metadata
    ):
        ssl_info = inspect_ssl_certificate(
            hostname,
            port=tls_port,
            timeout=5.0,
            connect_host=connect_ip,
            check_legacy=deep,
        )

    # 7. Audit HTTP Security Headers & WAF/CDN Detection
    if service_offline:
        headers: list[HeaderCheck] = []
        grade = "N/A"
        waf_cdn = None
    else:
        target_for_http = (
            target
            if "://" in target
            else (f"{hostname}:{target_port}" if target_port else hostname)
        )
        headers, grade, waf_cdn = audit_http_security_headers_and_waf(target_for_http)

    # 8. Audit Logging
    checks_run = ["dns", "ports"]
    if not service_offline:
        checks_run.extend(["tls", "headers"])
    if deep:
        checks_run.append("deep_ports_and_ciphers")
    log_network_scan_audit(
        target=target,
        resolved_ip=connect_ip,
        checks_run=checks_run,
        is_deep=deep,
        auth_status=auth_status,
    )

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
        authorization_status=auth_status,
        ports_checked=port_results,
        database_exposures_count=database_exposures,
        waf_or_cdn=waf_cdn,
        is_deep=deep,
        audit_logged=True,
        service_offline=service_offline,
        service_offline_message=service_offline_message,
    )


def audit_project_network(
    project_dir: Path,
    passive: bool = True,
    include_vendor: bool = False,
    stats: ExclusionStats | None = None,
) -> ProjectNetworkReport:
    """Scan project files to discover all declared network endpoints and analyze footprint.

    When passive=True (default), analysis operates entirely locally without sending any network packets.
    """
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

    # Matches standard, hex, octal, dword decimal, or cloud metadata IPs
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
                    ipv4_list, _, reverse_dns, is_priv, is_meta, ssrf_warn = resolve_ip_and_dns(
                        host
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
