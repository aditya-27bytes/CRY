"""Active network host probing, DNS resolution, port checks, and target audit."""

from __future__ import annotations

import ipaddress
import socket
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cry.network_auth import (
    check_target_permission,
    log_network_scan_audit,
)
from cry.network_ip import (
    is_cloud_metadata,
    is_internal,
    normalize_ip,
)
from cry.scanners.network_http import HeaderCheck
from cry.scanners.network_tls import SSLCertificateInfo


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


class DNSRebindingError(Exception):
    """Raised when host re-resolves to forbidden/internal IP right before socket connect."""

    pass


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

DATABASE_PORTS = DATABASE_CACHE_PORTS

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

DEFAULT_TOP_PORTS = DEFAULT_PROBE_PORTS

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

HIGH_RISK_PORTS = EXTENDED_PROBE_PORTS


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

    Supports both IPv4 and IPv6 addresses seamlessly.
    Returns (status, error_note) where status in ('OPEN', 'CLOSED', 'FILTERED').
    """
    if rate_delay > 0:
        time.sleep(rate_delay)
    try:
        ip_obj = ipaddress.ip_address(ip)
        family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
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
    from cry.scanners import network as _net

    if normalize_ip(hostname):
        return expected_ip

    fresh_ipv4, fresh_ipv6, _, _, _, _ = _net.resolve_ip_and_dns(hostname)
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


def audit_network_target(
    target: str,
    allow_local: bool = False,
    deep: bool = False,
    ports: list[int] | None = None,
) -> NetworkAuditReport:
    """Execute complete authorized network, IP lookup, port exposure, SSL/TLS, and header audit."""
    from cry.scanners import network as _net

    target_host, target_port = extract_host_and_port(target)
    hostname = target_host
    ipv4_list, ipv6_list, reverse_dns, is_private, is_metadata, ssrf_warning = (
        _net.resolve_ip_and_dns(hostname)
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
        connect_ip = _net.verify_ip_before_connect(hostname, primary_ip, allow_local=allow_local)
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

    # Collect alternative dual-stack IPs (e.g. ::1 vs 127.0.0.1 for localhost)
    alt_ips = [ip for ip in (ipv4_list + ipv6_list) if ip != connect_ip]

    for p in ports_to_probe:
        status, err_note = _net.probe_tcp_port(connect_ip, p, timeout=1.5, rate_delay=0.03)

        # If port is not OPEN on primary IP, check alternative dual-stack IP(s)
        if status != "OPEN" and alt_ips:
            for alt_ip in alt_ips:
                alt_status, alt_err = _net.probe_tcp_port(alt_ip, p, timeout=1.5, rate_delay=0.01)
                if alt_status == "OPEN":
                    status = "OPEN"
                    err_note = None
                    if p == target_port:
                        connect_ip = alt_ip
                    break

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
        ssl_info = _net.inspect_ssl_certificate(
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
        headers, grade, waf_cdn = _net.audit_http_security_headers_and_waf(target_for_http)

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
