"""Network security scanner and live IP / host intelligence facade for CRY.

This module re-exports components from modular submodules:
- network_footprint: Static code scanning & passive declared footprint analysis
- network_probe: Active host resolution, port probing & target audit
- network_tls: SSL/TLS certificate inspection & cipher review
- network_http: HTTP defense headers & Edge CDN/WAF detection
"""

from __future__ import annotations

from cry.scanners.network_footprint import (
    LINK_LOCAL_PATTERN,
    METADATA_IP_PATTERN,
    PLAINTEXT_HTTP_PATTERN,
    PRIVATE_IP_PATTERN,
    SCANNABLE_EXTENSIONS,
    SKIP_DIRS,
    SSRF_SINK_PATTERN,
    URL_PATTERN,
    DiscoveredEndpoint,
    NetworkScanner,
    ProjectNetworkReport,
    _should_skip,
    audit_project_network,
    scan_file_network,
    scan_network_code_patterns,
)
from cry.scanners.network_http import (
    HeaderCheck,
    audit_http_security_headers,
    audit_http_security_headers_and_waf,
    detect_waf_or_cdn,
)
from cry.scanners.network_probe import (
    COMMON_SERVICE_PORTS,
    DATABASE_CACHE_PORTS,
    DATABASE_PORTS,
    DEFAULT_PROBE_PORTS,
    DEFAULT_TOP_PORTS,
    EXTENDED_PROBE_PORTS,
    HIGH_RISK_PORTS,
    DNSRebindingError,
    NetworkAuditReport,
    PortCheckResult,
    _clean_target_hostname,
    audit_network_target,
    extract_host_and_port,
    parse_port_list,
    probe_tcp_port,
    resolve_ip_and_dns,
    verify_ip_before_connect,
)
from cry.scanners.network_tls import (
    WEAK_CIPHER_REGEX,
    SSLCertificateInfo,
    inspect_ssl_certificate,
)

__all__ = [
    "COMMON_SERVICE_PORTS",
    "DATABASE_CACHE_PORTS",
    "DATABASE_PORTS",
    "DEFAULT_PROBE_PORTS",
    "DEFAULT_TOP_PORTS",
    "DNSRebindingError",
    "DiscoveredEndpoint",
    "EXTENDED_PROBE_PORTS",
    "HIGH_RISK_PORTS",
    "HeaderCheck",
    "LINK_LOCAL_PATTERN",
    "METADATA_IP_PATTERN",
    "NetworkAuditReport",
    "NetworkScanner",
    "PLAINTEXT_HTTP_PATTERN",
    "PRIVATE_IP_PATTERN",
    "PortCheckResult",
    "ProjectNetworkReport",
    "SCANNABLE_EXTENSIONS",
    "SKIP_DIRS",
    "SSLCertificateInfo",
    "SSRF_SINK_PATTERN",
    "URL_PATTERN",
    "WEAK_CIPHER_REGEX",
    "_clean_target_hostname",
    "_should_skip",
    "audit_http_security_headers",
    "audit_http_security_headers_and_waf",
    "audit_network_target",
    "audit_project_network",
    "detect_waf_or_cdn",
    "extract_host_and_port",
    "inspect_ssl_certificate",
    "parse_port_list",
    "probe_tcp_port",
    "resolve_ip_and_dns",
    "scan_file_network",
    "scan_network_code_patterns",
    "verify_ip_before_connect",
]
