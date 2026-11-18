"""Unit tests for IP normalization, SSRF obfuscation detection, and passive footprint scanning."""

from pathlib import Path

from cry.models import Severity
from cry.network_ip import (
    detect_ip_obfuscation,
    get_ip_classification,
    is_cloud_metadata,
    is_internal,
    is_link_local,
    is_loopback,
    is_private_rfc1918,
    normalize_ip,
)
from cry.scanners.network import audit_project_network, scan_file_network

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "v04_network"


# ===========================================================================
# 1. IP Normalization Tests
# ===========================================================================


def test_normalize_standard_ips() -> None:
    """Standard IPv4 and IPv6 addresses must normalize to canonical strings."""
    assert normalize_ip("127.0.0.1") == "127.0.0.1"
    assert normalize_ip("169.254.169.254") == "169.254.169.254"
    assert normalize_ip("192.168.1.254") == "192.168.1.254"
    assert normalize_ip("::1") == "::1"
    assert normalize_ip("fd00:ec2::254") == "fd00:ec2::254"


def test_normalize_dword_decimal_ips() -> None:
    """32-bit dword decimal integers must normalize to standard dotted IPv4."""
    # 2130706433 == 127.0.0.1
    assert normalize_ip("2130706433") == "127.0.0.1"
    assert normalize_ip(2130706433) == "127.0.0.1"

    # 2852039166 == 169.254.169.254 (Cloud IMDS)
    assert normalize_ip("2852039166") == "169.254.169.254"
    assert normalize_ip(2852039166) == "169.254.169.254"

    # 3232235777 == 192.168.1.1
    assert normalize_ip("3232235777") == "192.168.1.1"


def test_normalize_hexadecimal_ips() -> None:
    """Single-integer hex and dotted hex must normalize to standard dotted IPv4."""
    # Single 32-bit hex
    assert normalize_ip("0x7f000001") == "127.0.0.1"
    assert normalize_ip("0X7F000001") == "127.0.0.1"
    assert normalize_ip("0xa9fea9fe") == "169.254.169.254"

    # Dotted hex
    assert normalize_ip("0x7f.0x0.0x0.0x1") == "127.0.0.1"
    assert normalize_ip("0x7f.0.0.1") == "127.0.0.1"
    assert normalize_ip("0xa9.0xfe.0xa9.0xfe") == "169.254.169.254"


def test_normalize_octal_dotted_ips() -> None:
    """Octal notation with leading zeros must parse and normalize to standard IPv4."""
    # 0177 == 127 decimal
    assert normalize_ip("0177.0.0.1") == "127.0.0.1"
    assert normalize_ip("0177.0000.0000.0001") == "127.0.0.1"

    # 0251 == 169, 0376 == 254
    assert normalize_ip("0251.0376.0251.0376") == "169.254.169.254"


def test_normalize_ipv6_mapped_ipv4() -> None:
    """IPv6-mapped IPv4 addresses must extract the underlying IPv4 address."""
    assert normalize_ip("::ffff:127.0.0.1") == "127.0.0.1"
    assert normalize_ip("[::ffff:127.0.0.1]") == "127.0.0.1"
    assert normalize_ip("::ffff:169.254.169.254") == "169.254.169.254"


def test_normalize_bsd_shortened_forms() -> None:
    """BSD shortened IPv4 notations (class A/B + host) must normalize properly."""
    assert normalize_ip("127.1") == "127.0.0.1"
    assert normalize_ip("10.1") == "10.0.0.1"
    assert normalize_ip("127.0.1") == "127.0.0.1"


def test_normalize_malformed_and_invalid_inputs() -> None:
    """Invalid, out-of-range, or malformed inputs must safely return None without throwing."""
    assert normalize_ip("999.999.999.999") is None
    assert normalize_ip("0xGG") is None
    assert normalize_ip("21307064339999999999") is None
    assert normalize_ip("-1") is None
    assert normalize_ip("") is None
    assert normalize_ip("not.an.ip.address") is None
    assert normalize_ip("http://127.0.0.1") is None  # Full URL, not bare IP
    assert normalize_ip(None) is None


# ===========================================================================
# 2. IP Classification Tests
# ===========================================================================


def test_ip_scope_classifications() -> None:
    """IP classification predicates must correctly identify security scopes."""
    # Metadata
    assert is_cloud_metadata("169.254.169.254") is True
    assert is_cloud_metadata("2852039166") is True
    assert is_cloud_metadata("0xa9fea9fe") is True
    assert is_cloud_metadata("fd00:ec2::254") is True
    assert is_cloud_metadata("8.8.8.8") is False

    # Loopback
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("2130706433") is True
    assert is_loopback("0x7f000001") is True
    assert is_loopback("0177.0.0.1") is True
    assert is_loopback("::1") is True
    assert is_loopback("localhost") is True
    assert is_loopback("192.168.1.1") is False

    # Private RFC-1918
    assert is_private_rfc1918("10.0.0.1") is True
    assert is_private_rfc1918("172.16.0.1") is True
    assert is_private_rfc1918("192.168.1.1") is True
    assert is_private_rfc1918("8.8.8.8") is False
    assert is_private_rfc1918("127.0.0.1") is False  # Loopback is not RFC1918

    # Link-local
    assert is_link_local("169.254.1.1") is True
    assert is_link_local("10.0.0.1") is False

    # Internal
    assert is_internal("127.0.0.1") is True
    assert is_internal("169.254.169.254") is True
    assert is_internal("10.0.0.1") is True
    assert is_internal("backend.local") is True
    assert is_internal("service.internal") is True
    assert is_internal("api.stripe.com") is False

    # Classification labels
    assert get_ip_classification("169.254.169.254") == "Cloud IMDS Metadata"
    assert get_ip_classification("fd00:ec2::254") == "Cloud IMDS Metadata"
    assert get_ip_classification("127.0.0.1") == "Loopback"
    assert get_ip_classification("10.0.0.1") == "RFC-1918 Private"
    assert get_ip_classification("169.254.1.1") == "Link-Local"
    assert get_ip_classification("93.184.216.34") == "Public Routable"


# ===========================================================================
# 3. Obfuscation Detection Tests
# ===========================================================================


def test_detect_ip_obfuscation() -> None:
    """detect_ip_obfuscation must identify dword decimal, hex, octal, and IPv6-mapped evasion."""
    is_obf, norm, desc = detect_ip_obfuscation("2130706433")
    assert is_obf is True
    assert norm == "127.0.0.1"
    assert "Dword" in str(desc)

    is_obf, norm, desc = detect_ip_obfuscation("0x7f000001")
    assert is_obf is True
    assert norm == "127.0.0.1"
    assert "Hex" in str(desc)

    is_obf, norm, desc = detect_ip_obfuscation("0177.0.0.1")
    assert is_obf is True
    assert norm == "127.0.0.1"
    assert "octal" in str(desc)

    is_obf, norm, desc = detect_ip_obfuscation("::ffff:127.0.0.1")
    assert is_obf is True
    assert norm == "127.0.0.1"
    assert "IPv6-mapped" in str(desc)

    # Standard clean IP is not obfuscated
    is_obf, norm, desc = detect_ip_obfuscation("127.0.0.1")
    assert is_obf is False


# ===========================================================================
# 4. Static Code Scanner Tests (Vulnerable vs Safe Fixtures)
# ===========================================================================


def test_scanner_flags_vulnerable_ssrf_and_metadata_fixtures() -> None:
    """scan_file_network must flag hardcoded metadata IPs, link-local IPs, and obfuscated SSRF."""
    vuln_file = FIXTURES_DIR / "vulnerable_ssrf_obfuscation.py"
    findings = scan_file_network(vuln_file, FIXTURES_DIR.parent)

    titles = [f.title for f in findings]
    severities = [f.severity for f in findings]

    # Verify IMDS IPv4 is flagged as CRITICAL
    assert any("Hardcoded Cloud Metadata IP (169.254.169.254)" in t for t in titles)
    # Verify IMDS IPv6 is flagged as CRITICAL
    assert any("Hardcoded Cloud Metadata IP (fd00:ec2::254)" in t for t in titles)
    # Verify Link-local is flagged
    assert any("Hardcoded Link-Local IP (169.254.42.1)" in t for t in titles)
    # Verify Obfuscated IP SSRF bypasses are flagged
    assert any("Obfuscated IP SSRF Bypass" in t for t in titles)

    # Ensure critical blockers exist
    assert Severity.CRITICAL in severities


def test_scanner_passes_safe_network_fixture() -> None:
    """scan_file_network must find zero critical blockers or obfuscation bypasses in safe fixture."""
    safe_file = FIXTURES_DIR / "safe_network_patterns.py"
    findings = scan_file_network(safe_file, FIXTURES_DIR.parent)

    # Must have zero critical findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 0

    # Must have zero SSRF bypass warnings
    obfuscation_findings = [f for f in findings if "Obfuscated IP" in f.title]
    assert len(obfuscation_findings) == 0


# ===========================================================================
# 5. Passive Footprint Discovery Tests (Zero Network Packets)
# ===========================================================================


def test_passive_network_footprint_analysis() -> None:
    """audit_project_network with passive=True must discover declared URLs and IPs with zero network packets."""
    report = audit_project_network(FIXTURES_DIR, passive=True)

    assert report.is_passive is True
    assert report.total_endpoints_found > 0
    assert len(report.internal_endpoints) > 0
    assert len(report.external_endpoints) > 0

    # Verify internal endpoints contain metadata and obfuscated items
    internal_hosts = [ep.host for ep in report.internal_endpoints]
    assert any("169.254.169.254" in h for h in internal_hosts)
    assert any("2130706433" in h for h in internal_hosts)
    assert any("0x7f000001" in h for h in internal_hosts)

    # Verify external endpoints contain GitHub/Stripe
    external_hosts = [ep.host for ep in report.external_endpoints]
    assert any("api.github.com" in h for h in external_hosts)
    assert any("api.stripe.com" in h for h in external_hosts)

    # Verify SSRF risk count is calculated
    assert report.ssrf_risks_count > 0
    assert report.private_ips_count > 0
