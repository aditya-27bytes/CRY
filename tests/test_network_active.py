"""Unit tests for CRY Milestone M4 active network checks and authorization engine.

Strictly mocks sockets, DNS, and HTTP — zero network packets transmitted.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cry.network_auth import (
    check_target_permission,
    get_or_create_authorization,
    is_target_authorized,
    load_authorizations,
    save_authorizations,
    verify_target_control,
)
from cry.scanners.network import (
    DNSRebindingError,
    SSLCertificateInfo,
    audit_network_target,
    detect_waf_or_cdn,
    parse_port_list,
    verify_ip_before_connect,
)


@pytest.fixture(autouse=True)
def isolate_cry_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate CRY config and state directory to avoid touching real ~/.cry."""
    home_dir = tmp_path / ".cry"
    home_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CRY_HOME", str(home_dir))
    return home_dir


def test_unauthorized_public_target_blocked() -> None:
    """Probing an unverified public domain is blocked before any packets are sent."""
    is_allowed, reason, token = check_target_permission("unowned-company.com", allow_local=False)
    assert is_allowed is False
    assert "not authorized" in reason.lower()
    assert token is not None
    assert token.startswith("cry-verify-")

    # Full audit call returns UNAUTHORIZED status and token
    with patch(
        "cry.scanners.network.resolve_ip_and_dns",
        return_value=(["93.184.216.34"], [], None, False, False, None),
    ):
        report = audit_network_target("unowned-company.com")
        assert report.authorization_status == "UNAUTHORIZED"
        assert report.authorization_token == token
        assert len(report.ports_checked) == 0


def test_authorization_verification_via_dns_txt() -> None:
    """Proving domain ownership via DNS TXT record successfully authorizes target."""
    target = "my-saas-app.com"
    record = get_or_create_authorization(target)
    token = record.token

    # Mock query_dns_txt to return matching TXT record
    with patch("cry.network_auth.query_dns_txt", return_value=[f"cry-verification={token}"]):
        verified, msg = verify_target_control(target)
        assert verified is True
        assert "DNS TXT" in msg
        assert is_target_authorized(target) is True


def test_authorization_verification_via_well_known_http() -> None:
    """Proving domain ownership via HTTP well-known file successfully authorizes target."""
    target = "api.my-domain.org"
    record = get_or_create_authorization(target)
    token = record.token

    # Mock query_dns_txt to return empty, and well_known to return file content
    with (
        patch("cry.network_auth.query_dns_txt", return_value=[]),
        patch("cry.network_auth.query_well_known_challenge", return_value=token),
    ):
        verified, msg = verify_target_control(target)
        assert verified is True
        assert "well-known" in msg
        assert is_target_authorized(target) is True


def test_authorization_verification_with_custom_port() -> None:
    """Proving domain ownership on a custom port queries the specified port."""
    target = "localhost"
    record = get_or_create_authorization(target)
    token = record.token

    with (
        patch("cry.network_auth.query_dns_txt", return_value=[]),
        patch("cry.network_auth.query_well_known_challenge", return_value=token) as mock_challenge,
    ):
        verified, msg = verify_target_control(target, port=3001)
        assert verified is True
        assert "3001" in msg
        mock_challenge.assert_called_with(target, port=3001)


def test_local_target_requires_allow_local() -> None:
    """Localhost and private RFC-1918 IPs require --allow-local."""
    # 1. 127.0.0.1 blocked without allow_local
    allowed, reason, _ = check_target_permission("127.0.0.1", allow_local=False)
    assert allowed is False
    assert "--allow-local" in reason

    # 2. 192.168.1.50 blocked without allow_local
    allowed, reason, _ = check_target_permission("192.168.1.50", allow_local=False)
    assert allowed is False
    assert "--allow-local" in reason

    # 3. Allowed when allow_local=True
    allowed, status, _ = check_target_permission("127.0.0.1", allow_local=True)
    assert allowed is True
    assert status == "AUTHORIZED_LOCAL"


def test_cloud_metadata_always_blocked_even_with_allow_local() -> None:
    """Active probing of Cloud Instance Metadata (169.254.169.254) is strictly forbidden."""
    for meta_ip in ("169.254.169.254", "169.254.169.253", "fd00:ec2::254"):
        allowed, reason, _ = check_target_permission(meta_ip, allow_local=True)
        assert allowed is False
        assert "PROHIBITED" in reason
        assert "cloud metadata" in reason.lower() or "metadata" in reason.lower()


def test_dns_rebinding_defense() -> None:
    """Detect DNS rebinding when domain re-resolves to internal IP right before socket connect."""
    # Domain initially looked public, but second lookup yields 127.0.0.1
    with patch(
        "cry.scanners.network.resolve_ip_and_dns",
        return_value=(["127.0.0.1"], [], None, True, False, "SSRF alert"),
    ):
        with pytest.raises(DNSRebindingError) as exc_info:
            verify_ip_before_connect("attacker-rebinding.com", "93.184.216.34", allow_local=False)
        assert "DNS Rebinding detected" in str(exc_info.value)


def test_tcp_port_probe_and_database_exposure_alert(isolate_cry_home: Path) -> None:
    """Ensure open database ports on public IPs trigger high-severity exposure alerts."""
    target = "app.verified-host.com"
    # Pre-authorize target
    rec = get_or_create_authorization(target)
    rec.verified_at = "2026-11-18T20:00:00Z"
    records = load_authorizations()
    records[target] = rec
    save_authorizations(records)

    def mock_probe(
        ip: str, port: int, timeout: float = 1.5, rate_delay: float = 0.0
    ) -> tuple[str, str | None]:
        # Return 5432 (Postgres) and 6379 (Redis) OPEN, other ports CLOSED
        if port in (5432, 6379):
            return "OPEN", None
        return "CLOSED", None

    with (
        patch(
            "cry.scanners.network.resolve_ip_and_dns",
            return_value=(["93.184.216.34"], [], "ptr.verified-host.com", False, False, None),
        ),
        patch("cry.scanners.network.verify_ip_before_connect", return_value="93.184.216.34"),
        patch("cry.scanners.network.probe_tcp_port", side_effect=mock_probe),
        patch("cry.scanners.network.inspect_ssl_certificate", return_value=None),
        patch(
            "cry.scanners.network.audit_http_security_headers_and_waf",
            return_value=([], "F", None),
        ),
    ):
        report = audit_network_target(target, allow_local=False, ports=[80, 5432, 6379])
        assert report.authorization_status == "AUTHORIZED_PUBLIC"
        assert report.database_exposures_count == 2
        open_ports = [p for p in report.ports_checked if p.status == "OPEN"]
        assert len(open_ports) == 2
        redis_check = next(p for p in open_ports if p.port == 6379)
        assert redis_check.severity == "CRITICAL"
        assert "EXPOSURE RISK" in (redis_check.note or "")


def test_deep_tls_review_weak_cipher_and_legacy_protocols(isolate_cry_home: Path) -> None:
    """Inspect SSL certificate with weak cipher detection and legacy TLS protocol review."""
    target = "secure.local"
    mock_ssl_info = SSLCertificateInfo(
        issuer="Let's Encrypt",
        subject="secure.local",
        valid_from="2026-01-01",
        valid_to="2026-12-31",
        days_remaining=45,
        is_expired=False,
        tls_version="TLSv1.2",
        cipher_suite="ECDHE-RSA-RC4-SHA",
        weak_ciphers=["ECDHE-RSA-RC4-SHA"],
        legacy_protocols_supported=["TLSv1.0"],
        platform_limitation_note="Testing note",
    )

    with (
        patch(
            "cry.scanners.network.resolve_ip_and_dns",
            return_value=(["127.0.0.1"], [], None, True, False, None),
        ),
        patch("cry.scanners.network.verify_ip_before_connect", return_value="127.0.0.1"),
        patch(
            "cry.scanners.network.probe_tcp_port",
            return_value=("OPEN", None),
        ),
        patch("cry.scanners.network.inspect_ssl_certificate", return_value=mock_ssl_info),
        patch(
            "cry.scanners.network.audit_http_security_headers_and_waf",
            return_value=([], "B", "Cloudflare Edge / WAF"),
        ),
    ):
        report = audit_network_target(target, allow_local=True, deep=True, ports=[443])
        assert report.authorization_status == "AUTHORIZED_LOCAL"
        assert report.ssl_info is not None
        assert "ECDHE-RSA-RC4-SHA" in report.ssl_info.weak_ciphers
        assert "TLSv1.0" in report.ssl_info.legacy_protocols_supported
        assert report.waf_or_cdn == "Cloudflare Edge / WAF"


def test_cdn_waf_identification() -> None:
    """Response headers correctly identify Edge CDN or WAF as informational."""
    # 1. Cloudflare
    cf_waf = detect_waf_or_cdn({"server": "cloudflare", "cf-ray": "8374829283"})
    assert cf_waf == "Cloudflare Edge / WAF"

    # 2. AWS CloudFront
    aws_waf = detect_waf_or_cdn({"via": "1.1 1234.cloudfront.net (CloudFront)"})
    assert aws_waf == "AWS CloudFront CDN"

    # 3. Fastly
    fastly_waf = detect_waf_or_cdn({"x-fastly-request-id": "abcd1234"})
    assert fastly_waf == "Fastly Edge CDN"

    # 4. Unknown
    none_waf = detect_waf_or_cdn({"server": "custom-internal"})
    assert none_waf is None


def test_audit_log_written_on_authorized_scan(isolate_cry_home: Path) -> None:
    """Every authorized scan records an audit log entry in ~/.cry/audit.log."""
    audit_file = isolate_cry_home / "audit.log"
    assert not audit_file.exists()

    with (
        patch(
            "cry.scanners.network.resolve_ip_and_dns",
            return_value=(["127.0.0.1"], [], None, True, False, None),
        ),
        patch("cry.scanners.network.verify_ip_before_connect", return_value="127.0.0.1"),
        patch("cry.scanners.network.probe_tcp_port", return_value=("CLOSED", None)),
        patch("cry.scanners.network.inspect_ssl_certificate", return_value=None),
        patch(
            "cry.scanners.network.audit_http_security_headers_and_waf",
            return_value=([], "F", None),
        ),
    ):
        report = audit_network_target("127.0.0.1", allow_local=True, ports=[80])
        assert report.audit_logged is True

    assert audit_file.exists()
    content = audit_file.read_text(encoding="utf-8")
    assert "127.0.0.1" in content
    log_entry = json.loads(content.strip().splitlines()[-1])
    assert log_entry["target"] == "127.0.0.1"
    assert log_entry["authorization_status"] == "AUTHORIZED_LOCAL"
    assert "ports" in log_entry["checks_run"]


def test_port_list_parsing_and_capping() -> None:
    """Port list parser handles ranges, individual ports, and enforces 100-port hard cap."""
    # 1. Defaults
    default_ports = parse_port_list(None)
    assert 80 in default_ports and 443 in default_ports

    # 2. Ranges and singles
    parsed = parse_port_list("80,443,8000-8003")
    assert parsed == [80, 443, 8000, 8001, 8002, 8003]

    # 3. Cap at 100 ports
    huge_range = parse_port_list("1-200")
    assert len(huge_range) == 100
    assert huge_range[0] == 1
    assert huge_range[-1] == 100


def test_target_service_offline_skips_http_headers() -> None:
    """When the target service port is offline (FILTERED/CLOSED), headers check is skipped."""
    with (
        patch(
            "cry.scanners.network.resolve_ip_and_dns",
            return_value=(["127.0.0.1"], ["::1"], "localhost", True, False, None),
        ),
        patch("cry.scanners.network.verify_ip_before_connect", return_value="127.0.0.1"),
        patch(
            "cry.scanners.network.probe_tcp_port",
            return_value=("FILTERED", "Timeout"),
        ),
    ):
        report = audit_network_target("http://localhost:3001/", allow_local=True)
        assert report.service_offline is True
        assert report.security_score == "N/A"
        assert len(report.security_headers) == 0
        assert "3001" in (report.service_offline_message or "")
        assert "service offline" in (report.service_offline_message or "")
