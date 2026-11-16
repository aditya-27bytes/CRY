"""Unit tests for Network Scanner and IP / Host Intelligence Engine."""

from pathlib import Path

from cry.models import Severity
from cry.scanners.network import (
    audit_http_security_headers,
    resolve_ip_and_dns,
    scan_file_network,
)


def test_detects_cloud_metadata_ip_leak(tmp_path: Path) -> None:
    """Ensure hardcoded 169.254.169.254 triggers a critical finding."""
    sample_file = tmp_path / "metadata_service.py"
    sample_file.write_text(
        'METADATA_URL = "http://169.254.169.254/latest/meta-data/"\n', encoding="utf-8"
    )

    findings = scan_file_network(sample_file, tmp_path)
    assert len(findings) >= 1
    imds = [f for f in findings if "Metadata IP" in f.title]
    assert len(imds) == 1
    assert imds[0].severity == Severity.CRITICAL
    assert imds[0].cwe_id == "CWE-918"


def test_detects_plaintext_http_api_call(tmp_path: Path) -> None:
    """Ensure unencrypted remote HTTP API endpoints are flagged."""
    sample_file = tmp_path / "api_client.py"
    sample_file.write_text(
        'API_ENDPOINT = "http://api.paymentprovider.com/v1/charge"\n', encoding="utf-8"
    )

    findings = scan_file_network(sample_file, tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "Plaintext HTTP" in findings[0].title
    assert findings[0].cwe_id == "CWE-319"


def test_detects_ssrf_request_sink(tmp_path: Path) -> None:
    """Ensure HTTP calls taking raw user input are flagged for SSRF."""
    sample_file = tmp_path / "proxy.py"
    sample_file.write_text(
        "def proxy_view(req):\n    return requests.get(req.query.target_url)\n", encoding="utf-8"
    )

    findings = scan_file_network(sample_file, tmp_path)
    assert len(findings) >= 1
    ssrf = [f for f in findings if "SSRF" in f.title]
    assert len(ssrf) == 1
    assert ssrf[0].severity == Severity.HIGH


def test_resolve_ip_detects_loopback() -> None:
    """Ensure 127.0.0.1 is flagged as private/loopback SSRF risk."""
    ipv4, _, _, is_private, is_metadata, warning = resolve_ip_and_dns("127.0.0.1")
    assert "127.0.0.1" in ipv4
    assert is_private is True
    assert is_metadata is False
    assert warning is not None
    assert "SSRF" in warning


def test_resolve_ip_detects_metadata_ip() -> None:
    """Ensure 169.254.169.254 is flagged as critical cloud metadata risk."""
    ipv4, _, _, _, is_metadata, warning = resolve_ip_and_dns("169.254.169.254")
    assert "169.254.169.254" in ipv4
    assert is_metadata is True
    assert warning is not None
    assert "Metadata IP" in warning


def test_security_headers_grading_on_unreachable_host() -> None:
    """Ensure unreachable host gracefully returns F grade without crashing."""
    checks, grade = audit_http_security_headers("127.0.0.1:54321", timeout=0.5)
    assert grade == "F"
    assert len(checks) == 6
    assert all(not c.present for c in checks)
