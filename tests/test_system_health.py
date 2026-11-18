"""Unit tests for CRY Host & Linux System Health Monitor engine."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from cry.system_health import (
    SystemHealthReport,
    collect_system_health,
    format_health_report_text,
    get_system_uptime,
    save_system_health_report,
)


def test_collect_system_health_returns_valid_report() -> None:
    """Ensure collect_system_health() populates all core telemetry fields."""
    report = collect_system_health()

    assert isinstance(report, SystemHealthReport)
    assert report.hostname != ""
    assert report.logged_user != ""
    assert report.cpu_cores >= 1
    assert report.disk_total_gb >= 0.0
    assert report.disk_percent >= 0.0
    assert report.uptime_seconds >= 0
    assert isinstance(report.timestamp, datetime)
    assert report.overall_status in ("NOMINAL", "WARNING", "CRITICAL")


def test_format_health_report_text() -> None:
    """Ensure report text format includes all necessary telemetry sections."""
    mock_report = SystemHealthReport(
        hostname="ubuntu-dev",
        logged_user="developer",
        timestamp=datetime(2026, 11, 18, 20, 0, 0, tzinfo=UTC),
        os_platform="Ubuntu 24.04 LTS (x86_64)",
        uptime_seconds=86400 + 3600 * 2,
        uptime_formatted="1d 2h",
        load_averages="0.25, 0.35, 0.40 (1m, 5m, 15m)",
        cpu_cores=8,
        cpu_utilization_pct=15.5,
        ram_used_gb=4.5,
        ram_total_gb=16.0,
        ram_percent=28.1,
        disk_used_gb=45.0,
        disk_total_gb=256.0,
        disk_free_gb=211.0,
        disk_percent=17.5,
        process_count=120,
        network_connected=True,
        network_status_msg="Online (DNS Reachable)",
        alerts=[],
        overall_status="NOMINAL",
    )

    formatted = format_health_report_text(mock_report)
    assert "ubuntu-dev" in formatted
    assert "developer" in formatted
    assert "Ubuntu 24.04 LTS" in formatted
    assert "1d 2h" in formatted
    assert "4.50 GB / 16.00 GB" in formatted
    assert "120" in formatted
    assert "NOMINAL" in formatted
    assert "all monitored thresholds healthy" in formatted


def test_save_system_health_report(tmp_path: Path) -> None:
    """Ensure reports are correctly persisted as timestamped text files."""
    mock_report = SystemHealthReport(
        hostname="test-host",
        logged_user="tester",
        timestamp=datetime(2026, 11, 18, 12, 30, 45, tzinfo=UTC),
    )

    saved_path = save_system_health_report(mock_report, output_dir=tmp_path)
    assert saved_path.exists()
    assert "system_health_20261118_123045.txt" in saved_path.name
    content = saved_path.read_text(encoding="utf-8")
    assert "test-host" in content
    assert "tester" in content


def test_health_alert_thresholds() -> None:
    """Test disk and memory health threshold alerts."""
    with (
        patch("cry.system_health.get_disk_stats", return_value=(450.0, 500.0, 50.0, 92.5)),
        patch("cry.system_health.get_memory_stats", return_value=(15.0, 16.0, 93.8)),
        patch("cry.system_health.probe_network_connectivity", return_value=(True, "Online")),
    ):
        report = collect_system_health()
        assert report.overall_status == "CRITICAL"
        assert any("Storage capacity critical" in a for a in report.alerts)
        assert any("High RAM consumption" in a for a in report.alerts)


def test_uptime_calculation() -> None:
    """Test system uptime retrieval returns valid formatted output."""
    sec, formatted = get_system_uptime()
    assert sec >= 0
    assert isinstance(formatted, str)
