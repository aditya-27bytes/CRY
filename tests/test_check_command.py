"""Tests for 'cry check' configuration and model validation command."""

from unittest.mock import patch

from typer.testing import CliRunner

from cry.cli import app


def test_check_command_output() -> None:
    """Ensure 'cry check' displays scanner readiness and configuration without host telemetry."""
    runner = CliRunner()
    with patch(
        "cry.commands.check._probe_provider_models",
        return_value=(True, ["mock-model"], "1 model(s) available"),
    ):
        result = runner.invoke(app, ["check"])
    assert result.exit_code == 0
    # Core configuration & scanners are present
    assert "CRY Environment & Configuration Check" in result.output
    assert "Python Engine" in result.output
    assert "Secrets Scanner" in result.output
    assert "SAST Engine" in result.output
    assert "Supply-Chain (SCA)" in result.output
    assert "Config Auditor" in result.output
    assert "Network & Host" in result.output

    # Off-mission host telemetry must NOT be present
    assert "Host & Linux System Health Monitor" not in result.output
    assert "System Load Averages" not in result.output
    assert "Memory (RAM)" not in result.output
    assert "Disk Storage" not in result.output
    assert "Active Processes" not in result.output
    assert "Proactive Health Alerts" not in result.output


def test_check_command_rejects_report_flag() -> None:
    """Ensure '--report' flag has been removed and is rejected."""
    runner = CliRunner()
    result = runner.invoke(app, ["check", "--report"])
    assert result.exit_code != 0
    assert "No such option" in result.output or "Error" in result.output
