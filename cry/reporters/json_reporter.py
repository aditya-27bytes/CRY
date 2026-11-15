"""JSON reporter for machine-readable scan output."""

from pathlib import Path

from cry.models import VerdictReport


def export_json_report(report: VerdictReport, output_path: Path) -> Path:
    """Export VerdictReport to a formatted JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    json_data = report.model_dump_json(indent=2)
    output_path.write_text(json_data, encoding="utf-8")
    return output_path
