"""Serialize diagnostic reports to disk."""

import json
from pathlib import Path
from typing import Any

from linuxmd.diagnostics.models import DiagnosticReport
from linuxmd.paths import output_directory


def output_path(filename: Path) -> Path:
    """Return an absolute path for a report in the repository output directory."""
    output_dir = output_directory()
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / filename.name


def write_report(report: DiagnosticReport, filename: Path, *, pretty: bool = True) -> Path:
    """Atomically write a diagnostic report under output/ and return its absolute path."""
    return write_json(report.to_dict(), filename, pretty=pretty)


def write_json(data: dict[str, Any], filename: Path, *, pretty: bool = True) -> Path:
    """Atomically write structured JSON under output/ and return its absolute path."""
    destination = output_path(filename)
    temporary = destination.with_name(f".{destination.name}.tmp")
    indent = 2 if pretty else None
    payload = json.dumps(data, indent=indent, sort_keys=True) + "\n"
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(destination)
    return destination
