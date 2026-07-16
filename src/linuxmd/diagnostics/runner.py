"""Run collectors and assemble diagnostic reports."""

from collections.abc import Iterable
from datetime import UTC, datetime

from linuxmd.collectors import SystemCollector
from linuxmd.collectors.base import Collector
from linuxmd.diagnostics.models import DiagnosticError, DiagnosticReport


def collect_diagnostics(
    collectors: Iterable[Collector] | None = None,
    *,
    generated_at: datetime | None = None,
) -> DiagnosticReport:
    """Run collectors, preserving partial output if one collector fails."""
    selected = tuple(collectors) if collectors is not None else (SystemCollector(),)
    timestamp = generated_at or datetime.now(UTC)
    diagnostics = {}
    errors: list[DiagnosticError] = []

    for collector in selected:
        try:
            diagnostics[collector.name] = collector.collect()
        except Exception as exc:
            errors.append(DiagnosticError(collector=collector.name, message=str(exc)))

    return DiagnosticReport(
        schema_version="1.0",
        generated_at=timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        diagnostics=diagnostics,
        errors=tuple(errors),
    )
