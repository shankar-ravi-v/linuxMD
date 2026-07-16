"""Tests for remote performance command orchestration."""

from collections import deque
from datetime import UTC, datetime

from linuxmd.collectors.performance import (
    CommandSpec,
    collect_performance,
    performance_commands,
    performance_report,
)


class FixtureRunner:
    def __init__(self, results) -> None:
        self.results = deque(results)
        self.commands: list[str] = []

    def run(self, command):
        self.commands.append(command)
        return self.results.popleft()


def test_orchestration_records_missing_commands(missing_sysstat_commands) -> None:
    specs = tuple(CommandSpec(name, name) for name in missing_sysstat_commands)
    runner = FixtureRunner(missing_sysstat_commands.values())

    diagnostics = collect_performance(
        runner,
        host="192.0.2.10",
        user="diagnostics",
        port=22,
        remote=True,
        duration=5,
        now=datetime(2026, 1, 1, tzinfo=UTC),
        commands=specs,
    )
    report = performance_report(diagnostics, generated_at=datetime(2026, 1, 1, tzinfo=UTC))

    assert len(diagnostics.raw_command_results) == 10
    assert any("mpstat: command is unavailable" in item for item in diagnostics.warnings)
    assert not any(
        finding.classification in {"likely_issue", "confirmed_issue"}
        for finding in diagnostics.findings
    )
    assert report.schema_version == "1.1"
    assert "performance" in report.diagnostics


def test_duration_controls_bounded_sample_count() -> None:
    commands = {spec.name: spec.command for spec in performance_commands(7)}

    assert commands["vmstat"].endswith("vmstat 1 7")
    assert commands["sar_tcp"].endswith("sar -n TCP,ETCP 1 7")
    assert commands["top"].endswith("top -b -n 1")
    assert commands["psi_cpu"].endswith("cat /proc/pressure/cpu")
