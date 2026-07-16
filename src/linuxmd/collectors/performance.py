"""Orchestrate local or remote Linux performance diagnostics."""

# Inspired by Brendan Gregg's 'Linux Performance Analysis in 60,000 Milliseconds,' originally
# published on the Netflix Technology Blog.

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter
from typing import Protocol

from linuxmd import __version__
from linuxmd.diagnostics.evidence import deterministic_correlations
from linuxmd.diagnostics.models import DiagnosticReport
from linuxmd.diagnostics.performance_findings import generate_findings, interpretation_summary
from linuxmd.diagnostics.performance_models import CommandResult, PerformanceDiagnostics
from linuxmd.diagnostics.performance_parsers import normalize_metrics


class CommandRunner(Protocol):
    """Execution interface used by the performance orchestrator."""

    def run(self, command: str) -> CommandResult:
        """Execute a diagnostic command."""
        ...


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """A named, read-only remote diagnostic command."""

    name: str
    command: str


def performance_commands(duration: int) -> tuple[CommandSpec, ...]:
    """Build the bounded command sequence for a requested sampling duration."""
    count = max(1, duration)
    return (
        _checked("uptime", "uptime", "uptime"),
        _checked(
            "cpu_capacity",
            "cat",
            "for f in /sys/devices/system/cpu/online /sys/devices/system/cpu/offline "
            "/proc/self/status /sys/fs/cgroup/cpuset.cpus.effective "
            "/sys/fs/cgroup/cpuset/cpuset.cpus /sys/fs/cgroup/cpu.max "
            "/sys/fs/cgroup/cpu/cpu.cfs_quota_us /sys/fs/cgroup/cpu/cpu.cfs_period_us; "
            'do [ -r "$f" ] && printf "FILE:%s\\n" "$f" && cat "$f"; done',
        ),
        _checked("dmesg", "dmesg", "dmesg --level=emerg,alert,crit,err,warn"),
        _checked("vmstat", "vmstat", f"vmstat 1 {count}"),
        _checked("psi_cpu", "cat", "cat /proc/pressure/cpu"),
        _checked("mpstat", "mpstat", f"mpstat -P ALL 1 {count}"),
        _checked("pidstat", "pidstat", f"pidstat 1 {count}"),
        _checked("iostat", "iostat", f"iostat -xz 1 {count}"),
        _checked("free", "free", "free -m"),
        _checked("sar_dev", "sar", f"sar -n DEV 1 {count}"),
        _checked("sar_tcp", "sar", f"sar -n TCP,ETCP 1 {count}"),
        _checked("top", "top", "top -b -n 1"),
    )


def collect_performance(
    runner: CommandRunner,
    *,
    host: str,
    user: str | None,
    port: int | None,
    remote: bool,
    duration: int,
    now: datetime | None = None,
    commands: Sequence[CommandSpec] | None = None,
    environment: dict | None = None,
    workload: dict | None = None,
    baseline: dict | None = None,
) -> PerformanceDiagnostics:
    """Execute the workflow and preserve partial results from independent commands."""
    started_at = now or datetime.now(UTC)
    started_clock = perf_counter()
    results: dict[str, CommandResult] = {}
    warnings: list[str] = []

    for spec in commands or performance_commands(duration):
        result = runner.run(spec.command)
        results[spec.name] = result
        if not result.command_available:
            warnings.append(f"{spec.name}: command is unavailable")
        elif result.status != "ok":
            detail = result.stderr.strip() or result.status
            warnings.append(f"{spec.name}: {detail}")
        if result.status in {"authentication_failed", "ssh_unavailable"}:
            warnings.append("Collection stopped because the SSH session could not be established")
            break

    metrics, parse_warnings = normalize_metrics(results)
    warnings.extend(parse_warnings)
    environment_context = environment or {
        "execution_type": "unknown",
        "platform_hint": None,
        "hardware_fidelity": "unknown",
        "performance_fidelity": "unknown",
    }
    sampling = {"duration_seconds": duration, "interval_seconds": 1, "sample_count": duration}
    workload_context = workload or {
        "declared": False,
        "name": None,
        "state": "unknown",
        "impact_observed": False,
    }
    baseline_context = baseline or {"type": "none", "reference": None, "comparable_run_count": 0}
    findings = generate_findings(
        metrics,
        environment=environment_context,
        sampling=sampling,
        workload=workload_context,
        baseline=baseline_context,
    )
    elapsed = round(perf_counter() - started_clock, 3)

    return PerformanceDiagnostics(
        metadata={
            "collector": "remote_linux_performance" if remote else "local_linux_performance",
            "linuxmd_version": __version__,
            "requested_duration_seconds": duration,
            "methodology": "bounded short-duration Linux performance sampling",
        },
        host={"address": host, "user": user, "port": port},
        collection_start=started_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        collection_duration=elapsed,
        environment=environment_context,
        sampling=sampling,
        workload=workload_context,
        baseline=baseline_context,
        raw_command_results=results,
        normalized_metrics=metrics,
        findings=findings,
        correlations=tuple(deterministic_correlations(metrics)),
        interpretation=interpretation_summary(
            findings,
            environment=environment_context,
            sampling=sampling,
            workload=workload_context,
            baseline=baseline_context,
        ),
        warnings=tuple(dict.fromkeys(warnings)),
    )


# Preserve the public name used by earlier releases.
collect_remote_performance = collect_performance


def performance_report(
    diagnostics: PerformanceDiagnostics,
    *,
    generated_at: datetime | None = None,
) -> DiagnosticReport:
    """Embed performance diagnostics in the existing versioned report shape."""
    timestamp = generated_at or datetime.now(UTC)
    return DiagnosticReport(
        schema_version="1.1",
        generated_at=timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        diagnostics={"performance": diagnostics.to_dict()},
    )


def _checked(name: str, executable: str, command: str) -> CommandSpec:
    shell = f"command -v {executable} >/dev/null 2>&1 || exit 127; LC_ALL=C {command}"
    return CommandSpec(name=name, command=shell)
