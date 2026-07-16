"""Reusable collection and deterministic-analysis workflows."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from linuxmd.collectors.performance import collect_performance, performance_report
from linuxmd.collectors.security import SecurityCollector
from linuxmd.collectors.system import SystemCollector
from linuxmd.diagnostics.performance_models import PerformanceDiagnostics
from linuxmd.diagnostics.runner import collect_diagnostics
from linuxmd.diagnostics.security import analyze_security
from linuxmd.diagnostics.writer import write_json, write_report
from linuxmd.local import LocalRunner
from linuxmd.remote import SSHConfig, SSHRunner

StageStatus = Literal["success", "skipped", "unsupported", "failed"]

DIAG_FILE = Path("diag.json")
PERFORMANCE_FILE = Path("performance.json")
SECURITY_FILE = Path("security.json")
SECURITY_ANALYSIS_FILE = Path("security-analysis.json")
ANALYSIS_FILE = Path("analysis.json")


@dataclass(slots=True)
class StageResult:
    """Outcome of one independently reportable workflow stage."""

    name: str
    status: StageStatus
    output_paths: list[Path] = field(default_factory=list)
    error: str | None = None
    data: Any = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class CollectorRegistration:
    """One collector available to the aggregate collection workflow."""

    name: str
    runner: Callable[[int, int], StageResult]
    default: bool = False


def run_system_collection() -> StageResult:
    """Collect static Linux system inventory into diag.json."""
    report = collect_diagnostics([SystemCollector()])
    try:
        output = write_report(report, DIAG_FILE)
    except OSError as exc:
        return StageResult("system", "failed", error=str(exc))
    if report.errors:
        return StageResult(
            "system",
            "failed",
            [output],
            "; ".join(error.message for error in report.errors),
            report,
        )
    system = report.diagnostics.get("system", {})
    status: StageStatus = "unsupported" if system.get("status") == "unsupported" else "success"
    return StageResult("system", status, [output], data=report)


def run_performance_collection(
    *,
    host: str | None = None,
    user: str | None = None,
    port: int = 22,
    identity_file: Path | None = None,
    duration: int = 5,
    timeout: int = 90,
) -> StageResult:
    """Collect a bounded local or SSH performance sample."""
    remote = host is not None
    runner = (
        SSHRunner(
            SSHConfig(
                host=host,
                user=user,
                port=port,
                identity_file=identity_file,
                timeout=timeout,
            )
        )
        if host is not None
        else LocalRunner(timeout=timeout)
    )
    diagnostics: PerformanceDiagnostics = collect_performance(
        runner,
        host=host or "localhost",
        user=user,
        port=port if remote else None,
        remote=remote,
        duration=duration,
    )
    try:
        output = write_report(performance_report(diagnostics), PERFORMANCE_FILE)
    except OSError as exc:
        return StageResult("performance", "failed", error=str(exc), data=diagnostics)
    return StageResult("performance", "success", [output], data=diagnostics)


def run_security_collection() -> StageResult:
    """Collect raw Linux security state."""
    raw = SecurityCollector().collect()
    try:
        output = write_json(raw, SECURITY_FILE)
    except OSError as exc:
        return StageResult("security_collection", "failed", error=str(exc), data=raw)
    status: StageStatus = "unsupported" if _all_sections_unsupported(raw) else "success"
    return StageResult("security_collection", status, [output], data=raw)


def _run_registered_system(duration: int, timeout: int) -> StageResult:
    del duration, timeout
    return run_system_collection()


def _run_registered_performance(duration: int, timeout: int) -> StageResult:
    return run_performance_collection(duration=duration, timeout=timeout)


def _run_registered_security(duration: int, timeout: int) -> StageResult:
    del duration, timeout
    return run_security_collection()


COLLECTOR_REGISTRY: tuple[CollectorRegistration, ...] = (
    CollectorRegistration("system", _run_registered_system, default=True),
    CollectorRegistration("performance", _run_registered_performance, default=True),
    CollectorRegistration("security", _run_registered_security, default=True),
)
DEFAULT_COLLECTORS: tuple[CollectorRegistration, ...] = tuple(
    collector for collector in COLLECTOR_REGISTRY if collector.default
)
ALL_COLLECTORS: tuple[CollectorRegistration, ...] = COLLECTOR_REGISTRY


def run_registered_collectors(
    *,
    include_all: bool = False,
    duration: int = 5,
    timeout: int = 90,
    registry: Iterable[CollectorRegistration] | None = None,
) -> list[StageResult]:
    """Run stable collectors by default or every registered collector on request."""
    available = tuple(registry) if registry is not None else COLLECTOR_REGISTRY
    selected = available if include_all else tuple(item for item in available if item.default)
    return [item.runner(duration, timeout) for item in selected]


def run_security_analysis(raw: dict[str, Any] | None) -> StageResult:
    """Analyze an in-memory raw security result deterministically."""
    if raw is None:
        return StageResult(
            "security_analysis",
            "skipped",
            error="security collection did not produce analyzable data",
        )
    analyzed = analyze_security(raw)
    try:
        output = write_json(analyzed, SECURITY_ANALYSIS_FILE)
    except OSError as exc:
        return StageResult("security_analysis", "failed", error=str(exc), data=analyzed)
    return StageResult("security_analysis", "success", [output], data=analyzed)


def run_all_collections(*, duration: int = 5, timeout: int = 90) -> list[StageResult]:
    """Run every local non-LLM stage in dependency order."""
    results = [
        run_system_collection(),
        run_performance_collection(duration=duration, timeout=timeout),
    ]
    security_collection = run_security_collection()
    results.append(security_collection)
    raw = (
        security_collection.data
        if security_collection.status in {"success", "unsupported"}
        else None
    )
    results.append(run_security_analysis(raw))
    return results


def _all_sections_unsupported(raw: dict[str, Any]) -> bool:
    sections = [value for value in raw.values() if isinstance(value, dict) and "status" in value]
    return bool(sections) and all(section.get("status") == "unsupported" for section in sections)
