"""Data models for remote performance diagnostics."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Captured outcome from one remote command."""

    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    command_available: bool
    elapsed_ms: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Finding:
    """An evidence-qualified interpretation limited to the sampled interval."""

    classification: str
    resource: str
    evidence: str
    explanation: str
    recommended_follow_up: str
    evidence_refs: tuple[str, ...] = ()
    temporal_scope: str = "sampled_interval"


@dataclass(frozen=True, slots=True)
class PerformanceDiagnostics:
    """Remote performance data embedded in the LinuxMD report envelope."""

    metadata: dict[str, Any]
    host: dict[str, Any]
    collection_start: str
    collection_duration: float
    environment: dict[str, Any] = field(default_factory=dict)
    sampling: dict[str, Any] = field(default_factory=dict)
    workload: dict[str, Any] = field(default_factory=dict)
    baseline: dict[str, Any] = field(default_factory=dict)
    raw_command_results: dict[str, CommandResult] = field(default_factory=dict)
    normalized_metrics: dict[str, Any] = field(default_factory=dict)
    findings: tuple[Finding, ...] = ()
    correlations: tuple[dict[str, Any], ...] = ()
    interpretation: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
