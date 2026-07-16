"""Data structures for diagnostic reports."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class DiagnosticError:
    """A non-fatal failure from an individual collector."""

    collector: str
    message: str


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    """Complete output produced by a LinuxMD run."""

    schema_version: str
    generated_at: str
    diagnostics: dict[str, Any] = field(default_factory=dict)
    errors: tuple[DiagnosticError, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Convert this report into JSON-serializable primitives."""
        return asdict(self)
