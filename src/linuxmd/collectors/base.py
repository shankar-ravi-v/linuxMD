"""Interfaces shared by diagnostic collectors."""

from typing import Any, Protocol


class Collector(Protocol):
    """A named component that returns JSON-serializable diagnostic data."""

    name: str

    def collect(self) -> dict[str, Any]:
        """Collect and return diagnostic values."""
        ...
