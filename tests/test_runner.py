"""Tests for diagnostic collection orchestration."""

from datetime import UTC, datetime

from linuxmd.diagnostics.runner import collect_diagnostics


class WorkingCollector:
    name = "working"

    def collect(self) -> dict[str, bool]:
        return {"healthy": True}


class BrokenCollector:
    name = "broken"

    def collect(self) -> dict[str, object]:
        raise RuntimeError("collector unavailable")


def test_collector_failures_are_non_fatal() -> None:
    report = collect_diagnostics(
        [WorkingCollector(), BrokenCollector()],
        generated_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
    )

    assert report.generated_at == "2026-01-02T03:04:05Z"
    assert report.diagnostics == {"working": {"healthy": True}}
    assert len(report.errors) == 1
    assert report.errors[0].collector == "broken"
    assert report.errors[0].message == "collector unavailable"
