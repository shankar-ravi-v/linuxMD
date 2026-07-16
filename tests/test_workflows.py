"""Tests for reusable collection workflow sequencing and output policy."""

import json
from dataclasses import replace
from pathlib import Path

from linuxmd.diagnostics.performance_models import CommandResult
from linuxmd.workflows import (
    ALL_COLLECTORS,
    DEFAULT_COLLECTORS,
    CollectorRegistration,
    StageResult,
    run_all_collections,
    run_performance_collection,
    run_registered_collectors,
)


def test_builtin_default_collector_registry_contains_only_primary_collectors() -> None:
    assert [item.name for item in DEFAULT_COLLECTORS] == ["system", "performance", "security"]
    assert [item.name for item in ALL_COLLECTORS] == ["system", "performance", "security"]


def test_all_runs_independent_stages_in_required_order(monkeypatch) -> None:
    calls = []
    raw = {"collector": "security"}

    def system():
        calls.append("system")
        return StageResult("system", "failed", error="failed")

    def performance(**kwargs):
        calls.append("performance")
        return StageResult("performance", "success", [Path("output/performance.json")])

    def security():
        calls.append("security_collection")
        return StageResult("security_collection", "success", data=raw)

    def analysis(value):
        calls.append(("security_analysis", value))
        return StageResult("security_analysis", "success")

    monkeypatch.setattr("linuxmd.workflows.run_system_collection", system)
    monkeypatch.setattr("linuxmd.workflows.run_performance_collection", performance)
    monkeypatch.setattr("linuxmd.workflows.run_security_collection", security)
    monkeypatch.setattr("linuxmd.workflows.run_security_analysis", analysis)

    results = run_all_collections(duration=3, timeout=10)

    assert calls == ["system", "performance", "security_collection", ("security_analysis", raw)]
    assert [result.status for result in results] == ["failed", "success", "success", "success"]


def test_registered_collectors_default_to_stable_baseline_and_all_includes_optional() -> None:
    calls = []

    def registration(name, default):
        def run(duration, timeout):
            calls.append((name, duration, timeout))
            return StageResult(name, "success")

        return CollectorRegistration(name, run, default=default)

    registry = (
        registration("system", True),
        registration("performance", True),
        registration("security", True),
        registration("experimental_gpu", False),
        registration("optional_pci", False),
    )

    defaults = run_registered_collectors(duration=7, timeout=20, registry=registry)
    assert [result.name for result in defaults] == ["system", "performance", "security"]
    assert calls == [
        ("system", 7, 20),
        ("performance", 7, 20),
        ("security", 7, 20),
    ]

    calls.clear()
    everything = run_registered_collectors(
        include_all=True, duration=7, timeout=20, registry=registry
    )
    assert [result.name for result in everything] == [
        "system",
        "performance",
        "security",
        "experimental_gpu",
        "optional_pci",
    ]


def test_remote_performance_workflow_writes_normalized_output(tmp_path, monkeypatch) -> None:
    class SuccessfulRunner:
        def __init__(self, config) -> None:
            self.config = config

        def run(self, command: str) -> CommandResult:
            output = "load average: 0.10, 0.20, 0.30" if command.endswith("uptime") else ""
            return replace(CommandResult("ok", 0, "", "", True, 1), stdout=output)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("linuxmd.workflows.SSHRunner", SuccessfulRunner)

    result = run_performance_collection(
        host="192.0.2.10", user="diagnostics", port=2222, duration=1, timeout=30
    )

    output = tmp_path / "output" / "performance.json"
    assert result.status == "success"
    assert result.output_paths == [output.resolve()]
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["diagnostics"]["performance"]["host"] == {
        "address": "192.0.2.10",
        "port": 2222,
        "user": "diagnostics",
    }
