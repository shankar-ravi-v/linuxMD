"""Tests for canonical CLI commands and runner delegation."""

from pathlib import Path

from typer.testing import CliRunner

from linuxmd.cli import app
from linuxmd.workflows import StageResult

runner = CliRunner()


def test_help_lists_only_canonical_primary_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("collect", "system", "performance", "security", "all", "analyze"):
        assert command in result.output
    assert "collect-performance" not in result.output


def test_removed_collect_performance_command_does_not_exist() -> None:
    result = runner.invoke(app, ["collect-performance"])

    assert result.exit_code != 0
    assert "No such command" in result.output


def test_collect_default_requests_only_stable_collectors(monkeypatch) -> None:
    captured = {}

    def run(**kwargs):
        captured.update(kwargs)
        return [
            StageResult("system", "success", [Path("output/diag.json")]),
            StageResult("performance", "success", [Path("output/performance.json")]),
            StageResult("security_collection", "success", [Path("output/security.json")]),
        ]

    monkeypatch.setattr("linuxmd.cli.run_registered_collectors", run)

    result = runner.invoke(app, ["collect"])

    assert result.exit_code == 0
    assert captured == {"include_all": False, "duration": 5, "timeout": 90}
    assert "Completed 3 collectors with 0 failures." in result.output
    for filename in ("output/diag.json", "output/performance.json", "output/security.json"):
        assert str(Path(filename)) in result.output


def test_collect_all_requests_full_registry(monkeypatch) -> None:
    captured = {}

    def run(**kwargs):
        captured.update(kwargs)
        return [
            StageResult("system", "success"),
            StageResult("performance", "success"),
            StageResult("security_collection", "success"),
            StageResult("experimental_gpu", "unsupported"),
        ]

    monkeypatch.setattr("linuxmd.cli.run_registered_collectors", run)

    result = runner.invoke(app, ["collect", "--all", "--duration", "9", "--timeout", "30"])

    assert result.exit_code == 0
    assert captured == {"include_all": True, "duration": 9, "timeout": 30}
    assert "Experimental Gpu: unsupported" in result.output
    assert "Completed 4 collectors with 0 failures." in result.output


def test_collect_preserves_failure_exit_behavior(monkeypatch) -> None:
    monkeypatch.setattr(
        "linuxmd.cli.run_registered_collectors",
        lambda **kwargs: [
            StageResult("system", "failed", error="inventory failed"),
            StageResult("performance", "success", [Path("output/performance.json")]),
            StageResult("security_collection", "unsupported", [Path("output/security.json")]),
        ],
    )

    result = runner.invoke(app, ["collect"])

    assert result.exit_code == 1
    assert "inventory failed" in result.output
    assert "Completed 3 collectors with 1 failures." in result.output


def test_collect_help_documents_all_registry_option() -> None:
    result = runner.invoke(app, ["collect", "--help"])

    assert result.exit_code == 0
    assert "--all" in result.output
    assert "experimental collectors" in result.output


def test_system_invokes_system_runner(monkeypatch) -> None:
    called = []

    def run():
        called.append("system")
        return StageResult("system", "success", [Path("output/diag.json")])

    monkeypatch.setattr("linuxmd.cli.run_system_collection", run)

    result = runner.invoke(app, ["system"])

    assert result.exit_code == 0
    assert called == ["system"]
    assert str(Path("output/diag.json")) in result.output


def test_performance_invokes_runner_with_remote_options(monkeypatch, tmp_path) -> None:
    captured = {}
    identity = tmp_path / "id_ed25519"
    identity.write_text("fixture", encoding="utf-8")

    def run(**kwargs):
        captured.update(kwargs)
        return StageResult("performance", "success", [Path("output/performance.json")])

    monkeypatch.setattr("linuxmd.cli.run_performance_collection", run)

    result = runner.invoke(
        app,
        [
            "performance",
            "--host",
            "192.0.2.10",
            "--user",
            "diagnostics",
            "--port",
            "2222",
            "--identity-file",
            str(identity),
            "--duration",
            "7",
            "--timeout",
            "30",
        ],
    )

    assert result.exit_code == 0
    assert captured["host"] == "192.0.2.10"
    assert captured["user"] == "diagnostics"
    assert captured["port"] == 2222
    assert captured["duration"] == 7
    assert captured["timeout"] == 30
    assert "sampling duration: 7s" in result.output
    assert str(Path("output/performance.json")) in result.output


def test_security_invokes_collection_then_analysis(monkeypatch) -> None:
    calls = []
    raw = {"collector": "security"}

    def collect():
        calls.append("collection")
        return StageResult(
            "security_collection", "success", [Path("output/security.json")], data=raw
        )

    def analyze(value):
        calls.append(("analysis", value))
        return StageResult("security_analysis", "success", [Path("output/security-analysis.json")])

    monkeypatch.setattr("linuxmd.cli.run_security_collection", collect)
    monkeypatch.setattr("linuxmd.cli.run_security_analysis", analyze)

    result = runner.invoke(app, ["security"])

    assert result.exit_code == 0
    assert calls == ["collection", ("analysis", raw)]
    assert str(Path("output/security.json")) in result.output
    assert str(Path("output/security-analysis.json")) in result.output


def test_all_prints_every_stage_and_needs_no_provider_environment(monkeypatch) -> None:
    monkeypatch.delenv("LINUXMD_PROVIDER", raising=False)
    monkeypatch.delenv("LINUXMD_API_KEY", raising=False)
    monkeypatch.setattr(
        "linuxmd.cli.create_provider",
        lambda *args: (_ for _ in ()).throw(AssertionError("all invoked LLM provider")),
    )
    monkeypatch.setattr(
        "linuxmd.cli.run_all_collections",
        lambda **kwargs: [
            StageResult("system", "success", [Path("output/diag.json")]),
            StageResult("performance", "success", [Path("output/performance.json")]),
            StageResult("security_collection", "success", [Path("output/security.json")]),
            StageResult("security_analysis", "success", [Path("output/security-analysis.json")]),
        ],
    )

    result = runner.invoke(app, ["all"])

    assert result.exit_code == 0
    for filename in (
        "output/diag.json",
        "output/performance.json",
        "output/security.json",
        "output/security-analysis.json",
    ):
        assert str(Path(filename)) in result.output
    assert "Completed 4 stages with 0 failures." in result.output


def test_all_exits_nonzero_when_a_stage_failed(monkeypatch) -> None:
    monkeypatch.setattr(
        "linuxmd.cli.run_all_collections",
        lambda **kwargs: [
            StageResult("system", "failed", error="inventory failed"),
            StageResult("performance", "success", [Path("output/performance.json")]),
            StageResult("security_collection", "unsupported", [Path("output/security.json")]),
            StageResult("security_analysis", "skipped", error="unsupported input"),
        ],
    )

    result = runner.invoke(app, ["all"])

    assert result.exit_code == 1
    assert "failed" in result.output
    assert "unsupported" in result.output
    assert "skipped" in result.output
    assert "Completed 4 stages with 1 failures." in result.output
