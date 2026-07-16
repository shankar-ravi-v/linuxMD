"""Tests for local subprocess execution."""

import subprocess

from linuxmd.local import LocalRunner


def test_local_runner_executes_through_shell(monkeypatch) -> None:
    captured = {}

    def succeed(arguments, **kwargs):
        captured["arguments"] = arguments
        return subprocess.CompletedProcess(arguments, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", succeed)

    result = LocalRunner(timeout=3).run("uptime")

    assert captured["arguments"] == ["sh", "-c", "uptime"]
    assert result.status == "ok"
    assert result.stdout == "ok\n"


def test_local_runner_marks_missing_command_unavailable(monkeypatch) -> None:
    def missing(arguments, **kwargs):
        return subprocess.CompletedProcess(arguments, 127, stdout="", stderr="not found")

    monkeypatch.setattr(subprocess, "run", missing)

    result = LocalRunner().run("missing-command")

    assert result.status == "unavailable"
    assert result.command_available is False
