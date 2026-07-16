"""Tests for SSH subprocess isolation and error translation."""

import subprocess
from pathlib import Path

from linuxmd.remote.ssh import SSHConfig, SSHRunner


def test_ssh_timeout(monkeypatch) -> None:
    def expire(*args, **kwargs):
        raise subprocess.TimeoutExpired("ssh", timeout=3, output="partial")

    monkeypatch.setattr(subprocess, "run", expire)

    result = SSHRunner(SSHConfig("server", "diagnostics", timeout=3)).run("uptime")

    assert result.status == "timeout"
    assert result.exit_code is None
    assert result.stdout == "partial"


def test_ssh_authentication_failure(monkeypatch) -> None:
    captured = {}

    def deny(arguments, **kwargs):
        captured["arguments"] = arguments
        return subprocess.CompletedProcess(
            arguments,
            255,
            stdout="",
            stderr="Permission denied (publickey).",
        )

    monkeypatch.setattr(subprocess, "run", deny)
    config = SSHConfig("192.168.1.100", "diagnostics", identity_file=Path("id_ed25519"))

    result = SSHRunner(config).run("uptime")

    assert result.status == "authentication_failed"
    assert "BatchMode=yes" in captured["arguments"]
    assert "password" not in " ".join(captured["arguments"]).lower()
    assert captured["arguments"][-2:] == ["diagnostics@192.168.1.100", "uptime"]
