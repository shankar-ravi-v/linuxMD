"""Safe, noninteractive command execution through the system SSH client."""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from linuxmd.diagnostics.performance_models import CommandResult


@dataclass(frozen=True, slots=True)
class SSHConfig:
    """Connection settings supported by the OpenSSH command-line client."""

    host: str
    user: str | None = None
    port: int = 22
    identity_file: Path | None = None
    timeout: int = 90


class SSHRunner:
    """Execute fixed commands remotely without shell interpolation or passwords."""

    def __init__(self, config: SSHConfig, *, executable: str = "ssh") -> None:
        self.config = config
        self.executable = executable

    def run(self, command: str) -> CommandResult:
        """Run one command and translate process outcomes into a structured result."""
        started = perf_counter()
        try:
            completed = subprocess.run(
                self._arguments(command),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.config.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                status="timeout",
                exit_code=None,
                stdout=_stream_text(exc.stdout),
                stderr=_stream_text(exc.stderr) or "SSH command timed out",
                command_available=True,
                elapsed_ms=_elapsed_ms(started),
            )
        except FileNotFoundError:
            return CommandResult(
                status="ssh_unavailable",
                exit_code=None,
                stdout="",
                stderr=f"SSH executable not found: {self.executable}",
                command_available=False,
                elapsed_ms=_elapsed_ms(started),
            )

        stderr = completed.stderr.strip()
        unavailable = completed.returncode == 127 or _is_missing_command(stderr)
        if completed.returncode == 0:
            status = "ok"
        elif unavailable:
            status = "unavailable"
        elif completed.returncode == 255 and _is_authentication_failure(stderr):
            status = "authentication_failed"
        elif completed.returncode == 255:
            status = "ssh_error"
        else:
            status = "error"

        return CommandResult(
            status=status,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=stderr,
            command_available=not unavailable,
            elapsed_ms=_elapsed_ms(started),
        )

    def _arguments(self, command: str) -> list[str]:
        connect_timeout = min(self.config.timeout, 30)
        arguments = [
            self.executable,
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={connect_timeout}",
            "-p",
            str(self.config.port),
        ]
        if self.config.identity_file is not None:
            arguments.extend(["-i", str(self.config.identity_file)])
        destination = (
            f"{self.config.user}@{self.config.host}" if self.config.user else self.config.host
        )
        arguments.extend(["--", destination, command])
        return arguments


def _elapsed_ms(started: float) -> int:
    return max(0, round((perf_counter() - started) * 1000))


def _stream_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _is_missing_command(stderr: str) -> bool:
    lowered = stderr.lower()
    return "command not found" in lowered or "not found" in lowered


def _is_authentication_failure(stderr: str) -> bool:
    lowered = stderr.lower()
    return "permission denied" in lowered or "authentication failed" in lowered
