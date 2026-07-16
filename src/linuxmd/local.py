"""Local command execution for Linux diagnostic collectors."""

import subprocess
from time import perf_counter

from linuxmd.diagnostics.performance_models import CommandResult


class LocalRunner:
    """Execute diagnostic commands on the local machine."""

    def __init__(self, *, timeout: int = 90, shell: str = "sh") -> None:
        self.timeout = timeout
        self.shell = shell

    def run(self, command: str) -> CommandResult:
        """Run one command locally and return its structured result."""
        started = perf_counter()
        try:
            completed = subprocess.run(
                [self.shell, "-c", command],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                status="timeout",
                exit_code=None,
                stdout=_stream_text(exc.stdout),
                stderr=_stream_text(exc.stderr) or "Local command timed out",
                command_available=True,
                elapsed_ms=_elapsed_ms(started),
            )
        except FileNotFoundError:
            return CommandResult(
                status="shell_unavailable",
                exit_code=None,
                stdout="",
                stderr=f"Local shell not found: {self.shell}",
                command_available=False,
                elapsed_ms=_elapsed_ms(started),
            )

        unavailable = completed.returncode == 127
        return CommandResult(
            status="ok" if completed.returncode == 0 else "unavailable" if unavailable else "error",
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr.strip(),
            command_available=not unavailable,
            elapsed_ms=_elapsed_ms(started),
        )


def _elapsed_ms(started: float) -> int:
    return max(0, round((perf_counter() - started) * 1000))


def _stream_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
