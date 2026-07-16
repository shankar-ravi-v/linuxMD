"""Read-only Intel MSR access and TDX-related field definitions."""

import os
import re
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

MSR_TME_ACTIVATE = 0x982
MSR_IA32_MCG_CAP = 0xA0
MSR_TDX_CAPABILITIES = 0x1401
MSR_TME_CAPABILITY = 0x981
MSR_KEY_ACTIVATION = 0x87

TDX_REGISTERS = (
    MSR_TME_ACTIVATE,
    MSR_IA32_MCG_CAP,
    MSR_TDX_CAPABILITIES,
    MSR_TME_CAPABILITY,
    MSR_KEY_ACTIVATION,
)


def extract_bits(value: int, high: int, low: int) -> int:
    """Extract an inclusive bit range from a non-negative integer."""
    if value < 0:
        raise ValueError("value must be non-negative")
    if high < low or low < 0:
        raise ValueError("invalid bit range")
    width = high - low + 1
    return (value >> low) & ((1 << width) - 1)


def parse_msr_hex(text: str) -> int:
    """Parse the complete hexadecimal value emitted by rdmsr."""
    value = text.strip()
    if not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", value):
        raise ValueError("rdmsr output is not hexadecimal")
    return int(value, 16)


class MsrReader:
    """Read explicitly requested MSRs without changing kernel or device state."""

    def __init__(
        self,
        *,
        root: Path,
        runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]],
        rdmsr_path: str | None,
        readable: Callable[[Path], bool] | None = None,
        cpu: int = 0,
    ) -> None:
        if cpu < 0:
            raise ValueError("CPU index must be non-negative")
        self.root = root
        self.runner = runner
        self.rdmsr_path = rdmsr_path
        self.readable = readable or (lambda path: os.access(path, os.R_OK))
        self.cpu = cpu
        self.cache: dict[int, dict[str, Any]] = {}

    def availability(self) -> dict[str, Any]:
        """Describe whether existing read-only MSR access can be used."""
        if not self.rdmsr_path:
            return {"status": "missing_tool", "reason": "rdmsr is not installed"}
        device = self.root / f"dev/cpu/{self.cpu}/msr"
        if not device.exists():
            return {
                "status": "module_not_loaded",
                "reason": f"{device.as_posix()} does not exist",
            }
        if not self.readable(device):
            return {
                "status": "permission_denied",
                "reason": f"{device.as_posix()} is not readable by the current process",
            }
        return {"status": "available", "device": device.as_posix()}

    def read_msr(self, register: int) -> dict[str, Any]:
        """Read one complete register value, caching it for field reuse."""
        if register < 0:
            raise ValueError("register address must be non-negative")
        if register in self.cache:
            return self.cache[register]
        availability = self.availability()
        if availability["status"] != "available":
            result = {
                **availability,
                "cpu": self.cpu,
                "register": f"0x{register:x}",
            }
            self.cache[register] = result
            return result
        arguments = [self.rdmsr_path or "rdmsr", "-p", str(self.cpu), f"0x{register:x}"]
        try:
            completed = self.runner(arguments)
        except subprocess.TimeoutExpired:
            result = self._failure(register, "error", "rdmsr timed out")
        except PermissionError:
            result = self._failure(register, "permission_denied", "MSR access was denied")
        except FileNotFoundError:
            result = self._failure(register, "missing_tool", "rdmsr is not installed")
        except OSError as exc:
            result = self._failure(register, "error", _sanitize_error(exc))
        else:
            if completed.returncode != 0:
                lowered = completed.stderr.lower()
                status = "permission_denied" if "permission" in lowered else "error"
                result = self._failure(register, status, _sanitize_text(completed.stderr))
            else:
                try:
                    value = parse_msr_hex(completed.stdout)
                except ValueError:
                    result = self._failure(register, "malformed_output", "invalid rdmsr output")
                else:
                    result = {
                        "status": "available",
                        "cpu": self.cpu,
                        "register": f"0x{register:x}",
                        "raw_value": f"0x{value:x}",
                        "value": value,
                    }
        self.cache[register] = result
        return result

    def _failure(self, register: int, status: str, reason: str) -> dict[str, Any]:
        return {
            "status": status,
            "cpu": self.cpu,
            "register": f"0x{register:x}",
            "reason": reason or "rdmsr failed",
        }


def decode_tdx_registers(reader: MsrReader) -> dict[str, Any]:
    """Read each TDX-related register once and decode all requested fields."""
    registers = {register: reader.read_msr(register) for register in TDX_REGISTERS}
    return {
        "status": _aggregate_status(registers.values()),
        "cpu": reader.cpu,
        "registers": {f"0x{register:x}": value for register, value in registers.items()},
        "observations": {
            "tme_enabled": _field(registers[MSR_TME_ACTIVATE], 1, 1, boolean=True),
            "sgx_mcheck_status": _field(registers[MSR_IA32_MCG_CAP], 63, 0),
            "tdx_enabled": _field(registers[MSR_TDX_CAPABILITIES], 11, 11, boolean=True),
            "maximum_tme_keys": _field(registers[MSR_TME_CAPABILITY], 50, 36),
            "activated_tme_keys": _field(registers[MSR_KEY_ACTIVATION], 31, 0),
            "activated_tdx_keys": _field(registers[MSR_KEY_ACTIVATION], 63, 32),
        },
    }


def _field(
    register: dict[str, Any], high: int, low: int, *, boolean: bool = False
) -> dict[str, Any]:
    evidence = {
        "register": register["register"],
        "bits": f"{high}:{low}",
        "cpu": register["cpu"],
    }
    if register["status"] != "available":
        return {"status": register["status"], "value": None, "evidence": evidence}
    value = extract_bits(register["value"], high, low)
    return {
        "status": "available",
        "value": bool(value) if boolean else value,
        "raw_field_value": value,
        "evidence": evidence,
    }


def _aggregate_status(registers: Any) -> str:
    statuses = {register["status"] for register in registers}
    return (
        "available"
        if statuses == {"available"}
        else next(iter(statuses))
        if len(statuses) == 1
        else "partial"
    )


def _sanitize_text(value: str) -> str:
    text = value.strip().splitlines()[0] if value.strip() else ""
    return text[:200]


def _sanitize_error(exc: BaseException) -> str:
    return _sanitize_text(str(exc))
