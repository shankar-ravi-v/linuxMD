"""Intel TDX host-readiness fact collection."""

import json
import re
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from linuxmd.collectors.vendors.intel.msr import MsrReader, decode_tdx_registers

TDX_INITIALIZED = re.compile(r"tdx:\s*TDX module initialized", re.IGNORECASE)
QGS_PACKAGES = ("tdx-qgs", "libsgx-dcap-default-qpl", "libsgx-dcap-ql")


def collect_intel_tdx(
    *,
    root: Path,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]],
    rdmsr_path: str | None,
    readable: Callable[[Path], bool] | None = None,
) -> dict[str, Any]:
    """Collect least-privileged Intel TDX host evidence in priority order."""
    errors: list[dict[str, str]] = []
    cpuinfo = _read_text(root / "proc/cpuinfo", errors) or ""
    flags = set(_cpu_flags(cpuinfo))
    hardware = {
        "status": "available" if cpuinfo else "unavailable",
        "cpu_flags": sorted(flags & {"tdx", "tdx_host", "vmx", "sgx", "tme"}),
        "tdx_flag_present": bool(flags & {"tdx", "tdx_host"}),
        "tme_flag_present": "tme" in flags,
    }
    kernel_paths = {
        "kvm_intel_module": root / "sys/module/kvm_intel",
        "tdx_firmware": root / "sys/firmware/tdx",
    }
    kernel_support = {
        "status": "available",
        **{name: path.exists() for name, path in kernel_paths.items()},
    }
    initialization = _kernel_initialization(runner)
    if initialization["status"] not in {"available", "unavailable"}:
        errors.append(
            {
                "check": "kernel_initialization",
                "status": initialization["status"],
                "message": initialization.get("reason", "dmesg unavailable"),
            }
        )
    reader = MsrReader(
        root=root,
        runner=runner,
        rdmsr_path=rdmsr_path,
        readable=readable,
        cpu=0,
    )
    registers = decode_tdx_registers(reader)
    attestation = _attestation_readiness(root, runner, errors)
    return {
        "status": "available",
        "hardware_capability": hardware,
        "kernel_support": kernel_support,
        "kernel_initialization": initialization,
        "privileged_register_verification": registers,
        "attestation_readiness": attestation,
        "errors": errors,
    }


def unsupported_tdx(reason: str) -> dict[str, Any]:
    """Return an explicit non-Intel result without probing Intel interfaces."""
    return {
        "status": "unsupported",
        "reason": reason,
        "hardware_capability": {"status": "unsupported"},
        "kernel_support": {"status": "unsupported"},
        "kernel_initialization": {"status": "unsupported"},
        "privileged_register_verification": {"status": "unsupported"},
        "attestation_readiness": {"status": "unsupported"},
        "errors": [],
    }


def _kernel_initialization(
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    try:
        completed = runner(["dmesg"])
    except FileNotFoundError:
        return {"status": "unavailable", "reason": "dmesg is not installed"}
    except PermissionError:
        return {"status": "permission_denied", "reason": "kernel log access was denied"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "reason": "dmesg timed out"}
    except OSError as exc:
        return {"status": "error", "reason": _safe_error(exc)}
    if completed.returncode != 0:
        denied = (
            "permission" in completed.stderr.lower()
            or "operation not permitted" in completed.stderr.lower()
        )
        return {
            "status": "permission_denied" if denied else "error",
            "reason": _safe_text(completed.stderr) or "dmesg failed",
        }
    matches = [match.group(0) for match in TDX_INITIALIZED.finditer(completed.stdout)][:10]
    return {
        "status": "available",
        "initialized": bool(matches),
        "evidence_source": "dmesg",
        "matched_messages": matches,
    }


def _attestation_readiness(
    root: Path,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]],
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    load = _safe_command(runner, ["systemctl", "show", "-p", "LoadState", "qgsd.service"])
    active = _safe_command(runner, ["systemctl", "is-active", "qgsd.service"])
    packages = _package_state(runner)
    config_path = root / "etc/sgx_default_qcnl.conf"
    config: dict[str, Any] = {
        "status": "unavailable",
        "exists": config_path.exists(),
        "readable": False,
        "pccs_url_configured": None,
        "use_secure_cert": None,
    }
    if config_path.exists():
        try:
            parsed = json.loads(config_path.read_text(encoding="utf-8", errors="replace"))
        except PermissionError:
            config.update(status="permission_denied")
            errors.append(
                {
                    "check": "attestation.qcnl_config",
                    "status": "permission_denied",
                    "message": "QCNL configuration is not readable",
                }
            )
        except (OSError, json.JSONDecodeError) as exc:
            config.update(status="error")
            errors.append(
                {
                    "check": "attestation.qcnl_config",
                    "status": "error",
                    "message": _safe_error(exc),
                }
            )
        else:
            config.update(
                status="available",
                readable=True,
                pccs_url_configured=bool(parsed.get("pccs_url")),
                use_secure_cert=parsed.get("use_secure_cert")
                if isinstance(parsed.get("use_secure_cert"), bool)
                else None,
            )
    return {
        "status": "available",
        "qgsd_service": {
            "exists": load.get("stdout") == "LoadState=loaded",
            "active": active.get("stdout") == "active",
            "check_status": active["status"],
        },
        "known_packages": packages,
        "qcnl_config": config,
    }


def _package_state(
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    results = {}
    for package in QGS_PACKAGES:
        deb = _safe_command(runner, ["dpkg-query", "-W", "-f=${Status}", package])
        rpm = (
            _safe_command(runner, ["rpm", "-q", package])
            if deb["status"] == "unavailable"
            else None
        )
        selected = rpm or deb
        results[package] = {
            "status": selected["status"],
            "installed": selected["status"] == "available"
            and ("installed" in selected["stdout"] or selected["stdout"].startswith(package)),
        }
    return results


def _safe_command(
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]], arguments: list[str]
) -> dict[str, str]:
    try:
        completed = runner(arguments)
    except FileNotFoundError:
        return {"status": "unavailable", "stdout": ""}
    except PermissionError:
        return {"status": "permission_denied", "stdout": ""}
    except subprocess.TimeoutExpired:
        return {"status": "error", "stdout": ""}
    except OSError:
        return {"status": "error", "stdout": ""}
    return {
        "status": "available" if completed.returncode == 0 else "unavailable",
        "stdout": completed.stdout.strip(),
    }


def _read_text(path: Path, errors: list[dict[str, str]]) -> str | None:
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        errors.append(
            {"check": path.as_posix(), "status": "permission_denied", "message": "read denied"}
        )
    except OSError as exc:
        errors.append({"check": path.as_posix(), "status": "error", "message": _safe_error(exc)})
    return None


def _cpu_flags(cpuinfo: str) -> list[str]:
    for line in cpuinfo.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in {"flags", "Features"}:
            return value.split()
    return []


def _safe_text(text: str) -> str:
    return (text.strip().splitlines() or [""])[0][:200]


def _safe_error(exc: BaseException) -> str:
    return _safe_text(str(exc))
