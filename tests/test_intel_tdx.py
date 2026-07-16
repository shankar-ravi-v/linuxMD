"""Unit tests for read-only Intel TDX host evidence."""

import json
import subprocess
from collections import Counter

import pytest

from linuxmd.collectors.security import SecurityCollector
from linuxmd.collectors.vendors.intel.msr import (
    MSR_IA32_MCG_CAP,
    MSR_KEY_ACTIVATION,
    MSR_TDX_CAPABILITIES,
    MSR_TME_ACTIVATE,
    MSR_TME_CAPABILITY,
    MsrReader,
    decode_tdx_registers,
    extract_bits,
    parse_msr_hex,
)
from linuxmd.collectors.vendors.intel.tdx import collect_intel_tdx
from linuxmd.diagnostics.security import analyze_security


def _completed(arguments, stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(arguments, returncode, stdout=stdout, stderr=stderr)


def _msr_root(tmp_path):
    device = tmp_path / "dev/cpu/0/msr"
    device.parent.mkdir(parents=True)
    device.write_bytes(b"")
    return tmp_path


def test_extract_bits_valid_ranges() -> None:
    assert extract_bits(0b110110, 4, 2) == 0b101
    assert extract_bits(1 << 63, 63, 32) == 1 << 31


@pytest.mark.parametrize("value,high,low", [(1, 0, 1), (1, 1, -1), (-1, 1, 0)])
def test_extract_bits_invalid_ranges(value, high, low) -> None:
    with pytest.raises(ValueError):
        extract_bits(value, high, low)


@pytest.mark.parametrize("text,value", [("ff\n", 255), ("0x10", 16), ("00000002", 2)])
def test_hexadecimal_msr_parsing(text, value) -> None:
    assert parse_msr_hex(text) == value


def test_malformed_rdmsr_output(tmp_path) -> None:
    reader = MsrReader(
        root=_msr_root(tmp_path),
        runner=lambda args: _completed(args, "not-hex"),
        rdmsr_path="rdmsr",
        readable=lambda path: True,
    )

    assert reader.read_msr(MSR_TME_ACTIVATE)["status"] == "malformed_output"


def test_rdmsr_missing_and_module_not_loaded(tmp_path) -> None:
    missing_tool = MsrReader(root=tmp_path, runner=lambda args: _completed(args), rdmsr_path=None)
    missing_device = MsrReader(
        root=tmp_path, runner=lambda args: _completed(args), rdmsr_path="rdmsr"
    )

    assert missing_tool.read_msr(MSR_TME_ACTIVATE)["status"] == "missing_tool"
    assert missing_device.read_msr(MSR_TME_ACTIVATE)["status"] == "module_not_loaded"


def test_msr_device_permission_denied(tmp_path) -> None:
    reader = MsrReader(
        root=_msr_root(tmp_path),
        runner=lambda args: _completed(args),
        rdmsr_path="rdmsr",
        readable=lambda path: False,
    )

    assert reader.read_msr(MSR_TME_ACTIVATE)["status"] == "permission_denied"


def test_rdmsr_timeout(tmp_path) -> None:
    def timeout(arguments):
        raise subprocess.TimeoutExpired(arguments, 10)

    reader = MsrReader(
        root=_msr_root(tmp_path),
        runner=timeout,
        rdmsr_path="rdmsr",
        readable=lambda path: True,
    )

    assert reader.read_msr(MSR_TME_ACTIVATE)["status"] == "error"


def test_tdx_register_fields_and_cache(tmp_path) -> None:
    values = {
        MSR_TME_ACTIVATE: 1 << 1,
        MSR_IA32_MCG_CAP: 0,
        MSR_TDX_CAPABILITIES: 1 << 11,
        MSR_TME_CAPABILITY: 128 << 36,
        MSR_KEY_ACTIVATION: (7 << 32) | 5,
    }
    calls = Counter()

    def run(arguments):
        register = int(arguments[-1], 16)
        calls[register] += 1
        return _completed(arguments, f"{values[register]:x}\n")

    reader = MsrReader(
        root=_msr_root(tmp_path),
        runner=run,
        rdmsr_path="rdmsr",
        readable=lambda path: True,
    )
    result = decode_tdx_registers(reader)
    observations = result["observations"]

    assert observations["tme_enabled"]["value"] is True
    assert observations["tdx_enabled"]["value"] is True
    assert observations["sgx_mcheck_status"]["value"] == 0
    assert observations["maximum_tme_keys"]["value"] == 128
    assert observations["activated_tme_keys"]["value"] == 5
    assert observations["activated_tdx_keys"]["value"] == 7
    assert calls[MSR_KEY_ACTIVATION] == 1
    assert all(count == 1 for count in calls.values())


@pytest.mark.parametrize(
    "register,value,field,expected",
    [
        (MSR_TME_ACTIVATE, 0, "tme_enabled", False),
        (MSR_TDX_CAPABILITIES, 0, "tdx_enabled", False),
    ],
)
def test_disabled_register_observations(tmp_path, register, value, field, expected) -> None:
    values = {
        MSR_TME_ACTIVATE: 2,
        MSR_IA32_MCG_CAP: 0,
        MSR_TDX_CAPABILITIES: 1 << 11,
        MSR_TME_CAPABILITY: 0,
        MSR_KEY_ACTIVATION: 0,
        register: value,
    }

    def run(arguments):
        return _completed(arguments, f"{values[int(arguments[-1], 16)]:x}")

    reader = MsrReader(
        root=_msr_root(tmp_path),
        runner=run,
        rdmsr_path="rdmsr",
        readable=lambda path: True,
    )

    assert decode_tdx_registers(reader)["observations"][field]["value"] is expected


@pytest.mark.parametrize(
    "stdout,initialized",
    [
        ("other message\ntdx: TDX module initialized\n", True),
        ("other kernel message\n", False),
    ],
)
def test_kernel_initialization_evidence(tmp_path, stdout, initialized) -> None:
    def run(arguments):
        if arguments[0] == "dmesg":
            return _completed(arguments, stdout)
        raise FileNotFoundError(arguments[0])

    result = collect_intel_tdx(root=tmp_path, runner=run, rdmsr_path=None)

    initialization = result["kernel_initialization"]
    assert initialization["initialized"] is initialized
    assert len(initialization["matched_messages"]) <= 10


def test_dmesg_permission_denied_is_not_disabled(tmp_path) -> None:
    def run(arguments):
        if arguments[0] == "dmesg":
            return _completed(arguments, returncode=1, stderr="Operation not permitted")
        raise FileNotFoundError(arguments[0])

    result = collect_intel_tdx(root=tmp_path, runner=run, rdmsr_path=None)

    assert result["kernel_initialization"]["status"] == "permission_denied"
    assert "initialized" not in result["kernel_initialization"]
    assert (
        result["privileged_register_verification"]["observations"]["tdx_enabled"]["value"] is None
    )


@pytest.mark.parametrize("active", [True, False])
def test_qgsd_service_state(tmp_path, active) -> None:
    def run(arguments):
        if arguments[:2] == ["systemctl", "show"]:
            return _completed(arguments, "LoadState=loaded")
        if arguments[:2] == ["systemctl", "is-active"]:
            return _completed(arguments, "active" if active else "inactive", 0 if active else 3)
        raise FileNotFoundError(arguments[0])

    result = collect_intel_tdx(root=tmp_path, runner=run, rdmsr_path=None)

    assert result["attestation_readiness"]["qgsd_service"]["active"] is active


def test_qcnl_missing_and_safe_fields_only(tmp_path) -> None:
    missing = collect_intel_tdx(
        root=tmp_path,
        runner=lambda args: (_ for _ in ()).throw(FileNotFoundError()),
        rdmsr_path=None,
    )
    assert missing["attestation_readiness"]["qcnl_config"]["exists"] is False

    config = tmp_path / "etc/sgx_default_qcnl.conf"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "pccs_url": "https://private.example",
                "use_secure_cert": False,
                "user_token": "sensitive-token",
                "client_password": "secret",
            }
        ),
        encoding="utf-8",
    )
    result = collect_intel_tdx(
        root=tmp_path,
        runner=lambda args: (_ for _ in ()).throw(FileNotFoundError()),
        rdmsr_path=None,
    )
    safe = result["attestation_readiness"]["qcnl_config"]
    serialized = json.dumps(safe)
    assert safe["pccs_url_configured"] is True
    assert safe["use_secure_cert"] is False
    assert "private.example" not in serialized
    assert "sensitive-token" not in serialized
    assert "secret" not in serialized


def test_qcnl_secure_cert_true(tmp_path) -> None:
    config = tmp_path / "etc/sgx_default_qcnl.conf"
    config.parent.mkdir(parents=True)
    config.write_text('{"use_secure_cert": true}', encoding="utf-8")

    result = collect_intel_tdx(
        root=tmp_path,
        runner=lambda args: (_ for _ in ()).throw(FileNotFoundError()),
        rdmsr_path=None,
    )

    assert result["attestation_readiness"]["qcnl_config"]["use_secure_cert"] is True


def test_generic_collector_invokes_intel_only_for_intel_vendor(tmp_path, monkeypatch) -> None:
    called = []

    def fake_tdx(**kwargs):
        called.append(True)
        return {"status": "available"}

    monkeypatch.setattr("linuxmd.collectors.security.collect_intel_tdx", fake_tdx)
    monkeypatch.setattr("linuxmd.collectors.security.shutil.which", lambda name: None)
    cpuinfo = tmp_path / "proc/cpuinfo"
    cpuinfo.parent.mkdir(parents=True)
    cpuinfo.write_text("vendor_id : GenuineIntel\nflags : tdx_host tme\n", encoding="utf-8")
    intel = SecurityCollector(
        root=tmp_path,
        platform_name="Linux",
        command_runner=lambda args: (_ for _ in ()).throw(FileNotFoundError()),
    ).collect()
    assert called == [True]
    assert intel["cpu_security"]["vendor_security"]["intel"]["tdx"]["status"] == "available"

    called.clear()
    cpuinfo.write_text("vendor_id : AuthenticAMD\nflags : sev\n", encoding="utf-8")
    amd = SecurityCollector(
        root=tmp_path,
        platform_name="Linux",
        command_runner=lambda args: (_ for _ in ()).throw(FileNotFoundError()),
    ).collect()
    assert called == []
    assert amd["cpu_security"]["vendor_security"]["intel"]["tdx"]["status"] == "unsupported"


def _security_with_tdx(tdx):
    return {
        "collector": "security",
        "cpu_security": {
            "status": "available",
            "vulnerabilities": {},
            "vendor_security": {"intel": {"tdx": tdx}},
        },
        "errors": [],
    }


def test_analyzer_reports_conflicting_tdx_evidence() -> None:
    tdx = {
        "status": "available",
        "kernel_initialization": {"status": "available", "initialized": True},
        "privileged_register_verification": {
            "observations": {
                "tdx_enabled": {"status": "available", "value": False},
                "tme_enabled": {"status": "available", "value": True},
            }
        },
        "attestation_readiness": {"qcnl_config": {"status": "unavailable"}},
    }

    result = analyze_security(_security_with_tdx(tdx))

    assert any("Contradictory Intel TDX evidence" in finding for finding in result["high_findings"])
    assert any("MSR 0x1401 bits 11:11" in finding for finding in result["high_findings"])


def test_analyzer_increases_confidence_when_kernel_and_msr_agree() -> None:
    tdx = {
        "status": "available",
        "kernel_initialization": {"status": "available", "initialized": True},
        "privileged_register_verification": {
            "observations": {
                "tdx_enabled": {"status": "available", "value": True},
                "tme_enabled": {"status": "available", "value": True},
            }
        },
        "attestation_readiness": {"qcnl_config": {"status": "available", "use_secure_cert": True}},
    }

    result = analyze_security(_security_with_tdx(tdx))

    assert result["confidence"] == "medium"
    assert any(
        "does not establish attestation readiness" in item for item in result["supporting_evidence"]
    )


def test_analyzer_records_privileged_gap_without_false_disabled_finding() -> None:
    observation = {"status": "permission_denied", "value": None}
    tdx = {
        "status": "available",
        "kernel_initialization": {"status": "permission_denied"},
        "privileged_register_verification": {
            "observations": {"tdx_enabled": observation, "tme_enabled": observation}
        },
        "attestation_readiness": {"qcnl_config": {"status": "available", "use_secure_cert": False}},
    }

    result = analyze_security(_security_with_tdx(tdx))

    assert any("permission_denied" in gap for gap in result["unknowns_and_gaps"])
    assert not any("tdx_enabled.value=False" in finding for finding in result["high_findings"])
    assert any("use_secure_cert=False" in finding for finding in result["medium_findings"])
