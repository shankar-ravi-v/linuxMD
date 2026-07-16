"""Host-independent tests for Linux security fact collection."""

import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from linuxmd.collectors.security import SecurityCollector


def _write(root: Path, path: str, content: str | bytes = "") -> Path:
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")
    return target


def _runner(outputs=None, failures=None):
    outputs = outputs or {}
    failures = failures or {}

    def run(arguments):
        command = arguments[0]
        if command in failures:
            raise failures[command]
        if command not in outputs:
            raise FileNotFoundError(command)
        stdout, returncode = outputs[command]
        return subprocess.CompletedProcess(arguments, returncode, stdout=stdout, stderr="")

    return run


def _collector(root: Path, outputs=None, failures=None) -> SecurityCollector:
    return SecurityCollector(
        root=root,
        platform_name="Linux",
        command_runner=_runner(outputs, failures),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


@pytest.mark.parametrize("value,state", [(1, "enabled"), (0, "disabled")])
def test_secure_boot_state(rooted_tmp_path, value, state) -> None:
    _write(
        rooted_tmp_path,
        "/sys/firmware/efi/efivars/SecureBoot-test",
        b"\x00\x00\x00\x00" + bytes([value]),
    )

    result = _collector(rooted_tmp_path).collect()

    assert result["platform_security"]["secure_boot"]["state"] == state


def test_secure_boot_unavailable_and_tpm_absent(tmp_path) -> None:
    result = _collector(tmp_path).collect()

    assert result["platform_security"]["secure_boot"]["state"] == "unavailable"
    assert result["platform_security"]["tpm"]["present"] is False


def test_tpm_lockdown_and_measured_boot_detected(tmp_path) -> None:
    _write(tmp_path, "/sys/class/tpm/tpm0/tpm_version_major", "2")
    _write(tmp_path, "/sys/kernel/security/lockdown", "none [integrity] confidentiality")
    _write(tmp_path, "/sys/kernel/security/tpm0/binary_bios_measurements", "events")

    result = _collector(tmp_path).collect()["platform_security"]

    assert result["tpm"] == {
        "present": True,
        "device_paths": ["sys/class/tpm/tpm0"],
        "version": "2",
    }
    assert result["kernel_lockdown"] == "none [integrity] confidentiality"
    assert result["measured_boot_event_log_available"] is True


def test_cpu_vulnerabilities_and_capabilities_are_parsed(tmp_path) -> None:
    _write(tmp_path, "/proc/cpuinfo", "vendor_id : GenuineIntel\nflags : smep smap ibrs\n")
    _write(tmp_path, "/sys/devices/system/cpu/vulnerabilities/meltdown", "Mitigation: PTI")
    _write(tmp_path, "/sys/devices/system/cpu/vulnerabilities/mmio", "Vulnerable")

    result = _collector(tmp_path).collect()["cpu_security"]

    assert result["vendor"] == "GenuineIntel"
    assert result["security_capabilities"] == ["ibrs", "smap", "smep"]
    assert result["vulnerabilities"]["mmio"] == "Vulnerable"


@pytest.mark.parametrize("enabled", [True, False])
def test_iommu_detection(tmp_path, enabled) -> None:
    if enabled:
        (tmp_path / "sys/kernel/iommu_groups/0").mkdir(parents=True)
        _write(tmp_path, "/proc/cmdline", "quiet intel_iommu=on")
    else:
        _write(tmp_path, "/proc/cmdline", "quiet")

    result = _collector(tmp_path).collect()["iommu_pcie_security"]

    if enabled:
        assert result["enabled"] is True
        assert result["status"] == "available"
    else:
        assert result["enabled"] is None
        assert result["status"] == "not_observable"
    assert result["iommu_groups_present"] is enabled


@pytest.mark.parametrize(
    "selinux,apparmor,expected_selinux,expected_apparmor",
    [("1", "Y", "enforcing", True), ("0", "N", "permissive", False)],
)
def test_mac_and_sysctl_state(
    tmp_path, selinux, apparmor, expected_selinux, expected_apparmor
) -> None:
    _write(tmp_path, "/sys/fs/selinux/enforce", selinux)
    _write(tmp_path, "/sys/module/apparmor/parameters/enabled", apparmor)
    _write(tmp_path, "/proc/sys/kernel/dmesg_restrict", "0")

    result = _collector(tmp_path).collect()["kernel_hardening"]

    assert result["selinux"]["state"] == expected_selinux
    assert result["apparmor"]["enabled"] is expected_apparmor
    assert result["sysctls"]["dmesg_restrict"] == "0"


def test_firewall_sockets_and_ssh_are_parsed(tmp_path) -> None:
    outputs = {
        "nft": ("table inet filter", 0),
        "ss": (
            'tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=10,fd=3))\n'
            'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=20,fd=3))',
            0,
        ),
        "sshd": ("permitrootlogin yes\npasswordauthentication yes\nmaxauthtries 3", 0),
        "systemctl": ("active", 0),
    }

    result = _collector(tmp_path, outputs).collect()

    network = result["firewall_network_exposure"]
    assert network["nftables"]["active_ruleset"] is True
    assert network["listening_sockets"][0]["bind_address"] == "127.0.0.1"
    assert network["listening_sockets"][1]["bind_address"] == "0.0.0.0"
    ssh = result["identity_access"]["ssh_server"]
    assert ssh["settings"]["permitrootlogin"] == "yes"
    assert ssh["settings"]["passwordauthentication"] == "yes"


def test_encrypted_root_filesystem_is_detected(tmp_path) -> None:
    _write(tmp_path, "/proc/mounts", "/dev/mapper/cryptroot / ext4 rw,relatime 0 0\n")
    _write(tmp_path, "/proc/swaps", "Filename Type Size Used Priority\n")

    result = _collector(tmp_path).collect()["storage_filesystem_security"]

    assert result["root_encrypted"] is True
    assert result["mounts"]["/"]["filesystem"] == "ext4"


def test_permission_denied_and_partial_command_failure_are_nonfatal(tmp_path, monkeypatch) -> None:
    restricted = _write(tmp_path, "/sys/kernel/security/lockdown", "integrity")
    original = SecurityCollector._read_path

    def deny(path):
        if path == restricted:
            raise PermissionError("root required")
        return original(path)

    monkeypatch.setattr(SecurityCollector, "_read_path", staticmethod(deny))
    result = _collector(tmp_path, failures={"lspci": PermissionError("root required")}).collect()

    assert result["platform_security"]["status"] == "available"
    assert result["platform_security"]["kernel_lockdown"] is None
    assert result["iommu_pcie_security"]["pcie_capabilities"]["status"] == "permission_denied"
    assert any(error["status"] == "permission_denied" for error in result["errors"])


def test_non_linux_platform_returns_unsupported(tmp_path) -> None:
    result = SecurityCollector(root=tmp_path, platform_name="Windows").collect()

    assert all(
        result[name]["status"] == "unsupported"
        for name in result
        if name
        in {
            "platform_security",
            "cpu_security",
            "virtualization_security",
            "iommu_pcie_security",
            "kernel_hardening",
            "firewall_network_exposure",
            "storage_filesystem_security",
            "identity_access",
            "updates",
            "container_security",
        }
    )


@pytest.fixture
def rooted_tmp_path(tmp_path):
    return tmp_path
