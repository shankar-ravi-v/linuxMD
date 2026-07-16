"""Tests for the system collector."""

import gzip
import subprocess
from datetime import UTC, datetime

from linuxmd.collectors.system import SystemCollector


def test_read_os_release(tmp_path) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text(
        '# comment\nNAME="Example Linux"\nVERSION_ID=42\nINVALID\n',
        encoding="utf-8",
    )

    assert SystemCollector._read_os_release(os_release) == {
        "name": "Example Linux",
        "version_id": "42",
    }


def test_missing_os_release_is_empty(tmp_path) -> None:
    assert SystemCollector._read_os_release(tmp_path / "missing") == {}


def _write(root, path, content=""):
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def test_comprehensive_linux_inventory(tmp_path, monkeypatch) -> None:
    _write(tmp_path, "/proc/sys/kernel/hostname", "inventory-host")
    _write(tmp_path, "/proc/sys/kernel/domainname", "example.test")
    _write(tmp_path, "/etc/machine-id", "machine-123")
    _write(tmp_path, "/proc/sys/kernel/random/boot_id", "boot-456")
    _write(tmp_path, "/etc/timezone", "America/Los_Angeles")
    _write(
        tmp_path,
        "/etc/os-release",
        'NAME="Example Linux"\nID=example\nVERSION="42 Stable"\nVERSION_ID=42\n',
    )
    _write(tmp_path, "/proc/version", "Linux version 6.8.0 (builder@example) #1 SMP")
    _write(tmp_path, "/proc/cmdline", "quiet iommu=on")
    _write(tmp_path, "/proc/uptime", "3600.50 7200.25")
    _write(
        tmp_path,
        "/proc/cpuinfo",
        """processor : 0
physical id : 0
core id : 0
cpu cores : 2
siblings : 4
vendor_id : GenuineIntel
cpu family : 6
model : 143
model name : Example CPU
stepping : 8
microcode : 0x2b000590
cache size : 30720 KB
flags : fpu vmx hypervisor smep

processor : 1
physical id : 0
core id : 0
flags : fpu vmx hypervisor smep

processor : 2
physical id : 0
core id : 1
flags : fpu vmx hypervisor smep

processor : 3
physical id : 0
core id : 1
flags : fpu vmx hypervisor smep
""",
    )
    _write(
        tmp_path,
        "/proc/meminfo",
        """MemTotal:       16384000 kB
MemFree:         1000000 kB
MemAvailable:    8000000 kB
Buffers:          100000 kB
Cached:          4000000 kB
SwapTotal:       2000000 kB
SwapFree:        1500000 kB
HugePages_Total:       8
HugePages_Free:        4
Hugepagesize:       2048 kB
""",
    )
    _write(tmp_path, "/proc/modules", "kvm 1 0 - Live 0x0\nkvm_intel 1 0 - Live 0x0\n")
    _write(tmp_path, "/proc/loadavg", "1.25 0.75 0.50 2/321 999")
    _write(
        tmp_path,
        "/proc/stat",
        "cpu 1 2 3 4\nbtime 1767225600\nprocs_running 3\nprocs_blocked 1\n",
    )
    _write(
        tmp_path,
        "/proc/mounts",
        "/dev/mapper/root / ext4 rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec 0 0\n",
    )
    _write(tmp_path, "/sys/class/dmi/id/product_name", "KVM Virtual Machine")
    _write(tmp_path, "/sys/class/dmi/id/sys_vendor", "QEMU")
    _write(tmp_path, "/proc/sys/kernel/osrelease", "6.8.0-linux")
    config = tmp_path / "proc/config.gz"
    with gzip.open(config, "wt", encoding="utf-8") as stream:
        stream.write("CONFIG_SECCOMP=y\n# CONFIG_DEBUG_INFO is not set\n")
    monkeypatch.setattr("socket.getfqdn", lambda hostname: f"{hostname}.example.test")

    result = SystemCollector(
        root=tmp_path,
        platform_name="Linux",
        kernel_release="6.8.0-test",
        now=datetime(2026, 1, 1, 1, 0, tzinfo=UTC),
    ).collect()

    assert result["status"] == "available"
    operating_system = result["operating_system"]
    assert operating_system["hostname"] == "inventory-host"
    assert operating_system["domain_name"] == "example.test"
    assert operating_system["machine_id"] == "machine-123"
    assert operating_system["boot_id"] == "boot-456"
    assert operating_system["uptime_seconds"] == 3600.5
    assert operating_system["boot_time_utc"] == "2026-01-01T00:00:00Z"
    assert operating_system["distribution"]["name"] == "Example Linux"
    cpu = result["cpu"]
    assert cpu["sockets"] == 1
    assert cpu["cores"] == 2
    assert cpu["threads"] == 4
    assert cpu["threads_per_core"] == 2.0
    assert cpu["vendor"] == "GenuineIntel"
    assert cpu["virtualization_flags"] == ["hypervisor", "vmx"]
    assert result["memory"]["total_kib"] == 16384000
    assert result["memory"]["huge_pages"]["size_kib"] == 2048
    assert result["kernel"]["loaded_module_count"] == 2
    assert result["kernel"]["configuration"]["CONFIG_SECCOMP"] == "y"
    assert result["processes"]["process_count"] == 321
    assert result["processes"]["running_processes"] == 3
    assert result["processes"]["blocked_processes"] == 1
    assert result["filesystems"]["filesystem_types"] == ["ext4", "proc"]
    assert result["virtualization"]["hypervisor"] == "kvm"
    assert result["virtualization"]["environment"] == "virtual_machine"


def test_container_wsl_and_kubernetes_detection(tmp_path) -> None:
    _write(tmp_path, "/proc/version", "Linux Microsoft WSL2")
    _write(tmp_path, "/proc/sys/kernel/osrelease", "5.15-microsoft-standard-WSL2")
    _write(tmp_path, "/.dockerenv")
    (tmp_path / "var/run/secrets/kubernetes.io/serviceaccount").mkdir(parents=True)

    result = SystemCollector(root=tmp_path, platform_name="Linux").collect()

    virtualization = result["virtualization"]
    assert virtualization["wsl"] is True
    assert virtualization["docker"] is True
    assert virtualization["kubernetes"] is True
    assert virtualization["environment"] == "wsl"


def test_non_linux_inventory_is_unsupported(tmp_path) -> None:
    result = SystemCollector(root=tmp_path, platform_name="Darwin").collect()

    assert result == {
        "status": "unsupported",
        "reason": "Comprehensive system inventory requires Linux procfs and sysfs",
        "platform": "Darwin",
    }


def _completed(command, stdout="", returncode=0):
    return subprocess.CompletedProcess(command, returncode, stdout, "")


def test_nvidia_gpu_inventory_handles_multiple_gpus_and_na(tmp_path) -> None:
    rows = "\n".join(
        [
            "0, NVIDIA RTX A6000, GPU-a, 00000000:00:06.0, 535.183.06, "
            "46068, 1, 0, 0, 30, 12.0, 300.0, Enabled, Default, 0",
            "1, NVIDIA RTX A6000, GPU-b, 00000000:00:07.0, 535.183.06, "
            "46068, N/A, N/A, 0, 31, N/A, 300.0, Disabled, Default, N/A",
        ]
    )

    def run(command, **kwargs):
        return _completed(
            command, "NVIDIA-SMI 535.183.06  CUDA Version: 12.2\n" if len(command) == 1 else rows
        )

    result = SystemCollector(root=tmp_path, platform_name="Linux", command_runner=run).collect()

    assert len(result["gpus"]) == 2
    assert result["gpus"][0]["cuda_driver_compatibility"] == "12.2"
    assert result["gpus"][0]["memory_total_mib"] == 46068
    assert result["gpus"][0]["persistence_mode"] is True
    assert result["gpus"][1]["memory_used_mib"] is None
    assert result["gpus"][1]["volatile_uncorrectable_ecc_errors"] is None


def test_nvidia_smi_missing_failure_and_malformed_output_are_optional(tmp_path) -> None:
    def missing(command, **kwargs):
        raise FileNotFoundError

    missing_result = SystemCollector(
        root=tmp_path, platform_name="Linux", command_runner=missing
    ).collect()
    assert missing_result["gpus"] == []
    assert missing_result["gpu_collection"]["status"] == "command_not_found"

    for output, code in (("error", 1), ("malformed,csv", 0)):

        def runner(command, *, _output=output, _code=code, **kwargs):
            return _completed(command, _output, _code)

        result = SystemCollector(
            root=tmp_path, platform_name="Linux", command_runner=runner
        ).collect()
        assert result["gpus"] == []
        assert result["gpu_collection"]["status"] == (
            "command_failed" if code else "no_supported_gpu"
        )


def test_openstack_platform_preserves_kvm_hypervisor_and_guest_topology(tmp_path) -> None:
    _write(tmp_path, "/sys/class/dmi/id/product_name", "OpenStack Nova")
    _write(tmp_path, "/sys/class/dmi/id/sys_vendor", "OpenStack Foundation")
    _write(tmp_path, "/proc/cpuinfo", "processor : 0\nflags : hypervisor")

    def run(command, **kwargs):
        if command[0] == "systemd-detect-virt":
            return _completed(command, "kvm\n")
        raise FileNotFoundError

    result = SystemCollector(root=tmp_path, platform_name="Linux", command_runner=run).collect()

    assert result["virtualization"]["platform"] == "openstack"
    assert result["virtualization"]["hypervisor"] == "kvm"
    assert result["virtualization"]["dmi_vendor"] == "OpenStack Foundation"
    assert result["virtualization"]["confidence"] == "high"
    assert result["cpu"]["topology_scope"] == "guest_visible"


def test_structured_cpu_caches_are_deduplicated(tmp_path) -> None:
    for cpu in (0, 1):
        base = f"/sys/devices/system/cpu/cpu{cpu}/cache/index0"
        _write(tmp_path, f"{base}/level", "1")
        _write(tmp_path, f"{base}/type", "Data")
        _write(tmp_path, f"{base}/size", "32K")
        _write(tmp_path, f"{base}/coherency_line_size", "64")
        _write(tmp_path, f"{base}/number_of_sets", "64")
        _write(tmp_path, f"{base}/ways_of_associativity", "8")
        _write(tmp_path, f"{base}/shared_cpu_list", "0-1")

    caches = SystemCollector(root=tmp_path, platform_name="Linux").collect()["cpu"]["caches"]

    assert caches == [
        {
            "level": 1,
            "type": "Data",
            "size_bytes": 32768,
            "line_size_bytes": 64,
            "number_of_sets": 64,
            "ways_of_associativity": 8,
            "shared_cpu_list": "0-1",
        }
    ]


def test_missing_cache_sysfs_returns_empty_list(tmp_path) -> None:
    assert SystemCollector(root=tmp_path, platform_name="Linux").collect()["cpu"]["caches"] == []
