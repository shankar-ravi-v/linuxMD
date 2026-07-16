"""Procfs/sysfs-first Linux system inventory collection."""

import csv
import gzip
import io
import os
import platform
import re
import shutil
import socket
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class SystemCollector:
    """Collect structured Linux inventory without shell command parsing."""

    name = "system"

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        platform_name: str | None = None,
        kernel_release: str | None = None,
        now: datetime | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        command_timeout: float = 5.0,
    ) -> None:
        self.root = root
        self.platform_name = platform_name or platform.system()
        self.kernel_release = kernel_release or platform.release()
        self.now = now
        self.command_runner = command_runner
        self.command_timeout = command_timeout
        self._last_command_error: str | None = None

    def collect(self) -> dict[str, Any]:
        """Return comprehensive Linux inventory or an unsupported result."""
        if self.platform_name != "Linux":
            return {
                "status": "unsupported",
                "reason": "Comprehensive system inventory requires Linux procfs and sysfs",
                "platform": self.platform_name,
            }

        uptime = self._uptime()
        virtualization = self._virtualization()
        gpus = self._gpus()
        return {
            "status": "available",
            "operating_system": self._operating_system(uptime),
            "cpu": self._cpu(virtualization),
            "gpus": gpus,
            "gpu_collection": {
                "status": "available" if gpus else self._last_command_error or "no_supported_gpu",
                "source": "nvidia-smi",
            },
            "memory": self._memory(),
            "kernel": self._kernel(),
            "processes": self._processes(uptime),
            "filesystems": self._filesystems(),
            "virtualization": virtualization,
        }

    def _operating_system(self, uptime: dict[str, float | None]) -> dict[str, Any]:
        hostname = self._read("/proc/sys/kernel/hostname") or platform.node()
        fqdn = socket.getfqdn(hostname)
        proc_domain = self._read("/proc/sys/kernel/domainname")
        inferred_domain = (
            fqdn.removeprefix(f"{hostname}.") if fqdn.startswith(f"{hostname}.") else ""
        )
        domain = proc_domain if proc_domain not in {None, "", "(none)"} else inferred_domain
        os_release = self._read_os_release(self._path("/etc/os-release"))
        version = self._read("/proc/version")
        command_line = self._read("/proc/cmdline")
        now = self.now or datetime.now(UTC)
        uptime_seconds = uptime["uptime_seconds"]
        boot_timestamp = _parse_proc_stat(self._read("/proc/stat") or "").get("btime")
        if boot_timestamp is None and uptime_seconds is not None:
            boot_timestamp = now.timestamp() - uptime_seconds
        boot_time = (
            datetime.fromtimestamp(boot_timestamp, tz=UTC).isoformat().replace("+00:00", "Z")
            if boot_timestamp is not None
            else None
        )
        return {
            "hostname": hostname,
            "domain_name": domain or None,
            "machine_id": self._read("/etc/machine-id"),
            "boot_id": self._read("/proc/sys/kernel/random/boot_id"),
            "kernel_version": self.kernel_release,
            "kernel_build": version,
            "kernel_command_line": command_line,
            "uptime_seconds": uptime_seconds,
            "boot_time_utc": boot_time,
            "timezone": self._timezone(),
            "distribution": {
                "name": os_release.get("name"),
                "version": os_release.get("version"),
                "version_id": os_release.get("version_id"),
                "id": os_release.get("id"),
                "id_like": os_release.get("id_like"),
                "pretty_name": os_release.get("pretty_name"),
            },
            "os_release": os_release,
        }

    def _cpu(self, virtualization: dict[str, Any]) -> dict[str, Any]:
        cpuinfo = self._read("/proc/cpuinfo") or ""
        processors = _parse_cpuinfo(cpuinfo)
        socket_ids = {item["physical_id"] for item in processors if item.get("physical_id")}
        core_ids = {
            (item.get("physical_id", "0"), item["core_id"])
            for item in processors
            if item.get("core_id")
        }
        first = processors[0] if processors else {}
        flags = sorted(
            {
                flag
                for processor in processors
                for flag in str(processor.get("flags") or processor.get("features") or "").split()
            }
        )
        virtualization_flags = [
            flag
            for flag in flags
            if flag in {"vmx", "svm", "hypervisor", "sev", "sev_es", "sev_snp", "tdx_guest"}
        ]
        cores = len(core_ids)
        if not cores:
            reported_cores = _integer(first.get("cpu_cores"))
            cores = (reported_cores or len(processors)) * max(1, len(socket_ids))
        return {
            "logical_processors": len(processors) or os.cpu_count(),
            "sockets": len(socket_ids) or (1 if processors else None),
            "cores": cores or None,
            "threads": len(processors) or os.cpu_count(),
            "threads_per_core": round(len(processors) / cores, 2) if processors and cores else None,
            "vendor": first.get("vendor_id") or first.get("cpu_implementer"),
            "model": first.get("model_name")
            or first.get("processor_name")
            or first.get("hardware"),
            "family": first.get("cpu_family"),
            "model_number": first.get("model"),
            "stepping": first.get("stepping"),
            "microcode": first.get("microcode"),
            "cache_sizes": sorted(
                {
                    str(item["cache_size"])
                    for item in processors
                    if item.get("cache_size") is not None
                }
            ),
            "caches": self._cpu_caches(),
            "topology_scope": (
                "guest_visible"
                if virtualization.get("environment") in {"virtual_machine", "container", "wsl"}
                else "physical"
                if virtualization.get("environment") == "bare_metal"
                else "unknown"
            ),
            "flags": flags,
            "virtualization_flags": virtualization_flags,
        }

    def _memory(self) -> dict[str, Any]:
        values = _parse_meminfo(self._read("/proc/meminfo") or "")
        selected = {
            "total_kib": values.get("MemTotal"),
            "available_kib": values.get("MemAvailable"),
            "free_kib": values.get("MemFree"),
            "buffers_kib": values.get("Buffers"),
            "cached_kib": values.get("Cached"),
            "swap_total_kib": values.get("SwapTotal"),
            "swap_free_kib": values.get("SwapFree"),
            "huge_pages": {
                "total": values.get("HugePages_Total"),
                "free": values.get("HugePages_Free"),
                "reserved": values.get("HugePages_Rsvd"),
                "surplus": values.get("HugePages_Surp"),
                "size_kib": values.get("Hugepagesize"),
            },
        }
        return {**selected, "raw_kib": values}

    def _kernel(self) -> dict[str, Any]:
        modules = self._read("/proc/modules")
        configuration, source = self._kernel_configuration()
        return {
            "release": self.kernel_release,
            "version": self._read("/proc/version"),
            "command_line": self._read("/proc/cmdline"),
            "loaded_module_count": len(modules.splitlines()) if modules is not None else None,
            "configuration_status": "available" if configuration is not None else "unavailable",
            "configuration_source": source,
            "configuration": configuration,
        }

    def _processes(self, uptime: dict[str, float | None]) -> dict[str, Any]:
        loadavg = (self._read("/proc/loadavg") or "").split()
        stat = _parse_proc_stat(self._read("/proc/stat") or "")
        running, total = _loadavg_process_counts(loadavg[3] if len(loadavg) > 3 else "")
        return {
            "load_average": {
                "1_minute": _float(loadavg[0]) if len(loadavg) > 0 else None,
                "5_minutes": _float(loadavg[1]) if len(loadavg) > 1 else None,
                "15_minutes": _float(loadavg[2]) if len(loadavg) > 2 else None,
            },
            "process_count": total,
            "running_processes": stat.get("procs_running", running),
            "blocked_processes": stat.get("procs_blocked"),
            "last_pid": _integer(loadavg[4]) if len(loadavg) > 4 else None,
            **uptime,
        }

    def _filesystems(self) -> dict[str, Any]:
        mounts = _parse_mounts(self._read("/proc/mounts") or "")
        try:
            usage = shutil.disk_usage(self.root)
        except OSError:
            root_stats = None
        else:
            root_stats = {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
            }
        return {
            "mounts": mounts,
            "filesystem_types": sorted({mount["filesystem"] for mount in mounts}),
            "root_statistics": root_stats,
        }

    def _virtualization(self) -> dict[str, Any]:
        cpuinfo = (self._read("/proc/cpuinfo") or "").lower()
        version = (self._read("/proc/version") or "").lower()
        os_release = (self._read("/proc/sys/kernel/osrelease") or "").lower()
        product = self._read("/sys/class/dmi/id/product_name")
        vendor = self._read("/sys/class/dmi/id/sys_vendor")
        dmi_hypervisor = _detect_hypervisor(product, vendor, cpuinfo)
        detected_virt = self._run_command(["systemd-detect-virt"])
        hypervisor = (
            detected_virt.stdout.strip().lower()
            if detected_virt
            and detected_virt.returncode == 0
            and detected_virt.stdout.strip() != "none"
            else dmi_hypervisor
        )
        combined_dmi = " ".join(filter(None, (product, vendor))).lower()
        platform_name = "openstack" if "openstack" in combined_dmi else dmi_hypervisor
        docker = self._path("/.dockerenv").exists()
        podman = self._path("/run/.containerenv").exists()
        kubernetes = self._path("/var/run/secrets/kubernetes.io/serviceaccount").exists()
        wsl = "microsoft" in version or "microsoft" in os_release
        in_container = docker or podman or kubernetes
        return {
            "environment": "wsl"
            if wsl
            else "container"
            if in_container
            else "virtual_machine"
            if hypervisor
            else "bare_metal"
            if product or vendor
            else "bare_metal_or_unknown",
            "platform": platform_name,
            "hypervisor_detected": hypervisor is not None,
            "hypervisor": hypervisor,
            "docker": docker,
            "podman": podman,
            "kubernetes": kubernetes,
            "wsl": wsl,
            "running_inside_container": in_container,
            "dmi_product_name": product,
            "dmi_system_vendor": vendor,
            "dmi_product": product,
            "dmi_vendor": vendor,
            "confidence": "high" if platform_name or hypervisor else "low",
        }

    def _gpus(self) -> list[dict[str, Any]]:
        fields = (
            "index,name,uuid,pci.bus_id,driver_version,memory.total,memory.used,"
            "utilization.gpu,utilization.memory,temperature.gpu,power.draw,power.limit,"
            "persistence_mode,compute_mode,ecc.errors.uncorrected.volatile.total"
        )
        result = self._run_command(
            ["nvidia-smi", f"--query-gpu={fields}", "--format=csv,noheader,nounits"]
        )
        if result is None:
            return []
        if result.returncode != 0:
            self._last_command_error = "command_failed"
            return []
        cuda = self._nvidia_cuda_compatibility()
        gpus = []
        for row in csv.reader(io.StringIO(result.stdout)):
            if len(row) != 15:
                continue
            values = [value.strip() for value in row]
            gpus.append(
                {
                    "vendor": "NVIDIA",
                    "index": _integer_or_none(values[0]),
                    "model": _optional(values[1]),
                    "uuid": _optional(values[2]),
                    "pci_address": _optional(values[3]),
                    "driver_version": _optional(values[4]),
                    "cuda_driver_compatibility": cuda,
                    "memory_total_mib": _integer_or_none(values[5]),
                    "memory_used_mib": _integer_or_none(values[6]),
                    "gpu_utilization_percent": _integer_or_none(values[7]),
                    "memory_utilization_percent": _integer_or_none(values[8]),
                    "temperature_c": _integer_or_none(values[9]),
                    "power_draw_w": _float(values[10]),
                    "power_limit_w": _float(values[11]),
                    "persistence_mode": _boolean(values[12]),
                    "compute_mode": _optional(values[13]),
                    "volatile_uncorrectable_ecc_errors": _integer_or_none(values[14]),
                }
            )
        return gpus

    def _nvidia_cuda_compatibility(self) -> str | None:
        result = self._run_command(["nvidia-smi"])
        if result is None or result.returncode != 0:
            return None
        match = re.search(r"CUDA Version:\s*([0-9.]+)", result.stdout)
        return match.group(1) if match else None

    def _cpu_caches(self) -> list[dict[str, Any]]:
        caches = {}
        for index in sorted(self._path("/sys/devices/system/cpu").glob("cpu*/cache/index*")):
            entry = {
                "level": _integer_or_none(_read_path(index / "level")),
                "type": _read_path(index / "type"),
                "size_bytes": _cache_size_bytes(_read_path(index / "size")),
                "line_size_bytes": _integer_or_none(_read_path(index / "coherency_line_size")),
                "number_of_sets": _integer_or_none(_read_path(index / "number_of_sets")),
                "ways_of_associativity": _integer_or_none(
                    _read_path(index / "ways_of_associativity")
                ),
                "shared_cpu_list": _read_path(index / "shared_cpu_list"),
            }
            key = tuple(entry.values())
            caches[key] = entry
        return sorted(
            caches.values(),
            key=lambda item: (
                item["level"] or 0,
                item["type"] or "",
                item["shared_cpu_list"] or "",
            ),
        )

    def _run_command(self, command: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
        self._last_command_error = None
        runner = self.command_runner
        if runner is None and self.root != Path("/"):
            return None
        runner = runner or subprocess.run
        try:
            return runner(
                list(command),
                capture_output=True,
                text=True,
                timeout=self.command_timeout,
                check=False,
            )
        except FileNotFoundError:
            self._last_command_error = "command_not_found"
            return None
        except subprocess.TimeoutExpired:
            self._last_command_error = "command_timeout"
            return None
        except OSError:
            self._last_command_error = "command_failed"
            return None

    def _uptime(self) -> dict[str, float | None]:
        fields = (self._read("/proc/uptime") or "").split()
        return {
            "uptime_seconds": _float(fields[0]) if fields else None,
            "idle_seconds": _float(fields[1]) if len(fields) > 1 else None,
        }

    def _timezone(self) -> dict[str, str | None]:
        configured = self._read("/etc/timezone")
        current = datetime.now().astimezone()
        return {
            "name": configured or current.tzname(),
            "utc_offset": current.strftime("%z") or None,
        }

    def _kernel_configuration(self) -> tuple[dict[str, str] | None, str | None]:
        proc_config = self._path("/proc/config.gz")
        if proc_config.is_file():
            try:
                with gzip.open(proc_config, "rt", encoding="utf-8", errors="replace") as stream:
                    return _parse_kernel_config(stream.read()), "/proc/config.gz"
            except OSError:
                pass
        boot_config = self._path(f"/boot/config-{self.kernel_release}")
        try:
            return _parse_kernel_config(boot_config.read_text(encoding="utf-8")), str(
                Path("/boot") / boot_config.name
            )
        except OSError:
            return None, None

    def _read(self, path: str) -> str | None:
        try:
            return self._path(path).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None

    def _path(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    @staticmethod
    def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
        """Parse the standard os-release file when it is available."""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {}
        return _parse_key_values(text)


def _parse_cpuinfo(text: str) -> list[dict[str, str]]:
    processors = []
    for block in text.strip().split("\n\n") if text.strip() else []:
        values = {}
        for line in block.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                values[key.strip().lower().replace(" ", "_")] = value.strip()
        if values:
            processors.append(values)
    return processors


def _parse_meminfo(text: str) -> dict[str, int]:
    values = {}
    for line in text.splitlines():
        key, separator, remainder = line.partition(":")
        if not separator:
            continue
        fields = remainder.split()
        if fields and fields[0].isdigit():
            values[key] = int(fields[0])
    return values


def _parse_mounts(text: str) -> list[dict[str, Any]]:
    mounts = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            mounts.append(
                {
                    "source": fields[0].replace("\\040", " "),
                    "target": fields[1].replace("\\040", " "),
                    "filesystem": fields[2],
                    "options": fields[3].split(","),
                }
            )
    return mounts


def _parse_proc_stat(text: str) -> dict[str, int]:
    values = {}
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key in {"btime", "procs_running", "procs_blocked"} and value.strip().isdigit():
            values[key] = int(value)
    return values


def _loadavg_process_counts(value: str) -> tuple[int | None, int | None]:
    running, separator, total = value.partition("/")
    if not separator:
        return None, None
    return _integer(running), _integer(total)


def _parse_kernel_config(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", maxsplit=1)
            values[key] = value.strip().strip('"')
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2 : -len(" is not set")]] = "not_set"
    return values


def _parse_key_values(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", maxsplit=1)
            values[key.lower()] = value.strip().strip("\"'")
    return values


def _detect_hypervisor(product: str | None, vendor: str | None, cpuinfo: str) -> str | None:
    combined = " ".join(filter(None, (product, vendor))).lower()
    signatures = {
        "kvm": ("kvm", "qemu"),
        "vmware": ("vmware",),
        "hyper-v": ("virtual machine", "microsoft corporation"),
        "xen": ("xen",),
        "virtualbox": ("virtualbox",),
        "amazon_ec2": ("amazon ec2",),
        "google_compute_engine": ("google compute engine",),
    }
    for name, markers in signatures.items():
        if any(marker in combined for marker in markers):
            return name
    return "unknown" if "hypervisor" in cpuinfo else None


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _integer_or_none(value: Any) -> int | None:
    number = _float(value)
    return int(number) if number is not None else None


def _optional(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return None if not text or text.lower() in {"n/a", "not supported", "[not supported]"} else text


def _boolean(value: Any) -> bool | None:
    text = str(value).strip().lower()
    if text in {"enabled", "on", "yes", "true"}:
        return True
    if text in {"disabled", "off", "no", "false"}:
        return False
    return None


def _read_path(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _cache_size_bytes(value: str | None) -> int | None:
    if not value:
        return None
    match = re.fullmatch(r"\s*(\d+)\s*([KMG])?\s*", value, re.IGNORECASE)
    if not match:
        return None
    scale = {None: 1, "K": 1024, "M": 1024**2, "G": 1024**3}
    return int(match.group(1)) * scale[match.group(2).upper() if match.group(2) else None]
