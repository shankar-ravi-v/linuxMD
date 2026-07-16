"""Best-effort, read-only Linux platform security fact collection."""

import platform
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from linuxmd.collectors.vendors.intel.tdx import collect_intel_tdx, unsupported_tdx

SECTION_NAMES = (
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
)
MOUNT_TARGETS = {"/", "/boot", "/boot/efi", "/tmp", "/var/tmp", "/home", "/dev/shm"}
SECURITY_SYSCTLS = {
    "yama_ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope",
    "unprivileged_bpf_disabled": "/proc/sys/kernel/unprivileged_bpf_disabled",
    "unprivileged_userns_clone": "/proc/sys/kernel/unprivileged_userns_clone",
    "kptr_restrict": "/proc/sys/kernel/kptr_restrict",
    "dmesg_restrict": "/proc/sys/kernel/dmesg_restrict",
    "perf_event_paranoid": "/proc/sys/kernel/perf_event_paranoid",
    "modules_disabled": "/proc/sys/kernel/modules_disabled",
    "randomize_va_space": "/proc/sys/kernel/randomize_va_space",
}


class SecurityCollector:
    """Collect Linux security state without changing system configuration."""

    name = "security"

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        platform_name: str | None = None,
        command_runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None,
        generated_at: datetime | None = None,
    ) -> None:
        self.root = root
        self.platform_name = platform_name or platform.system()
        self.command_runner = command_runner or self._run_command
        self.generated_at = generated_at
        self.errors: list[dict[str, str]] = []

    def collect(self) -> dict[str, Any]:
        """Return raw security facts with non-fatal per-section failures."""
        timestamp = self.generated_at or datetime.now(UTC)
        result: dict[str, Any] = {
            "collector": self.name,
            "generated_at": timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        }
        if self.platform_name != "Linux":
            for name in SECTION_NAMES:
                result[name] = {"status": "unsupported", "reason": "Linux is required"}
            result["errors"] = []
            return result

        probes = {
            "platform_security": self._platform_security,
            "cpu_security": self._cpu_security,
            "virtualization_security": self._virtualization_security,
            "iommu_pcie_security": self._iommu_pcie_security,
            "kernel_hardening": self._kernel_hardening,
            "firewall_network_exposure": self._firewall_network_exposure,
            "storage_filesystem_security": self._storage_filesystem_security,
            "identity_access": self._identity_access,
            "updates": self._updates,
            "container_security": self._container_security,
        }
        for name, probe in probes.items():
            try:
                result[name] = {"status": "available", **probe()}
            except PermissionError as exc:
                self._error(name, "permission_denied", exc)
                result[name] = {"status": "permission_denied", "reason": str(exc)}
            except OSError as exc:
                self._error(name, "error", exc)
                result[name] = {"status": "error", "reason": str(exc)}
        result["errors"] = self.errors
        return result

    def _platform_security(self) -> dict[str, Any]:
        efi = self._path("/sys/firmware/efi")
        tpm_devices = sorted(self._path("/sys/class/tpm").glob("tpm*"))
        return {
            "boot_mode": "uefi" if efi.is_dir() else "legacy_or_unknown",
            "secure_boot": self._secure_boot(),
            "kernel_lockdown": self._read("/sys/kernel/security/lockdown"),
            "tpm": {
                "present": bool(tpm_devices),
                "device_paths": [path.relative_to(self.root).as_posix() for path in tpm_devices],
                "version": self._tpm_version(tpm_devices),
            },
            "measured_boot_event_log_available": self._path(
                "/sys/kernel/security/tpm0/binary_bios_measurements"
            ).is_file(),
            "ima": {
                "available": self._path("/sys/kernel/security/ima").exists(),
                "policy": self._read("/sys/kernel/security/ima/policy"),
            },
            "evm_available": self._path("/sys/kernel/security/evm").exists(),
        }

    def _cpu_security(self) -> dict[str, Any]:
        cpuinfo = self._read("/proc/cpuinfo") or ""
        vendor = _first_cpu_value(cpuinfo, ("vendor_id", "CPU implementer", "Hardware"))
        flags = set((_first_cpu_value(cpuinfo, ("flags", "Features")) or "").split())
        capabilities = sorted(
            flags
            & {
                "ibrs",
                "ibpb",
                "stibp",
                "ssbd",
                "md_clear",
                "arch_capabilities",
                "smap",
                "smep",
                "nx",
                "sev",
                "sev_es",
                "sev_snp",
                "tdx_guest",
            }
        )
        vulnerabilities = {}
        directory = self._path("/sys/devices/system/cpu/vulnerabilities")
        if directory.is_dir():
            for path in sorted(directory.iterdir()):
                if path.is_file():
                    vulnerabilities[path.name] = self._read_path(path)
        if vendor == "GenuineIntel":
            intel_tdx = collect_intel_tdx(
                root=self.root,
                runner=self.command_runner,
                rdmsr_path=shutil.which("rdmsr"),
            )
        else:
            intel_tdx = unsupported_tdx(f"CPU vendor {vendor or 'unknown'} is not GenuineIntel")
        return {
            "vendor": vendor,
            "security_capabilities": capabilities,
            "vulnerabilities": vulnerabilities,
            "vendor_security": {"intel": {"tdx": intel_tdx}},
        }

    def _virtualization_security(self) -> dict[str, Any]:
        cpuinfo = self._read("/proc/cpuinfo") or ""
        command = self._command(["systemd-detect-virt"])
        detected = command.get("stdout") or None
        in_container = (
            self._path("/.dockerenv").exists() or self._path("/run/.containerenv").exists()
        )
        environment = (
            "container"
            if in_container
            else "vm"
            if detected not in {None, "none"}
            else "bare_metal"
        )
        return {
            "environment": environment,
            "virtualization_type": detected,
            "intel_tdx_available": "tdx_guest" in cpuinfo
            or self._path("/sys/firmware/tdx").exists(),
            "amd_sev_available": " sev " in f" {cpuinfo} ",
            "amd_sev_es_available": "sev_es" in cpuinfo,
            "amd_sev_snp_available": "sev_snp" in cpuinfo,
        }

    def _iommu_pcie_security(self) -> dict[str, Any]:
        groups = self._path("/sys/kernel/iommu_groups")
        group_count = len([path for path in groups.glob("*") if path.is_dir()])
        cmdline = self._read("/proc/cmdline") or ""
        parameters = [
            token
            for token in cmdline.split()
            if token.startswith(("intel_iommu=", "amd_iommu=", "iommu="))
        ]
        pci = self._command(["lspci", "-vv"])
        pci_text = pci.get("stdout", "")
        observable = group_count > 0 or bool(parameters)
        enabled = group_count > 0 or any("=on" in value for value in parameters)
        return {
            "applicable": None,
            "observable": observable,
            "status": "available" if observable else "not_observable",
            "value": enabled if observable else None,
            "enabled": enabled if observable else None,
            "evidence_source": "sysfs iommu groups and kernel command line",
            "iommu_groups_present": group_count > 0,
            "iommu_group_count": group_count,
            "kernel_parameters": parameters,
            "intel_vtd_indicator": any(value.startswith("intel_iommu=") for value in parameters),
            "amd_vi_indicator": any(value.startswith("amd_iommu=") for value in parameters),
            "pcie_capabilities": {
                "status": pci["status"],
                "acs_visible": "Access Control Services" in pci_text or "ACSCap" in pci_text,
                "ats_visible": "ATSCap" in pci_text,
                "pri_visible": "PRICtl" in pci_text or "PRI" in pci_text,
                "pasid_visible": "PASID" in pci_text,
            },
        }

    def _kernel_hardening(self) -> dict[str, Any]:
        status = self._read("/proc/self/status") or ""
        selinux = self._read("/sys/fs/selinux/enforce")
        apparmor = self._read("/sys/module/apparmor/parameters/enabled")
        return {
            "kernel_version": platform.release(),
            "distribution": _parse_key_values(self._read("/etc/os-release") or ""),
            "selinux": {
                "supported": self._path("/sys/fs/selinux").exists(),
                "state": "enforcing"
                if selinux == "1"
                else "permissive"
                if selinux == "0"
                else None,
            },
            "apparmor": {
                "supported": self._path("/sys/module/apparmor").exists(),
                "enabled": apparmor in {"Y", "y", "1"},
            },
            "seccomp": _status_value(status, "Seccomp"),
            "sysctls": {name: self._read(path) for name, path in SECURITY_SYSCTLS.items()},
            "module_signature_enforcement": self._read("/sys/module/module/parameters/sig_enforce"),
            "fips_mode": self._read("/proc/sys/crypto/fips_enabled"),
        }

    def _firewall_network_exposure(self) -> dict[str, Any]:
        nft = self._command(["nft", "list", "ruleset"])
        iptables = self._command(["iptables", "-S"])
        firewalld = self._command(["firewall-cmd", "--state"])
        ufw = self._command(["ufw", "status"])
        sockets = self._command(["ss", "-H", "-lntu", "-p"])
        return {
            "nftables": {
                "status": nft["status"],
                "active_ruleset": nft["status"] == "available" and bool(nft["stdout"]),
            },
            "iptables": {
                "status": iptables["status"],
                "available": iptables["status"] != "unavailable",
            },
            "firewalld": {
                "status": firewalld["status"],
                "active": firewalld["stdout"] == "running",
            },
            "ufw": {"status": ufw["status"], "active": "Status: active" in ufw["stdout"]},
            "listening_sockets": _parse_listening_sockets(sockets.get("stdout", "")),
            "socket_collection_status": sockets["status"],
        }

    def _storage_filesystem_security(self) -> dict[str, Any]:
        mounts = _parse_mounts(self._read("/proc/mounts") or "")
        selected = {target: mounts[target] for target in MOUNT_TARGETS if target in mounts}
        root_mount = selected.get("/", {})
        swaps = _parse_swaps(self._read("/proc/swaps") or "")
        lsblk = self._command(["lsblk", "--json", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"])
        encrypted = str(root_mount.get("source", "")).startswith("/dev/mapper/")
        if lsblk["status"] == "available":
            encrypted = encrypted or '"type":"crypt"' in lsblk["stdout"].replace(" ", "").lower()
        return {
            "mounts": selected,
            "root_encrypted": encrypted,
            "encryption_detection_status": lsblk["status"],
            "swap_devices": swaps,
            "encrypted_swap_determined": all(
                str(item["device"]).startswith("/dev/mapper/") for item in swaps
            )
            if swaps
            else None,
        }

    def _identity_access(self) -> dict[str, Any]:
        ssh = self._command(["sshd", "-T"])
        ssh_settings = _parse_sshd_settings(ssh.get("stdout", ""))
        ssh_service = self._command(["systemctl", "is-active", "sshd"])
        if ssh_service["status"] != "available":
            ssh_service = self._command(["systemctl", "is-active", "ssh"])
        sudo_available = (
            any(self._path(path).is_file() for path in ("/usr/bin/sudo", "/bin/sudo"))
            or shutil.which("sudo") is not None
        )
        return {
            "ssh_server": {
                "installed": ssh["status"] != "unavailable",
                "active": ssh_service.get("stdout") == "active",
                "effective_config_status": ssh["status"],
                "settings": ssh_settings,
            },
            "sudo": {
                "available": sudo_available,
                "passwordless_rules": self._sudo_nopasswd_metadata(),
            },
        }

    def _updates(self) -> dict[str, Any]:
        managers = []
        for command in ("apt-get", "dnf", "yum", "zypper", "pacman", "apk"):
            result = self._command([command, "--version"])
            if result["status"] != "unavailable":
                managers.append(command)
        automatic = {
            service: self._command(["systemctl", "is-active", service]).get("stdout") == "active"
            for service in ("unattended-upgrades", "dnf-automatic.timer", "yum-cron")
        }
        return {
            "package_managers": managers,
            "security_updates_available": None,
            "security_updates_status": "unavailable",
            "automatic_update_services": automatic,
            "reboot_required": self._path("/var/run/reboot-required").exists(),
        }

    def _container_security(self) -> dict[str, Any]:
        in_container = (
            self._path("/.dockerenv").exists() or self._path("/run/.containerenv").exists()
        )
        runtimes = {}
        for runtime in ("docker", "podman", "containerd", "kubectl"):
            command = (
                [runtime, "version"] if runtime != "kubectl" else [runtime, "version", "--client"]
            )
            result = self._command(command)
            runtimes[runtime] = {
                "status": result["status"],
                "available": result["status"] != "unavailable",
            }
        return {
            "running_inside_container": in_container,
            "runtime_components": runtimes,
            "security_context": {
                "seccomp": _status_value(self._read("/proc/self/status") or "", "Seccomp"),
                "no_new_privileges": _status_value(
                    self._read("/proc/self/status") or "", "NoNewPrivs"
                ),
            },
        }

    def _secure_boot(self) -> dict[str, Any]:
        variables = list(self._path("/sys/firmware/efi/efivars").glob("SecureBoot-*"))
        if not variables:
            return {"state": "unavailable", "reason": "SecureBoot EFI variable not available"}
        try:
            data = variables[0].read_bytes()
        except PermissionError as exc:
            self._error("platform_security.secure_boot", "permission_denied", exc)
            return {"state": "permission_denied", "reason": str(exc)}
        except OSError as exc:
            self._error("platform_security.secure_boot", "error", exc)
            return {"state": "error", "reason": str(exc)}
        return {
            "state": "enabled" if data and data[-1] == 1 else "disabled",
            "raw_value": data[-1] if data else None,
        }

    def _tpm_version(self, devices: list[Path]) -> str | None:
        for device in devices:
            value = self._read_path(device / "tpm_version_major")
            if value:
                return value
            if (device / "device" / "description").exists():
                description = self._read_path(device / "device" / "description") or ""
                match = re.search(r"TPM\s*(\d(?:\.\d)?)", description, re.IGNORECASE)
                if match:
                    return match.group(1)
        return None

    def _sudo_nopasswd_metadata(self) -> dict[str, Any]:
        paths = [self._path("/etc/sudoers")]
        directory = self._path("/etc/sudoers.d")
        if directory.is_dir():
            paths.extend(path for path in directory.iterdir() if path.is_file())
        matches = []
        status = "available"
        for path in paths:
            if not path.exists():
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except PermissionError as exc:
                status = "permission_denied"
                self._error("identity_access.sudo", status, exc)
                continue
            except OSError as exc:
                status = "error"
                self._error("identity_access.sudo", status, exc)
                continue
            matches.extend(
                {"file": path.relative_to(self.root).as_posix(), "line": number}
                for number, line in enumerate(lines, start=1)
                if "NOPASSWD:" in line and not line.lstrip().startswith("#")
            )
        return {"status": status, "count": len(matches), "locations": matches}

    def _read(self, path: str) -> str | None:
        target = self._path(path)
        if not target.exists():
            return None
        try:
            return self._read_path(target)
        except PermissionError as exc:
            self._error(path, "permission_denied", exc)
            return None
        except OSError as exc:
            self._error(path, "error", exc)
            return None

    @staticmethod
    def _read_path(path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace").strip()

    def _path(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def _command(self, arguments: Sequence[str]) -> dict[str, Any]:
        try:
            completed = self.command_runner(arguments)
        except FileNotFoundError:
            return {"status": "unavailable", "stdout": "", "stderr": "command not found"}
        except PermissionError as exc:
            self._error("command:" + arguments[0], "permission_denied", exc)
            return {"status": "permission_denied", "stdout": "", "stderr": str(exc)}
        except subprocess.TimeoutExpired:
            return {"status": "error", "stdout": "", "stderr": "command timed out"}
        except OSError as exc:
            self._error("command:" + arguments[0], "error", exc)
            return {"status": "error", "stdout": "", "stderr": str(exc)}
        status = "available" if completed.returncode == 0 else "error"
        return {
            "status": status,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }

    @staticmethod
    def _run_command(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(arguments),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )

    def _error(self, check: str, status: str, exc: BaseException) -> None:
        self.errors.append({"check": check, "status": status, "message": str(exc)})


def _first_cpu_value(text: str, keys: tuple[str, ...]) -> str | None:
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", maxsplit=1)
        if key.strip() in keys:
            return value.strip()
    return None


def _status_value(text: str, key: str) -> int | None:
    match = re.search(rf"^{re.escape(key)}:\s*(\d+)", text, re.MULTILINE)
    return int(match.group(1)) if match else None


def _parse_key_values(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", maxsplit=1)
            values[key.lower()] = value.strip().strip("\"'")
    return values


def _parse_mounts(text: str) -> dict[str, dict[str, Any]]:
    mounts = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        source, target, filesystem, options = fields[:4]
        option_list = options.split(",")
        mounts[target.replace("\\040", " ")] = {
            "source": source,
            "filesystem": filesystem,
            "options": option_list,
            "security_options": [
                option
                for option in option_list
                if option in {"ro", "rw", "nosuid", "nodev", "noexec"}
            ],
        }
    return mounts


def _parse_swaps(text: str) -> list[dict[str, str]]:
    swaps = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2:
            swaps.append({"device": fields[0], "type": fields[1]})
    return swaps


def _parse_sshd_settings(text: str) -> dict[str, Any]:
    wanted = {
        "permitrootlogin",
        "passwordauthentication",
        "pubkeyauthentication",
        "permitemptypasswords",
        "maxauthtries",
        "x11forwarding",
        "allowusers",
        "allowgroups",
    }
    values = {}
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key.lower() in wanted and value:
            values[key.lower()] = value.strip()
    return values


def _parse_listening_sockets(text: str) -> list[dict[str, Any]]:
    sockets = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        protocol = fields[0].lower()
        local = fields[4]
        address, port = _split_address_port(local)
        process_text = " ".join(fields[6:]) if len(fields) > 6 else ""
        pid_match = re.search(r"pid=(\d+)", process_text)
        name_match = re.search(r'users:\(\("([^\"]+)', process_text)
        sockets.append(
            {
                "protocol": protocol,
                "bind_address": address,
                "port": int(port) if port.isdigit() else port,
                "pid": int(pid_match.group(1)) if pid_match else None,
                "process": name_match.group(1) if name_match else None,
            }
        )
    return sockets


def _split_address_port(value: str) -> tuple[str, str]:
    if value.startswith("[") and "]:" in value:
        address, port = value.rsplit(":", maxsplit=1)
        return address.strip("[]"), port
    if ":" in value:
        return tuple(value.rsplit(":", maxsplit=1))  # type: ignore[return-value]
    return value, ""
