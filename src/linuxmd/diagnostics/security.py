"""Deterministic, evidence-based interpretation of security collector facts."""

from typing import Any

from linuxmd.diagnostics.evidence import classify_bind_address


def analyze_security(security: dict[str, Any]) -> dict[str, Any]:
    """Analyze only collected security facts without inferring absent evidence."""
    critical: list[str] = []
    high: list[str] = []
    medium: list[str] = []
    low: list[str] = []
    evidence: list[str] = []
    actions: list[str] = []
    unknowns: list[str] = []
    applicability: list[dict[str, str]] = []

    if security.get("collector") != "security":
        unknowns.append("collector: expected security collector output was not identified.")

    for section_name in (
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
    ):
        section = security.get(section_name)
        if not isinstance(section, dict) or section.get("status") in {
            "unavailable",
            "unsupported",
            "permission_denied",
            "error",
        }:
            status = section.get("status", "missing") if isinstance(section, dict) else "missing"
            unknowns.append(f"{section_name}.status={status}: evidence is unavailable.")

    platform_security = security.get("platform_security", {})
    secure_boot = platform_security.get("secure_boot", {})
    secure_boot_state = secure_boot.get("state") if isinstance(secure_boot, dict) else None
    environment = security.get("virtualization_security", {}).get("environment")
    restricted_guest = str(environment or "").lower() in {"wsl", "wsl2"}
    if secure_boot_state == "disabled":
        target = medium if environment == "bare_metal" else low
        target.append(
            "Potentially risky configuration: "
            f"platform_security.secure_boot.state={secure_boot_state}."
        )
        evidence.append(f"platform_security.secure_boot.state={secure_boot_state}")
        actions.append("Review firmware Secure Boot policy and signed boot-chain requirements.")
    elif secure_boot_state in {"unavailable", None} and restricted_guest:
        applicability.append(
            {
                "check": "platform_security.secure_boot",
                "status": "not_observable_in_environment",
            }
        )
    elif secure_boot_state == "permission_denied":
        applicability.append(
            {
                "check": "platform_security.secure_boot",
                "status": "not_observable_with_current_privilege",
            }
        )
        unknowns.append(
            "platform_security.secure_boot.state=permission_denied: this specific check is not "
            "observable with current privilege."
        )
    elif secure_boot_state in {"unavailable", None}:
        unknowns.append(
            "platform_security.secure_boot.state="
            f"{secure_boot_state or 'missing'}: state is unknown."
        )

    vulnerabilities = security.get("cpu_security", {}).get("vulnerabilities", {})
    if isinstance(vulnerabilities, dict):
        for name, value in vulnerabilities.items():
            normalized = str(value).lower()
            if "vulnerable" in normalized and "not affected" not in normalized:
                high.append(
                    "Confirmed kernel-reported weakness: "
                    f"cpu_security.vulnerabilities.{name}={value}."
                )
                evidence.append(f"cpu_security.vulnerabilities.{name}={value}")
                actions.append(
                    f"Review kernel and CPU microcode mitigation guidance for {name}; "
                    "verify after reboot."
                )

    tdx = (
        security.get("cpu_security", {}).get("vendor_security", {}).get("intel", {}).get("tdx", {})
    )
    if restricted_guest:
        applicability.append(
            {
                "check": "cpu_security.vendor_security.intel.tdx.host_msr_verification",
                "status": "not_applicable",
            }
        )
    elif tdx.get("status") != "unsupported":
        register_verification = tdx.get("privileged_register_verification", {})
        observations = register_verification.get("observations", {})
        tme = observations.get("tme_enabled", {})
        tdx_enabled = observations.get("tdx_enabled", {})
        initialization = tdx.get("kernel_initialization", {})
        if tme.get("status") == "available" and tme.get("value") is False:
            high.append(
                "Confirmed Intel TDX prerequisite failure: cpu_security.vendor_security.intel."
                "tdx.privileged_register_verification.observations.tme_enabled.value=False "
                "(MSR 0x982 bits 1:1, CPU 0)."
            )
            evidence.append(
                "cpu_security.vendor_security.intel.tdx.privileged_register_verification."
                "observations.tme_enabled: register=0x982 bits=1:1 cpu=0 value=False"
            )
            actions.append("Review Intel TME firmware configuration before relying on TDX.")
        elif tme.get("status") == "available" and tme.get("value") is True:
            evidence.append(
                "cpu_security.vendor_security.intel.tdx.privileged_register_verification."
                "observations.tme_enabled: register=0x982 bits=1:1 cpu=0 value=True"
            )
        if tdx_enabled.get("status") == "available" and tdx_enabled.get("value") is False:
            high.append(
                "Confirmed Intel TDX configuration finding: cpu_security.vendor_security.intel."
                "tdx.privileged_register_verification.observations.tdx_enabled.value=False "
                "(MSR 0x1401 bits 11:11, CPU 0)."
            )
            evidence.append(
                "cpu_security.vendor_security.intel.tdx.privileged_register_verification."
                "observations.tdx_enabled: register=0x1401 bits=11:11 cpu=0 value=False"
            )
            actions.append("Review Intel TDX firmware and host-kernel enablement configuration.")
        elif tdx_enabled.get("status") == "available" and tdx_enabled.get("value") is True:
            evidence.append(
                "cpu_security.vendor_security.intel.tdx.privileged_register_verification."
                "observations.tdx_enabled: register=0x1401 bits=11:11 cpu=0 value=True"
            )
        for name, observation in observations.items():
            if observation.get("status") in {
                "permission_denied",
                "module_not_loaded",
                "missing_tool",
            }:
                unknowns.append(
                    "cpu_security.vendor_security.intel.tdx.privileged_register_verification."
                    f"observations.{name}.status={observation.get('status')}: privileged MSR "
                    "evidence is unavailable and does not indicate a disabled feature."
                )
        initialized = initialization.get("initialized")
        enabled = tdx_enabled.get("value") if tdx_enabled.get("status") == "available" else None
        if initialized is True:
            evidence.append(
                "cpu_security.vendor_security.intel.tdx.kernel_initialization.initialized=True "
                "evidence_source=dmesg"
            )
        if initialized is True and enabled is True:
            evidence.append(
                "Intel TDX kernel initialization and MSR 0x1401 bits 11:11 agree; this supports "
                "host enablement but does not establish attestation readiness."
            )
        if initialized is True and enabled is False:
            high.append(
                "Contradictory Intel TDX evidence: dmesg reports module initialization, while "
                "MSR 0x1401 bits 11:11 reports tdx_enabled=False."
            )
            actions.append(
                "Recheck TDX state after reboot and compare kernel, firmware, and MSR evidence."
            )
        qcnl = tdx.get("attestation_readiness", {}).get("qcnl_config", {})
        if qcnl.get("status") == "available" and qcnl.get("use_secure_cert") is False:
            medium.append(
                "Potentially risky Intel QGS configuration: cpu_security.vendor_security.intel."
                "tdx.attestation_readiness.qcnl_config.use_secure_cert=False."
            )
            evidence.append(
                "cpu_security.vendor_security.intel.tdx.attestation_readiness.qcnl_config."
                "use_secure_cert=False"
            )
            actions.append("Configure QCNL to validate PCCS TLS certificates where appropriate.")

    iommu = security.get("iommu_pcie_security", {})
    iommu_assessable = (
        iommu.get("applicable") is True
        and iommu.get("observable") is True
        and iommu.get("status") == "available"
    )
    if iommu_assessable and iommu.get("enabled") is False:
        medium.append(
            "Contextual isolation risk: iommu_pcie_security.enabled=False with applicable=True, "
            "observable=True, and status=available; relevance depends on deployment role and "
            "threat model."
        )
        evidence.append(
            "iommu_pcie_security.enabled=False applicable=True observable=True status=available"
        )
        actions.append(
            "Review whether IOMMU isolation is required for this deployment role and threat model."
        )
    elif iommu.get("enabled") is False and not iommu_assessable:
        unknowns.append(
            "IOMMU state is not assessable because applicability or observability is not "
            "established."
        )

    hardening = security.get("kernel_hardening", {})
    selinux = hardening.get("selinux", {})
    if selinux.get("supported") and selinux.get("state") == "permissive":
        medium.append("Potentially risky configuration: kernel_hardening.selinux.state=permissive.")
        evidence.append("kernel_hardening.selinux.state=permissive")
        actions.append(
            "Review SELinux denials, policy readiness, and whether enforcing mode is appropriate."
        )
    apparmor = hardening.get("apparmor", {})
    if apparmor.get("supported") and apparmor.get("enabled") is False:
        medium.append("Potentially risky configuration: kernel_hardening.apparmor.enabled=False.")
        evidence.append("kernel_hardening.apparmor.enabled=False")
        actions.append(
            "Review AppArmor service, profiles, and intended mandatory access-control policy."
        )

    sysctls = hardening.get("sysctls", {})
    risky_sysctls = {
        "kptr_restrict": {"0"},
        "dmesg_restrict": {"0"},
        "unprivileged_bpf_disabled": {"0"},
        "randomize_va_space": {"0"},
    }
    for name, risky_values in risky_sysctls.items():
        value = sysctls.get(name)
        if value in risky_values:
            medium.append(
                f"Potentially risky configuration: kernel_hardening.sysctls.{name}={value}."
            )
            evidence.append(f"kernel_hardening.sysctls.{name}={value}")
            actions.append(f"Validate the workload need and hardening policy for sysctl {name}.")
    perf = sysctls.get("perf_event_paranoid")
    if _integer(perf) is not None and _integer(perf) < 2:
        low.append(
            "Potentially broad performance-counter access: "
            f"kernel_hardening.sysctls.perf_event_paranoid={perf}."
        )
        evidence.append(f"kernel_hardening.sysctls.perf_event_paranoid={perf}")

    identity = security.get("identity_access", {}).get("ssh_server", {})
    settings = identity.get("settings", {})
    root_login = str(settings.get("permitrootlogin", "")).lower()
    password_auth = str(settings.get("passwordauthentication", "")).lower()
    if root_login == "yes":
        high.append(
            "Confirmed risky SSH configuration: identity_access.ssh_server.settings."
            "permitrootlogin=yes."
        )
        evidence.append("identity_access.ssh_server.settings.permitrootlogin=yes")
        actions.append(
            "Set PermitRootLogin to prohibit-password or no after validating access paths."
        )
    if password_auth == "yes":
        target = high if _has_wildcard_ssh(security) else medium
        target.append(
            "Potentially risky SSH configuration: identity_access.ssh_server.settings."
            "passwordauthentication=yes."
        )
        evidence.append("identity_access.ssh_server.settings.passwordauthentication=yes")
        actions.append("Prefer key-based SSH authentication and review brute-force protections.")

    network = security.get("firewall_network_exposure", {})
    sockets = network.get("listening_sockets", [])
    wildcard_sockets = [item for item in sockets if _is_wildcard(item.get("bind_address"))]
    socket_classes = [classify_bind_address(item.get("bind_address")) for item in sockets]
    loopback_sockets = [
        item for item in sockets if classify_bind_address(item.get("bind_address")) == "loopback"
    ]
    for item in wildcard_sockets:
        low.append(
            "Informational network exposure: firewall_network_exposure.listening_sockets has "
            f"{item.get('protocol')} {item.get('bind_address')}:{item.get('port')} "
            f"process={item.get('process')} pid={item.get('pid')}."
        )
        evidence.append(
            "firewall_network_exposure.listening_sockets="
            f"{item.get('bind_address')}:{item.get('port')}/{item.get('protocol')}"
        )
    if loopback_sockets:
        evidence.append(
            "firewall_network_exposure.listening_sockets includes loopback-bound services; bind "
            "addresses alone do not establish reachability."
        )
    if sockets and all(
        kind in {"loopback", "private/internal", "link-local"} for kind in socket_classes
    ):
        evidence.append(
            "No clearly world-facing listening sockets were identified. Observed listeners were "
            "bound to loopback or internal addresses; reachability was not tested."
        )
    firewall_active = any(
        network.get(name, {}).get("active") or network.get(name, {}).get("active_ruleset")
        for name in ("nftables", "firewalld", "ufw")
    )
    firewall_available = any(
        network.get(name, {}).get("status") == "available"
        for name in ("nftables", "iptables", "firewalld", "ufw")
    )
    if wildcard_sockets and not firewall_active:
        medium.append(
            "Contextual exposure risk: wildcard-bound services were observed while no active "
            f"firewall was detected (firewall_available={firewall_available})."
        )
        evidence.append(f"firewall_network_exposure.firewall_active={firewall_active}")
        actions.append("Verify host and upstream firewall policy for each wildcard-bound service.")

    storage = security.get("storage_filesystem_security", {})
    if storage.get("root_encrypted") is True:
        low.append("Informational observation: storage_filesystem_security.root_encrypted=True.")
        evidence.append("storage_filesystem_security.root_encrypted=True")
    elif storage.get("encryption_detection_status") in {"permission_denied", "unavailable"}:
        unknowns.append(
            "storage_filesystem_security.root_encrypted: encryption state could not be determined."
        )

    for error in security.get("errors", []):
        if isinstance(error, dict):
            unknowns.append(
                f"{error.get('check', 'unknown')} ({error.get('status', 'error')}): "
                f"{error.get('message', 'collection failed')}"
            )

    observed = len(evidence)
    confidence = "high" if observed >= 8 and not unknowns else "medium" if observed >= 3 else "low"
    summary = (
        f"Deterministic security review found {len(critical)} critical, {len(high)} high, "
        f"{len(medium)} medium, and {len(low)} low/informational findings. "
        "No evidence of active compromise was found in the collected diagnostics. This is "
        "diagnostic guidance, not malware scanning, forensic analysis, or a compliance "
        "determination."
    )
    return {
        "security_summary": summary,
        "critical_findings": critical,
        "high_findings": high,
        "medium_findings": medium,
        "low_findings": low,
        "supporting_evidence": list(dict.fromkeys(evidence)),
        "recommended_next_actions": list(dict.fromkeys(actions)),
        "unknowns_and_gaps": list(dict.fromkeys(unknowns)),
        "confidence": confidence,
        "applicability": applicability,
    }


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_wildcard(address: Any) -> bool:
    return address in {"0.0.0.0", "::", "*"}


def _is_localhost(address: Any) -> bool:
    return classify_bind_address(address) == "loopback"


def _has_wildcard_ssh(security: dict[str, Any]) -> bool:
    sockets = security.get("firewall_network_exposure", {}).get("listening_sockets", [])
    return any(
        _is_wildcard(item.get("bind_address")) and item.get("port") == 22 for item in sockets
    )
