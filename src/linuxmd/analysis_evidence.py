"""Deterministic evidence metadata and conservative fallback analysis."""

import re
from copy import deepcopy
from typing import Any

from linuxmd.analysis_schema import SUBSYSTEMS
from linuxmd.diagnostics.evidence import (
    deterministic_correlations,
    evidence_reference_catalog,
    performance_evidence_refs,
    stable_evidence_refs,
)


def derive_evidence_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    """Derive authoritative sampling and CPU facts from the compact report payload."""
    context = payload.get("assessment_context", {})
    sampling = context.get("sampling", {})
    performance = payload.get("performance", {})
    metrics = performance.get("normalized_metrics", {})
    duration = _number(sampling.get("duration_seconds"))
    interval = _number(sampling.get("interval_seconds"))
    count = _integer(sampling.get("sample_count"))
    available = sorted(key for key, value in metrics.items() if value not in ({}, [], None))
    expected = {"cpu", "memory", "disk", "network", "processes", "kernel"}
    missing = sorted(expected - set(available))
    finding_text = str(payload.get("deterministic_findings", {})).lower()
    cpu = metrics.get("cpu", {})
    correlations = deterministic_correlations(metrics)
    pressure = _cpu_pressure_observed(cpu, finding_text) or any(
        item["correlation_id"] == "cpu_contention_pattern" for item in correlations
    )
    short_window = duration is None or duration <= 5
    utilization_available = cpu.get("idle_pct") is not None or bool(
        cpu.get("utilization_samples_pct")
    )
    processes = metrics.get("processes", {})
    runnable_available = bool(processes.get("runnable_samples"))
    psi_available = bool(metrics.get("scheduler_pressure"))
    cpu_missing = []
    if not utilization_available:
        cpu_missing.append("CPU utilization and idle telemetry")
    if not runnable_available:
        cpu_missing.append("runnable task or run-queue telemetry")
    if not psi_available:
        cpu_missing.append("CPU PSI telemetry")
    cpu_coverage = (
        "sufficient"
        if utilization_available and (runnable_available or psi_available)
        else "partial"
    )
    supports_trends = bool(count and count >= 30 and duration and duration >= 30)
    supports_persistence = bool(count and count >= 60 and duration and duration >= 60)
    temporal_confidence = "low" if short_window else "medium" if supports_trends else "low"
    overall_confidence = "medium" if supports_trends and cpu_coverage == "sufficient" else "low"
    storage_coverage = _storage_coverage(metrics)
    network_coverage = _network_coverage(metrics)
    kernel_coverage = _kernel_coverage(payload)
    security_coverage = _security_coverage(payload)
    environment_summary = _environment_summary(payload.get("system", {}))
    environment_scope = _environment_scope(payload.get("system", {}))
    ref_catalog = evidence_reference_catalog(payload)
    allowed_refs = sorted(
        {
            ref
            for resource in ("cpu", "disk", "network", "memory", "hardware")
            for ref in performance_evidence_refs(resource, metrics)
        }
        | {signal for correlation in correlations for signal in correlation["signals"]}
        | {ref for refs in ref_catalog.values() for ref in refs}
    )
    return {
        "measurement_window_seconds": duration,
        "sample_interval_seconds": interval,
        "sample_count": count,
        "measurement_kind": "bounded_sample" if duration is not None else "inventory_snapshot",
        "supports_trend_analysis": supports_trends,
        "supports_persistence_claims": supports_persistence,
        "temporal_confidence": temporal_confidence,
        "overall_assessment_confidence": overall_confidence,
        "deterministic_environment_summary": environment_summary,
        "deterministic_environment_scope": environment_scope,
        "available_metric_families": available,
        "missing_metric_families": missing,
        "observed_pressure_flags": {"cpu": pressure},
        "evidence_coverage": {
            "cpu": {
                "coverage": cpu_coverage,
                "missing_metrics": cpu_missing,
                "pressure_observed": pressure,
                "status": "attention"
                if pressure
                else "healthy"
                if cpu_coverage == "sufficient"
                else "unknown",
            },
            "storage": storage_coverage,
            "network": network_coverage,
            "kernel": kernel_coverage,
            "security": security_coverage,
        },
        "allowed_evidence_refs": allowed_refs,
        "evidence_reference_catalog": ref_catalog,
        "correlations": correlations,
    }


def overlay_authoritative_fields(
    response: dict[str, Any], evidence: dict[str, Any]
) -> dict[str, Any]:
    """Overlay fields controlled by deterministic evidence without changing prose or evidence."""
    result = deepcopy(response)
    cpu = result.get("subsystem_health", {}).get("cpu")
    authority = evidence["evidence_coverage"]["cpu"]
    if isinstance(cpu, dict):
        for field in ("coverage", "missing_metrics", "status"):
            cpu[field] = deepcopy(authority[field])
    for name in ("storage", "network", "kernel", "security"):
        subsystem = result.get("subsystem_health", {}).get(name)
        local = evidence["evidence_coverage"][name]
        if isinstance(subsystem, dict):
            for field in ("coverage", "missing_metrics", "status"):
                subsystem[field] = deepcopy(local[field])
            if local.get("summary"):
                subsystem["summary"] = local["summary"]
            subsystem["limitations"] = deepcopy(local.get("limitations", []))
            subsystem["not_applicable"] = deepcopy(local.get("not_applicable", []))
            subsystem["coverage_limitations"] = deepcopy(local.get("coverage_limitations", []))
    result["confidence"] = evidence["overall_assessment_confidence"]
    scope = result.get("assessment_scope")
    local_environment = evidence.get("deterministic_environment_scope")
    if isinstance(scope, dict) and local_environment:
        scope["environment"] = local_environment
    result["evidence_qualification"] = {
        "temporal_confidence": evidence["temporal_confidence"],
        "overall_assessment_confidence": evidence["overall_assessment_confidence"],
    }
    allowed = evidence.get("allowed_evidence_refs", [])
    for group_name in ("active_concerns", "observations"):
        for item in result.get(group_name, []):
            if not isinstance(item, dict):
                continue
            local_refs = _authoritative_finding_refs(item, evidence)
            item["evidence_refs"] = stable_evidence_refs(local_refs, allowed)
            item["temporal_scope"] = _authoritative_temporal_scope(item, evidence)
    security_authority = evidence["evidence_coverage"].get("security", {})
    if security_authority.get("status") == "attention" and not _has_security_finding(
        result.get("observations", [])
    ):
        result.setdefault("observations", []).append(_security_observation(evidence))
    result["correlations"] = deepcopy(evidence.get("correlations", []))
    return result


def conservative_fallback(
    evidence: dict[str, Any], *, provider: str, reason: str
) -> dict[str, Any]:
    """Build a schema-valid report whose claims do not exceed deterministic evidence."""
    duration = evidence.get("measurement_window_seconds")
    window = f"{duration:g} seconds" if duration is not None else "Not established"
    cpu_authority = evidence["evidence_coverage"]["cpu"]
    subsystems = {
        name: {
            "status": "unknown",
            "summary": f"{name.title()} health was not established by the available evidence.",
            "coverage": "insufficient",
            "missing_metrics": [f"sufficient {name} telemetry"],
        }
        for name in SUBSYSTEMS
    }
    subsystems["cpu"] = {
        "status": cpu_authority["status"],
        "summary": (
            "CPU pressure was observed during the sampled interval."
            if cpu_authority["pressure_observed"]
            else "No CPU pressure was observed during the sampled interval."
        ),
        "coverage": cpu_authority["coverage"],
        "missing_metrics": deepcopy(cpu_authority["missing_metrics"]),
    }
    kernel_authority = evidence["evidence_coverage"].get("kernel")
    if kernel_authority:
        subsystems["kernel"] = {
            "status": kernel_authority["status"],
            "summary": kernel_authority.get(
                "summary", "No current kernel issue was observed in the available evidence."
            ),
            "coverage": kernel_authority["coverage"],
            "missing_metrics": deepcopy(kernel_authority["missing_metrics"]),
            "limitations": [],
            "not_applicable": [],
            "coverage_limitations": deepcopy(kernel_authority.get("coverage_limitations", [])),
        }
    subsystems["security"]["summary"] = (
        "No evidence of active compromise was found in the collected diagnostics; LinuxMD does "
        "not perform malware scanning or forensic analysis."
    )
    security_authority = evidence["evidence_coverage"].get("security", {})
    subsystems["security"].update(
        {
            "coverage": security_authority.get("coverage", "insufficient"),
            "status": security_authority.get("status", "unknown"),
            "summary": security_authority.get("summary", subsystems["security"]["summary"]),
            "missing_metrics": deepcopy(security_authority.get("missing_metrics", [])),
            "limitations": deepcopy(security_authority.get("limitations", [])),
            "not_applicable": deepcopy(security_authority.get("not_applicable", [])),
            "coverage_limitations": deepcopy(security_authority.get("coverage_limitations", [])),
        }
    )
    pressure = cpu_authority["pressure_observed"]
    concerns = (
        [
            {
                "title": "CPU pressure during sampled interval",
                "category": "performance",
                "severity": "medium",
                "assessment": "indication",
                "description": "Deterministic metrics indicated CPU pressure in the sample.",
                "evidence": ["deterministic evidence flag observed_pressure_flags.cpu=true"],
                "evidence_refs": stable_evidence_refs(
                    performance_evidence_refs(
                        "cpu", _metrics_from_allowed_refs(evidence.get("allowed_evidence_refs", []))
                    ),
                    evidence.get("allowed_evidence_refs", []),
                ),
                "temporal_scope": "sampled_interval",
            }
        ]
        if pressure
        else []
    )
    return {
        "overall_health": "attention_recommended" if pressure else "unknown",
        "assessment_summary": "A conservative deterministic assessment was produced.",
        "assessment_scope": {
            "environment": evidence.get("deterministic_environment_scope")
            or "Collected Linux environment",
            "measurement_window": window,
            "workload_state": "unknown",
            "baseline": "none",
        },
        "subsystem_health": subsystems,
        "performance_assessment": (
            "The evidence describes only the sampled interval and cannot establish long-term "
            "health."
        ),
        "active_concerns": concerns,
        "observations": (
            [_security_observation(evidence)]
            if security_authority.get("status") == "attention"
            else []
        ),
        "recommended_actions": [],
        "confidence": "low",
        "evidence_qualification": {
            "temporal_confidence": evidence["temporal_confidence"],
            "overall_assessment_confidence": evidence["overall_assessment_confidence"],
        },
        "correlations": deepcopy(evidence.get("correlations", [])),
        "generation": {
            "mode": "deterministic_fallback",
            "provider_attempted": provider,
            "provider_output_accepted": False,
            "fallback_reason": reason,
        },
    }


def _finding_resource(item: dict[str, Any]) -> str:
    text = f"{item.get('title', '')} {item.get('description', '')}".lower()
    for resource, terms in {
        "cpu": ("cpu", "scheduler"),
        "disk": ("disk", "storage", "i/o"),
        "network": ("network", "tcp", "packet"),
        "memory": ("memory", "swap", "reclaim"),
        "hardware": ("hardware", "kernel"),
    }.items():
        if any(term in text for term in terms):
            return resource
    return "unknown"


def _authoritative_finding_refs(item: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    """Select only locally controlled references relevant to this finding's meaning."""
    text = f"{item.get('title', '')} {item.get('description', '')}".lower()
    catalog = evidence.get("evidence_reference_catalog", {})
    for marker, key in (
        ("apparmor", "apparmor"),
        ("dmesg_restrict", "dmesg_restrict"),
        ("secure boot", "secure_boot"),
    ):
        if marker in text:
            return catalog.get(key, [])
    if any(term in text for term in ("missing storage", "storage telemetry", "storage coverage")):
        return catalog.get("storage_coverage", [])
    if any(term in text for term in ("missing network", "network telemetry", "network coverage")):
        return catalog.get("network_coverage", [])
    if any(
        term in text
        for term in ("optional diagnostic tool", "mpstat", "pidstat", "iostat", "sar unavailable")
    ):
        return sorted(
            {
                *catalog.get("storage_coverage", []),
                *catalog.get("network_coverage", []),
            }
        )
    resource = _finding_resource(item)
    return performance_evidence_refs(
        resource, _metrics_from_allowed_refs(evidence.get("allowed_evidence_refs", []))
    )


def _metrics_from_allowed_refs(allowed: list[str]) -> dict[str, Any]:
    """Create presence markers so the shared ref constructor remains authoritative."""
    metrics: dict[str, Any] = {}
    for ref in allowed:
        if ".cpu." in ref:
            metrics.setdefault("cpu", {})[ref.rsplit(".", 1)[-1]] = 1
        if ".processes.runnable_samples" in ref:
            metrics.setdefault("processes", {})["runnable_samples"] = [1]
        if ".processes.blocked_samples" in ref:
            metrics.setdefault("processes", {})["blocked_samples"] = [1]
        if ".scheduler_pressure." in ref:
            metrics["scheduler_pressure"] = {"some": {"avg10": 1}}
        if ref.endswith(".disks"):
            metrics["disks"] = [{}]
        if ".tcp." in ref:
            metrics["tcp"] = {"retransmissions_per_second": 1}
        if ".kernel." in ref:
            metrics["kernel"] = {"recent_warnings_errors": [{}]}
    return metrics


def _authoritative_temporal_scope(item: dict[str, Any], evidence: dict[str, Any]) -> str:
    text = f"{item.get('title', '')} {item.get('description', '')}".lower()
    if any(term in text for term in ("apparmor", "dmesg_restrict", "sysctl")):
        return "configuration_state"
    if any(term in text for term in ("historical", "prior", "kernel log", "dmesg", "crash")):
        return "historical_event"
    if any(
        term in text
        for term in ("optional diagnostic tool", "iostat", "sar installed", "mpstat", "pidstat")
    ):
        return "configuration_state"
    if "secure boot" in text and any(
        term in text for term in ("wsl", "guest", "unavailable", "not observable")
    ):
        return "environment_state"
    if any(term in text for term in ("wsl", "virtualization limitation", "guest visibility")):
        return "environment_state"
    if any(term in text for term in ("configuration", "configured", "hardening")):
        return "configuration_state"
    if evidence.get("supports_trend_analysis") and any(
        term in text for term in ("trend", "direction", "increasing", "decreasing")
    ):
        return "multi_sample_trend"
    if evidence.get("measurement_window_seconds") is not None:
        return "sampled_interval"
    return "unknown"


def _kernel_coverage(payload: dict[str, Any]) -> dict[str, Any]:
    system = payload.get("system", {})
    virtualization = payload.get("system", {}).get("virtualization", {})
    environment = str(virtualization.get("environment") or "").lower()
    restricted_guest = environment in {"wsl", "virtual_machine", "container"} or bool(
        virtualization.get("wsl")
    )
    guest_evidence = bool(system.get("operating_system", {}).get("kernel_release")) or bool(
        payload.get("performance", {}).get("normalized_metrics", {}).get("kernel")
    )
    if restricted_guest:
        return {
            "coverage": "partial",
            "missing_metrics": [],
            "coverage_limitations": [
                {
                    "type": "not_observable_in_environment",
                    "item": "host firmware, host kernel, physical hardware, and platform events",
                }
            ],
            "status": "healthy" if guest_evidence else "unknown",
            "summary": (
                "No current guest-visible kernel issue was observed."
                if guest_evidence
                else "Guest-kernel health was not established by the available evidence."
            ),
        }
    if guest_evidence:
        return {"coverage": "sufficient", "missing_metrics": [], "status": "healthy"}
    return {
        "coverage": "insufficient",
        "missing_metrics": ["kernel inventory or guest-visible kernel events"],
        "status": "unknown",
    }


def _security_coverage(payload: dict[str, Any]) -> dict[str, Any]:
    security = payload.get("security", {})
    virtualization = payload.get("system", {}).get("virtualization", {})
    environment = str(virtualization.get("environment") or "").lower()
    is_wsl = environment == "wsl" or bool(virtualization.get("wsl"))
    not_applicable = ["TDX host MSR verification (WSL2 guest)"] if is_wsl else []
    limitations: list[str] = []
    coverage_limitations: list[dict[str, str]] = []

    def collect(value: Any, path: str = "security") -> None:
        if isinstance(value, dict):
            status = value.get("status")
            check_path = str(value.get("check") or path)
            if status == "permission_denied":
                item = _display_check_path(check_path)
                limitations.append(f"{item} (permission denied)")
                coverage_limitations.append({"type": "permission_denied", "item": item})
            elif status == "missing_tool" and not (is_wsl and "tdx" in path.lower()):
                item = _display_check_path(check_path)
                limitations.append(f"{item} (missing tool)")
                coverage_limitations.append({"type": "missing_tool", "item": item})
            for key, item in value.items():
                collect(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                collect(item, f"{path}[{index}]")

    collect(security)
    secure_boot = security.get("platform_security", {}).get("secure_boot", {})
    if is_wsl and secure_boot and secure_boot.get("state") in {"unavailable", None}:
        coverage_limitations.append(
            {
                "type": "not_observable_in_environment",
                "item": "Secure Boot state",
            }
        )
    limitations = sorted(set(limitations))
    coverage_limitations = sorted(
        {tuple(item.items()) for item in coverage_limitations}, key=lambda item: str(item)
    )
    coverage_limitations = [dict(item) for item in coverage_limitations]
    finding_labels = _authoritative_security_findings(payload)
    if not security:
        return {
            "coverage": "insufficient",
            "missing_metrics": ["security collector evidence"],
            "status": "unknown",
            "limitations": [],
            "not_applicable": not_applicable,
            "coverage_limitations": [],
        }
    partial = bool(coverage_limitations)
    status = "attention" if finding_labels else "unknown" if partial else "healthy"
    summary = _security_summary(finding_labels, partial)
    return {
        "coverage": "partial" if partial else "sufficient",
        "missing_metrics": [],
        "status": status,
        "summary": summary,
        "limitations": limitations,
        "not_applicable": not_applicable,
        "coverage_limitations": coverage_limitations,
        "findings": finding_labels,
    }


def _authoritative_security_findings(payload: dict[str, Any]) -> list[str]:
    """Return concise labels for deterministic security findings requiring review."""
    security = payload.get("security", {})
    hardening = security.get("kernel_hardening", {})
    findings = []
    apparmor = hardening.get("apparmor", {})
    if apparmor.get("supported") is True and apparmor.get("enabled") is False:
        findings.append("AppArmor is supported but not enabled")
    if str(hardening.get("sysctls", {}).get("dmesg_restrict")) == "0":
        findings.append("dmesg_restrict=0")
    deterministic = payload.get("deterministic_findings", {}).get("security_analysis", {})
    warning_count = sum(
        len(deterministic.get(key, []))
        for key in ("critical_findings", "high_findings", "medium_findings")
        if isinstance(deterministic.get(key, []), list)
    )
    if warning_count and not findings:
        findings.append("Deterministic security findings require review")
    return findings


def _security_summary(findings: list[str], partial: bool) -> str:
    if findings:
        posture = " and ".join(findings) + "."
    else:
        posture = "No security finding requiring attention was identified in observable evidence."
    if partial:
        posture += " Some host-level and privileged checks are not observable in this environment."
    return posture + " No evidence of active compromise was found in the collected diagnostics."


def _has_security_finding(observations: list[Any]) -> bool:
    return any(
        isinstance(item, dict)
        and any(
            marker in f"{item.get('title', '')} {item.get('description', '')}".lower()
            for marker in ("apparmor", "dmesg_restrict", "security hardening")
        )
        for item in observations
    )


def _security_observation(evidence: dict[str, Any]) -> dict[str, Any]:
    authority = evidence["evidence_coverage"]["security"]
    findings = authority.get("findings", ["Deterministic security findings require review"])
    catalog = evidence.get("evidence_reference_catalog", {})
    refs = []
    if any("AppArmor" in finding for finding in findings):
        refs.extend(catalog.get("apparmor", []))
    if any("dmesg_restrict" in finding for finding in findings):
        refs.extend(catalog.get("dmesg_restrict", []))
    return {
        "title": "Deterministic security hardening findings",
        "description": " and ".join(findings) + ".",
        "evidence": findings,
        "evidence_refs": sorted(set(refs)),
        "temporal_scope": "configuration_state",
    }


def _display_check_path(path: str) -> str:
    leaf = path.rsplit(".", 1)[-1].replace("_", " ")
    return leaf if leaf != "status" else path.rsplit(".", 2)[-2].replace("_", " ")


def _cpu_pressure_observed(cpu: Any, finding_text: str) -> bool:
    if any(term in finding_text for term in ("cpu pressure", "cpu saturation", "run_queue_ratio")):
        return "no cpu pressure" not in finding_text
    if isinstance(cpu, dict):
        ratio = _number(cpu.get("run_queue_ratio"))
        return bool(ratio is not None and ratio > 1)
    return False


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _integer(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None else None


def _storage_coverage(metrics: dict[str, Any]) -> dict[str, Any]:
    disks = metrics.get("disks", [])
    latency_available = bool(disks) and any(
        disk.get("await_ms") is not None or disk.get("queue_depth") is not None for disk in disks
    )
    return {
        "coverage": "sufficient" if latency_available else "insufficient",
        "missing_metrics": []
        if latency_available
        else ["storage latency or queue-depth telemetry"],
        "status": "unknown",
    }


def _network_coverage(metrics: dict[str, Any]) -> dict[str, Any]:
    sufficient = bool(metrics.get("network_interfaces")) and bool(metrics.get("tcp"))
    return {
        "coverage": "sufficient" if sufficient else "insufficient",
        "missing_metrics": [] if sufficient else ["network interface and TCP error telemetry"],
        "status": "unknown",
    }


def _environment_summary(system: Any) -> str:
    """Build a bounded environment sentence from normalized inventory fields."""
    if not isinstance(system, dict):
        return "The collected Linux environment was assessed."
    operating = system.get("operating_system", {})
    distribution = operating.get("distribution", {})
    virtualization = system.get("virtualization", {})
    environment = str(virtualization.get("environment") or "").lower()
    platform = str(virtualization.get("platform") or "").lower()
    if environment == "wsl" or virtualization.get("wsl"):
        subject = "The system is a WSL2 guest"
    elif environment == "virtual_machine":
        subject = (
            f"The system is a {platform.title()} virtual machine"
            if platform
            else "The system is a virtual machine"
        )
    elif environment == "container":
        subject = "The system is a Linux container"
    else:
        subject = "The system is a Linux environment"
    name = distribution.get("name") or distribution.get("id")
    version = distribution.get("version_id") or distribution.get("version")
    os_text = " ".join(str(item) for item in (name, version) if item)
    kernel = _normalized_version(operating.get("kernel_release"))
    details = []
    if os_text:
        details.append(f"running {os_text}")
    if kernel:
        details.append(f"on Linux kernel {kernel}")
    return subject + (" " + " ".join(details) if details else "") + "."


def _environment_scope(system: Any) -> str | None:
    """Build the compact authoritative platform description used by report scope."""
    if not isinstance(system, dict) or not system:
        return None
    operating = system.get("operating_system", {})
    distribution = operating.get("distribution", {})
    virtualization = system.get("virtualization", {})
    environment = str(virtualization.get("environment") or "").lower()
    platform = str(virtualization.get("platform") or "").lower()
    if environment == "wsl" or virtualization.get("wsl"):
        subject = "WSL2 guest"
    elif environment == "virtual_machine":
        subject = f"{platform.title()} virtual machine" if platform else "Virtual machine"
    elif environment == "container":
        subject = "Linux container"
    else:
        subject = "Linux environment"
    name = distribution.get("name") or distribution.get("id")
    version = distribution.get("version_id") or distribution.get("version")
    os_text = " ".join(str(item) for item in (name, version) if item)
    kernel = _normalized_version(operating.get("kernel_release"))
    if os_text:
        subject += f" on {os_text}"
    if kernel:
        subject += f", kernel {kernel}"
    return subject


def _normalized_version(value: Any) -> str | None:
    """Return an authoritative version with only dotted-number spacing repaired."""
    text = str(value or "").strip()
    if not text:
        return None
    return re.sub(r"(?<=\d)\.\s+(?=\d)", ".", text)
