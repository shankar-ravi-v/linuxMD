"""Build a compact, provider-independent diagnostic analysis payload."""

import json
import os
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from linuxmd.analysis import AnalysisError


class PayloadConfigError(AnalysisError):
    """A payload compaction limit is invalid."""


class PayloadTooLargeError(AnalysisError):
    """Safe compaction could not satisfy the configured payload limit."""

    def __init__(self, size_kib: float, limit_kib: int, sections: list[tuple[str, float]]) -> None:
        self.size_kib = size_kib
        self.limit_kib = limit_kib
        self.sections = sections
        details = "\n".join(f"  {name}: {size:.1f} KiB" for name, size in sections[:5])
        super().__init__(
            f"Analysis payload remains {size_kib:.1f} KiB after safe compaction "
            f"(limit: {limit_kib} KiB).\nLargest sections:\n{details}\n"
            "Increase LINUXMD_MAX_PAYLOAD_KIB or collect a shorter diagnostic sample."
        )


@dataclass(frozen=True, slots=True)
class PayloadLimits:
    """Bounds for low-priority payload entries."""

    max_payload_kib: int = 80
    max_log_events: int = 30
    max_processes: int = 10
    max_raw_samples: int = 20

    @classmethod
    def from_environment(cls) -> "PayloadLimits":
        return cls(
            max_payload_kib=_positive_env("LINUXMD_MAX_PAYLOAD_KIB", 80),
            max_log_events=_positive_env("LINUXMD_MAX_LOG_EVENTS", 30),
            max_processes=_positive_env("LINUXMD_MAX_PROCESSES", 10),
            max_raw_samples=_positive_env("LINUXMD_MAX_RAW_SAMPLES", 20),
        )


@dataclass(frozen=True, slots=True)
class PayloadStats:
    """Measured compaction statistics for terminal and debug output."""

    raw_bytes: int
    compacted_bytes: int
    section_bytes: dict[str, int]
    log_events_retained: int = 0
    log_events_removed: int = 0
    processes_retained: int = 0
    processes_removed: int = 0
    raw_samples_retained: int = 0
    raw_samples_summarized: int = 0

    @property
    def reduction_percent(self) -> float:
        if not self.raw_bytes:
            return 0.0
        return 100 * (1 - self.compacted_bytes / self.raw_bytes)


def json_size_bytes(value: Any) -> int:
    """Measure the UTF-8 size of the same stable JSON representation providers receive."""
    return len(json.dumps(value, sort_keys=True).encode("utf-8"))


def build_analysis_payload(
    reports: dict[str, Any], limits: PayloadLimits | None = None
) -> tuple[dict[str, Any], PayloadStats]:
    """Select diagnostic evidence without changing the complete local reports."""
    limits = limits or PayloadLimits.from_environment()
    raw_bytes = json_size_bytes({"reports": reports})
    diag = _report_body(reports.get("diag.json"), "system")
    performance = _report_body(reports.get("performance.json"), "performance")
    security = reports.get("security.json") or {}
    security_analysis = reports.get("security-analysis.json") or {}

    system = _system_context(diag)
    if isinstance(reports.get("diag.json"), dict):
        system["collection_timestamp"] = reports["diag.json"].get("generated_at")
    compact_performance, counts = _performance_context(performance, limits)
    compact_security = _security_context(security)
    deterministic = _drop_empty(
        {
            "performance_findings": deepcopy(performance.get("findings", [])),
            "performance_interpretation": deepcopy(performance.get("interpretation", {})),
            "security_analysis": deepcopy(security_analysis),
            "active_concerns": _find_named_values(reports, "active_concerns"),
        }
    )
    payload = _drop_empty(
        {
            "metadata": {
                "tool": "linuxMD",
                "analysis_type": "cross_report_health_assessment",
                "payload_version": 1,
                "source_reports": sorted(reports),
            },
            "assessment_context": {
                "environment": deepcopy(performance.get("environment", {})),
                "sampling": deepcopy(performance.get("sampling", {})),
                "workload": deepcopy(performance.get("workload", {})),
                "baseline": deepcopy(performance.get("baseline", {})),
            },
            "system": system,
            "performance": compact_performance,
            "security": compact_security,
            "deterministic_findings": deterministic,
        }
    )
    payload = _sanitize(payload)
    payload["evidence_index"] = _evidence_index(payload)
    compacted_bytes = json_size_bytes(payload)
    section_bytes = {key: json_size_bytes(value) for key, value in payload.items()}
    if compacted_bytes > limits.max_payload_kib * 1024:
        _additional_safe_reduction(payload)
        compacted_bytes = json_size_bytes(payload)
        section_bytes = {key: json_size_bytes(value) for key, value in payload.items()}
    stats = PayloadStats(raw_bytes, compacted_bytes, section_bytes, **counts)
    if compacted_bytes > limits.max_payload_kib * 1024:
        largest = sorted(
            ((name, size / 1024) for name, size in section_bytes.items()),
            key=lambda item: item[1],
            reverse=True,
        )
        raise PayloadTooLargeError(compacted_bytes / 1024, limits.max_payload_kib, largest)
    return payload, stats


def _additional_safe_reduction(payload: dict[str, Any]) -> None:
    """Reduce only low-priority bounded detail while retaining findings and their evidence."""
    performance = payload.get("performance", {})
    performance["kernel_events"] = performance.get("kernel_events", [])[:5]
    metrics = performance.get("normalized_metrics", {})
    metrics["busiest_processes"] = metrics.get("busiest_processes", [])[:3]
    _bound_representative_samples(metrics, 5)
    payload["evidence_index"] = payload.get("evidence_index", [])[:40]


def _bound_representative_samples(value: Any, limit: int) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "representative_samples" and isinstance(item, list):
                value[key] = item[:limit]
            else:
                _bound_representative_samples(item, limit)
    elif isinstance(value, list):
        for item in value:
            _bound_representative_samples(item, limit)


def _positive_env(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise PayloadConfigError(f"{name} must be a positive integer.") from exc
    if parsed <= 0:
        raise PayloadConfigError(f"{name} must be a positive integer.")
    return parsed


def _report_body(report: Any, name: str) -> dict[str, Any]:
    if not isinstance(report, dict):
        return {}
    diagnostics = report.get("diagnostics")
    if isinstance(diagnostics, dict) and isinstance(diagnostics.get(name), dict):
        return diagnostics[name]
    return report


def _system_context(system: dict[str, Any]) -> dict[str, Any]:
    operating = system.get("operating_system", {})
    cpu = system.get("cpu", {})
    memory = system.get("memory", {})
    filesystems = system.get("filesystems", {})
    virtualization = system.get("virtualization", {})
    kernel = system.get("kernel", {})
    distribution = operating.get("distribution", {})
    root_mount = next(
        (item for item in filesystems.get("mounts", []) if item.get("mount_point") == "/"), {}
    )
    return _drop_empty(
        {
            "collection_timestamp": system.get("generated_at"),
            "operating_system": {
                "hostname": operating.get("hostname"),
                "distribution": _select(
                    distribution, "pretty_name", "name", "id", "version", "version_id"
                ),
                "kernel_release": operating.get("kernel_version"),
                "kernel_build": operating.get("kernel_build"),
                "architecture": operating.get("architecture") or system.get("architecture"),
                "uptime_seconds": operating.get("uptime_seconds"),
                "timezone": operating.get("timezone"),
            },
            "cpu": {
                "vendor": cpu.get("vendor"),
                "model": cpu.get("model"),
                "online_logical_cpu_count": cpu.get("logical_processors"),
                "sockets": cpu.get("sockets"),
                "cores": cpu.get("cores"),
                "threads": cpu.get("threads"),
                "topology_scope": cpu.get("topology_scope"),
                "caches": deepcopy(cpu.get("caches", [])),
                "virtualization_flags": cpu.get("virtualization_flags"),
            },
            "gpus": deepcopy(system.get("gpus", [])),
            "memory": _select(
                memory, "total_kib", "available_kib", "swap_total_kib", "swap_free_kib"
            ),
            "root_filesystem": {
                "mount": root_mount,
                "statistics": filesystems.get("root_statistics"),
            },
            "virtualization": _select(
                virtualization,
                "environment",
                "platform",
                "hypervisor",
                "hypervisor_detected",
                "running_inside_container",
                "docker",
                "podman",
                "kubernetes",
                "wsl",
                "dmi_vendor",
                "dmi_product",
                "confidence",
            ),
            "kernel_configuration": _reduced_kernel_configuration(kernel.get("configuration")),
        }
    )


def _reduced_kernel_configuration(configuration: Any) -> dict[str, Any]:
    """Select analysis-relevant kernel settings while preserving the full raw report."""
    if not isinstance(configuration, dict):
        return {}
    prefixes = (
        "CONFIG_SECURITY",
        "CONFIG_HARDENED",
        "CONFIG_STACKPROTECTOR",
        "CONFIG_STRICT_",
        "CONFIG_RANDOMIZE",
        "CONFIG_KASLR",
        "CONFIG_SECCOMP",
        "CONFIG_LSM",
        "CONFIG_KVM",
        "CONFIG_VHOST",
        "CONFIG_VIRTIO",
        "CONFIG_HYPERV",
        "CONFIG_XEN",
        "CONFIG_IOMMU",
        "CONFIG_AMD_IOMMU",
        "CONFIG_INTEL_IOMMU",
        "CONFIG_SEV",
        "CONFIG_TDX",
        "CONFIG_BPF",
        "CONFIG_CGROUP",
        "CONFIG_NAMESPACES",
        "CONFIG_USER_NS",
        "CONFIG_NUMA",
        "CONFIG_HUGETLB",
        "CONFIG_TRANSPARENT_HUGEPAGE",
        "CONFIG_PCI",
        "CONFIG_VFIO",
        "CONFIG_DRM",
        "CONFIG_NOUVEAU",
        "CONFIG_NVIDIA",
    )
    selected = {
        key: configuration[key]
        for key in sorted(configuration)
        if any(key.startswith(prefix) for prefix in prefixes)
    }
    return {
        "selected": selected,
        "raw_entry_count": len(configuration),
        "selected_entry_count": len(selected),
        "full_configuration_available_in_raw_report": True,
    }


def _performance_context(
    performance: dict[str, Any], limits: PayloadLimits
) -> tuple[dict[str, Any], dict[str, int]]:
    metrics = deepcopy(performance.get("normalized_metrics", {}))
    processes = metrics.get("busiest_processes", [])
    retained_processes = processes[: limits.max_processes]
    metrics["busiest_processes"] = retained_processes
    cpu = metrics.get("cpu", {})
    process_metrics = metrics.get("processes", {})
    effective = (
        cpu.get("effective_cpu_capacity")
        or metrics.get("effective_cpu_capacity")
        or performance.get("cpu_capacity", {}).get("effective_cpu_capacity")
    )
    cpu_samples = deepcopy(cpu.get("utilization_samples_pct", []))
    run_samples = deepcopy(process_metrics.get("runnable_samples", []))
    sample_stats = {"retained": 0, "summarized": 0}
    _summarize_sample_lists(metrics, limits.max_raw_samples, sample_stats)
    events = metrics.get("kernel", {}).get("recent_warnings_errors", [])
    compact_events = _deduplicate_events(events, limits.max_log_events)
    if "kernel" in metrics:
        metrics["kernel"].pop("recent_warnings_errors", None)
    context = _drop_empty(
        {
            "collection_timestamp": performance.get("collection_start"),
            "sampling": deepcopy(performance.get("sampling", {})),
            "effective_cpu_capacity": effective,
            "cpu_summary": _numeric_summary(cpu_samples, near_zero_idle=True),
            "run_queue_summary": _run_queue_summary(run_samples, effective),
            "normalized_metrics": metrics,
            "correlations": deepcopy(performance.get("correlations", [])),
            "coverage_gaps": deepcopy(performance.get("warnings", [])),
            "kernel_events": compact_events,
        }
    )
    return context, {
        "log_events_retained": len(compact_events),
        "log_events_removed": max(0, len(events) - len(compact_events)),
        "processes_retained": len(retained_processes),
        "processes_removed": max(0, len(processes) - len(retained_processes)),
        "raw_samples_retained": sample_stats["retained"],
        "raw_samples_summarized": sample_stats["summarized"],
    }


def _security_context(security: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(security, dict):
        return {}
    return _drop_empty(
        {
            "collection_timestamp": security.get("generated_at"),
            "platform_security": deepcopy(security.get("platform_security", {})),
            "cpu_security": deepcopy(security.get("cpu_security", {})),
            "virtualization_security": deepcopy(security.get("virtualization_security", {})),
            "iommu_pcie_security": deepcopy(security.get("iommu_pcie_security", {})),
            "kernel_hardening": deepcopy(security.get("kernel_hardening", {})),
            "network_exposure": _select(
                security.get("firewall_network_exposure", {}),
                "status",
                "nftables",
                "iptables",
                "firewalld",
                "ufw",
                "listening_sockets",
            ),
            "storage_security": deepcopy(security.get("storage_filesystem_security", {})),
            "identity_access": deepcopy(security.get("identity_access", {})),
            "unknowns": deepcopy(security.get("errors", [])),
        }
    )


def _deduplicate_events(events: list[Any], limit: int) -> list[dict[str, Any]]:
    combined: dict[str, dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        message = " ".join(str(event.get("message", "")).split())[:500]
        if not message:
            continue
        key = message.lower()
        current = combined.get(key)
        count = int(event.get("count") or event.get("occurrence_count") or 1)
        if current:
            current["occurrence_count"] += count
            current["last_occurrence"] = event.get("last_timestamp") or event.get("timestamp")
            continue
        combined[key] = _drop_empty(
            {
                "source": event.get("source", "dmesg"),
                "timestamp": event.get("timestamp"),
                "severity": event.get("severity", "warning"),
                "subsystem": event.get("subsystem", "kernel"),
                "message": message,
                "occurrence_count": count,
                "first_occurrence": event.get("first_timestamp") or event.get("timestamp"),
                "last_occurrence": event.get("last_timestamp") or event.get("timestamp"),
                "state": event.get("state", "historical_observation"),
            }
        )
    return list(combined.values())[:limit]


def _summarize_sample_lists(value: Any, limit: int, stats: dict[str, int]) -> None:
    if isinstance(value, dict):
        for key, item in list(value.items()):
            if (
                isinstance(item, list)
                and "samples" in key
                and all(isinstance(number, (int, float)) for number in item)
            ):
                if len(item) > limit:
                    value[key] = {
                        **_numeric_summary(item),
                        "representative_samples": item[:limit],
                    }
                    stats["retained"] += limit
                    stats["summarized"] += len(item) - limit
                else:
                    stats["retained"] += len(item)
            else:
                _summarize_sample_lists(item, limit, stats)
    elif isinstance(value, list):
        for item in value:
            _summarize_sample_lists(item, limit, stats)


def _numeric_summary(values: list[Any], *, near_zero_idle: bool = False) -> dict[str, Any]:
    numeric = [float(value) for value in values if isinstance(value, (int, float))]
    if not numeric:
        return {}
    ordered = sorted(numeric)
    summary = {
        "sample_count": len(numeric),
        "minimum": min(numeric),
        "maximum": max(numeric),
        "average": round(sum(numeric) / len(numeric), 4),
        "p50": ordered[int((len(ordered) - 1) * 0.50)],
        "p95": ordered[int((len(ordered) - 1) * 0.95)],
    }
    if near_zero_idle:
        summary["samples_near_zero_idle_pct"] = round(
            100 * sum(value >= 98 for value in numeric) / len(numeric), 2
        )
    return summary


def _run_queue_summary(values: list[Any], capacity: Any) -> dict[str, Any]:
    summary = _numeric_summary(values)
    if not summary or not isinstance(capacity, (int, float)) or capacity <= 0:
        return summary
    summary["effective_cpu_capacity"] = capacity
    summary["average_ratio"] = round(summary["average"] / capacity, 4)
    summary["maximum_ratio"] = round(summary["maximum"] / capacity, 4)
    summary["samples_above_capacity_pct"] = round(
        100 * sum(float(value) > capacity for value in values) / len(values), 2
    )
    return summary


def _evidence_index(payload: dict[str, Any]) -> list[dict[str, Any]]:
    entries = []
    deterministic = payload.get("deterministic_findings", {})
    roots = (
        (payload.get("system"), "diag.json", "system"),
        (payload.get("performance"), "performance.json", "performance"),
        (payload.get("security"), "security.json", "security"),
        (
            deterministic.get("performance_findings"),
            "performance.json",
            "deterministic_findings.performance_findings",
        ),
        (
            deterministic.get("performance_interpretation"),
            "performance.json",
            "deterministic_findings.performance_interpretation",
        ),
        (
            deterministic.get("security_analysis"),
            "security-analysis.json",
            "deterministic_findings.security_analysis",
        ),
    )
    for value, report, path in roots:
        _collect_evidence(value, report, path, entries)
    return entries[:80]


def _collect_evidence(value: Any, report: str, path: str, entries: list[dict[str, Any]]) -> None:
    if len(entries) >= 80:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _collect_evidence(item, report, f"{path}.{key}", entries)
    elif isinstance(value, (str, int, float, bool)) and value not in ("", None):
        entries.append(
            {
                "id": f"evidence.{len(entries) + 1:03d}",
                "report": report,
                "path": path,
                "value": value,
            }
        )


def _find_named_values(value: Any, name: str) -> list[Any]:
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == name and isinstance(item, list):
                found.extend(deepcopy(item))
            else:
                found.extend(_find_named_values(item, name))
    elif isinstance(value, list):
        for item in value:
            found.extend(_find_named_values(item, name))
    return found


def _select(value: Any, *keys: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return _drop_empty({key: deepcopy(value.get(key)) for key in keys})


def _drop_empty(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: compact
            for key, item in value.items()
            if (compact := _drop_empty(item)) not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [
            compact for item in value if (compact := _drop_empty(item)) not in (None, "", [], {})
        ]
    return value


def _sanitize(value: Any) -> Any:
    sensitive_keys = {
        "api_key",
        "apikey",
        "authorization",
        "access_token",
        "refresh_token",
        "private_key",
        "cookie",
        "credentials",
    }
    if isinstance(value, dict):
        return {
            key: _sanitize(item)
            for key, item in value.items()
            if key.lower().replace("-", "_") not in sensitive_keys
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value
