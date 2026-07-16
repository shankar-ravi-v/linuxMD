"""Stable evidence provenance, temporal scopes, and conservative correlations."""

from collections.abc import Iterable
from ipaddress import ip_address
from typing import Any

TEMPORAL_SCOPES = {
    "instantaneous",
    "sampled_interval",
    "multi_sample_trend",
    "historical_event",
    "configuration_state",
    "environment_state",
    "unknown",
}

AUTHORITATIVE_COVERAGE_REFS = {
    "storage": "authoritative_evidence_assessment.evidence_coverage.storage",
    "network": "authoritative_evidence_assessment.evidence_coverage.network",
}

SECURITY_FINDING_REFS = {
    "apparmor": (
        "security.kernel_hardening.apparmor.enabled",
        "security.kernel_hardening.apparmor.supported",
    ),
    "dmesg_restrict": ("security.kernel_hardening.sysctls.dmesg_restrict",),
    "secure_boot": (
        "security.platform_security.secure_boot.state",
        "security.platform_security.secure_boot.reason",
    ),
}

CORRELATION_IDS = {
    "cpu_contention_pattern",
    "storage_bottleneck_pattern",
    "network_pressure_pattern",
}

METRIC_REFS = {
    "cpu_busy": "performance.normalized_metrics.cpu.busy_pct",
    "cpu_idle": "performance.normalized_metrics.cpu.idle_pct",
    "cpu_samples": "performance.normalized_metrics.cpu.utilization_samples_pct",
    "run_queue": "performance.normalized_metrics.processes.runnable_samples",
    "cpu_psi": "performance.normalized_metrics.scheduler_pressure.some.avg10",
    "io_wait": "performance.normalized_metrics.cpu.iowait_pct",
    "disks": "performance.normalized_metrics.disks",
    "blocked": "performance.normalized_metrics.processes.blocked_samples",
    "retransmissions": "performance.normalized_metrics.tcp.retransmissions_per_second",
    "softirq": "performance.normalized_metrics.cpu.softirq_pct",
    "kernel_events": "performance.normalized_metrics.kernel.recent_warnings_errors",
}


def stable_evidence_refs(values: Iterable[str], allowed: Iterable[str]) -> list[str]:
    """Return unique controlled references, silently dropping optional unknown paths."""
    permitted = set(allowed)
    return sorted({value for value in values if isinstance(value, str) and value in permitted})


def path_exists(value: Any, path: str) -> bool:
    """Return whether a dotted path exists in a nested authoritative mapping."""
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return True


def evidence_reference_catalog(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Build controlled finding-specific references that exist in local evidence."""
    catalog = {
        key: [path for path in paths if path_exists(payload, path)]
        for key, paths in SECURITY_FINDING_REFS.items()
    }
    coverage_gap = (
        ["performance.coverage_gaps"] if path_exists(payload, "performance.coverage_gaps") else []
    )
    for resource, reference in AUTHORITATIVE_COVERAGE_REFS.items():
        catalog[f"{resource}_coverage"] = [*coverage_gap, reference]
    return catalog


def classify_bind_address(address: Any) -> str:
    """Classify a bind address without inferring end-to-end reachability."""
    text = str(address or "").strip().strip("[]")
    if text in {"0.0.0.0", "::", "*"}:
        return "wildcard"
    try:
        parsed = ip_address(text)
    except ValueError:
        return "unknown"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_private:
        return "private/internal"
    if parsed.is_global:
        return "public"
    return "unknown"


def performance_evidence_refs(resource: str, metrics: dict[str, Any]) -> list[str]:
    """Return locally supported references for one deterministic performance finding."""
    refs = []
    if resource == "cpu":
        cpu = metrics.get("cpu", {})
        if cpu.get("idle_pct") is not None:
            refs.append(METRIC_REFS["cpu_idle"])
        if cpu.get("utilization_samples_pct"):
            refs.append(METRIC_REFS["cpu_samples"])
        if metrics.get("processes", {}).get("runnable_samples"):
            refs.append(METRIC_REFS["run_queue"])
        if metrics.get("scheduler_pressure"):
            refs.append(METRIC_REFS["cpu_psi"])
    elif resource == "disk":
        if metrics.get("cpu", {}).get("iowait_pct") is not None:
            refs.append(METRIC_REFS["io_wait"])
        if metrics.get("disks"):
            refs.append(METRIC_REFS["disks"])
        if metrics.get("processes", {}).get("blocked_samples"):
            refs.append(METRIC_REFS["blocked"])
    elif resource == "network":
        if metrics.get("tcp"):
            refs.append(METRIC_REFS["retransmissions"])
        if metrics.get("cpu", {}).get("softirq_pct") is not None:
            refs.append(METRIC_REFS["softirq"])
    elif resource == "hardware" and metrics.get("kernel"):
        refs.append(METRIC_REFS["kernel_events"])
    return sorted(set(refs))


def deterministic_correlations(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect a small controlled set of cross-signal indications."""
    correlations = []
    cpu = metrics.get("cpu", {})
    processes = metrics.get("processes", {})
    capacity = float(metrics.get("effective_cpu_capacity") or metrics.get("logical_cpu_count") or 0)
    runnable = processes.get("runnable_samples", [])
    queue_pressure = bool(capacity and any(float(value) / capacity > 1 for value in runnable))
    psi = metrics.get("scheduler_pressure", {}).get("some", {}).get("avg10", 0)
    psi_pressure = float(psi or 0) > 0
    busy = 100.0 - float(cpu.get("idle_pct", 100.0) or 0)
    if queue_pressure and psi_pressure and busy >= 90:
        correlations.append(
            _correlation(
                "cpu_contention_pattern",
                [METRIC_REFS["run_queue"], METRIC_REFS["cpu_psi"], METRIC_REFS["cpu_idle"]],
            )
        )

    iowait = float(cpu.get("iowait_pct", 0) or 0)
    blocked = any(float(value) > 0 for value in processes.get("blocked_samples", []))
    storage_signal = any(
        float(disk.get("await_ms", 0) or 0) >= 20 or float(disk.get("queue_depth", 0) or 0) >= 1
        for disk in metrics.get("disks", [])
    )
    if storage_signal and (iowait >= 10 or blocked):
        signals = [METRIC_REFS["disks"]]
        signals.append(METRIC_REFS["io_wait"] if iowait >= 10 else METRIC_REFS["blocked"])
        correlations.append(_correlation("storage_bottleneck_pattern", signals))

    retransmits = float(metrics.get("tcp", {}).get("retransmissions_per_second", 0) or 0)
    softirq = float(cpu.get("softirq_pct", 0) or 0)
    network_coverage = metrics.get("network_coverage") == "sufficient"
    if retransmits > 0 and softirq > 0 and network_coverage:
        correlations.append(
            _correlation(
                "network_pressure_pattern",
                [METRIC_REFS["retransmissions"], METRIC_REFS["softirq"]],
            )
        )
    return correlations


def _correlation(correlation_id: str, signals: list[str]) -> dict[str, Any]:
    return {
        "correlation_id": correlation_id,
        "classification": "indication",
        "signals": sorted(signals),
        "temporal_scope": "sampled_interval",
    }
