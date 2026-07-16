"""Evidence-qualified interpretation of bounded Linux performance samples."""

from dataclasses import replace
from typing import Any

from linuxmd.diagnostics.evidence import performance_evidence_refs
from linuxmd.diagnostics.performance_models import Finding

HIGH_CPU_PCT = 90.0
ELEVATED_IOWAIT_PCT = 10.0
HIGH_DISK_AWAIT_MS = 20.0
HIGH_DISK_QUEUE_DEPTH = 1.0


def generate_findings(
    metrics: dict[str, Any],
    *,
    environment: dict[str, Any] | None = None,
    sampling: dict[str, Any] | None = None,
    workload: dict[str, Any] | None = None,
    baseline: dict[str, Any] | None = None,
) -> tuple[Finding, ...]:
    """Classify conclusions by evidence strength, correlation, and context."""
    environment = environment or {}
    sampling = sampling or {}
    workload = workload or {}
    baseline = baseline or {}
    findings: list[Finding] = []
    sample_count = int(sampling.get("sample_count") or 0)
    interval = _interval_text(sampling)
    quantitative = environment.get("performance_fidelity", "unknown") not in {
        "limited",
        "not_representative",
    }

    cpu = metrics.get("cpu", {})
    processes = metrics.get("processes", {})
    utilization_samples = cpu.get("utilization_samples_pct", [])
    high_samples = sum(value >= HIGH_CPU_PCT for value in utilization_samples)
    utilization = 100.0 - cpu.get("idle_pct", 100.0)
    cpu_count = metrics.get("effective_cpu_capacity") or metrics.get("logical_cpu_count", 0)
    runnable_samples = processes.get("runnable_samples", [])
    run_queue_ratios = [value / cpu_count for value in runnable_samples] if cpu_count else []
    pressured_samples = sum(value > 1.0 for value in run_queue_ratios)
    sustained = high_samples > 1 and sample_count and high_samples / sample_count >= 0.5
    queue_pressure = pressured_samples > 1
    psi = metrics.get("scheduler_pressure", {})
    psi_some = float(psi.get("some", {}).get("avg10", 0.0) or 0.0)
    psi_full = float(psi.get("full", {}).get("avg10", 0.0) or 0.0)
    psi_pressure = psi_some >= 10.0 or psi_full >= 1.0
    load_average = metrics.get("load_average_1m")
    load_ratio = (
        float(load_average) / float(cpu_count)
        if isinstance(load_average, (int, float)) and cpu_count
        else None
    )
    load_pressure = load_ratio is not None and load_ratio > 1.0
    baseline_delta = _baseline_delta(utilization, baseline, "cpu_utilization_pct")
    impact = bool(workload.get("impact_observed"))
    intentional = workload.get("intentional") is True

    if high_samples or utilization >= HIGH_CPU_PCT:
        classification = "observation"
        explanation = "A CPU utilization threshold was crossed, without enough evidence of impact."
        if quantitative and sustained:
            classification = "indication"
            explanation = (
                "Intentional CPU capacity consumption was observed without established contention."
                if intentional
                else "Utilization was repeatedly elevated during the supplied interval."
            )
        if quantitative and sustained and (queue_pressure or psi_pressure or load_pressure):
            classification = "likely_issue"
            explanation = (
                "Elevated utilization and scheduler pressure occurred concurrently during the "
                "supplied interval."
            )
        if classification == "likely_issue" and (impact or baseline_delta is not None):
            classification = "confirmed_issue"
            explanation = (
                "Correlated CPU pressure coincided with direct workload impact or a comparable "
                "baseline regression during the supplied interval."
            )
        count_text = (
            f"{high_samples} of {sample_count} samples"
            if utilization_samples and sample_count
            else f"the aggregate value ({utilization:.1f}%)"
        )
        evidence = f"CPU utilization was at least {HIGH_CPU_PCT:.0f}% in {count_text} {interval}."
        if run_queue_ratios:
            evidence += (
                f" Run queue ratio exceeded 1.0 in {pressured_samples} of "
                f"{len(run_queue_ratios)} samples."
            )
        if load_ratio is not None:
            evidence += (
                f" Raw 1-minute load was {float(load_average):.2f} against effective CPU "
                f"capacity {float(cpu_count):.2f} (load ratio {load_ratio:.3f})."
            )
        if baseline_delta is not None:
            evidence += f" It was {baseline_delta:+.1f} percentage points from the baseline."
        findings.append(
            _finding(
                classification,
                "cpu",
                evidence,
                explanation,
                "Repeat with workload latency and scheduler measurements before changing "
                "configuration.",
            )
        )

    runnable = processes.get("runnable_average", 0.0)
    if cpu_count and runnable > cpu_count and not (sustained and queue_pressure):
        findings.append(
            _finding(
                "indication" if quantitative and pressured_samples > 1 else "observation",
                "cpu",
                f"Average runnable processes were {runnable:.2f} for {cpu_count} logical CPUs "
                f"{interval}.",
                "Runnable demand exceeded available execution slots in the supplied measurements.",
                "Correlate a longer scheduler sample with CPU utilization and workload latency.",
            )
        )

    _append_indications(findings, metrics, interval, quantitative)

    kernel = metrics.get("kernel", {})
    if kernel.get("oom_detected"):
        findings.append(
            _finding(
                "observation",
                "memory",
                "The collected kernel log contained an out-of-memory or process-kill signature.",
                "This is a logged event, not evidence of sustained memory pressure or current "
                "impact.",
                "Inspect the event timestamp and correlate it with memory, cgroup, and workload "
                "data.",
            )
        )
    if kernel.get("hardware_error_detected"):
        findings.append(
            _finding(
                "observation",
                "hardware",
                "The collected kernel log contained a hardware or I/O warning signature.",
                "A kernel warning alone does not establish current performance impact.",
                "Review complete platform logs and gather non-invasive measurements around the "
                "event.",
            )
        )
    return tuple(
        replace(
            finding,
            evidence_refs=tuple(performance_evidence_refs(finding.resource, metrics)),
            temporal_scope=(
                "historical_event"
                if "kernel log" in finding.evidence.lower()
                else "sampled_interval"
            ),
        )
        for finding in findings
    )


def interpretation_summary(
    findings: tuple[Finding, ...],
    *,
    environment: dict[str, Any],
    sampling: dict[str, Any],
    workload: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    """Compute confidence from sampling quality and corroborating context."""
    duration = float(sampling.get("duration_seconds") or 0)
    count = int(sampling.get("sample_count") or 0)
    fidelity = environment.get("performance_fidelity", "unknown")
    baseline_type = baseline.get("type", "none")
    impact = bool(workload.get("impact_observed"))
    correlated = any(
        item.classification in {"likely_issue", "confirmed_issue"} for item in findings
    )
    confidence = "low"
    if duration >= 60 and count >= 30 and fidelity == "representative" and correlated:
        confidence = "medium"
    if (
        confidence == "medium"
        and impact
        and baseline_type in {"machine_historical", "workload"}
        and any(item.classification == "confirmed_issue" for item in findings)
    ):
        confidence = "high"
    limitations = []
    if duration < 60 or count < 30:
        limitations.append("The bounded sample is short and does not establish persistence.")
    if baseline_type in {None, "none", "generic"}:
        limitations.append("No machine- or workload-specific comparable baseline was available.")
    if fidelity in {"limited", "not_representative", "unknown"}:
        limitations.append(
            f"Performance fidelity is {fidelity}; quantitative claims are constrained."
        )
    if not impact:
        limitations.append("No direct workload impact was declared or measured.")
    return {"confidence": confidence, "limitations": limitations}


def _append_indications(
    findings: list[Finding], metrics: dict[str, Any], interval: str, quantitative: bool
) -> None:
    classification = "indication" if quantitative else "observation"
    cpu = metrics.get("cpu", {})
    if cpu.get("iowait_pct", 0.0) >= ELEVATED_IOWAIT_PCT:
        findings.append(
            _finding(
                classification,
                "disk",
                f"Average CPU I/O wait was {cpu['iowait_pct']:.1f}% {interval}.",
                "This may accompany storage pressure but does not establish impact.",
                "Correlate device latency, queueing, utilization, and workload latency.",
            )
        )
    swap = metrics.get("swap_activity", {})
    if swap.get("swap_in_kbps", 0.0) > 0 or swap.get("swap_out_kbps", 0.0) > 0:
        findings.append(
            _finding(
                classification,
                "memory",
                f"Swap activity was observed {interval}: "
                f"si={swap.get('swap_in_kbps', 0.0):.2f}, "
                f"so={swap.get('swap_out_kbps', 0.0):.2f} KiB/s.",
                "Swap activity alone does not prove harmful memory pressure.",
                "Correlate memory availability, reclaim, paging, and workload latency.",
            )
        )
    for disk in metrics.get("disks", []):
        if (
            disk.get("await_ms", 0.0) >= HIGH_DISK_AWAIT_MS
            or disk.get("queue_depth", 0.0) >= HIGH_DISK_QUEUE_DEPTH
        ):
            findings.append(
                _finding(
                    classification,
                    "disk",
                    f"{disk['device']}: await={disk.get('await_ms', 0.0):.1f} ms and queue "
                    f"depth={disk.get('queue_depth', 0.0):.2f} {interval}.",
                    "Device expectations and workload impact are not established by this snapshot.",
                    "Compare with a device or workload baseline and application latency.",
                )
            )
    retransmits = metrics.get("tcp", {}).get("retransmissions_per_second", 0.0)
    if retransmits > 0:
        findings.append(
            _finding(
                classification,
                "network",
                f"TCP retransmissions averaged {retransmits:.2f}/s {interval}.",
                "This may reflect loss or congestion, but the snapshot cannot locate cause or "
                "impact.",
                "Measure longer and correlate interface errors, path loss, and affected "
                "connections.",
            )
        )


def _baseline_delta(value: float, baseline: dict[str, Any], key: str) -> float | None:
    if baseline.get("type") not in {"machine_historical", "workload"}:
        return None
    reference = baseline.get("reference")
    if not isinstance(reference, dict) or not isinstance(reference.get(key), (int, float)):
        return None
    return value - float(reference[key])


def _interval_text(sampling: dict[str, Any]) -> str:
    duration = sampling.get("duration_seconds")
    return (
        f"during the {duration:g}-second sample"
        if isinstance(duration, (int, float))
        else "during the supplied sample"
    )


def _finding(
    classification: str, resource: str, evidence: str, explanation: str, recommended_follow_up: str
) -> Finding:
    return Finding(classification, resource, evidence, explanation, recommended_follow_up)
