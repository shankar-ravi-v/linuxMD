"""Evidence-quality tests for deterministic performance interpretation."""

import pytest

from linuxmd.diagnostics.evidence import deterministic_correlations
from linuxmd.diagnostics.performance_findings import (
    generate_findings,
    interpretation_summary,
)


def _metrics(
    utilization: list[float],
    runnable: list[float] | None = None,
    *,
    kernel_warning: bool = False,
    load_average: float = 0.5,
    psi_some: float = 0.0,
) -> dict:
    runnable = runnable or [0.5] * len(utilization)
    return {
        "logical_cpu_count": 4,
        "load_average_1m": load_average,
        "cpu": {
            "idle_pct": 100.0 - sum(utilization) / len(utilization),
            "iowait_pct": 0.0,
            "utilization_samples_pct": utilization,
        },
        "processes": {
            "runnable_average": sum(runnable) / len(runnable),
            "runnable_samples": runnable,
        },
        "kernel": {"hardware_error_detected": kernel_warning},
        "scheduler_pressure": {"some": {"avg10": psi_some}},
    }


def _context(
    count: int,
    *,
    fidelity: str = "representative",
    baseline_type: str = "none",
    reference: dict | None = None,
    impact: bool = False,
    execution_type: str = "unknown",
) -> dict:
    return {
        "environment": {
            "execution_type": execution_type,
            "platform_hint": None,
            "hardware_fidelity": "unknown",
            "performance_fidelity": fidelity,
        },
        "sampling": {"duration_seconds": count, "interval_seconds": 1, "sample_count": count},
        "workload": {
            "declared": impact,
            "name": "test" if impact else None,
            "state": "active" if impact else "unknown",
            "impact_observed": impact,
        },
        "baseline": {
            "type": baseline_type,
            "reference": reference,
            "comparable_run_count": 5 if reference else 0,
        },
    }


def _cpu_finding(metrics: dict, context: dict):
    return next(
        finding for finding in generate_findings(metrics, **context) if finding.resource == "cpu"
    )


def test_one_isolated_cpu_spike_is_observation() -> None:
    context = _context(60)
    finding = _cpu_finding(_metrics([95.0] + [20.0] * 59), context)

    assert finding.classification == "observation"
    assert "1 of 60 samples" in finding.evidence
    assert "performance.normalized_metrics.cpu.utilization_samples_pct" in finding.evidence_refs
    assert finding.temporal_scope == "sampled_interval"


def test_cpu_utilization_alone_does_not_create_contention_correlation() -> None:
    metrics = _metrics([100.0] * 5, [2.0] * 5)

    assert deterministic_correlations(metrics) == []


def test_cpu_utilization_run_queue_and_psi_create_contention_correlation() -> None:
    metrics = _metrics([100.0] * 5, [8.0] * 5, psi_some=0.22)

    correlations = deterministic_correlations(metrics)

    assert correlations[0]["correlation_id"] == "cpu_contention_pattern"
    assert correlations[0]["classification"] == "indication"
    assert correlations[0]["temporal_scope"] == "sampled_interval"


def test_missing_storage_latency_prevents_storage_correlation() -> None:
    metrics = _metrics([20.0] * 5)
    metrics["cpu"]["iowait_pct"] = 25.0
    metrics["processes"]["blocked_samples"] = [2.0] * 5

    assert not any(
        item["correlation_id"] == "storage_bottleneck_pattern"
        for item in deterministic_correlations(metrics)
    )


def test_sustained_cpu_without_run_queue_pressure_is_indication() -> None:
    context = _context(60)
    finding = _cpu_finding(_metrics([95.0] * 60), context)

    assert finding.classification == "indication"


def test_full_utilization_with_load_below_cpu_count_is_not_saturation() -> None:
    context = _context(60)
    finding = _cpu_finding(_metrics([100.0] * 60, [2.0] * 60, load_average=3.0), context)

    assert finding.classification == "indication"
    assert "saturation" not in finding.explanation.lower()


def test_full_utilization_with_run_queue_below_cpu_count_is_not_saturation() -> None:
    finding = _cpu_finding(_metrics([100.0] * 60, [3.0] * 60), _context(60))

    assert finding.classification == "indication"


def test_full_utilization_with_run_queue_above_cpu_count_is_likely_issue() -> None:
    finding = _cpu_finding(_metrics([100.0] * 60, [6.0] * 60), _context(60))

    assert finding.classification == "likely_issue"


def test_intentional_synthetic_load_is_capacity_observation_without_pressure() -> None:
    context = _context(60)
    context["workload"].update(
        {
            "declared": True,
            "name": "synthetic load test",
            "state": "active",
            "intentional": True,
        }
    )
    finding = _cpu_finding(_metrics([100.0] * 60, [3.0] * 60), context)

    assert finding.classification == "indication"
    assert "intentional" in finding.explanation.lower()


@pytest.mark.parametrize("process_name", ["yes", "database", "stress-ng", "worker"])
def test_process_names_do_not_change_cpu_classification(process_name) -> None:
    metrics = _metrics([100.0] * 60, [3.0] * 60)
    metrics["busiest_processes"] = [{"command": process_name, "cpu_pct": 100.0}]

    finding = _cpu_finding(metrics, _context(60))

    assert finding.classification == "indication"


def test_sustained_cpu_utilization_with_scheduler_psi_is_likely_issue() -> None:
    finding = _cpu_finding(_metrics([100.0] * 60, [3.0] * 60, psi_some=25.0), _context(60))

    assert finding.classification == "likely_issue"


def test_large_system_run_queue_is_interpreted_against_effective_capacity() -> None:
    metrics = _metrics([99.0] * 60, [390.0] * 60, load_average=390.0, psi_some=20.0)
    metrics["logical_cpu_count"] = 320
    metrics["effective_cpu_capacity"] = 300

    finding = _cpu_finding(metrics, _context(60))

    assert finding.classification == "likely_issue"
    assert "60 of 60 samples" in finding.evidence


def test_sustained_cpu_with_run_queue_pressure_is_likely_issue() -> None:
    context = _context(60)
    finding = _cpu_finding(_metrics([95.0] * 60, [8.0] * 60), context)

    assert finding.classification == "likely_issue"


def test_short_sample_without_baseline_constrains_confidence() -> None:
    context = _context(5)
    findings = generate_findings(_metrics([95.0] * 5, [8.0] * 5), **context)
    summary = interpretation_summary(findings, **context)

    assert summary["confidence"] == "low"
    assert any("short" in item for item in summary["limitations"])
    assert any("baseline" in item for item in summary["limitations"])


def test_simulator_with_non_representative_fidelity_limits_quantitative_claim() -> None:
    context = _context(60, fidelity="not_representative", execution_type="simulator")
    finding = _cpu_finding(_metrics([99.0] * 60, [20.0] * 60), context)

    assert finding.classification == "observation"


@pytest.mark.parametrize("baseline_type", ["machine_historical", "workload"])
def test_comparable_baseline_regression_is_quantified(baseline_type) -> None:
    context = _context(
        60,
        baseline_type=baseline_type,
        reference={"cpu_utilization_pct": 50.0},
    )
    finding = _cpu_finding(_metrics([95.0] * 60, [8.0] * 60), context)

    assert finding.classification == "confirmed_issue"
    assert "+45.0 percentage points" in finding.evidence


def test_kernel_warning_without_measured_impact_is_observation() -> None:
    context = _context(60)
    findings = generate_findings(_metrics([20.0] * 60, kernel_warning=True), **context)
    finding = next(item for item in findings if item.resource == "hardware")

    assert finding.classification == "observation"
    assert "does not establish current performance impact" in finding.explanation
    assert finding.temporal_scope == "historical_event"


def test_one_historical_process_crash_is_not_a_likely_performance_issue() -> None:
    context = _context(60)
    metrics = _metrics([20.0] * 60)
    metrics["kernel"]["historical_process_crashes"] = ["service exited once"]

    findings = generate_findings(metrics, **context)

    assert not any(item.classification in {"likely_issue", "confirmed_issue"} for item in findings)


def test_kernel_advisory_without_measured_degradation_is_not_likely_issue() -> None:
    context = _context(60)
    metrics = _metrics([20.0] * 60)
    metrics["kernel"]["performance_advisories"] = ["generic advisory"]

    findings = generate_findings(metrics, **context)

    assert not any(item.classification in {"likely_issue", "confirmed_issue"} for item in findings)


def test_healthy_low_load_system_has_no_performance_findings() -> None:
    context = _context(60)
    metrics = _metrics([10.0] * 60, [0.2] * 60)

    findings = generate_findings(metrics, **context)

    assert findings == ()


def test_workload_impact_with_correlated_signals_confirms_issue() -> None:
    context = _context(60, impact=True)
    finding = _cpu_finding(_metrics([95.0] * 60, [8.0] * 60), context)

    assert finding.classification == "confirmed_issue"


def test_multiple_correlated_signals_raise_confidence_only_to_medium_without_baseline() -> None:
    context = _context(60)
    findings = generate_findings(_metrics([95.0] * 60, [8.0] * 60), **context)
    summary = interpretation_summary(findings, **context)

    assert any(item.classification == "likely_issue" for item in findings)
    assert summary["confidence"] == "medium"
