"""Focused tests for semantic analysis validation."""

import pytest

from linuxmd.analysis import cpu_concern_has_pressure_evidence, semantic_validation_errors


def _cpu_concern(evidence: list[str]) -> dict:
    return {
        "title": "CPU pressure",
        "category": "performance",
        "severity": "high",
        "assessment": "likely_issue",
        "description": "CPU capacity pressure occurred during the sampled interval.",
        "evidence": evidence,
        "evidence_refs": [],
        "temporal_scope": "sampled_interval",
    }


@pytest.mark.parametrize(
    "evidence",
    [
        "run_queue_ratio=2.0",
        "Run queue depth average 8.0 on 4 CPUs",
        "PSI some avg10=88.54",
    ],
)
def test_cpu_concern_recognizes_numeric_pressure_evidence(evidence: str) -> None:
    assert cpu_concern_has_pressure_evidence(_cpu_concern([evidence])) is True


@pytest.mark.parametrize(
    "evidence",
    [
        "run_queue_ratio=1.0",
        "Run queue depth 2 on 4 CPUs",
        "PSI some avg10=0",
        "CPU utilization 100% in 4 of 4 samples",
    ],
)
def test_cpu_concern_rejects_numeric_evidence_without_pressure(evidence: str) -> None:
    assert cpu_concern_has_pressure_evidence(_cpu_concern([evidence])) is False


def test_original_provider_cpu_concern_passes_semantic_validation() -> None:
    concern = _cpu_concern(
        [
            "CPU utilization 100% in 4 of 4 samples",
            "Run queue depth average 8.0 on 4 CPUs",
            "PSI some avg10=88.54",
            "Busiest processes: stress-ng",
        ]
    )
    response = {
        "overall_health": "attention_recommended",
        "assessment_summary": "CPU pressure requires attention during the sampled interval.",
        "assessment_scope": {
            "environment": "Linux host",
            "measurement_window": "60 seconds",
            "workload_state": "active",
            "baseline": "none",
        },
        "subsystem_health": {
            name: {
                "status": "attention" if name == "cpu" else "healthy",
                "summary": "Pressure observed." if name == "cpu" else "No issue observed.",
                "coverage": "sufficient",
                "missing_metrics": [],
            }
            for name in ("cpu", "memory", "storage", "network", "kernel", "security")
        },
        "performance_assessment": "CPU pressure was observed during the sampled interval.",
        "active_concerns": [concern],
        "observations": [],
        "recommended_actions": [],
        "confidence": "medium",
        "evidence_qualification": {
            "temporal_confidence": "medium",
            "overall_assessment_confidence": "medium",
        },
        "correlations": [],
    }

    assert cpu_concern_has_pressure_evidence(concern) is True
    assert semantic_validation_errors(response) == []
