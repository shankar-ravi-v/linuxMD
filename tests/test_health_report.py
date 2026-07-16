"""Health assessment schema and terminal presentation tests."""

from pathlib import Path

import pytest

from linuxmd.analysis import ProviderError, validate_analysis
from linuxmd.health_report import format_health_assessment


def _assessment() -> dict:
    return {
        "overall_health": "healthy",
        "assessment_summary": (
            "The system appeared healthy during the sampled interval; this does not establish "
            "long-term stability."
        ),
        "assessment_scope": {
            "environment": "Linux virtual machine",
            "measurement_window": "60 seconds, 60 samples",
            "workload_state": "idle",
            "baseline": "none",
        },
        "subsystem_health": {
            name: {
                "status": "healthy",
                "summary": "No pressure was observed in the sample.",
                "coverage": "sufficient",
                "missing_metrics": [],
            }
            for name in ("cpu", "memory", "storage", "network", "kernel", "security")
        },
        "performance_assessment": (
            "No CPU, memory, storage, network, or scheduler bottleneck was detected during "
            "the supplied measurement window."
        ),
        "active_concerns": [],
        "observations": [],
        "recommended_actions": [],
        "confidence": "medium",
    }


def test_normalized_health_assessment_matches_schema() -> None:
    result = _assessment()

    assert validate_analysis(result, provider="test") == {
        **result,
        "correlations": [],
        "evidence_qualification": {
            "temporal_confidence": "low",
            "overall_assessment_confidence": "medium",
        },
    }


def test_schema_rejects_incomplete_subsystem_evidence() -> None:
    result = _assessment()
    del result["subsystem_health"]["storage"]

    with pytest.raises(ProviderError, match="structural validation"):
        validate_analysis(result, provider="test")


def test_terminal_uses_health_sections_and_friendly_empty_content() -> None:
    output = format_health_assessment(
        _assessment(),
        provider="openai",
        model="gpt-5-mini",
        output_path=Path("output/analysis.json"),
    )

    assert "LinuxMD Health Assessment" in output
    assert "Overall health" in output
    assert "Assessment scope" in output
    assert "Subsystem health" in output
    assert "Performance assessment" in output
    assert "Active concerns" in output
    assert "Environment and historical observations" not in output
    assert "Evidence\n" not in output
    assert "No active concerns were detected during the sampled interval." in output
    assert "[]" not in output
    assert "{}" not in output


def test_detailed_renderer_separates_not_applicable_from_missing() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["security"].update(
        {
            "limitations": ["sudoers configuration (permission denied)"],
            "not_applicable": ["TDX host MSR verification (WSL2 guest)"],
        }
    )

    output = format_health_assessment(
        result,
        provider="deepseek",
        model="test",
        output_path=Path("output/analysis.json"),
        detail_level="detailed",
    )

    assert "Limited:\n             sudoers configuration (permission denied)" in output
    assert "Not applicable:\n             TDX host MSR verification (WSL2 guest)" in output
    assert "Missing: TDX host MSR verification" not in output


def test_default_and_detailed_render_same_security_status() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["security"].update(
        {
            "status": "attention",
            "coverage": "partial",
            "summary": "AppArmor is supported but not enabled.",
            "coverage_limitations": [
                {"type": "permission_denied", "item": "sudoers configuration"}
            ],
        }
    )

    outputs = [
        format_health_assessment(
            result,
            provider="deepseek",
            model="test",
            output_path=Path("output/analysis.json"),
            detail_level=detail,
        )
        for detail in ("concise", "detailed")
    ]

    assert all("Security   Attention" in output for output in outputs)


def test_historical_observation_remains_separate_from_active_concerns() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["observations"] = [
        {
            "title": "Historical process crash",
            "description": "A user-space crash was recorded; no continuing impact is shown.",
            "evidence": ["security.json kernel.history[0]"],
        }
    ]
    output = format_health_assessment(
        result,
        provider="gemini",
        model="gemini-2.5-flash",
        output_path=Path("output/analysis.json"),
        detail_level="detailed",
    )

    active = output.split("Active concerns", 1)[1].split(
        "Environment and historical observations", 1
    )[0]
    observations = output.split("Environment and historical observations", 1)[1]
    assert "Historical process crash" not in active
    assert "Historical process crash" in observations
    assert "Healthy with observations" in output


def test_correlated_cpu_impact_can_render_as_degraded_active_concern() -> None:
    result = _assessment()
    result["overall_health"] = "degraded"
    result["subsystem_health"]["cpu"] = {
        "status": "degraded",
        "summary": "Utilization and run queue pressure coincided with workload latency.",
        "coverage": "sufficient",
        "missing_metrics": [],
    }
    result["active_concerns"] = [
        {
            "title": "CPU saturation during sample",
            "category": "performance",
            "severity": "high",
            "assessment": "confirmed_issue",
            "description": "Correlated scheduler pressure had measured workload impact.",
            "evidence": [
                "performance.json: 58/60 high-utilization samples",
                "performance.json: run queue exceeded logical CPUs with workload latency",
            ],
        }
    ]

    normalized = validate_analysis(result, provider="test")
    output = format_health_assessment(
        normalized,
        provider="openai",
        model="gpt-5-mini",
        output_path=Path("output/analysis.json"),
    )

    assert "Degraded" in output
    assert "CPU saturation during sample" in output
    assert "58/60 high-utilization samples" in output


def test_incomplete_evidence_can_use_unknown_subsystem_status() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["storage"] = {
        "status": "unknown",
        "summary": "Storage sampling was unavailable.",
        "coverage": "insufficient",
        "missing_metrics": ["device latency", "queue depth", "utilization", "device errors"],
    }
    result["confidence"] = "low"

    assert (
        validate_analysis(result, provider="test")["subsystem_health"]["storage"]["status"]
        == "unknown"
    )


def test_older_analysis_without_provenance_fields_loads_conservatively() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["observations"] = [
        {"title": "Legacy event", "description": "A prior event was logged.", "evidence": []}
    ]

    validated = validate_analysis(result, provider="legacy")

    assert validated["observations"][0]["evidence_refs"] == []
    assert validated["observations"][0]["temporal_scope"] == "unknown"
    assert validated["correlations"] == []


def test_five_second_cpu_summary_rejects_exact_sustained_pressure_sentence() -> None:
    result = _assessment()
    result["assessment_scope"]["measurement_window"] = "5 seconds, single sampling window"
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["cpu"].update(
        {
            "status": "unknown",
            "coverage": "partial",
            "missing_metrics": ["mpstat", "pidstat"],
            "summary": "PSI some avg10 0.22, but no sustained pressure.",
        }
    )
    result["confidence"] = "low"

    with pytest.raises(ProviderError, match="five-second sample cannot support persistence"):
        validate_analysis(result, provider="test")


def test_five_second_cpu_summary_accepts_time_bounded_replacement() -> None:
    result = _assessment()
    result["assessment_scope"]["measurement_window"] = "5 seconds, single sampling window"
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["cpu"].update(
        {
            "status": "unknown",
            "coverage": "partial",
            "missing_metrics": ["mpstat", "pidstat"],
            "summary": (
                "PSI some avg10 was 0.22, and no scheduler pressure was observed during the "
                "sampled interval."
            ),
        }
    )
    result["confidence"] = "low"

    assert validate_analysis(result, provider="test")["subsystem_health"]["cpu"]["status"] == (
        "unknown"
    )


def test_limited_coverage_cannot_use_healthy_subsystem_status() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["memory"].update(
        {"status": "healthy", "coverage": "limited", "missing_metrics": ["reclaim latency"]}
    )

    with pytest.raises(ProviderError, match="cannot be healthy when coverage is limited"):
        validate_analysis(result, provider="test")


@pytest.mark.parametrize(
    ("limitation_type", "item"),
    [
        ("permission_denied", "sudoers configuration"),
        ("not_observable_in_environment", "Secure Boot state"),
    ],
)
def test_security_partial_coverage_accepts_non_metric_limitation(limitation_type, item) -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["security"].update(
        {
            "status": "unknown",
            "coverage": "partial",
            "missing_metrics": [],
            "coverage_limitations": [{"type": limitation_type, "item": item}],
        }
    )

    validated = validate_analysis(result, provider="test")

    assert validated["subsystem_health"]["security"]["missing_metrics"] == []


@pytest.mark.parametrize("subsystem", ["storage", "network"])
def test_required_telemetry_gap_still_requires_missing_metrics(subsystem) -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"][subsystem].update(
        {"status": "unknown", "coverage": "insufficient", "missing_metrics": []}
    )

    with pytest.raises(ProviderError, match="must identify missing metrics"):
        validate_analysis(result, provider="test")


def test_active_concern_cannot_use_healthy_overall_status() -> None:
    result = _assessment()
    result["overall_health"] = "healthy"
    result["subsystem_health"]["memory"]["status"] = "attention"
    result["active_concerns"] = [
        {
            "title": "Memory pressure",
            "category": "performance",
            "severity": "medium",
            "assessment": "indication",
            "description": "Reclaim activity indicates current memory pressure.",
            "evidence": ["performance.json reclaim activity"],
        }
    ]

    with pytest.raises(ProviderError, match="Overall health cannot be healthy"):
        validate_analysis(result, provider="test")


@pytest.mark.parametrize(
    "subsystem,title,description,evidence",
    [
        (
            "memory",
            "Memory pressure during sample",
            "Sustained reclaim and swapping coincided with workload latency.",
            "performance.json memory.swap_out and reclaim samples",
        ),
        (
            "storage",
            "Storage latency during sample",
            "Latency and queueing coincided with measured workload impact.",
            "performance.json disk await, queue depth, and workload latency",
        ),
    ],
)
def test_correlated_subsystem_impact_normalizes_as_active_concern(
    subsystem, title, description, evidence
) -> None:
    result = _assessment()
    result["overall_health"] = "degraded"
    result["subsystem_health"][subsystem] = {
        "status": "degraded",
        "summary": description,
        "coverage": "sufficient",
        "missing_metrics": [],
    }
    result["active_concerns"] = [
        {
            "title": title,
            "category": "performance",
            "severity": "high",
            "assessment": "confirmed_issue",
            "description": description,
            "evidence": [evidence, "workload latency increased during the same samples"],
        }
    ]

    assert validate_analysis(result, provider="test")["active_concerns"][0]["title"] == title


def test_security_hardening_opportunity_does_not_claim_compromise() -> None:
    result = _assessment()
    result["overall_health"] = "attention_recommended"
    result["subsystem_health"]["security"] = {
        "status": "attention",
        "summary": "A hardening weakness merits review; no compromise was observed.",
        "coverage": "sufficient",
        "missing_metrics": [],
    }
    result["active_concerns"] = [
        {
            "title": "SSH password authentication enabled",
            "category": "security",
            "severity": "medium",
            "assessment": "indication",
            "description": "The configuration increases authentication exposure.",
            "evidence": ["security.json identity_access.ssh.password_authentication=true"],
        }
    ]

    normalized = validate_analysis(result, provider="test")

    assert normalized["overall_health"] == "attention_recommended"
    assert "no compromise" in normalized["subsystem_health"]["security"]["summary"]


@pytest.mark.parametrize(
    "title,description",
    [
        ("Journal recovery", "Recovery followed an unclean shutdown; no ongoing impact is shown."),
        (
            "Network-driver advisory",
            "An advisory was logged, but measured network degradation was not demonstrated.",
        ),
        (
            "Missing optional utilities",
            "mpstat, pidstat, iostat, and sar were unavailable, reducing measurement coverage.",
        ),
    ],
)
def test_non_active_events_remain_observations(title, description) -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["observations"] = [{"title": title, "description": description, "evidence": ["report"]}]

    normalized = validate_analysis(result, provider="test")

    assert normalized["active_concerns"] == []
    assert normalized["observations"][0]["title"] == title


def test_optional_hardening_alone_is_healthy_with_observations() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["observations"] = [
        {
            "title": "Optional kernel hardening",
            "description": "Review may be appropriate for the deployment threat model.",
            "evidence": ["security.json kernel_hardening.sysctls.dmesg_restrict=0"],
        }
    ]
    result["recommended_actions"] = [
        {
            "category": "hardening_review",
            "action": "Review dmesg access policy.",
            "rationale": "Applicability depends on deployment role and threat model.",
        }
    ]

    normalized = validate_analysis(result, provider="test")

    assert normalized["overall_health"] == "healthy_with_observations"
    assert normalized["active_concerns"] == []


def test_overall_health_summary_avoids_absolute_long_term_claims() -> None:
    summary = _assessment()["assessment_summary"].lower()

    assert "during the sampled interval" in summary
    assert "fully healthy" not in summary
    assert "highly stable" not in summary
    assert "completely idle" not in summary


def test_healthy_requires_more_than_absence_of_activity() -> None:
    result = _assessment()
    result["subsystem_health"]["network"] = {
        "status": "healthy",
        "summary": "No network errors were observed.",
        "coverage": "insufficient",
        "missing_metrics": ["throughput", "retransmissions", "drops", "latency"],
    }

    with pytest.raises(ProviderError, match="cannot be healthy when coverage is insufficient"):
        validate_analysis(result, provider="test")


def test_missing_storage_and_network_metrics_produce_unknown_status() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["storage"] = {
        "status": "unknown",
        "summary": "Filesystem capacity was available, but device behavior was not measured.",
        "coverage": "insufficient",
        "missing_metrics": ["latency", "queue depth", "utilization", "device errors"],
    }
    result["subsystem_health"]["network"] = {
        "status": "unknown",
        "summary": "Network operational behavior was not measured.",
        "coverage": "insufficient",
        "missing_metrics": ["throughput", "retransmissions", "drops", "latency", "errors"],
    }
    result["confidence"] = "low"

    normalized = validate_analysis(result, provider="test")

    assert normalized["subsystem_health"]["storage"]["status"] == "unknown"
    assert normalized["subsystem_health"]["network"]["status"] == "unknown"


def test_performance_summary_separates_observed_health_from_insufficient_coverage() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    for subsystem in ("storage", "network"):
        result["subsystem_health"][subsystem] = {
            "status": "unknown",
            "summary": "Telemetry was insufficient to assess bottlenecks.",
            "coverage": "insufficient",
            "missing_metrics": ["latency", "saturation", "errors"],
        }
    result["performance_assessment"] = (
        "No CPU, memory, or scheduler pressure was observed during the sampled interval. "
        "Storage and network telemetry was insufficient to rule out bottlenecks in those "
        "subsystems."
    )

    normalized = validate_analysis(result, provider="test")

    assert "No CPU, memory, or scheduler pressure" in normalized["performance_assessment"]
    assert "insufficient to rule out" in normalized["performance_assessment"]


def test_incomplete_coverage_prevents_high_confidence() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["storage"]["status"] = "unknown"
    result["subsystem_health"]["storage"]["coverage"] = "limited"
    result["subsystem_health"]["storage"]["missing_metrics"] = ["device latency"]
    result["confidence"] = "high"

    with pytest.raises(ProviderError, match="Confidence cannot be high"):
        validate_analysis(result, provider="test")


def test_recommendations_are_separated_by_purpose() -> None:
    result = _assessment()
    result["overall_health"] = "degraded"
    result["active_concerns"] = [
        {
            "title": "Confirmed workload overload",
            "category": "performance",
            "severity": "high",
            "assessment": "confirmed_issue",
            "description": "Measured saturation coincided with workload latency.",
            "evidence": [
                "performance.json correlated utilization samples",
                "performance.json workload latency impact",
            ],
        }
    ]
    result["recommended_actions"] = [
        {
            "category": "immediate_remediation",
            "action": "Reduce the confirmed workload overload.",
            "rationale": "Measured latency and saturation show current impact.",
        },
        {
            "category": "diagnostic_follow_up",
            "action": "Collect device latency metrics.",
            "rationale": "Current storage evidence is incomplete.",
        },
        {
            "category": "hardening_review",
            "action": "Review whether the control applies to this threat model.",
            "rationale": "Applicability must be established before enabling it.",
        },
    ]
    output = format_health_assessment(
        validate_analysis(result, provider="test"),
        provider="openai",
        model="gpt-5-mini",
        output_path=Path("output/analysis.json"),
        detail_level="detailed",
    )

    assert "Immediate remediation" in output
    assert "Diagnostic follow-up" in output
    assert "Optional hardening review" in output


def test_no_active_concern_prints_no_immediate_remediation() -> None:
    output = format_health_assessment(
        _assessment(),
        provider="openai",
        model="gpt-5-mini",
        output_path=Path("output/analysis.json"),
    )

    assert "No immediate remediation is required." in output


def test_cpu_subsystem_cannot_be_healthy_with_active_cpu_concern() -> None:
    result = _assessment()
    result["overall_health"] = "attention_recommended"
    result["active_concerns"] = [
        {
            "title": "CPU contention",
            "category": "performance",
            "severity": "medium",
            "assessment": "likely_issue",
            "description": "Runnable demand exceeded CPU capacity.",
            "evidence": [
                "CPU utilization was high across repeated samples",
                "run queue exceeded 8 logical CPUs across repeated samples",
            ],
        }
    ]

    with pytest.raises(ProviderError, match="CPU cannot be healthy"):
        validate_analysis(result, provider="test")


def test_high_utilization_and_subcapacity_load_do_not_support_saturation_claim() -> None:
    result = _assessment()
    result["overall_health"] = "attention_recommended"
    result["subsystem_health"]["cpu"]["status"] = "attention"
    result["active_concerns"] = [
        {
            "title": "CPU saturation",
            "category": "performance",
            "severity": "medium",
            "assessment": "likely_issue",
            "description": "CPU idle reached zero during the sample.",
            "evidence": [
                "CPU idle was 0% across repeated samples",
                "load average was 3.00 on 8 logical CPUs",
            ],
        }
    ]

    with pytest.raises(ProviderError, match="requires explicit scheduler"):
        validate_analysis(result, provider="test")


def test_cpu_saturation_with_run_queue_and_workload_impact_is_consistent() -> None:
    result = _assessment()
    result["overall_health"] = "degraded"
    result["subsystem_health"]["cpu"] = {
        "status": "degraded",
        "summary": "Capacity pressure coincided with workload latency.",
        "coverage": "sufficient",
        "missing_metrics": [],
    }
    result["active_concerns"] = [
        {
            "title": "CPU saturation",
            "category": "performance",
            "severity": "high",
            "assessment": "confirmed_issue",
            "description": "CPU capacity pressure affected workload latency.",
            "evidence": [
                "run queue exceeded 8 logical CPUs across repeated samples",
                "workload latency increased during the same interval",
            ],
        }
    ]

    assert validate_analysis(result, provider="test")["overall_health"] == "degraded"


def test_intentional_high_cpu_utilization_can_remain_an_observation() -> None:
    result = _assessment()
    result["overall_health"] = "healthy_with_observations"
    result["subsystem_health"]["cpu"] = {
        "status": "attention",
        "summary": "Intentional capacity consumption occurred without established contention.",
        "coverage": "sufficient",
        "missing_metrics": [],
    }
    result["observations"] = [
        {
            "title": "Intentional CPU load test",
            "description": "Utilization reached 100%; no scheduler delay or impact was measured.",
            "evidence": ["load average 3.00 on 8 logical CPUs; yes processes consumed CPU"],
        }
    ]

    normalized = validate_analysis(result, provider="test")

    assert normalized["active_concerns"] == []
    assert normalized["overall_health"] == "healthy_with_observations"
