"""Tests for the single-request analysis validation workflow."""

from copy import deepcopy

import pytest

from linuxmd.analysis import validate_analysis
from linuxmd.analysis_evidence import (
    conservative_fallback,
    derive_evidence_assessment,
    overlay_authoritative_fields,
)
from linuxmd.analysis_repair import (
    analyze_once,
    normalize_coverage_statuses,
    normalize_malformed_summary,
    normalize_security_wording,
    normalize_temporal_claims,
    normalize_version_spacing,
)


def _short_evidence(*, pressure=False):
    return {
        "supports_persistence_claims": False,
        "observed_pressure_flags": {"cpu": pressure},
    }


def _environment_evidence():
    return {
        "deterministic_environment_summary": (
            "The system is a WSL2 guest running Ubuntu 24.04 on Linux kernel "
            "6.6.87.2-microsoft-standard-WSL2."
        ),
        "evidence_coverage": {
            "storage": {"coverage": "insufficient"},
            "network": {"coverage": "insufficient"},
        },
    }


@pytest.mark.parametrize(
    "summary",
    [
        "The system is a WSL2 guest (Ubuntu 24.04 on kernel 6.6.x.",
        "The system is a WSL2 guest running Ubuntu 24. 04 on kernel 6. 6.",
        "The system is a WSL2 guest running Ubuntu 24.04 on kernel 6.6.",
        "The system is a WSL2 guest running Ubuntu 24.04 on kernel",
    ],
)
def test_malformed_summary_is_rebuilt_from_authoritative_environment(summary) -> None:
    response = {"assessment_summary": summary, "performance_assessment": "Unchanged."}

    normalized, notes = normalize_malformed_summary(response, _environment_evidence())

    assert normalized["assessment_summary"] == (
        "No active operational issues were detected during the sampled interval. "
        "Limited storage and network telemetry is documented below."
    )
    assert normalized["performance_assessment"] == "Unchanged."
    assert notes[0]["reason"] == ("malformed_or_truncated_environment_restatement_removed")


def test_valid_environment_only_summary_is_replaced_with_health_summary() -> None:
    summary = (
        "The system is a WSL2 guest running Ubuntu 24.04 on Linux kernel "
        "6.6.87.2-microsoft-standard-WSL2."
    )

    normalized, notes = normalize_malformed_summary(
        {"assessment_summary": summary}, _environment_evidence()
    )

    assert normalized["assessment_summary"].startswith("No active operational issues")
    assert notes[0]["reason"] == "provider_environment_restatement_removed"


def test_environment_summary_is_derived_from_normalized_inventory() -> None:
    evidence = derive_evidence_assessment(
        {
            "system": {
                "operating_system": {
                    "distribution": {"name": "Ubuntu", "version_id": "24.04"},
                    "kernel_release": "6.6.87.2-microsoft-standard-WSL2",
                },
                "virtualization": {"environment": "wsl"},
            }
        }
    )

    assert evidence["deterministic_environment_summary"] == (
        "The system is a WSL2 guest running Ubuntu 24.04 on Linux kernel "
        "6.6.87.2-microsoft-standard-WSL2."
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Ubuntu 24. 04", "Ubuntu 24.04"),
        ("kernel 6. 6", "kernel 6.6"),
        ("Python 3. 12.5", "Python 3.12.5"),
        ("Ubuntu 24.04 on kernel 6.6", "Ubuntu 24.04 on kernel 6.6"),
    ],
)
def test_version_spacing_normalization_is_narrow(value, expected) -> None:
    assert normalize_version_spacing(value) == expected


def test_summary_without_environment_information_is_unchanged() -> None:
    summary = "No active concerns were detected during the sampled interval."

    normalized, notes = normalize_malformed_summary(
        {"assessment_summary": summary}, _environment_evidence()
    )

    assert normalized["assessment_summary"] == summary
    assert notes == []


def test_malformed_environment_is_replaced_but_health_interpretation_is_preserved() -> None:
    summary = (
        "The system is a WSL2 guest (Ubuntu 24. 04, kernel 6. 6. "
        "No active concerns were detected during the sampled interval."
    )

    normalized, _ = normalize_malformed_summary(
        {"assessment_summary": summary}, _environment_evidence()
    )

    assert normalized["assessment_summary"] == (
        "No active concerns were detected during the sampled interval."
    )


def test_exact_deepseek_phrase_is_narrowed_without_changing_number() -> None:
    response = {
        "assessment_summary": "PSI some avg10 0.22, but no sustained pressure.",
        "performance_assessment": "No issue was observed.",
        "subsystem_health": {"cpu": {"summary": "PSI some avg10 0.22, but no sustained pressure."}},
    }

    normalized, notes = normalize_temporal_claims(response, _short_evidence())

    assert normalized["subsystem_health"]["cpu"]["summary"] == (
        "PSI some avg10 0.22, but no pressure was observed during the sampled interval."
    )
    assert "0.22" in normalized["subsystem_health"]["cpu"]["summary"]
    assert response["subsystem_health"]["cpu"]["summary"].endswith("sustained pressure.")
    assert notes


def test_detected_pressure_is_never_normalized_away() -> None:
    response = {
        "assessment_summary": "CPU sustained pressure was detected.",
        "performance_assessment": "CPU sustained pressure was detected.",
        "subsystem_health": {"cpu": {"summary": "CPU sustained pressure was detected."}},
    }

    normalized, notes = normalize_temporal_claims(response, _short_evidence(pressure=True))

    assert normalized == response
    assert notes == []


def test_short_sample_with_cpu_telemetry_is_healthy_with_low_temporal_confidence() -> None:
    payload = {
        "assessment_context": {
            "sampling": {"duration_seconds": 5, "interval_seconds": 1, "sample_count": 5}
        },
        "performance": {
            "normalized_metrics": {
                "cpu": {"idle_pct": 99, "utilization_samples_pct": [1] * 5},
                "processes": {"runnable_samples": [0.2] * 5, "blocked_samples": [0] * 5},
                "scheduler_pressure": {"some": {"avg10": 0.0}},
            }
        },
        "deterministic_findings": {},
    }
    evidence = derive_evidence_assessment(payload)
    response = {"subsystem_health": {"cpu": {"status": "healthy", "coverage": "sufficient"}}}

    overlaid = overlay_authoritative_fields(response, evidence)

    assert evidence["measurement_window_seconds"] == 5
    assert evidence["supports_persistence_claims"] is False
    assert overlaid["subsystem_health"]["cpu"]["status"] == "healthy"
    assert overlaid["subsystem_health"]["cpu"]["coverage"] == "sufficient"
    assert evidence["temporal_confidence"] == "low"
    assert evidence["overall_assessment_confidence"] == "low"
    assert overlaid["confidence"] == "low"


def test_short_sample_with_missing_cpu_metric_families_remains_unknown() -> None:
    payload = {
        "assessment_context": {
            "sampling": {"duration_seconds": 5, "interval_seconds": 1, "sample_count": 5}
        },
        "performance": {"normalized_metrics": {"cpu": {"idle_pct": 99}}},
        "deterministic_findings": {},
    }

    evidence = derive_evidence_assessment(payload)

    assert evidence["evidence_coverage"]["cpu"]["coverage"] == "partial"
    assert evidence["evidence_coverage"]["cpu"]["status"] == "unknown"
    assert (
        "runnable task or run-queue telemetry"
        in evidence["evidence_coverage"]["cpu"]["missing_metrics"]
    )
    assert evidence["temporal_confidence"] == "low"


def test_missing_storage_and_network_metrics_remain_unknown() -> None:
    evidence = derive_evidence_assessment(
        {
            "assessment_context": {"sampling": {"duration_seconds": 5, "sample_count": 5}},
            "performance": {"normalized_metrics": {}},
            "deterministic_findings": {},
        }
    )

    assert evidence["evidence_coverage"]["storage"]["status"] == "unknown"
    assert evidence["evidence_coverage"]["storage"]["coverage"] == "insufficient"
    assert evidence["evidence_coverage"]["network"]["status"] == "unknown"
    assert evidence["evidence_coverage"]["network"]["coverage"] == "insufficient"


def test_provider_cannot_invent_reference_or_strengthen_temporal_scope() -> None:
    payload = {
        "assessment_context": {
            "sampling": {"duration_seconds": 5, "interval_seconds": 1, "sample_count": 5}
        },
        "performance": {
            "normalized_metrics": {
                "logical_cpu_count": 4,
                "cpu": {"idle_pct": 99, "utilization_samples_pct": [1] * 5},
            }
        },
        "deterministic_findings": {},
    }
    evidence = derive_evidence_assessment(payload)
    response = {
        "subsystem_health": {"cpu": {}},
        "active_concerns": [
            {
                "title": "CPU observation",
                "description": "CPU activity was sampled.",
                "evidence_refs": ["invented.secret.path"],
                "temporal_scope": "multi_sample_trend",
            }
        ],
        "observations": [],
        "correlations": [
            {
                "correlation_id": "invented_correlation",
                "classification": "indication",
                "signals": ["invented.secret.path"],
                "temporal_scope": "multi_sample_trend",
            }
        ],
    }

    overlaid = overlay_authoritative_fields(response, evidence)

    concern = overlaid["active_concerns"][0]
    assert "invented.secret.path" not in concern["evidence_refs"]
    assert concern["temporal_scope"] == "sampled_interval"
    assert overlaid["correlations"] == evidence["correlations"]


@pytest.mark.parametrize(
    ("title", "expected_refs", "scope"),
    [
        (
            "AppArmor disabled",
            {
                "security.kernel_hardening.apparmor.enabled",
                "security.kernel_hardening.apparmor.supported",
            },
            "configuration_state",
        ),
        (
            "dmesg_restrict is disabled",
            {"security.kernel_hardening.sysctls.dmesg_restrict"},
            "configuration_state",
        ),
        (
            "Secure Boot unavailable in WSL2",
            {
                "security.platform_security.secure_boot.state",
                "security.platform_security.secure_boot.reason",
            },
            "environment_state",
        ),
    ],
)
def test_security_findings_receive_relevant_authoritative_refs(title, expected_refs, scope) -> None:
    payload = {
        "system": {"virtualization": {"environment": "wsl", "wsl": True}},
        "security": {
            "kernel_hardening": {
                "apparmor": {"enabled": False, "supported": True},
                "sysctls": {"dmesg_restrict": "0"},
            },
            "platform_security": {"secure_boot": {"state": "unavailable", "reason": "WSL guest"}},
        },
        "performance": {"coverage_gaps": ["iostat unavailable"], "normalized_metrics": {}},
    }
    evidence = derive_evidence_assessment(payload)
    response = {
        "subsystem_health": {name: {} for name in ("cpu", "storage", "network", "kernel")},
        "active_concerns": [],
        "observations": [
            {
                "title": title,
                "description": title,
                "evidence_refs": ["performance.normalized_metrics.kernel.recent_warnings_errors"],
                "temporal_scope": "multi_sample_trend",
            }
        ],
    }

    finding = overlay_authoritative_fields(response, evidence)["observations"][0]

    assert set(finding["evidence_refs"]) == expected_refs
    assert finding["temporal_scope"] == scope


def test_missing_storage_uses_coverage_not_cpu_signals() -> None:
    payload = {
        "performance": {
            "coverage_gaps": ["iostat unavailable"],
            "normalized_metrics": {
                "cpu": {"iowait_pct": 2},
                "processes": {"blocked_samples": [0]},
            },
        }
    }
    evidence = derive_evidence_assessment(payload)
    response = {
        "subsystem_health": {name: {} for name in ("cpu", "storage", "network", "kernel")},
        "active_concerns": [],
        "observations": [
            {
                "title": "Missing storage telemetry",
                "description": "Storage coverage is incomplete.",
                "evidence_refs": ["performance.normalized_metrics.cpu.iowait_pct"],
            }
        ],
    }

    finding = overlay_authoritative_fields(response, evidence)["observations"][0]

    assert "authoritative_evidence_assessment.evidence_coverage.storage" in finding["evidence_refs"]
    assert not any("iowait" in ref or "blocked" in ref for ref in finding["evidence_refs"])


def test_wsl_kernel_is_healthy_with_partial_guest_visible_coverage() -> None:
    evidence = derive_evidence_assessment(
        {
            "system": {
                "operating_system": {"kernel_release": "6.6.87.2-microsoft-standard-WSL2"},
                "virtualization": {"environment": "wsl", "wsl": True},
            }
        }
    )
    response = {
        "subsystem_health": {name: {} for name in ("cpu", "storage", "network", "kernel")},
        "active_concerns": [],
        "observations": [],
    }

    kernel = overlay_authoritative_fields(response, evidence)["subsystem_health"]["kernel"]

    assert kernel["status"] == "healthy"
    assert kernel["coverage"] == "partial"
    assert "guest-visible" in kernel["summary"]


def test_historical_dmesg_warning_has_historical_scope() -> None:
    evidence = derive_evidence_assessment(
        {
            "system": {"virtualization": {"environment": "wsl", "wsl": True}},
            "performance": {"normalized_metrics": {"kernel": {"recent_warnings_errors": [{}]}}},
        }
    )
    response = {
        "subsystem_health": {name: {} for name in ("cpu", "storage", "network", "kernel")},
        "active_concerns": [],
        "observations": [
            {
                "title": "Historical dmesg warning",
                "description": "A prior kernel log warning was recorded.",
                "evidence_refs": [],
                "temporal_scope": "sampled_interval",
            }
        ],
    }

    finding = overlay_authoritative_fields(response, evidence)["observations"][0]

    assert finding["temporal_scope"] == "historical_event"


def test_optional_diagnostic_tools_have_configuration_scope() -> None:
    evidence = derive_evidence_assessment(
        {"assessment_context": {"sampling": {"duration_seconds": 5}}}
    )
    response = {
        "subsystem_health": {
            name: {} for name in ("cpu", "storage", "network", "kernel", "security")
        },
        "active_concerns": [],
        "observations": [
            {
                "title": "Missing optional diagnostic tools",
                "description": "iostat, sar, mpstat, and pidstat are not installed.",
                "evidence_refs": [],
                "temporal_scope": "sampled_interval",
            }
        ],
    }

    finding = overlay_authoritative_fields(response, evidence)["observations"][0]

    assert finding["temporal_scope"] == "configuration_state"


def test_wsl_tdx_not_applicable_does_not_reduce_security_coverage() -> None:
    evidence = derive_evidence_assessment(
        {
            "system": {"virtualization": {"environment": "wsl", "wsl": True}},
            "security": {
                "cpu_security": {
                    "vendor_security": {
                        "intel": {
                            "tdx": {"privileged_register_verification": {"status": "missing_tool"}}
                        }
                    }
                }
            },
        }
    )

    security = evidence["evidence_coverage"]["security"]

    assert security["coverage"] == "sufficient"
    assert security["limitations"] == []
    assert security["not_applicable"] == ["TDX host MSR verification (WSL2 guest)"]


def test_permission_denied_creates_only_relevant_security_limitation() -> None:
    evidence = derive_evidence_assessment(
        {
            "security": {
                "identity_access": {"sudoers": {"status": "permission_denied"}},
                "kernel_hardening": {"status": "available"},
            }
        }
    )

    security = evidence["evidence_coverage"]["security"]

    assert security["coverage"] == "partial"
    assert security["limitations"] == ["sudoers (permission denied)"]
    assert security["missing_metrics"] == []


@pytest.mark.parametrize(
    "hardening",
    [
        {"apparmor": {"supported": True, "enabled": False}},
        {"sysctls": {"dmesg_restrict": "0"}},
    ],
)
def test_authoritative_hardening_finding_overrides_partial_security_unknown(hardening) -> None:
    evidence = derive_evidence_assessment(
        {
            "security": {
                "kernel_hardening": hardening,
                "identity_access": {"sudoers": {"status": "permission_denied"}},
            }
        }
    )
    response = {
        "subsystem_health": {
            "cpu": {},
            "storage": {},
            "network": {},
            "kernel": {},
            "security": {
                "status": "unknown",
                "coverage": "partial",
                "summary": "Security posture was unknown.",
                "missing_metrics": [],
            },
        },
        "active_concerns": [],
        "observations": [],
    }

    security = overlay_authoritative_fields(response, evidence)["subsystem_health"]["security"]

    assert security["status"] == "attention"
    assert security["coverage"] == "partial"


def test_partial_security_coverage_without_finding_remains_unknown() -> None:
    evidence = derive_evidence_assessment(
        {"security": {"identity_access": {"sudoers": {"status": "permission_denied"}}}}
    )

    assert evidence["evidence_coverage"]["security"]["status"] == "unknown"


def test_absent_security_evidence_remains_unknown() -> None:
    evidence = derive_evidence_assessment({})

    assert evidence["evidence_coverage"]["security"]["status"] == "unknown"


def test_missing_tool_observation_uses_coverage_references() -> None:
    evidence = derive_evidence_assessment(
        {
            "performance": {
                "coverage_gaps": ["mpstat, pidstat, iostat, and sar unavailable"],
                "normalized_metrics": {
                    "cpu": {"iowait_pct": 2},
                    "processes": {"blocked_samples": [0]},
                },
            }
        }
    )
    response = {
        "subsystem_health": {name: {} for name in ("cpu", "storage", "network", "kernel")},
        "active_concerns": [],
        "observations": [
            {
                "title": "Missing optional diagnostic tools",
                "description": "mpstat, pidstat, iostat, and sar are unavailable.",
                "evidence_refs": ["performance.normalized_metrics.cpu.iowait_pct"],
            }
        ],
    }

    finding = overlay_authoritative_fields(response, evidence)["observations"][0]

    assert "performance.coverage_gaps" in finding["evidence_refs"]
    assert not any("iowait" in ref or "blocked" in ref for ref in finding["evidence_refs"])


def test_network_wording_does_not_infer_reachability() -> None:
    response = {
        "observations": [
            {"description": "Listening sockets are all on localhost/private addresses."}
        ]
    }

    normalized, _ = normalize_security_wording(response)
    wording = normalized["observations"][0]["description"]

    assert wording == (
        "Observed listeners were bound to loopback or private/internal addresses; "
        "reachability was not assessed."
    )


def test_wsl_security_fallback_with_non_metric_limitations_validates() -> None:
    evidence = derive_evidence_assessment(
        {
            "system": {"virtualization": {"environment": "wsl", "wsl": True}},
            "security": {
                "platform_security": {"secure_boot": {"state": "unavailable"}},
                "identity_access": {"sudoers": {"status": "permission_denied"}},
                "cpu_security": {
                    "vendor_security": {
                        "intel": {
                            "tdx": {"privileged_register_verification": {"status": "missing_tool"}}
                        }
                    }
                },
            },
        }
    )

    fallback = validate_analysis(
        conservative_fallback(evidence, provider="deepseek", reason="test"),
        provider="deterministic_fallback",
    )
    security = fallback["subsystem_health"]["security"]

    assert security["coverage"] == "partial"
    assert security["missing_metrics"] == []
    assert {item["type"] for item in security["coverage_limitations"]} == {
        "permission_denied",
        "not_observable_in_environment",
    }
    assert security["not_applicable"] == ["TDX host MSR verification (WSL2 guest)"]


def test_security_fallback_uses_authoritative_attention_status() -> None:
    evidence = derive_evidence_assessment(
        {
            "security": {
                "kernel_hardening": {
                    "apparmor": {"supported": True, "enabled": False},
                    "sysctls": {"dmesg_restrict": "0"},
                },
                "identity_access": {"sudoers": {"status": "permission_denied"}},
            }
        }
    )

    fallback = validate_analysis(
        conservative_fallback(evidence, provider="deepseek", reason="test"),
        provider="deterministic_fallback",
    )

    assert fallback["subsystem_health"]["security"]["status"] == "attention"


def test_fallback_contains_provenance_temporal_scope_and_correlations() -> None:
    payload = {
        "assessment_context": {
            "sampling": {"duration_seconds": 5, "interval_seconds": 1, "sample_count": 5}
        },
        "performance": {
            "normalized_metrics": {
                "logical_cpu_count": 4,
                "effective_cpu_capacity": 4,
                "cpu": {"idle_pct": 0, "utilization_samples_pct": [100] * 5},
                "processes": {"runnable_samples": [8] * 5},
                "scheduler_pressure": {"some": {"avg10": 0.22}},
            }
        },
        "deterministic_findings": {"cpu pressure": True},
    }
    evidence = derive_evidence_assessment(payload)

    fallback = validate_analysis(
        conservative_fallback(evidence, provider="deepseek", reason="test"),
        provider="fallback",
    )

    assert fallback["active_concerns"][0]["evidence_refs"]
    assert fallback["active_concerns"][0]["temporal_scope"] == "sampled_interval"
    assert fallback["correlations"][0]["correlation_id"] == "cpu_contention_pattern"
    assert (
        "No evidence of active compromise was found"
        in fallback["subsystem_health"]["security"]["summary"]
    )


@pytest.mark.parametrize("subsystem", ["cpu", "memory", "kernel"])
@pytest.mark.parametrize("coverage", ["partial", "limited"])
def test_limited_healthy_status_normalizes_to_unknown(subsystem, coverage) -> None:
    response = {
        "subsystem_health": {
            subsystem: {
                "status": "healthy",
                "coverage": coverage,
                "summary": "No issue was observed.",
                "missing_metrics": ["extended telemetry"],
            }
        },
        "active_concerns": [],
        "observations": [{"title": "kept"}],
        "recommended_actions": [{"action": "kept"}],
    }

    normalized, notes = normalize_coverage_statuses(response)

    assert normalized["subsystem_health"][subsystem]["status"] == "unknown"
    assert normalized["subsystem_health"][subsystem]["summary"] == "No issue was observed."
    assert notes == [
        {
            "path": f"subsystem_health.{subsystem}.status",
            "from": "healthy",
            "to": "unknown",
            "reason": f"Coverage was {coverage}.",
        }
    ]


def test_sufficient_healthy_and_limited_attention_are_unchanged() -> None:
    response = {
        "subsystem_health": {
            "cpu": {"status": "healthy", "coverage": "sufficient"},
            "memory": {"status": "attention", "coverage": "limited"},
        },
        "active_concerns": [],
    }

    normalized, notes = normalize_coverage_statuses(response)

    assert normalized == response
    assert notes == []


def test_active_fault_prevents_healthy_status_normalization() -> None:
    response = {
        "subsystem_health": {"memory": {"status": "healthy", "coverage": "limited"}},
        "active_concerns": [
            {
                "title": "Memory pressure",
                "description": "Reclaim is affecting the workload.",
                "evidence": ["swap activity"],
            }
        ],
    }

    normalized, notes = normalize_coverage_statuses(response)

    assert normalized == deepcopy(response)
    assert notes == []


def test_analyze_once_calls_provider_exactly_once(monkeypatch) -> None:
    calls = 0
    result = {
        "overall_health": "healthy",
        "assessment_summary": "Healthy during the sampled interval.",
        "assessment_scope": {
            "environment": "host",
            "measurement_window": "one minute",
            "workload_state": "idle",
            "baseline": "none",
        },
        "subsystem_health": {},
        "active_concerns": [],
        "observations": [],
        "performance_assessment": "No supported bottleneck.",
        "recommendations": [],
        "confidence": {"level": "low", "rationale": "Short sample."},
    }

    class Provider:
        def generate(self, payload):
            nonlocal calls
            calls += 1
            return result

    monkeypatch.setattr("linuxmd.analysis_repair.validate_analysis_structure", lambda *a, **k: None)
    monkeypatch.setattr("linuxmd.analysis_repair.validate_analysis", lambda value, **k: value)

    expected = {
        **result,
        "confidence": "low",
        "correlations": [],
        "evidence_qualification": {
            "temporal_confidence": "low",
            "overall_assessment_confidence": "low",
        },
    }
    assert analyze_once(Provider(), {}, provider_name="gemini").result == expected
    assert calls == 1
