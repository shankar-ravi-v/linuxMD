"""Provider-independent compact analysis payload tests."""

import json
from copy import deepcopy

import pytest

from linuxmd.analysis_payload import (
    PayloadConfigError,
    PayloadLimits,
    PayloadTooLargeError,
    build_analysis_payload,
    json_size_bytes,
)


def _reports() -> dict:
    events = [
        {
            "message": "driver warning",
            "count": 1,
            "first_timestamp": str(index),
            "last_timestamp": str(index),
        }
        for index in range(10)
    ]
    processes = [
        {"pid": index, "command": f"worker-{index}", "cpu_pct": 90 - index} for index in range(20)
    ]
    return {
        "diag.json": {
            "generated_at": "2026-01-01T00:00:00Z",
            "diagnostics": {
                "system": {
                    "operating_system": {
                        "hostname": "host",
                        "kernel_version": "6.8.0",
                        "distribution": {"pretty_name": "Example Linux"},
                    },
                    "cpu": {
                        "vendor": "GenuineIntel",
                        "model": "Example CPU",
                        "logical_processors": 300,
                        "flags": [f"flag-{index}" for index in range(5000)],
                    },
                    "memory": {"total_kib": 1024, "available_kib": 768},
                    "kernel": {"configuration": "X" * 100_000},
                }
            },
        },
        "performance.json": {
            "diagnostics": {
                "performance": {
                    "sampling": {
                        "duration_seconds": 60,
                        "interval_seconds": 1,
                        "sample_count": 60,
                    },
                    "environment": {"execution_type": "virtual_machine"},
                    "workload": {"state": "active"},
                    "baseline": {"type": "none"},
                    "normalized_metrics": {
                        "effective_cpu_capacity": 4,
                        "cpu": {
                            "idle_pct": 0,
                            "utilization_samples_pct": [100.0] * 60,
                        },
                        "processes": {
                            "runnable_samples": [5.0] * 60,
                            "blocked_samples": [0.0] * 60,
                        },
                        "busiest_processes": processes,
                        "kernel": {"recent_warnings_errors": events},
                    },
                    "raw_command_results": {
                        "dmesg": {"stdout": "full dmesg text " * 5000},
                        "top": {"stdout": "full top text " * 5000},
                    },
                    "findings": [
                        {
                            "classification": "likely_issue",
                            "evidence": ["run_queue_ratio=1.25 for 60 of 60 samples"],
                        }
                    ],
                }
            }
        },
        "security.json": {
            "platform_security": {
                "secure_boot": {
                    "applicable": True,
                    "observable": True,
                    "status": "available",
                    "value": False,
                    "evidence_source": "efivarfs",
                }
            },
            "errors": [{"status": "permission_denied", "path": "kernel log"}],
            "api_key": "must-not-leak",
        },
        "security-analysis.json": {
            "medium_findings": ["Secure Boot is disabled."],
            "supporting_evidence": ["platform_security.secure_boot.value=false"],
            "unknowns_and_gaps": ["Kernel log permission denied."],
        },
    }


def test_payload_compacts_without_mutating_raw_reports() -> None:
    reports = _reports()
    original = deepcopy(reports)

    payload, stats = build_analysis_payload(reports)

    assert reports == original
    assert stats.compacted_bytes < stats.raw_bytes * 0.5
    assert stats.compacted_bytes == json_size_bytes(payload)
    assert payload["metadata"]["source_reports"] == sorted(reports)
    serialized = json.dumps(payload)
    assert "full dmesg text" not in serialized
    assert "full top text" not in serialized
    assert "flag-4999" not in serialized


def test_kernel_configuration_is_deterministically_reduced_but_raw_is_preserved() -> None:
    reports = _reports()
    configuration = {
        "CONFIG_SECCOMP": "y",
        "CONFIG_KVM": "m",
        "CONFIG_IOMMU_SUPPORT": "y",
        "CONFIG_BPF": "y",
        "CONFIG_CGROUPS": "y",
        "CONFIG_NUMA": "y",
        "CONFIG_PCI": "y",
        "CONFIG_DRM_NOUVEAU": "m",
        "CONFIG_UNRELATED_DRIVER": "m",
    }
    reports["diag.json"]["diagnostics"]["system"]["kernel"]["configuration"] = configuration
    original = deepcopy(reports)

    first, _ = build_analysis_payload(reports)
    second, _ = build_analysis_payload(reports)
    reduced = first["system"]["kernel_configuration"]

    assert reports == original
    assert first == second
    assert reduced["raw_entry_count"] == 9
    assert reduced["selected_entry_count"] == 8
    assert reduced["full_configuration_available_in_raw_report"] is True
    assert "CONFIG_UNRELATED_DRIVER" not in reduced["selected"]
    assert configuration == reports["diag.json"]["diagnostics"]["system"]["kernel"]["configuration"]


def test_logs_are_deduplicated_and_processes_and_samples_are_bounded() -> None:
    payload, stats = build_analysis_payload(
        _reports(),
        PayloadLimits(max_log_events=3, max_processes=4, max_raw_samples=5),
    )

    performance = payload["performance"]
    assert len(performance["kernel_events"]) == 1
    assert performance["kernel_events"][0]["occurrence_count"] == 10
    assert len(performance["normalized_metrics"]["busiest_processes"]) == 4
    samples = performance["normalized_metrics"]["cpu"]["utilization_samples_pct"]
    assert len(samples["representative_samples"]) == 5
    assert samples["sample_count"] == 60
    assert stats.processes_removed == 16
    assert stats.raw_samples_summarized > 0


def test_cpu_aggregates_effective_capacity_and_security_evidence_are_preserved() -> None:
    payload, _ = build_analysis_payload(_reports())

    performance = payload["performance"]
    assert performance["effective_cpu_capacity"] == 4
    assert performance["cpu_summary"]["average"] == 100
    assert performance["run_queue_summary"]["average_ratio"] == 1.25
    control = payload["security"]["platform_security"]["secure_boot"]
    assert control["applicable"] is True
    assert control["observable"] is True
    assert "platform_security.secure_boot.value=false" in json.dumps(
        payload["deterministic_findings"]
    )
    assert "must-not-leak" not in json.dumps(payload)


def test_active_concern_evidence_is_retained() -> None:
    reports = _reports()
    reports["performance.json"]["active_concerns"] = [
        {"title": "Current issue", "evidence": ["critical direct evidence"]}
    ]

    payload, _ = build_analysis_payload(reports)

    assert "critical direct evidence" in json.dumps(payload["deterministic_findings"])


@pytest.mark.parametrize(
    "name",
    [
        "LINUXMD_MAX_PAYLOAD_KIB",
        "LINUXMD_MAX_LOG_EVENTS",
        "LINUXMD_MAX_PROCESSES",
        "LINUXMD_MAX_RAW_SAMPLES",
    ],
)
@pytest.mark.parametrize("value", ["0", "-1", "invalid"])
def test_invalid_environment_limits_fail_cleanly(monkeypatch, name, value) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(PayloadConfigError, match=name):
        PayloadLimits.from_environment()


def test_oversized_payload_reports_largest_sections() -> None:
    reports = _reports()
    reports["security-analysis.json"]["medium_findings"] = ["important " * 5000]

    with pytest.raises(PayloadTooLargeError) as error:
        build_analysis_payload(reports, PayloadLimits(max_payload_kib=1))

    assert error.value.sections
    assert "Largest sections" in str(error.value)
