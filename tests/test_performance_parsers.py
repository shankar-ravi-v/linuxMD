"""Unit tests for normalized performance parsing."""

import pytest

from linuxmd.diagnostics.performance_findings import generate_findings
from linuxmd.diagnostics.performance_parsers import (
    add_cpu_ratios,
    normalize_metrics,
    parse_cpu_capacity,
    parse_cpu_pressure,
    parse_kernel_messages,
)


def _resources(results) -> set[str]:
    metrics, _ = normalize_metrics(results)
    return {finding.resource for finding in generate_findings(metrics)}


def test_healthy_linux_server(healthy_command_results) -> None:
    metrics, warnings = normalize_metrics(healthy_command_results)

    assert warnings == ()
    assert metrics["load_average_1m"] == 0.4
    assert metrics["logical_cpu_count"] == 2
    assert metrics["cpu"]["idle_pct"] == 90.0
    assert metrics["busiest_processes"][0]["command"] == "api"
    assert metrics["memory"]["available_mib"] == 5500.0
    assert metrics["disks"][0]["read_kbps"] == 20.0
    assert metrics["network_interfaces"][0]["receive_kbps"] == 512.0
    assert metrics["tcp"]["active_opens_per_second"] == 1.0
    assert generate_findings(metrics) == ()


def test_cpu_saturated_server(cpu_saturated_server) -> None:
    assert "cpu" in _resources(cpu_saturated_server)


def test_memory_pressure_and_swapping(memory_pressure_server) -> None:
    assert "memory" in _resources(memory_pressure_server)


def test_disk_latency(disk_latency_server) -> None:
    assert "disk" in _resources(disk_latency_server)


def test_tcp_retransmissions(tcp_retransmission_server) -> None:
    metrics, _ = normalize_metrics(tcp_retransmission_server)
    findings = generate_findings(metrics)

    assert metrics["tcp"]["retransmissions_per_second"] == 4.5
    assert any(finding.resource == "network" for finding in findings)


def test_missing_sysstat_commands_are_ignored(missing_sysstat_commands) -> None:
    metrics, warnings = normalize_metrics(missing_sysstat_commands)

    assert metrics["load_average_1m"] == 0.4
    assert warnings == ()
    assert metrics["disks"] == []


def test_malformed_output_is_nonfatal(malformed_command_results) -> None:
    metrics, warnings = normalize_metrics(malformed_command_results)

    assert metrics["disks"] == []
    assert len(warnings) >= 8


def test_repeated_kernel_messages_are_deduplicated() -> None:
    parsed = parse_kernel_messages(
        """[  10.125] I/O error on device sda
[  11.500] I/O error on device sda
[  12.750] I/O error on device sda (repeated 3 times)
"""
    )

    assert parsed["recent_warnings_errors"] == [
        {
            "message": "I/O error on device sda",
            "count": 5,
            "first_timestamp": "10.125",
            "last_timestamp": "12.750",
        }
    ]
    assert parsed["hardware_error_detected"] is True


def test_unique_kernel_messages_are_preserved_in_first_occurrence_order() -> None:
    parsed = parse_kernel_messages(
        """[Mon Jul 14 09:00:00 2026] first unique warning
[Mon Jul 14 09:00:01 2026] second unique warning
[Mon Jul 14 09:00:02 2026] first unique warning
third warning without a timestamp
"""
    )

    assert parsed["recent_warnings_errors"] == [
        {
            "message": "first unique warning",
            "count": 2,
            "first_timestamp": "Mon Jul 14 09:00:00 2026",
            "last_timestamp": "Mon Jul 14 09:00:02 2026",
        },
        {
            "message": "second unique warning",
            "count": 1,
            "first_timestamp": "Mon Jul 14 09:00:01 2026",
            "last_timestamp": "Mon Jul 14 09:00:01 2026",
        },
        {
            "message": "third warning without a timestamp",
            "count": 1,
            "first_timestamp": None,
            "last_timestamp": None,
        },
    ]


def test_cpu_pressure_stall_information_is_structured() -> None:
    parsed = parse_cpu_pressure(
        "some avg10=12.50 avg60=4.00 avg300=1.00 total=12345\n"
        "full avg10=0.25 avg60=0.10 avg300=0.05 total=123\n"
    )

    assert parsed["some"]["avg10"] == 12.5
    assert parsed["full"]["total"] == 123.0


def test_cgroup_quota_limits_large_host_effective_capacity() -> None:
    capacity = parse_cpu_capacity(
        "FILE:/sys/devices/system/cpu/online\n0-299\n"
        "FILE:/proc/self/status\nCpus_allowed_list:\t0-299\n"
        "FILE:/sys/fs/cgroup/cpu.max\n400000 100000\n"
    )

    assert capacity["online_logical_cpu_count"] == 300
    assert capacity["effective_cpu_capacity"] == 4.0
    assert capacity["capacity_limited"] is True


def test_cpuset_restricts_effective_capacity() -> None:
    capacity = parse_cpu_capacity(
        "FILE:/sys/devices/system/cpu/online\n0-299\n"
        "FILE:/sys/fs/cgroup/cpuset.cpus.effective\n32-47\n"
    )

    assert capacity["cpuset_cpu_count"] == 16
    assert capacity["effective_cpu_capacity"] == 16


@pytest.mark.parametrize(
    "cpus,load,run_queue,expected_load_ratio",
    [(2, 1.0, 1.0, 0.5), (8, 3.0, 3.0, 0.375), (64, 24.0, 20.0, 0.375), (300, 120.0, 90.0, 0.4)],
)
def test_cpu_ratios_scale_with_effective_capacity(
    cpus, load, run_queue, expected_load_ratio
) -> None:
    metrics = {
        "logical_cpu_count": cpus,
        "load_average_1m": load,
        "load_average_5m": load / 2,
        "load_average_15m": load / 4,
        "cpu": {"idle_pct": 5.0},
        "processes": {
            "runnable_average": run_queue,
            "blocked_average": 0.0,
            "context_switches_per_second": 1000.0,
        },
        "scheduler_pressure": {},
    }

    add_cpu_ratios(metrics, {})

    assert metrics["cpu_busy_ratio"] == 0.95
    assert metrics["load_1m_ratio"] == expected_load_ratio
    assert metrics["run_queue_ratio"] == round(run_queue / cpus, 4)
