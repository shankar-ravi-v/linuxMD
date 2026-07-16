"""Reusable command-output fixtures for remote performance tests."""

import json as jsonlib
import urllib.error
import urllib.request
from dataclasses import replace

import httpx
import pytest

from linuxmd.diagnostics.performance_models import CommandResult


@pytest.fixture(autouse=True)
def mock_httpx_through_urllib(monkeypatch):
    """Keep provider tests network-free while they migrate from urllib to httpx."""

    class MockClient:
        def __init__(self, *, timeout, **kwargs):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, url, *, json: dict, headers: dict):
            request = urllib.request.Request(
                url,
                data=jsonlib.dumps(json).encode("utf-8"),
                headers={"Content-Type": "application/json", **headers},
                method="POST",
            )
            httpx_request = httpx.Request("POST", url)
            try:
                response = urllib.request.urlopen(request, timeout=self.timeout.connect)
            except urllib.error.HTTPError as exc:
                body = exc.read() if exc.fp is not None else b"{}"
                parsed = jsonlib.loads(body.decode("utf-8")) if body else {}
                result = httpx.Response(
                    exc.code,
                    json=parsed,
                    headers=dict(exc.headers or {}),
                    request=httpx_request,
                )
                result.raise_for_status()
            except urllib.error.URLError as exc:
                raise httpx.ConnectError(str(exc.reason), request=httpx_request) from exc
            except TimeoutError as exc:
                raise httpx.ConnectTimeout("mock connect timeout", request=httpx_request) from exc
            try:
                with response:
                    body = response.read()
            except TimeoutError as exc:
                raise httpx.ReadTimeout("mock read timeout", request=httpx_request) from exc
            return httpx.Response(200, content=body, request=httpx_request)

    monkeypatch.setattr("linuxmd.providers.httpx.Client", MockClient)


def result(stdout: str = "", **changes: object) -> CommandResult:
    """Build a successful command result with optional field overrides."""
    base = CommandResult("ok", 0, stdout, "", True, 10)
    return replace(base, **changes)


@pytest.fixture
def healthy_command_results() -> dict[str, CommandResult]:
    return {
        "uptime": result(" 10:00:00 up 5 days, 2 users, load average: 0.40, 0.35, 0.30\n"),
        "dmesg": result(""),
        "vmstat": result(
            "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n"
            " r  b swpd free buff cache si so bi bo in cs us sy id wa st\n"
            " 1  0 0 1000 100 2000 0 0 1 2 100 200 5 2 92 1 0\n"
            " 1  0 0 1000 100 2000 0 0 0 1 110 210 7 3 89 1 0\n"
            " 1  0 0 1000 100 2000 0 0 0 1 105 205 6 2 91 1 0\n"
        ),
        "mpstat": result(
            "Average: CPU %usr %nice %sys %iowait %irq %soft %steal %guest %gnice %idle\n"
            "Average: all 6.00 0.00 2.00 1.00 0.00 1.00 0.00 0.00 0.00 90.00\n"
            "Average: 0 7.00 0.00 2.00 1.00 0.00 1.00 0.00 0.00 0.00 89.00\n"
            "Average: 1 5.00 0.00 2.00 1.00 0.00 1.00 0.00 0.00 0.00 91.00\n"
        ),
        "pidstat": result(
            "Average: UID PID %usr %system %guest %wait %CPU CPU Command\n"
            "Average: 1000 101 2.00 1.00 0.00 0.00 3.00 0 api\n"
            "Average: 1000 202 1.00 0.50 0.00 0.00 1.50 1 worker\n"
        ),
        "iostat": result(
            "Device r/s rkB/s w/s wkB/s aqu-sz await %util\n"
            "sda 1.0 10.0 2.0 20.0 0.02 1.5 2.0\n"
            "Device r/s rkB/s w/s wkB/s aqu-sz await %util\n"
            "sda 2.0 20.0 3.0 30.0 0.05 2.0 3.0\n"
        ),
        "free": result(
            "              total used free shared buff/cache available\n"
            "Mem:           8000 2000 1000 100 5000 5500\n"
            "Swap:          2048 0 2048\n"
        ),
        "sar_dev": result(
            "Average: IFACE rxpck/s txpck/s rxkB/s txkB/s\n"
            "Average: lo 10.00 10.00 1.00 1.00\n"
            "Average: eth0 100.00 80.00 512.00 256.00\n"
        ),
        "sar_tcp": result(
            "Average: active/s passive/s iseg/s oseg/s\n"
            "Average: 1.00 2.00 100.00 100.00\n"
            "Average: atmptf/s estres/s retrans/s isegerr/s orsts/s\n"
            "Average: 0.00 0.00 0.00 0.00 0.00\n"
        ),
        "top": result(
            "top - 10:00:00 up 5 days\n"
            "%Cpu(s): 6.0 us, 2.0 sy, 0.0 ni, 91.0 id, 1.0 wa, 0.0 hi, 0.0 si, 0.0 st\n"
            "PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND\n"
            "101 app 20 0 1000 100 50 S 3.0 1.0 0:01 api\n"
        ),
    }


@pytest.fixture
def cpu_saturated_server(healthy_command_results) -> dict[str, CommandResult]:
    values = dict(healthy_command_results)
    values["vmstat"] = result(
        "r b swpd free buff cache si so bi bo in cs us sy id wa st\n"
        "6 0 0 1000 100 2000 0 0 0 0 100 200 94 3 3 0 0\n"
        "7 0 0 1000 100 2000 0 0 0 0 100 200 95 3 2 0 0\n"
    )
    return values


@pytest.fixture
def memory_pressure_server(healthy_command_results) -> dict[str, CommandResult]:
    values = dict(healthy_command_results)
    values["vmstat"] = result(
        "r b swpd free buff cache si so bi bo in cs us sy id wa st\n"
        "1 0 512 100 50 200 0 0 0 0 100 200 5 2 93 0 0\n"
        "1 0 768 80 50 180 128 64 0 0 100 200 5 2 93 0 0\n"
    )
    values["free"] = result("Mem: 8000 7600 100 0 300 200\nSwap: 2048 768 1280\n")
    return values


@pytest.fixture
def disk_latency_server(healthy_command_results) -> dict[str, CommandResult]:
    values = dict(healthy_command_results)
    values["iostat"] = result(
        "Device r/s rkB/s w/s wkB/s aqu-sz await %util\n"
        "nvme0n1 10 100 20 200 0.1 2.0 10.0\n"
        "Device r/s rkB/s w/s wkB/s aqu-sz await %util\n"
        "nvme0n1 200 20000 300 30000 4.5 45.0 98.0\n"
    )
    return values


@pytest.fixture
def tcp_retransmission_server(healthy_command_results) -> dict[str, CommandResult]:
    values = dict(healthy_command_results)
    values["sar_tcp"] = result(
        "Average: active/s passive/s iseg/s oseg/s\n"
        "Average: 2.00 3.00 100.00 100.00\n"
        "Average: atmptf/s estres/s retrans/s isegerr/s orsts/s\n"
        "Average: 0.00 0.00 4.50 0.00 0.00\n"
    )
    return values


@pytest.fixture
def missing_sysstat_commands(healthy_command_results) -> dict[str, CommandResult]:
    values = dict(healthy_command_results)
    missing = result(
        status="unavailable",
        exit_code=127,
        stderr="sh: command not found",
        command_available=False,
    )
    for name in ("mpstat", "pidstat", "iostat", "sar_dev", "sar_tcp"):
        values[name] = missing
    return values


@pytest.fixture
def malformed_command_results() -> dict[str, CommandResult]:
    return {
        name: result("this is not valid command output\n")
        for name in (
            "uptime",
            "dmesg",
            "vmstat",
            "mpstat",
            "pidstat",
            "iostat",
            "free",
            "sar_dev",
            "sar_tcp",
            "top",
        )
    }
