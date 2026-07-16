"""Pure parsers for common Linux performance command output."""

import re
from collections import defaultdict
from collections.abc import Callable, Mapping
from statistics import fmean
from typing import Any

from linuxmd.diagnostics.performance_models import CommandResult

NUMBER = r"[-+]?\d+(?:\.\d+)?"
DMESG_TIMESTAMP = re.compile(r"^\s*\[\s*([^]]+?)\s*]\s*(.*)$")
DMESG_REPETITION = re.compile(
    r"\s*(?:\(|\[)?repeated\s+(\d+)\s+times?(?:\)|])?\s*$",
    re.IGNORECASE,
)


def parse_uptime(text: str) -> dict[str, float]:
    """Extract the one, five, and fifteen minute load averages."""
    match = re.search(
        rf"load averages?:\s*({NUMBER})[, ]+\s*({NUMBER})[, ]+\s*({NUMBER})",
        text,
        re.IGNORECASE,
    )
    if not match:
        return {}
    values = [float(value) for value in match.groups()]
    return dict(
        zip(("load_average_1m", "load_average_5m", "load_average_15m"), values, strict=True)
    )


def parse_vmstat(text: str) -> dict[str, Any]:
    """Normalize process, CPU, swap, and paging counters from vmstat."""
    header: list[str] | None = None
    samples: list[dict[str, float]] = []
    for line in text.splitlines():
        tokens = line.split()
        if tokens[:2] == ["r", "b"]:
            header = tokens
            continue
        if (
            header
            and len(tokens) >= len(header)
            and all(_is_number(v) for v in tokens[-len(header) :])
        ):
            values = [float(value) for value in tokens[-len(header) :]]
            samples.append(dict(zip(header, values, strict=True)))
    samples = _interval_samples(samples)
    if not samples:
        return {}
    return {
        "processes": {
            "runnable_average": _average(samples, "r"),
            "runnable_max": _maximum(samples, "r"),
            "blocked_average": _average(samples, "b"),
            "blocked_max": _maximum(samples, "b"),
            "runnable_samples": [sample.get("r", 0.0) for sample in samples],
            "blocked_samples": [sample.get("b", 0.0) for sample in samples],
            "context_switches_per_second": _average(samples, "cs"),
            "context_switch_samples_per_second": [sample.get("cs", 0.0) for sample in samples],
        },
        "cpu": {
            "user_pct": _average(samples, "us"),
            "system_pct": _average(samples, "sy"),
            "idle_pct": _average(samples, "id"),
            "iowait_pct": _average(samples, "wa"),
            "steal_pct": _average(samples, "st"),
            "utilization_samples_pct": [100.0 - sample.get("id", 100.0) for sample in samples],
        },
        "swap_activity": {
            "swap_in_kbps": _average(samples, "si"),
            "swap_out_kbps": _average(samples, "so"),
        },
    }


def parse_cpu_pressure(text: str) -> dict[str, Any]:
    """Parse Linux CPU pressure-stall information from procfs."""
    pressure: dict[str, Any] = {}
    for line in text.splitlines():
        tokens = line.split()
        if not tokens or tokens[0] not in {"some", "full"}:
            continue
        values = {}
        for token in tokens[1:]:
            if "=" not in token:
                continue
            name, value = token.split("=", 1)
            values[name] = float(value) if _is_number(value) else value
        pressure[tokens[0]] = values
    return pressure


def parse_cpu_capacity(text: str) -> dict[str, Any]:
    """Derive effective CPU capacity from online, affinity, cpuset, and quota evidence."""
    files: dict[str, str] = {}
    current = None
    for line in text.splitlines():
        if line.startswith("FILE:"):
            current = line.removeprefix("FILE:").strip()
            files[current] = ""
        elif current:
            files[current] += ("\n" if files[current] else "") + line
    online = _cpu_list_count(files.get("/sys/devices/system/cpu/online"))
    offline = _cpu_list_count(files.get("/sys/devices/system/cpu/offline"))
    affinity = _status_cpu_list(files.get("/proc/self/status", ""), "Cpus_allowed_list")
    cpuset = _cpu_list_count(
        files.get("/sys/fs/cgroup/cpuset.cpus.effective")
        or files.get("/sys/fs/cgroup/cpuset/cpuset.cpus")
    )
    quota = _cpu_quota_capacity(files)
    limits = [value for value in (online, affinity, cpuset, quota) if value and value > 0]
    return {
        "online_logical_cpu_count": online,
        "offline_logical_cpu_count": offline,
        "affinity_cpu_count": affinity,
        "cpuset_cpu_count": cpuset,
        "cgroup_quota_cpu_capacity": quota,
        "effective_cpu_capacity": min(limits) if limits else None,
        "capacity_limited": bool(limits and online and min(limits) < online),
        "evidence_sources": sorted(files),
    }


def parse_mpstat(text: str) -> dict[str, Any]:
    """Extract aggregate and per-CPU utilization from mpstat."""
    header: list[str] | None = None
    rows: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        tokens = line.split()
        if "CPU" in tokens and "%idle" in tokens:
            start = tokens.index("CPU")
            header = tokens[start:]
            continue
        if not header or len(tokens) < len(header):
            continue
        metrics_count = len(header) - 1
        values = tokens[-metrics_count:]
        cpu_index = len(tokens) - metrics_count - 1
        if cpu_index < 0 or not all(_is_number(value) for value in values):
            continue
        cpu = tokens[cpu_index]
        metrics = dict(zip(header[1:], (float(value) for value in values), strict=True))
        rows[cpu] = _cpu_metrics(metrics)
    if not rows:
        return {}
    aggregate = rows.pop("all", {})
    per_cpu = [{"cpu": cpu, **values} for cpu, values in sorted(rows.items(), key=_cpu_key)]
    return {"aggregate": aggregate, "per_cpu": per_cpu, "logical_cpu_count": len(per_cpu)}


def parse_pidstat(text: str, *, limit: int = 10) -> list[dict[str, Any]]:
    """Return the busiest processes reported by pidstat."""
    header: list[str] | None = None
    processes: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        tokens = line.split()
        if "PID" in tokens and "%CPU" in tokens and "Command" in tokens:
            header = tokens[tokens.index("PID") :]
            continue
        if not header or len(tokens) < len(header):
            continue
        aligned = tokens[-len(header) :]
        row = dict(zip(header, aligned, strict=True))
        if not row["PID"].isdigit() or not _is_number(row["%CPU"]):
            continue
        pid = int(row["PID"])
        processes[pid] = {
            "pid": pid,
            "command": row["Command"],
            "cpu_pct": float(row["%CPU"]),
            "user_pct": _float(row.get("%usr")),
            "system_pct": _float(row.get("%system")),
            "wait_pct": _float(row.get("%wait")),
        }
    return sorted(processes.values(), key=lambda item: item["cpu_pct"], reverse=True)[:limit]


def parse_iostat(text: str) -> list[dict[str, Any]]:
    """Normalize extended per-device I/O statistics."""
    header: list[str] | None = None
    devices: defaultdict[str, list[dict[str, float]]] = defaultdict(list)
    for line in text.splitlines():
        tokens = line.replace("Device:", "Device").split()
        if tokens and tokens[0] == "Device" and "%util" in tokens:
            header = tokens
            continue
        if not header or len(tokens) < len(header) or tokens[0].lower().startswith("avg-cpu"):
            continue
        values = tokens[1 : len(header)]
        if not values or not all(_is_number(value) for value in values):
            continue
        devices[tokens[0]].append(
            dict(zip(header[1:], (float(value) for value in values), strict=True))
        )

    output = []
    for device, rows in sorted(devices.items()):
        rows = _interval_samples(rows)
        output.append(
            {
                "device": device,
                "read_kbps": _average_alias(rows, ("rkB/s", "rKB/s")),
                "write_kbps": _average_alias(rows, ("wkB/s", "wKB/s")),
                "queue_depth": _average_alias(rows, ("aqu-sz", "avgqu-sz")),
                "await_ms": _average_await(rows),
                "utilization_pct": _average_alias(rows, ("%util",)),
            }
        )
    return output


def parse_free(text: str) -> dict[str, Any]:
    """Extract memory and swap totals in MiB from free output."""
    result: dict[str, Any] = {}
    for line in text.splitlines():
        tokens = line.split()
        if not tokens or tokens[0] not in {"Mem:", "Swap:"}:
            continue
        if len(tokens) < 4 or not all(_is_number(value) for value in tokens[1:4]):
            continue
        key = "memory" if tokens[0] == "Mem:" else "swap"
        result[key] = {
            "total_mib": float(tokens[1]),
            "used_mib": float(tokens[2]),
            "free_mib": float(tokens[3]),
        }
        if key == "memory" and len(tokens) > 6 and _is_number(tokens[6]):
            result[key]["available_mib"] = float(tokens[6])
    return result


def parse_sar_dev(text: str) -> list[dict[str, Any]]:
    """Extract per-interface receive and transmit throughput."""
    header, rows = _parse_sar_rows(text, required="IFACE")
    if not header:
        return []
    interfaces: dict[str, dict[str, str]] = {}
    for row in rows:
        interface = row.get("IFACE", "")
        if interface and interface != "lo":
            interfaces[interface] = row
    return [
        {
            "interface": interface,
            "receive_kbps": _float_alias(row, ("rxkB/s", "rxKB/s")),
            "transmit_kbps": _float_alias(row, ("txkB/s", "txKB/s")),
        }
        for interface, row in sorted(interfaces.items())
    ]


def parse_sar_tcp(text: str) -> dict[str, float]:
    """Extract TCP connection and retransmission rates."""
    metrics: dict[str, float] = {}
    header: list[str] | None = None
    kind: str | None = None
    for line in text.splitlines():
        tokens = line.split()
        if "active/s" in tokens:
            header = tokens[tokens.index("active/s") :]
            kind = "connections"
            continue
        if "retrans/s" in tokens:
            header = tokens[tokens.index("retrans/s") :]
            kind = "errors"
            continue
        if not header or len(tokens) < len(header):
            continue
        values = tokens[-len(header) :]
        if not all(_is_number(value) for value in values):
            continue
        row = dict(zip(header, values, strict=True))
        if kind == "connections":
            metrics["active_opens_per_second"] = _float(row.get("active/s"))
            metrics["passive_opens_per_second"] = _float(row.get("passive/s"))
        elif kind == "errors":
            metrics["retransmissions_per_second"] = _float(row.get("retrans/s"))
    return metrics


def parse_top(text: str, *, limit: int = 10) -> dict[str, Any]:
    """Extract a fallback CPU summary and busiest process list from batch top."""
    result: dict[str, Any] = {}
    cpu_match = re.search(
        rf"%?Cpu\(s\):\s*({NUMBER})\s*us.*?({NUMBER})\s*sy.*?({NUMBER})\s*ni.*?"
        rf"({NUMBER})\s*id.*?({NUMBER})\s*wa.*?({NUMBER})\s*hi.*?"
        rf"({NUMBER})\s*si.*?({NUMBER})\s*st",
        text,
        re.IGNORECASE,
    )
    if cpu_match:
        values = [float(value) for value in cpu_match.groups()]
        result["cpu"] = {
            "user_pct": values[0],
            "system_pct": values[1],
            "idle_pct": values[3],
            "iowait_pct": values[4],
            "steal_pct": values[7],
        }
    processes = []
    header: list[str] | None = None
    for line in text.splitlines():
        tokens = line.split()
        if tokens[:2] == ["PID", "USER"] and "%CPU" in tokens and "COMMAND" in tokens:
            header = tokens
            continue
        if not header or len(tokens) < len(header):
            continue
        row = dict(zip(header, tokens[: len(header)], strict=True))
        if not row["PID"].isdigit() or not _is_number(row["%CPU"]):
            continue
        processes.append(
            {
                "pid": int(row["PID"]),
                "command": row["COMMAND"],
                "cpu_pct": float(row["%CPU"]),
                "memory_pct": _float(row.get("%MEM")),
            }
        )
    result["busiest_processes"] = sorted(processes, key=lambda item: item["cpu_pct"], reverse=True)[
        :limit
    ]
    return result


def parse_kernel_messages(text: str) -> dict[str, Any]:
    """Deduplicate kernel messages while retaining occurrence and timestamp information."""
    messages: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        timestamp, message, count = _parse_kernel_message(line)
        if not message:
            continue
        if message not in messages:
            messages[message] = {
                "message": message,
                "count": count,
                "first_timestamp": timestamp,
                "last_timestamp": timestamp,
            }
            continue
        entry = messages[message]
        entry["count"] += count
        if timestamp is not None:
            entry["last_timestamp"] = timestamp

    unique_messages = list(messages.values())
    joined = "\n".join(messages).lower()
    return {
        "recent_warnings_errors": unique_messages,
        "oom_detected": bool(re.search(r"out of memory|oom-kill|killed process", joined)),
        "hardware_error_detected": bool(
            re.search(r"hardware error|machine check|mce:|i/o error|medium error", joined)
        ),
    }


def _parse_kernel_message(line: str) -> tuple[str | None, str, int]:
    """Separate dmesg metadata from the text used to identify a unique message."""
    message = line.strip()
    if not message:
        return None, "", 0

    timestamp = None
    timestamp_match = DMESG_TIMESTAMP.match(message)
    if timestamp_match:
        timestamp, message = timestamp_match.groups()
        timestamp = timestamp.strip()

    count = 1
    repetition_match = DMESG_REPETITION.search(message)
    if repetition_match:
        count = int(repetition_match.group(1))
        message = message[: repetition_match.start()].rstrip()
    return timestamp, message, count


def normalize_metrics(
    results: Mapping[str, CommandResult],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Apply independent parsers and assemble a stable normalized metric tree."""
    parsers: dict[str, Callable[[str], Any]] = {
        "uptime": parse_uptime,
        "vmstat": parse_vmstat,
        "mpstat": parse_mpstat,
        "pidstat": parse_pidstat,
        "iostat": parse_iostat,
        "free": parse_free,
        "sar_dev": parse_sar_dev,
        "sar_tcp": parse_sar_tcp,
        "top": parse_top,
        "dmesg": parse_kernel_messages,
        "psi_cpu": parse_cpu_pressure,
        "cpu_capacity": parse_cpu_capacity,
    }
    parsed: dict[str, Any] = {}
    warnings: list[str] = []
    for name, parser in parsers.items():
        result = results.get(name)
        if result is None or result.status != "ok":
            continue
        try:
            value = parser(result.stdout)
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            warnings.append(f"{name}: output could not be parsed ({exc})")
            continue
        if not value and name != "dmesg":
            warnings.append(f"{name}: output did not contain recognized metrics")
            continue
        parsed[name] = value

    metrics: dict[str, Any] = {}
    metrics.update(parsed.get("uptime", {}))
    vmstat = parsed.get("vmstat", {})
    if vmstat:
        metrics.update(vmstat)
    mpstat = parsed.get("mpstat", {})
    if mpstat:
        metrics["per_cpu"] = mpstat.get("per_cpu", [])
        metrics["logical_cpu_count"] = mpstat.get("logical_cpu_count", 0)
        if "cpu" not in metrics and mpstat.get("aggregate"):
            metrics["cpu"] = mpstat["aggregate"]
    top = parsed.get("top", {})
    if "cpu" not in metrics and top.get("cpu"):
        metrics["cpu"] = top["cpu"]
    metrics["busiest_processes"] = parsed.get("pidstat") or top.get("busiest_processes", [])
    if parsed.get("free"):
        metrics.update(parsed["free"])
    metrics["disks"] = parsed.get("iostat", [])
    metrics["network_interfaces"] = parsed.get("sar_dev", [])
    metrics["tcp"] = parsed.get("sar_tcp", {})
    metrics["kernel"] = parsed.get("dmesg", parse_kernel_messages(""))
    metrics["scheduler_pressure"] = parsed.get("psi_cpu", {})
    capacity = parsed.get("cpu_capacity", {})
    metrics["cpu_capacity"] = capacity
    add_cpu_ratios(metrics, capacity)
    return metrics, tuple(warnings)


def add_cpu_ratios(metrics: dict[str, Any], capacity: dict[str, Any]) -> None:
    """Add scale-independent CPU ratios while retaining their raw source values."""
    logical = metrics.get("logical_cpu_count") or capacity.get("online_logical_cpu_count")
    effective = capacity.get("effective_cpu_capacity") or logical
    metrics["logical_cpu_count"] = logical
    metrics["effective_cpu_capacity"] = effective
    cpu = metrics.get("cpu", {})
    processes = metrics.get("processes", {})
    idle = cpu.get("idle_pct")
    metrics["cpu_idle_ratio"] = round(float(idle) / 100, 4) if idle is not None else None
    metrics["cpu_busy_ratio"] = (
        round(1 - metrics["cpu_idle_ratio"], 4) if metrics["cpu_idle_ratio"] is not None else None
    )
    run_queue = processes.get("runnable_average")
    metrics["run_queue_depth"] = run_queue
    metrics["runnable_task_count"] = run_queue
    metrics["blocked_task_count"] = processes.get("blocked_average")
    metrics["context_switch_rate"] = processes.get("context_switches_per_second")
    metrics["run_queue_ratio"] = _capacity_ratio(run_queue, effective)
    for suffix in ("1m", "5m", "15m"):
        metrics[f"load_{suffix}_ratio"] = _capacity_ratio(
            metrics.get(f"load_average_{suffix}"), effective
        )
    pressure = metrics.get("scheduler_pressure", {})
    metrics["scheduler_psi_some"] = pressure.get("some", {}).get("avg10")
    metrics["scheduler_psi_full"] = pressure.get("full", {}).get("avg10")


def _capacity_ratio(value: Any, capacity: Any) -> float | None:
    if (
        not isinstance(value, (int, float))
        or not isinstance(capacity, (int, float))
        or capacity <= 0
    ):
        return None
    return round(float(value) / float(capacity), 4)


def _cpu_list_count(value: str | None) -> int | None:
    if not value or not value.strip():
        return None
    count = 0
    try:
        for part in value.strip().split(","):
            bounds = [int(item) for item in part.split("-", 1)]
            count += bounds[-1] - bounds[0] + 1
    except ValueError:
        return None
    return count


def _status_cpu_list(status: str, field: str) -> int | None:
    for line in status.splitlines():
        if line.startswith(f"{field}:"):
            return _cpu_list_count(line.split(":", 1)[1])
    return None


def _cpu_quota_capacity(files: dict[str, str]) -> float | None:
    cpu_max = files.get("/sys/fs/cgroup/cpu.max", "").split()
    if len(cpu_max) >= 2 and cpu_max[0] != "max":
        try:
            return round(int(cpu_max[0]) / int(cpu_max[1]), 4)
        except (ValueError, ZeroDivisionError):
            return None
    try:
        quota = int(files.get("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "-1").strip())
        period = int(files.get("/sys/fs/cgroup/cpu/cpu.cfs_period_us", "0").strip())
    except ValueError:
        return None
    return round(quota / period, 4) if quota > 0 and period > 0 else None


def _parse_sar_rows(text: str, *, required: str) -> tuple[list[str], list[dict[str, str]]]:
    header: list[str] | None = None
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        tokens = line.split()
        if required in tokens:
            header = tokens[tokens.index(required) :]
            if required != header[0]:
                continue
            if required in {"active/s", "retrans/s"}:
                header = tokens[tokens.index(required) :]
            elif required == "IFACE":
                header = tokens[tokens.index("IFACE") :]
            continue
        if not header or len(tokens) < len(header):
            continue
        values = tokens[-len(header) :]
        if header[0] != "IFACE" and not all(_is_number(value) for value in values):
            continue
        if header[0] == "IFACE" and not all(_is_number(value) for value in values[1:]):
            continue
        rows.append(dict(zip(header, values, strict=True)))
    return header or [], rows


def _cpu_metrics(metrics: Mapping[str, float]) -> dict[str, float]:
    return {
        "user_pct": metrics.get("%usr", 0.0) + metrics.get("%nice", 0.0),
        "system_pct": metrics.get("%sys", 0.0),
        "idle_pct": metrics.get("%idle", 0.0),
        "iowait_pct": metrics.get("%iowait", 0.0),
        "steal_pct": metrics.get("%steal", 0.0),
        "utilization_pct": 100.0 - metrics.get("%idle", 100.0),
    }


def _interval_samples(rows: list[dict[str, float]]) -> list[dict[str, float]]:
    return rows[1:] if len(rows) > 1 else rows


def _average(rows: list[dict[str, float]], key: str) -> float:
    return round(fmean(row.get(key, 0.0) for row in rows), 3)


def _maximum(rows: list[dict[str, float]], key: str) -> float:
    return max((row.get(key, 0.0) for row in rows), default=0.0)


def _average_alias(rows: list[dict[str, float]], aliases: tuple[str, ...]) -> float:
    for alias in aliases:
        if any(alias in row for row in rows):
            return _average(rows, alias)
    return 0.0


def _average_await(rows: list[dict[str, float]]) -> float:
    if any("await" in row for row in rows):
        return _average(rows, "await")
    return max(_average_alias(rows, ("r_await",)), _average_alias(rows, ("w_await",)))


def _float(value: str | None) -> float:
    return float(value) if value is not None and _is_number(value) else 0.0


def _float_alias(row: Mapping[str, str], aliases: tuple[str, ...]) -> float:
    return next((_float(row.get(alias)) for alias in aliases if alias in row), 0.0)


def _is_number(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def _cpu_key(item: tuple[str, dict[str, float]]) -> tuple[int, str]:
    cpu = item[0]
    return (0, f"{int(cpu):08d}") if cpu.isdigit() else (1, cpu)
