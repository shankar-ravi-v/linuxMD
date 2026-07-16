# Performance Diagnostics

LinuxMD's bounded performance workflow is inspired by Brendan Gregg's “Linux Performance Analysis
in 60,000 Milliseconds.” LinuxMD implements the workflow independently and combines it with
structured evidence qualification.

## Sampling

`linuxmd performance` defaults to a five-second per-command sample. Tools run sequentially, so the
requested duration is not the complete wall-clock runtime. A bounded sample can miss intermittent
events and cannot prove long-term stability.

```console
uv run linuxmd performance --duration 10 --timeout 90
```

## Optional tools

`mpstat`, `pidstat`, `iostat`, and `sar` usually come from `sysstat`. Missing tools are recorded as
coverage gaps rather than faults. Storage may remain unknown without device latency, queue depth,
utilization, or error telemetry. Network may remain unknown without error, drop, retransmission, or
latency evidence.

## CPU interpretation

High utilization is capacity consumption, not automatically pressure. CPU pressure requires
scheduler or capacity evidence such as a capacity-relative run queue, CPU PSI, scheduling delay, or
runnable backlog. Confirmed impact additionally requires workload latency, throughput, deadline, or
responsiveness evidence.

Load and runnable tasks are normalized against `effective_cpu_capacity`, which accounts where
possible for online CPUs, affinity, cpusets, and cgroup quotas. Reports retain raw values and add
ratios including CPU busy/idle, run queue, and load averages.

## Findings and baselines

Findings progress from observation to indication, likely issue, and confirmed issue as independent
signals and direct impact increase. Without a comparable machine or workload baseline, thresholds
are generic screening heuristics. Configuration changes are not recommended solely from a warning.

Raw command output and normalized metrics coexist in `performance.json` for auditability and parser
improvement. Treat process names, kernel messages, and host details as sensitive.
