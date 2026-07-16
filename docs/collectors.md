# Collectors

LinuxMD currently registers system, performance, and security collectors. The default `collect`
workflow runs these baseline collectors; `collect --all` runs every registered collector, including
future optional or experimental entries.

## System inventory

`linuxmd system` writes `output/diag.json`. The collector uses procfs and sysfs where practical and
records operating-system identity, CPU and guest-visible topology, structured caches, memory,
filesystems, kernel information, virtualization, containers, WSL, and supported NVIDIA GPU facts.

NVIDIA inventory uses optional `nvidia-smi`. `cuda_driver_compatibility` describes driver
compatibility, not proof of an installed CUDA toolkit. VM CPU topology is labeled guest-visible and
must not be interpreted as physical host ownership.

## Performance collector

`linuxmd performance` writes `output/performance.json`. It runs bounded, read-only commands and
preserves raw command results alongside normalized metrics and deterministic findings. Optional
sysstat tools improve CPU, process, storage, and historical coverage.

## Security collector

`linuxmd security` writes `output/security.json`, then runs the deterministic analyzer and writes
`output/security-analysis.json`. Optional or inaccessible checks degrade gracefully and preserve
statuses such as permission denied, missing tool, unavailable, and not applicable.

## Combined workflows

`linuxmd collect` collects the three raw reports. `linuxmd all` runs all local collectors plus the
deterministic security analyzer. Neither command invokes an LLM.

## Adding a collector

Implement the `Collector` protocol under `src/linuxmd/collectors`, assign a unique name, and add the
stage to `workflows.py`. Values must be JSON serializable and reports should use the centralized
diagnostic writer so output remains under the project-level `output/` directory.
