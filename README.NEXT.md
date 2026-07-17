# LinuxMD User Guide

This guide continues after the five-minute [Quick Start](README.md#quick-start). It covers normal
operation, providers, outputs, remote collection, Docker, development, limitations, and links to
the technical documentation.

## Requirements

- Linux target environment
- Python 3.12 or later
- [uv](https://docs.astral.sh/uv/)
- Standard procps tools such as `uptime`, `vmstat`, `free`, and `top`
- Optional `sysstat` tools (`mpstat`, `pidstat`, `iostat`, and `sar`) for broader coverage
- OpenSSH client and key-based access for remote performance collection

## Running Without an LLM

No API credentials are needed for collection, validation, or deterministic security analysis:

```console
uv run linuxmd collect
uv run linuxmd security
uv run linuxmd all
uv run linuxmd analyze
```

`collect` writes system, performance, and security reports. `security` collects security facts and
runs the deterministic security analyzer. `all` runs the complete local non-LLM workflow.

With no provider configured, `analyze` validates discovered reports, reports which deterministic
results are available, and explains how to configure an LLM. It does not make a network request or
create or overwrite `output/analysis.json`.

## LLM Providers

| Provider | Default model | Default base URL |
| --- | --- | --- |
| OpenAI | `gpt-5-mini` | `https://api.openai.com/v1` |
| Gemini | `gemini-2.5-flash` | `https://generativelanguage.googleapis.com/v1beta/openai` |
| DeepSeek | `deepseek-v4-flash` | `https://api.deepseek.com` |

Generic configuration:

```console
export LINUXMD_PROVIDER=openai|gemini|deepseek
export LINUXMD_API_KEY=your_api_key
export LINUXMD_MODEL=optional_model_override
uv run linuxmd analyze
```

Provider responses do not replace collected facts. LinuxMD overlays authoritative evidence,
normalizes bounded claims, validates structure and semantics, and writes only a validated assessment
or valid deterministic fallback.

Useful environment variables include:

- `LINUXMD_BASE_URL`: compatible endpoint override
- `LINUXMD_TIMEOUT_SECONDS`: response/read timeout, default `600`
- `LINUXMD_CONNECT_TIMEOUT_SECONDS`: connection timeout, default `30`
- `LINUXMD_PROVIDER_DEBUG=1`: sanitized provider diagnostics

Use `linuxmd analyze --verbose` for credential-free endpoint and timeout details. LinuxMD does not
automatically retry provider requests. See [LLM providers](docs/providers.md) for Bash and
PowerShell examples, timeout phases, custom URLs, and debug behavior.

## Command Reference

| Command | Purpose |
| --- | --- |
| `linuxmd collect` | Run the default baseline collectors |
| `linuxmd collect --all` | Run all registered collectors |
| `linuxmd all` | Run local collectors and deterministic security analysis |
| `linuxmd system` | Collect system inventory |
| `linuxmd performance` | Collect bounded performance telemetry |
| `linuxmd security` | Collect and analyze security evidence |
| `linuxmd analyze` | Validate reports or run configured LLM analysis |
| `linuxmd analyze --detailed` | Show detailed evidence, scope, and limitations |

Run `uv run linuxmd --help` or append `--help` to a command for current options.

## Output Files

| File | Contents |
| --- | --- |
| `output/diag.json` | System inventory |
| `output/performance.json` | Bounded performance sample and normalized metrics |
| `output/security.json` | Collected security facts |
| `output/security-analysis.json` | Deterministic security findings |
| `output/analysis.json` | Validated provider-assisted assessment or deterministic fallback |

Reports are ignored by Git, but they may contain sensitive host names, process names, kernel
messages, network state, and operational information. Handle and share them accordingly.

## Remote Collection

Remote collection currently applies to bounded performance telemetry. LinuxMD uses the system SSH
client in batch mode and does not accept or store plaintext passwords.

```console
uv run linuxmd performance --host 192.168.1.100 --user diagnostics
```

Specify a port, identity file, duration, and command timeout when needed:

```console
uv run linuxmd performance \
  --host app-01.example.net \
  --user diagnostics \
  --port 2222 \
  --identity-file ~/.ssh/diagnostics_ed25519 \
  --duration 10 \
  --timeout 90
```

The remote account needs permission to run diagnostic tools. LinuxMD does not request sudo or
elevate privileges. See [Remote collection](docs/remote-collection.md).

## Docker

Build the image and write reports under the mounted `output/` directory:

```console
docker build -t linuxmd .
docker run --rm -v "${PWD}:/data" linuxmd
```

The container runs `linuxmd all` as an unprivileged user. System and filesystem values describe the
container unless host resources are deliberately mounted.

## Development

Install from the lockfile and run the checks used by CI:

```console
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change and [CHANGELOG.md](CHANGELOG.md)
for release notes. The [release checklist](docs/RELEASE_CHECKLIST.md) records publishing checks.

## Limitations

- LinuxMD is experimental alpha software; report schemas and behavior may evolve before 1.0.
- A bounded sample is not a machine or workload baseline and cannot prove long-term health.
- Missing tools, permissions, and environment visibility reduce or qualify evidence coverage.
- Storage and network may remain `Unknown` without latency, queue, error, retransmission, or
  saturation telemetry.
- Guest-visible CPU topology does not establish physical host ownership.
- CUDA driver compatibility does not prove that a CUDA toolkit is installed.
- Provider output is validated but is not infallible.
- LinuxMD does not provide malware scanning, forensic analysis, penetration testing, compliance
  certification, a formal security audit, hardware certification, or guaranteed root cause.

## Attribution

LinuxMD's bounded performance workflow is inspired by Brendan Gregg's “Linux Performance Analysis
in 60,000 Milliseconds,” originally published on the Netflix Technology Blog. LinuxMD implements
its workflow independently, does not reproduce the article, and extends beyond performance
collection into system inventory, security evidence, and validated cross-report interpretation.

See [Performance diagnostics](docs/performance.md) for sampling methodology and evidence limits.

## Documentation

- [Architecture and trust model](docs/architecture.md)
- [Collectors](docs/collectors.md)
- [Analysis and health model](docs/analysis-model.md)
- [Performance diagnostics](docs/performance.md)
- [Security diagnostics](docs/security.md)
- [LLM providers](docs/providers.md)
- [Remote collection](docs/remote-collection.md)
- [Schemas and evidence](docs/schema.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)

# Feature Roadmap

LinuxMD is evolving from a Linux diagnostics utility into a system-scale analysis
framework for modern AI infrastructure. The roadmap below represents the current
technical direction and may evolve as the project matures.

## Phase 1 — Foundation (Current)

Core platform

- System inventory collection
- Performance diagnostics
- Security evidence collection
- Deterministic security analysis
- Structured JSON evidence
- Provider-assisted LLM analysis
- Evidence validation and authoritative overlays
- Multiple LLM providers

---

## Phase 2 — Platform Visibility

Expand hardware awareness beyond the operating system.

Planned capabilities include:

- PCIe topology discovery
- PCIe link width and generation validation
- NUMA topology analysis
- CPU cache hierarchy reporting
- Memory topology
- Storage topology
- Network topology
- Kernel configuration inspection
- Virtualization detection
- Container and Kubernetes awareness

---

## Phase 3 — Performance Intelligence

Move beyond snapshot collection toward subsystem diagnostics.

Potential additions include:

- Extended performance sampling
- eBPF-based collectors
- CPU scheduler analysis
- Interrupt distribution
- NUMA locality validation
- Memory pressure analysis
- Cache efficiency
- Storage latency analysis
- Network latency and retransmission analysis
- GPU utilization and bottleneck detection

---

## Phase 4 — AI Infrastructure

Support heterogeneous accelerator platforms.

Areas of interest include:

- NVIDIA GPU diagnostics
- AMD GPU diagnostics
- Intel GPU diagnostics
- CUDA runtime inspection
- ROCm inspection
- CXL topology
- DPU awareness
- SmartNIC diagnostics
- NVMe health analysis
- High-speed networking validation
- Multi-node cluster visibility

---

## Phase 5 — Intelligent Analysis

Increase deterministic reasoning while reducing LLM dependence.

Potential work includes:

- Cross-collector correlation
- Rule-based expert system
- Confidence scoring
- Health scoring
- Drift detection
- Baseline comparison
- Regression detection
- Root cause hypothesis generation
- Recommendation ranking
- Explainable evidence chains

---

## Phase 6 — Enterprise Scale

Long-term direction for production environments.

Possible capabilities:

- Fleet-wide analysis
- Historical trend analysis
- Continuous monitoring
- Scheduled collections
- Central evidence repository
- Web dashboard
- REST API
- Alerting
- Report generation
- CI/CD integration

---

## Design Principles

LinuxMD is guided by several core principles.

- Evidence before interpretation
- Deterministic analysis whenever possible
- LLMs assist rather than replace engineering judgment
- Versioned schemas
- Transparent confidence levels
- Vendor-neutral architecture
- Open and extensible collector framework

---

This roadmap reflects the current direction of the project rather than a
commitment to delivery dates or feature completeness.

## License

LinuxMD is licensed under the MIT License. See [LICENSE](LICENSE) for details.
