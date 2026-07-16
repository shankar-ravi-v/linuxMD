# LinuxMD

LinuxMD is an experimental open-source System-Scale Analysis tool for Linux.

It collects structured system, performance, and security evidence, preserves versioned JSON
reports, and can optionally use an LLM to produce a validated cross-report health assessment.

LinuxMD `v0.1.0-alpha` is intended for early testing and feedback. Schemas, collectors, and
analysis behavior may evolve before a stable release.

Collection, report validation, and deterministic security analysis work without an LLM. A complete
cross-report health assessment currently requires a configured LLM provider, except when LinuxMD
creates its deterministic fallback after invalid provider output. Collected facts remain
authoritative, and provider output is treated as untrusted until it passes structural and semantic
validation.

## Project Status

LinuxMD is an experimental alpha with an architecture that is stabilizing. Current functionality
is usable for evaluation and diagnostic workflows, but output compatibility may change before 1.0.
Feedback, bug reports, feature requests, and pull requests are welcome.

## Requirements

- Linux target environment
- Python 3.12 or later
- [uv](https://docs.astral.sh/uv/)
- Standard procps tools such as `uptime`, `vmstat`, `free`, and `top`
- Optional `sysstat` tools (`mpstat`, `pidstat`, `iostat`, and `sar`) for broader coverage
- OpenSSH client and key-based access for remote performance collection

## Quick Start

### 1. Clone and install

```console
git clone <repository-url>
cd linuxMD
uv sync
```

Replace `<repository-url>` with the GitHub repository URL.

### 2. Collect diagnostics

```console
uv run linuxmd collect
```

This writes:

- `output/diag.json`
- `output/performance.json`
- `output/security.json`

Run the deterministic security collector and analyzer:

```console
uv run linuxmd security
```

Or run the complete local non-LLM workflow:

```console
uv run linuxmd all
```

### 3. Validate the reports

```console
uv run linuxmd analyze
```

Without provider configuration, this validates the reports, reports which deterministic results
are available, and explains how to configure an LLM. It does not make a network request or produce
a cross-report health assessment.

### 4. Optional: generate an LLM-assisted health assessment

```console
export LINUXMD_PROVIDER=deepseek
export LINUXMD_API_KEY=<your_api_key>

uv run linuxmd analyze
```

For the detailed terminal report:

```console
uv run linuxmd analyze --detailed
```

Never commit API keys or include them in diagnostic reports.

## Example Assessment

Provider-assisted results use a compact health-oriented terminal report:

```text
LinuxMD Health Assessment

Overall health
--------------
Healthy with observations

Subsystem health
----------------
Cpu        Healthy
Memory     Healthy
Storage    Unknown — insufficient telemetry
Network    Unknown — insufficient telemetry
Security   Attention
```

Results depend on the environment, permissions, installed tools, workload, and sampling duration.

## Running Without an LLM

No API credentials are needed for collection or deterministic security analysis:

```console
uv run linuxmd collect
uv run linuxmd security
uv run linuxmd all
```

With no provider configured, `linuxmd analyze` validates discovered reports and points to available
deterministic security results. It does not create or overwrite `output/analysis.json`.

## Optional LLM Providers

| Provider | Default model |
| --- | --- |
| OpenAI | `gpt-5-mini` |
| Gemini | `gemini-2.5-flash` |
| DeepSeek | `deepseek-v4-flash` |

Generic configuration:

```console
export LINUXMD_PROVIDER=<openai|gemini|deepseek>
export LINUXMD_API_KEY=<your_api_key>
export LINUXMD_MODEL=<optional_model_override>

uv run linuxmd analyze
```

Provider responses do not replace collected facts. LinuxMD overlays authoritative local evidence,
validates the result, and writes only a validated assessment or valid deterministic fallback. See
[LLM providers](docs/providers.md) for base URLs, timeouts, PowerShell examples, and debugging.

## Main Commands

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

Reports may contain sensitive host, process, kernel, network, and operational information. Generated
reports are ignored by Git, but users remain responsible for handling and sharing them safely.

## Remote Performance Collection

LinuxMD can collect bounded performance telemetry over SSH:

```console
uv run linuxmd performance --host app-01.example.net --user diagnostics
```

LinuxMD uses the system SSH client in batch mode and does not accept or store plaintext passwords.
See [Remote collection](docs/remote-collection.md) for ports, identity files, and permissions.

## Docker

Build and run the current container workflow:

```console
docker build -t linuxmd .
docker run --rm -v "${PWD}:/data" linuxmd
```

The container runs `linuxmd all` as an unprivileged user and writes reports under `/data/output/`.
Reported system values describe the container unless host resources are deliberately mounted.

## Important Limitations

- LinuxMD is experimental alpha software.
- A bounded sample does not prove long-term system or workload health.
- Missing tools, permissions, and environment visibility can reduce evidence coverage.
- Storage and network may remain `Unknown` without latency, error, and saturation telemetry.
- LLM output is validated but must not be treated as infallible.
- LinuxMD provides diagnostic guidance, not a security audit, compliance certification, malware
  scan, hardware certification, or guaranteed root-cause determination.

LinuxMD's bounded performance workflow is inspired by Brendan Gregg's “Linux Performance Analysis
in 60,000 Milliseconds.” LinuxMD implements its workflow independently and extends beyond
performance collection.

## Development

Run the checks used by CI:

```console
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change and [CHANGELOG.md](CHANGELOG.md)
for release notes.

## Documentation

- [Architecture and trust model](docs/architecture.md)
- [Collectors](docs/collectors.md)
- [Analysis and health model](docs/analysis-model.md)
- [Performance diagnostics](docs/performance.md)
- [Security diagnostics](docs/security.md)
- [LLM providers](docs/providers.md)
- [Remote collection](docs/remote-collection.md)
- [Schemas and evidence](docs/schema.md)
- [Roadmap](docs/roadmap.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)

## License

LinuxMD is licensed under the MIT License. See [LICENSE](LICENSE) for details.
