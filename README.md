# LinuxMD

<p align="center">
  <img src="assets/linuxmd-logo.svg"
       alt="LinuxMD — System-Scale Analysis for Linux"
       width="420">
</p>

LinuxMD is an experimental open-source System-Scale Analysis tool for Linux. It collects structured
system, performance, and security evidence and can optionally use an LLM to produce a validated
cross-report health assessment.

> **This guide is intentionally brief.**
>
> If your goal is simply to install LinuxMD and perform your first analysis, this guide should take
> less than **5 minutes**.
>
> After your first successful run, continue with **[README.NEXT.md](README.NEXT.md)** for detailed
> usage, architecture, providers, output formats, development workflow, and project roadmap.

## Project Status

LinuxMD `v0.1.0-alpha` is intended for early testing and feedback. Schemas, collectors, and
analysis behavior may evolve before a stable release.

## Quick Start

LinuxMD uses **uv** for dependency and environment management.

If you don't already have it installed, install **uv** first:

https://docs.astral.sh/uv/ then clone and install LinuxMD:

```console
git clone <repository-url>
cd linuxMD
uv sync
```

Collect system, performance, and security reports:

```console
uv run linuxmd collect
```

Run the deterministic security analyzer:

```console
uv run linuxmd security
```

Validate the reports:

```console
uv run linuxmd analyze
```

Without an LLM provider, this validates local reports and makes no network request.

## Optional LLM Analysis

Configure OpenAI, Gemini, or DeepSeek to generate a validated cross-report health assessment:

```console
export LINUXMD_PROVIDER=deepseek
export LINUXMD_API_KEY=<your_api_key>
uv run linuxmd analyze
```

For a detailed terminal report:

```console
uv run linuxmd analyze --detailed
```

## Example Output

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

## Important Notes

- Collection and deterministic security analysis do not require an LLM.
- A complete cross-report assessment currently requires a configured provider, except for the
  deterministic fallback path after invalid provider output.
- Results depend on permissions, installed tools, workload, environment, and sampling duration.
- Reports may contain sensitive host and operational information.
- LinuxMD provides diagnostic guidance, not a security audit or guaranteed root-cause analysis.

## Next Steps

- [README.NEXT.md](README.NEXT.md) - complete user guide
- [Architecture and trust model](docs/architecture.md)
- [LLM providers](docs/providers.md)
- [Schemas and evidence](docs/schema.md)
- [Contributing](CONTRIBUTING.md)
