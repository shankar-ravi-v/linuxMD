# Why LinuxMD?

Modern AI infrastructure has evolved far beyond traditional Linux servers. A single AI system may include CPUs, GPUs, CXL memory expanders, PCIe fabrics, NVLink/NVSwitch interconnects, DPUs, SmartNICs, NVMe storage, 400–800 Gb Ethernet, InfiniBand, and increasingly unified memory spanning multiple devices.

Historically, enterprise operating systems such as Solaris Fault Management Architecture (FMA) demonstrated the value of correlating hardware telemetry instead of reacting to isolated errors. Techniques such as SERD (Statistical Event Rate Discriminator) analyzed recurring fault patterns over time, allowing the operating system to distinguish transient failures from persistent hardware faults and proactively retire failing components such as memory DIMMs.

Modern Linux provides many excellent subsystem-specific capabilities—including EDAC for memory errors, Machine Check Architecture (MCA), AER for PCIe, NVMe health reporting, GPU telemetry, networking statistics, and numerous kernel tracing facilities. These tools provide valuable information individually, but they generally operate independently.

The remaining challenge is system-level correlation across hardware and software.

When a production AI system experiences degraded performance or intermittent failures, the root cause may span multiple layers. A PCIe link retraining event may coincide with GPU throttling, NUMA memory imbalance, CXL latency changes, storage congestion, firmware warnings, scheduler behavior, or application-level performance regressions. Engineers are often left manually collecting evidence from many independent tools before forming a complete picture.

LinuxMD was created to help bridge that gap. It collects structured diagnostic evidence from multiple hardware and software subsystems, normalizes that information into a common schema, performs deterministic analysis where possible, and can optionally leverage an LLM to correlate evidence across reports and produce a validated system-scale health assessment.

The long-term vision is to evolve LinuxMD into a system-scale analysis framework capable of helping engineers diagnose, validate, and understand increasingly complex AI infrastructure.

# Get Started

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

LinuxMD has undergone limited testing and should be considered experimental software. 

Questions or feedback are always welcome. You can reach me via LinkedIn: www.linkedin.com/in/ravi1shankar

## Quick Start

LinuxMD uses **uv** for dependency and environment management.

If you don't already have it installed, install **uv** first:

curl -LsSf https://astral.sh/uv/install.sh | sh

This installs uv into:

~/.local/bin

Then either start a new shell or run:

source ~/.bashrc

More info: https://docs.astral.sh/uv/

```console
git clone https://github.com/shankar-ravi-v/linuxMD.git
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
export LINUXMD_API_KEY=your_api_key
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

- [README.NEXT.md](README.NEXT.md) - complete user guide and feature roadmap
- [Architecture and trust model](docs/architecture.md)
- [LLM providers](docs/providers.md)
- [Schemas and evidence](docs/schema.md)
- [Contributing](CONTRIBUTING.md)
