# Roadmap

LinuxMD is an experimental alpha. Roadmap items are directions for exploration, not release
commitments.

Potential areas include:

- richer PCIe topology and device relationship reporting
- broader NUMA topology and locality analysis
- additional NVIDIA and other GPU diagnostics
- clearer container and Kubernetes resource context
- more conservative deterministic cross-signal correlations
- broader distribution, cloud, virtual-machine, and bare-metal validation
- stronger schema migration and compatibility tooling
- expanded deterministic health assessment where evidence rules are sufficiently reliable
- additional storage and network telemetry sources
- reusable anonymization and report-sharing guidance

False negatives are generally preferable to speculative correlations. New deterministic rules
should identify authoritative inputs, applicability, temporal scope, and validation behavior before
they affect final status.
