# Security Diagnostics

`linuxmd security` performs read-only security collection followed by deterministic analysis. It
writes raw facts to `security.json` and findings to `security-analysis.json`.

## Scope

Collection covers observable boot and platform security, CPU vulnerability files, virtualization,
IOMMU and PCIe indicators, kernel hardening, firewall state, listening sockets, storage indicators,
SSH and sudo metadata, update services, and container context.

Applicability and observability are explicit. A missing host-only check in WSL2 is not a guest
coverage failure. Permission denial affects only the blocked check. Bind addresses are classified
as loopback, wildcard, private/internal, link-local, public, or unknown; bind address alone does not
establish reachability.

## Deterministic analyzer

The analyzer cites collected fields and separates actionable hardening findings from missing or
non-applicable evidence. Observable findings such as supported-but-disabled AppArmor or
`dmesg_restrict=0` can produce Security `Attention` even when host-level coverage is partial.

## Intel TDX

On supported Intel host environments, LinuxMD records TDX CPU flags, host kernel paths, bounded
kernel-log initialization evidence, QGS visibility, selected non-sensitive QCNL state, and optional
read-only MSR verification. It never invokes sudo, installs `msr-tools`, loads kernel modules,
writes MSRs, or changes firmware and services. Host-MSR verification is not applicable in WSL2.

## Non-goals

LinuxMD does not scan for malware, conduct forensic or penetration testing, validate every package
or application, prove compromise absence, or implement a compliance framework. “No evidence of
active compromise” is limited to collected diagnostics and is not a comprehensive detection claim.
