# Architecture and Trust Model

LinuxMD separates evidence collection from interpretation. The processing path is:

```text
collectors
  -> versioned raw reports
  -> normalized, compact provider payload
  -> deterministic evidence qualification
  -> optional LLM interpretation
  -> structural and semantic validation
  -> authoritative evidence overlay
  -> validated assessment or deterministic fallback
```

## Sources of truth

Collector reports and deterministic findings are authoritative. Provider interpretation cannot
change distribution identity, kernel version, virtualization type, CPU capacity, memory size,
sampling metadata, coverage, applicability, or supported evidence references.

Raw reports remain unchanged under `output/`. Provider payload reduction removes redundant or
high-volume data from the network request but does not modify the source files.

## Provider boundary

LLM output is untrusted structured input. LinuxMD parses it against a shared schema, overlays local
facts, narrows unsupported wording, and performs semantic validation. Invalid intermediate output
never overwrites the last valid `analysis.json`.

If local normalization cannot resolve an invalid provider result, the workflow may make its bounded
correction attempt. If the result remains invalid, LinuxMD constructs and validates a conservative
deterministic fallback. Authentication and network failures do not fabricate a fallback diagnosis.

## Provider-free operation

Collection, report validation, payload normalization, and deterministic security analysis require
no LLM. A complete cross-report health assessment currently requires a configured provider, except
for fallback generation after invalid provider output.

## Evidence limits

Missing telemetry reduces coverage rather than proving health or failure. Non-applicable checks do
not reduce coverage. Permission and environment visibility limitations remain scoped to the checks
they affect. Bounded samples support claims only about their observed interval.
