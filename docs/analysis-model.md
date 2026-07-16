# Analysis and Health Model

With a configured provider, LinuxMD combines normalized reports into a cross-report health
assessment. Deterministic fields remain authoritative; the provider primarily explains evidence,
prioritizes concerns, and proposes bounded recommendations.

## Health classifications

- `Healthy`: sufficient relevant evidence supports no active issue.
- `Healthy with observations`: no active issue is supported, but context, historical events,
  hardening findings, or coverage limitations merit mention.
- `Attention recommended`: a supported concern requires review without demonstrated outage.
- `Degraded`: correlated evidence supports current operational impact.
- `Unknown`: available evidence cannot support a stronger classification.

Subsystem status and evidence coverage are separate. Observable security findings can produce
`Attention` with partial coverage. Non-applicable checks do not reduce coverage.

## Concerns and observations

Active concerns represent currently supported problems. Historical events, corrected faults,
environment limitations, optional tools, and contextual hardening findings normally remain
observations unless evidence shows current impact.

## Confidence and time

LinuxMD records overall and temporal confidence. A short sample may characterize its sampled
interval but cannot establish persistence or long-term stability. Supported temporal scopes include
instantaneous, sampled interval, multi-sample trend, historical event, configuration state,
environment state, and unknown.

## Provenance and normalization

Findings use controlled `evidence_refs` paths validated against authoritative payload data.
Provider-created unrelated paths are removed or replaced. LinuxMD also narrows unsupported temporal
phrasing and replaces provider-authored platform facts with deterministic inventory.

## Fallback

Fallback output uses the same schema and semantic validator as provider output. It is conservative,
records `generation.mode=deterministic_fallback`, and is written atomically only after validation.
