# Schemas and Evidence

LinuxMD reports use a versioned JSON envelope with a generation timestamp, diagnostic body, and
non-fatal error collection. Collector-specific content lives below `diagnostics` in raw collection
reports.

```json
{
  "schema_version": "1.1",
  "generated_at": "2026-07-13T20:00:00Z",
  "diagnostics": {
    "performance": {
      "sampling": {
        "duration_seconds": 5,
        "interval_seconds": 1,
        "sample_count": 5
      },
      "normalized_metrics": {},
      "findings": [],
      "warnings": []
    }
  },
  "errors": []
}
```

## Compatibility

Schema versions may evolve during the alpha period. Readers conservatively default newer analysis
metadata where practical; for example, older findings without provenance receive empty
`evidence_refs` and an `unknown` temporal scope. Unknown future fields remain tolerated where the
current report reader permits them.

## Evidence references

Final findings use stable machine-readable paths such as
`performance.normalized_metrics.scheduler_pressure.some.avg10` or
`security.kernel_hardening.apparmor.enabled`. LinuxMD validates references against local evidence
and finding-specific controlled mappings. Large values remain in source reports rather than being
copied into reference arrays.

## Temporal scope and coverage

Temporal scope distinguishes instantaneous facts, bounded samples, trends, historical events,
configuration state, and environment state. Coverage records genuine missing metrics separately
from permission, environment visibility, unsupported, and not-applicable checks. Not-applicable
checks do not reduce coverage.

`analysis.json` uses one shared shape for accepted provider output and deterministic fallback. It is
replaced atomically only after structural and semantic validation.
