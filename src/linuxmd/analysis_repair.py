"""Provider-independent validation and narrow normalization workflow."""

import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from linuxmd.analysis import (
    AnalysisValidationError,
    cpu_concern_has_pressure_evidence,
    cpu_concern_has_workload_impact,
    is_cpu_saturation_claim,
    validate_analysis,
    validate_analysis_structure,
)
from linuxmd.analysis_evidence import (
    conservative_fallback,
    derive_evidence_assessment,
    overlay_authoritative_fields,
)
from linuxmd.diagnostics.evidence import classify_bind_address


@dataclass(frozen=True, slots=True)
class AnalysisOutcome:
    """A validated result and internal normalization metadata."""

    result: dict[str, Any]
    normalization_notes: tuple[dict[str, str], ...] = ()
    provider_original: dict[str, Any] | None = None
    provider_repaired: dict[str, Any] | None = None
    fallback_used: bool = False
    warning: str | None = None


def analyze_once(provider: Any, payload: dict[str, Any], *, provider_name: str) -> AnalysisOutcome:
    """Apply deterministic authority, local narrowing, one repair, then fallback."""
    evidence = derive_evidence_assessment(payload)
    payload = deepcopy(payload)
    payload["authoritative_evidence_assessment"] = evidence
    generate = getattr(provider, "generate", None)
    original = generate(payload) if callable(generate) else provider.analyze(payload)
    candidate = overlay_authoritative_fields(original, evidence)
    validate_analysis_structure(candidate, provider=provider_name)
    notes = _authoritative_overlay_notes(original, candidate)
    candidate, summary_notes = normalize_malformed_summary(candidate, evidence)
    notes.extend(summary_notes)
    candidate, security_notes = normalize_security_wording(candidate)
    notes.extend(security_notes)
    candidate, temporal_notes = normalize_temporal_claims(candidate, evidence)
    notes.extend(temporal_notes)
    try:
        result = validate_analysis(candidate, provider=provider_name)
    except AnalysisValidationError as first_error:
        repair = getattr(provider, "repair", None)
        repaired = None
        if callable(repair):
            repaired = repair(
                candidate, [issue.to_dict() for issue in first_error.issues], evidence
            )
            try:
                repaired_candidate = overlay_authoritative_fields(repaired, evidence)
                validate_analysis_structure(repaired_candidate, provider=provider_name)
                repaired_candidate, summary_notes = normalize_malformed_summary(
                    repaired_candidate, evidence
                )
                repaired_candidate, security_notes = normalize_security_wording(repaired_candidate)
                repaired_candidate, repair_notes = normalize_temporal_claims(
                    repaired_candidate, evidence
                )
                result = validate_analysis(repaired_candidate, provider=provider_name)
                return AnalysisOutcome(
                    result,
                    normalization_notes=tuple(
                        [*notes, *summary_notes, *security_notes, *repair_notes]
                    ),
                    provider_original=original,
                    provider_repaired=repaired,
                )
            except AnalysisValidationError:
                pass
        fallback_candidate = conservative_fallback(
            evidence, provider=provider_name, reason="semantic_validation_failed"
        )
        try:
            fallback = validate_analysis(
                fallback_candidate,
                provider="deterministic_fallback",
            )
        except AnalysisValidationError as fallback_error:
            raise AnalysisValidationError(
                "internal deterministic fallback",
                fallback_error.kind,
                fallback_error.issues,
                fallback_candidate,
            ) from fallback_error
        return AnalysisOutcome(
            fallback,
            normalization_notes=tuple(notes),
            provider_original=original,
            provider_repaired=repaired,
            fallback_used=True,
            warning="Provider output failed semantic validation; deterministic fallback generated.",
        )
    return AnalysisOutcome(
        result,
        normalization_notes=tuple(notes),
        provider_original=original if notes else None,
    )


def normalize_malformed_summary(
    response: dict[str, Any], evidence: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Remove provider-authored environment restatements from the health summary."""
    normalized = deepcopy(response)
    summary = normalized.get("assessment_summary")
    if not isinstance(summary, str) or not _contains_environment_text(summary):
        return normalized, []
    interpretation = _health_interpretation(summary)
    replacement = interpretation or _deterministic_health_summary(normalized, evidence)
    if replacement == summary:
        return normalized, []
    normalized["assessment_summary"] = replacement
    return normalized, [
        {
            "path": "assessment_summary",
            "from": summary,
            "to": replacement,
            "reason": (
                "malformed_or_truncated_environment_restatement_removed"
                if _summary_is_malformed(summary)
                else "provider_environment_restatement_removed"
            ),
        }
    ]


def normalize_version_spacing(text: str) -> str:
    """Remove whitespace only between components of dotted numeric versions."""
    return re.sub(r"(?<=\d)\.\s+(?=\d)", ".", text)


def _contains_environment_text(summary: str) -> bool:
    return bool(
        re.search(
            r"\b(?:WSL2?|Ubuntu|Linux\s+kernel|kernel\s+\d|virtual\s+machine|container)\b",
            summary,
            re.IGNORECASE,
        )
    )


def _health_interpretation(summary: str) -> str:
    """Return provider health prose that follows an environment introduction."""
    text = normalize_version_spacing(summary.strip())
    boundary = re.search(
        r"[.!?;]\s+(?=(?:Healthy|Unhealthy|No\s+active|No\s+CPU|CPU\s+pressure|"
        r"Memory|Storage|Network|Overall|The\s+assessment)\b)",
        text,
        re.IGNORECASE,
    )
    return text[boundary.end() :].strip() if boundary else ""


def _deterministic_health_summary(response: dict[str, Any], evidence: dict[str, Any]) -> str:
    """Describe health conservatively when provider prose only repeats platform facts."""
    if response.get("active_concerns"):
        return "Active operational concerns were identified and are documented below."
    coverage = evidence.get("evidence_coverage", {})
    limited = [
        name
        for name in ("storage", "network")
        if isinstance(coverage.get(name), dict) and coverage[name].get("coverage") != "sufficient"
    ]
    summary = "No active operational issues were detected during the sampled interval."
    if limited:
        names = " and ".join(limited)
        summary += f" Limited {names} telemetry is documented below."
    return summary


def _summary_is_malformed(summary: str) -> bool:
    text = summary.strip()
    if not text or text.count("(") != text.count(")"):
        return True
    if re.search(r"\b\d+\.\s+\d+\b", text):
        return True
    if re.search(r"\b(?:kernel|version)\s+\d+\.\s*\d+\.?$", text, re.IGNORECASE):
        return True
    return text[-1] not in ".!?)]"


def _authoritative_overlay_notes(
    original: dict[str, Any], overlaid: dict[str, Any]
) -> list[dict[str, str]]:
    notes = []
    before = original.get("subsystem_health", {}).get("cpu", {})
    after = overlaid.get("subsystem_health", {}).get("cpu", {})
    for field in ("status", "coverage", "missing_metrics"):
        if before.get(field) != after.get(field):
            notes.append(
                {
                    "path": f"subsystem_health.cpu.{field}",
                    "from": str(before.get(field)),
                    "to": str(after.get(field)),
                    "reason": "authoritative_evidence_overlay",
                }
            )
    return notes


def normalize_temporal_claims(
    response: dict[str, Any], evidence: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Narrow unsupported persistence wording without changing numbers or evidence."""
    normalized = deepcopy(response)
    if evidence.get("supports_persistence_claims") or evidence.get(
        "observed_pressure_flags", {}
    ).get("cpu"):
        return normalized, []
    notes: list[dict[str, str]] = []
    paths = [
        ("assessment_summary", normalized),
        ("performance_assessment", normalized),
        ("subsystem_health.cpu.summary", normalized.get("subsystem_health", {}).get("cpu", {})),
    ]
    for group_name in ("active_concerns", "observations"):
        for index, item in enumerate(normalized.get(group_name, [])):
            if item.get("temporal_scope") in {
                "multi_sample_trend",
                "configuration_state",
                "environment_state",
            }:
                continue
            paths.extend(
                (
                    (f"{group_name}[{index}].title", item),
                    (f"{group_name}[{index}].description", item),
                )
            )
    for path, owner in paths:
        key = path.rsplit(".", 1)[-1]
        value = owner.get(key) if isinstance(owner, dict) else None
        if not isinstance(value, str):
            continue
        revised = re.sub(
            r"\bno\s+(?:sustained|persistent|ongoing)\s+(?:scheduler\s+)?pressure\b",
            "no pressure was observed during the sampled interval",
            value,
            flags=re.IGNORECASE,
        )
        revised = re.sub(
            r"\bCPU\s+remained\s+idle\b",
            "CPU was idle during the sampled interval",
            revised,
            flags=re.IGNORECASE,
        )
        revised = re.sub(
            r"\bCPU\s+is\s+consistently\s+healthy\b",
            "No CPU issue was observed during the sampled interval",
            revised,
            flags=re.IGNORECASE,
        )
        if revised != value:
            owner[key] = revised
            notes.append(
                {
                    "path": path,
                    "from": value,
                    "to": revised,
                    "reason": "unsupported_persistence_claim",
                }
            )
    return normalized, notes


def normalize_security_wording(
    response: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Narrow unsupported broad compromise-detection claims in provider prose."""
    normalized = deepcopy(response)
    notes: list[dict[str, str]] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, str):
                    revised = re.sub(
                        r"\bNo active compromise (?:was )?detected\.?",
                        "No evidence of active compromise was found in the collected diagnostics.",
                        item,
                        flags=re.IGNORECASE,
                    )
                    if "localhost" in revised.lower():
                        revised = re.sub(
                            r"Listening sockets are all on localhost/private addresses\.?",
                            "Observed listeners were bound to loopback or private/internal "
                            "addresses; reachability was not assessed.",
                            revised,
                            flags=re.IGNORECASE,
                        )
                        for address in re.findall(
                            r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", revised
                        ):
                            if classify_bind_address(address) != "loopback":
                                revised = re.sub(
                                    rf"[^.!?]*\b{re.escape(address)}\b[^.!?]*"
                                    r"\blocalhost(?:-only)?\b[^.!?]*[.!?]?",
                                    " No clearly world-facing listening socket was identified; "
                                    "bind addresses alone do not establish reachability.",
                                    revised,
                                    flags=re.IGNORECASE,
                                ).strip()
                    if revised != item:
                        value[key] = revised
                        notes.append(
                            {
                                "path": f"{path}.{key}".lstrip("."),
                                "from": item,
                                "to": revised,
                                "reason": "bounded_security_scope",
                            }
                        )
                else:
                    visit(item, f"{path}.{key}".lstrip("."))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")

    visit(normalized, "")
    return normalized, notes


def normalize_coverage_statuses(
    response: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Convert unsupported healthy conclusions to unknown without hiding active faults."""
    normalized = deepcopy(response)
    notes: list[dict[str, str]] = []
    concerns = normalized.get("active_concerns", [])
    for name, subsystem in normalized.get("subsystem_health", {}).items():
        coverage = subsystem.get("coverage")
        if (
            subsystem.get("status") != "healthy"
            or coverage not in {"partial", "limited", "insufficient"}
            or any(_concern_mentions_subsystem(item, name) for item in concerns)
        ):
            continue
        subsystem["status"] = "unknown"
        notes.append(
            {
                "path": f"subsystem_health.{name}.status",
                "from": "healthy",
                "to": "unknown",
                "reason": f"Coverage was {coverage}.",
            }
        )
    return normalized, notes


def _concern_mentions_subsystem(concern: Any, subsystem: str) -> bool:
    if not isinstance(concern, dict):
        return False
    text = " ".join(
        [
            str(concern.get("title", "")),
            str(concern.get("description", "")),
            *(str(item) for item in concern.get("evidence", [])),
        ]
    ).lower()
    aliases = {"cpu": ("cpu", "processor", "scheduler"), "memory": ("memory", "swap", "reclaim")}
    return any(term in text for term in aliases.get(subsystem, (subsystem,)))


def normalize_safe_inconsistencies(
    response: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Normalize only explicit status/coverage contradictions without changing evidence."""
    normalized = deepcopy(response)
    notes = []
    subsystems = normalized.get("subsystem_health")
    if not isinstance(subsystems, dict):
        return normalized, notes
    concerns = normalized.get("active_concerns")
    observations = normalized.get("observations")
    moved_cpu_claim = False
    downgraded_confirmed_cpu = False
    if isinstance(concerns, list) and isinstance(observations, list):
        retained = []
        for index, concern in enumerate(concerns):
            if (
                isinstance(concern, dict)
                and is_cpu_saturation_claim(concern)
                and not cpu_concern_has_pressure_evidence(concern)
            ):
                observations.append(
                    {
                        "title": "High CPU utilization during sampled interval",
                        "description": (
                            "High CPU utilization was observed during the sampled interval, but "
                            "the supplied scheduler and capacity-pressure evidence does not "
                            "establish CPU saturation or scheduler contention."
                        ),
                        "evidence": deepcopy(concern.get("evidence", [])),
                    }
                )
                notes.append(
                    {
                        "path": f"active_concerns[{index}]",
                        "action": "moved_to_observations",
                        "reason": "unsupported_cpu_saturation_claim",
                    }
                )
                moved_cpu_claim = True
            else:
                if (
                    isinstance(concern, dict)
                    and is_cpu_saturation_claim(concern)
                    and concern.get("assessment") == "confirmed_issue"
                    and cpu_concern_has_pressure_evidence(concern)
                    and not cpu_concern_has_workload_impact(concern)
                ):
                    concern["assessment"] = "likely_issue"
                    concern["title"] = "Temporary CPU pressure during sampled interval"
                    concern["description"] = (
                        "CPU capacity-pressure evidence was observed during the sampled interval, "
                        "but no measured workload impact established a confirmed bottleneck."
                    )
                    notes.append(
                        {
                            "path": f"active_concerns[{index}].assessment",
                            "from": "confirmed_issue",
                            "to": "likely_issue",
                            "reason": "confirmed_cpu_bottleneck_requires_impact",
                        }
                    )
                    downgraded_confirmed_cpu = True
                retained.append(concern)
        normalized["active_concerns"] = retained
    remaining = normalized.get("active_concerns", [])
    remaining_cpu_concern = any(
        isinstance(item, dict) and _is_cpu_concern(item) for item in remaining
    )
    if downgraded_confirmed_cpu:
        cpu = subsystems.get("cpu", {})
        if cpu.get("status") == "degraded":
            cpu["status"] = "attention"
            cpu["summary"] = (
                "CPU pressure was observed during the sampled interval, but no measured workload "
                "impact established a confirmed bottleneck."
            )
            notes.append(
                {
                    "path": "subsystem_health.cpu.status",
                    "from": "degraded",
                    "to": "attention",
                    "reason": "confirmed_cpu_bottleneck_requires_impact",
                }
            )
        if normalized.get("overall_health") == "degraded" and not any(
            item.get("assessment") == "confirmed_issue" for item in remaining
        ):
            normalized["overall_health"] = "attention_recommended"
            notes.append(
                {
                    "path": "overall_health",
                    "from": "degraded",
                    "to": "attention_recommended",
                    "reason": "confirmed_cpu_bottleneck_requires_impact",
                }
            )
    if moved_cpu_claim:
        cpu = subsystems.get("cpu", {})
        if not remaining_cpu_concern and cpu.get("status") in {"attention", "degraded"}:
            old_status = cpu["status"]
            cpu["status"] = "healthy" if cpu.get("coverage") == "sufficient" else "unknown"
            cpu["summary"] = (
                "High CPU utilization was observed, but saturation was not established."
            )
            notes.append(
                {
                    "path": "subsystem_health.cpu.status",
                    "from": old_status,
                    "to": cpu["status"],
                    "reason": "unsupported_cpu_saturation_claim",
                }
            )
        old_overall = normalized.get("overall_health")
        if not remaining:
            normalized["overall_health"] = "healthy_with_observations"
        elif any(item.get("assessment") == "confirmed_issue" for item in remaining):
            normalized["overall_health"] = "degraded"
        else:
            normalized["overall_health"] = "attention_recommended"
        if old_overall != normalized["overall_health"]:
            notes.append(
                {
                    "path": "overall_health",
                    "from": str(old_overall),
                    "to": normalized["overall_health"],
                    "reason": "unsupported_cpu_saturation_claim_removed",
                }
            )
        if not remaining:
            normalized["assessment_summary"] = (
                "High CPU utilization was observed during the sampled interval, but no current "
                "operational CPU issue was established."
            )
        if not remaining_cpu_concern:
            normalized["performance_assessment"] = _remove_unsupported_cpu_claims(
                str(normalized.get("performance_assessment", ""))
            )
    for name, subsystem in subsystems.items():
        if not isinstance(subsystem, dict):
            continue
        if subsystem.get("status") == "healthy" and subsystem.get("coverage") == "insufficient":
            subsystem["status"] = "unknown"
            summary = str(subsystem.get("summary", "")).rstrip().rstrip(".")
            qualifier = f"Available telemetry was insufficient to assess {name} health."
            if "insufficient" not in summary.lower():
                subsystem["summary"] = f"{summary}, but {qualifier[0].lower() + qualifier[1:]}"
            notes.append(
                {
                    "path": f"subsystem_health.{name}.status",
                    "from": "healthy",
                    "to": "unknown",
                    "reason": "healthy_requires_sufficient_coverage",
                }
            )
    return normalized, notes


def _remove_unsupported_cpu_claims(assessment: str) -> str:
    claim_terms = (
        "cpu saturation",
        "cpu bottleneck",
        "scheduler contention",
        "severe cpu pressure",
        "exhausted cpu capacity",
    )
    sentences = [item.strip() for item in assessment.replace("\n", " ").split(".") if item.strip()]
    replacement = (
        "High CPU utilization was observed during the sampled interval, but saturation and "
        "scheduler contention were not established"
    )
    rewritten = []
    replaced = False
    for sentence in sentences:
        if any(term in sentence.lower() for term in claim_terms):
            if not replaced:
                rewritten.append(replacement)
                replaced = True
            continue
        rewritten.append(sentence)
    return ". ".join(rewritten) + "."


def _is_cpu_concern(concern: dict[str, Any]) -> bool:
    text = " ".join(
        [
            str(concern.get("title", "")),
            str(concern.get("description", "")),
            *(str(item) for item in concern.get("evidence", [])),
        ]
    ).lower()
    return "cpu" in text or "scheduler" in text
