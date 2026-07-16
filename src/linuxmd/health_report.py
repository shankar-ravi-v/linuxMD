"""Human-readable terminal formatting for normalized health assessments."""

from pathlib import Path
from typing import Any, Literal

from linuxmd.analysis_schema import SUBSYSTEMS

DISPLAY_HEALTH = {
    "healthy": "Healthy",
    "healthy_with_observations": "Healthy with observations",
    "attention_recommended": "Attention recommended",
    "attention": "Attention",
    "degraded": "Degraded",
    "unknown": "Unknown",
}


def format_health_assessment(
    result: dict[str, Any],
    *,
    provider: str,
    model: str,
    output_path: Path,
    detail_level: Literal["concise", "detailed"] = "concise",
) -> str:
    """Render normalized health data according to the requested display detail."""
    detailed = detail_level == "detailed"
    concerns = result["active_concerns"]
    lines = ["LinuxMD Health Assessment", ""]
    _section(lines, "Overall health")
    summary = _display_summary(result["assessment_summary"], has_concerns=bool(concerns))
    lines.extend([DISPLAY_HEALTH[result["overall_health"]], "", summary, ""])
    scope = result["assessment_scope"]
    _section(lines, "Assessment scope")
    lines.extend(
        [
            f"Environment:        {scope['environment']}",
            f"Measurement window: {scope['measurement_window']}",
            f"Workload state:     {scope['workload_state']}",
            f"Baseline:           {scope['baseline']}",
            "",
        ]
    )
    _section(lines, "Subsystem health")
    for name in SUBSYSTEMS:
        subsystem = result["subsystem_health"][name]
        status = DISPLAY_HEALTH[subsystem["status"]]
        if detailed:
            lines.append(
                f"{name.title():<10} {status} "
                f"({subsystem['coverage']} coverage): {subsystem['summary']}"
            )
        elif subsystem["status"] == "unknown":
            lines.append(f"{name.title():<10} {status} — insufficient telemetry")
        elif subsystem["status"] == "attention":
            lines.append(f"{name.title():<10} {status} — {subsystem['summary']}")
        else:
            lines.append(f"{name.title():<10} {status}")
        if detailed and subsystem["missing_metrics"]:
            lines.append(f"           Missing: {', '.join(subsystem['missing_metrics'])}")
        structured_limitations = subsystem.get("coverage_limitations", [])
        if detailed and structured_limitations:
            lines.append("           Limited:")
            lines.extend(
                f"             {item['item']} ({item['type'].replace('_', ' ')})"
                for item in structured_limitations
            )
        elif detailed and subsystem.get("limitations"):
            lines.append("           Limited:")
            lines.extend(f"             {item}" for item in subsystem["limitations"])
        if detailed and subsystem.get("not_applicable"):
            lines.append("           Not applicable:")
            lines.extend(f"             {item}" for item in subsystem["not_applicable"])
    lines.append("")
    _section(lines, "Performance assessment")
    lines.extend([result["performance_assessment"], ""])
    _section(lines, "Active concerns")
    if concerns:
        for number, concern in enumerate(concerns, 1):
            lines.append(
                f"{number}. {concern['title']} [{concern['severity']}; "
                f"{concern['assessment']}]: {concern['description']}"
            )
            if not detailed:
                for evidence in concern["evidence"]:
                    lines.append(f"   Evidence: {evidence}")
            if detailed:
                lines.append(f"   Temporal scope: {concern.get('temporal_scope', 'unknown')}")
                for reference in concern.get("evidence_refs", []):
                    lines.append(f"   Evidence ref: {reference}")
    else:
        lines.append("No active concerns were detected during the sampled interval.")
    lines.append("")
    if detailed:
        _section(lines, "Environment and historical observations")
        _number_items(
            lines,
            result["observations"],
            empty="No contextual or historical observations were recorded.",
            show_metadata=True,
        )
        lines.append("")
        correlations = result.get("correlations", [])
        if correlations:
            _section(lines, "Deterministic correlations")
            for correlation in correlations:
                lines.append(
                    f"{correlation['correlation_id']} [{correlation['temporal_scope']}]: "
                    + ", ".join(correlation["signals"])
                )
            lines.append("")
    _section(lines, "Recommended actions")
    _recommended_actions(
        lines,
        result["recommended_actions"],
        has_concerns=bool(concerns),
        detailed=detailed,
    )
    lines.append("")
    if detailed:
        _section(lines, "Evidence")
        evidence = [item for concern in concerns for item in concern["evidence"]]
        evidence.extend(
            item for observation in result["observations"] for item in observation["evidence"]
        )
        _number_strings(lines, evidence, empty="No additional evidence entries were supplied.")
        lines.append("")
    lines.extend(
        [
            f"Confidence: {result['confidence']}",
            *(
                [
                    "Temporal confidence: "
                    + result.get("evidence_qualification", {}).get("temporal_confidence", "unknown")
                ]
                if detailed
                else []
            ),
            f"Provider: {provider}",
            f"Model: {model}",
            "",
            f"Full JSON written to {output_path}",
        ]
    )
    return "\n".join(lines)


def _section(lines: list[str], title: str) -> None:
    lines.extend([title, "-" * len(title), ""])


def _number_strings(lines: list[str], values: list[str], *, empty: str) -> None:
    if not values:
        lines.append(empty)
        return
    for number, value in enumerate(values, 1):
        lines.append(f"{number}. {value}")


def _number_items(
    lines: list[str], values: list[dict[str, Any]], *, empty: str, show_metadata: bool = False
) -> None:
    if not values:
        lines.append(empty)
        return
    for number, value in enumerate(values, 1):
        lines.append(f"{number}. {value['title']}: {value['description']}")
        if show_metadata:
            lines.append(f"   Temporal scope: {value.get('temporal_scope', 'unknown')}")
            for reference in value.get("evidence_refs", []):
                lines.append(f"   Evidence ref: {reference}")


def _recommended_actions(
    lines: list[str],
    values: list[dict[str, str]],
    *,
    has_concerns: bool,
    detailed: bool,
) -> None:
    if not has_concerns:
        lines.append("Immediate remediation:")
        lines.append("  No immediate remediation is required.")
    if not values:
        return
    labels = {
        "immediate_remediation": "Immediate remediation",
        "diagnostic_follow_up": "Diagnostic follow-up",
        "hardening_review": "Optional hardening review",
    }
    for category, label in labels.items():
        if not detailed and category == "hardening_review":
            continue
        if not detailed and category == "diagnostic_follow_up" and not has_concerns:
            continue
        matching = [value for value in values if value["category"] == category]
        if not matching:
            continue
        lines.append(f"{label}:")
        for number, value in enumerate(matching, 1):
            lines.append(f"  {number}. {value['action']} — {value['rationale']}")


def _display_summary(summary: str, *, has_concerns: bool) -> str:
    """Suppress non-operational historical detail from the concise summary."""
    if has_concerns:
        return summary.strip()
    excluded = ("historical", "warning", "advisory", "recovery", "optional hardening")
    sentences = [sentence.strip() for sentence in summary.replace("\n", " ").split(".")]
    current = [
        sentence
        for sentence in sentences
        if sentence and not any(term in sentence.lower() for term in excluded)
    ]
    return ". ".join(current[:3]) + ("." if current else "")
