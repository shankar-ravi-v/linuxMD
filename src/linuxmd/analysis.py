"""Load diagnostic reports and validate structured LLM analyses."""

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from linuxmd.analysis_schema import ANALYSIS_SCHEMA
from linuxmd.paths import output_directory, project_root
from linuxmd.workflows import (
    DIAG_FILE,
    PERFORMANCE_FILE,
    SECURITY_ANALYSIS_FILE,
    SECURITY_FILE,
)


class AnalysisError(Exception):
    """A user-facing analysis failure that should not produce a traceback."""


class MissingReportError(AnalysisError):
    """A required input report does not exist."""


class InvalidReportError(AnalysisError):
    """A required input report is not valid JSON."""


class ProviderError(AnalysisError):
    """An LLM provider could not return a usable analysis."""


class ProviderJSONDecodeError(ProviderError):
    """A provider response could not be decoded as analysis JSON."""

    def __init__(self, message: str, *, raw_response: str | None = None) -> None:
        self.raw_response = raw_response
        super().__init__(message)


class ProviderRequestError(ProviderError):
    """A categorized provider transport or HTTP failure."""

    def __init__(
        self,
        provider: str,
        category: str,
        message: str,
        *,
        status: int | None = None,
        endpoint: str | None = None,
        timeout: float | None = None,
        retried: bool = False,
        attempt_failures: tuple[str, ...] = (),
    ) -> None:
        self.provider = provider
        self.category = category
        self.status = status
        self.endpoint = endpoint
        self.timeout = timeout
        self.retried = retried
        self.attempt_failures = attempt_failures
        if attempt_failures:
            history = "\n".join(f"  {failure}" for failure in attempt_failures)
            message = f"{message}\nAttempt history:\n{history}"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One machine-readable structural or semantic validation failure."""

    path: str
    code: str
    message: str
    current_value: Any = None
    expected: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "code": self.code,
            "message": self.message,
            "current_value": self.current_value,
            "expected": self.expected,
        }


class AnalysisValidationError(ProviderError):
    """A decoded response failed structural or semantic validation."""

    def __init__(
        self, provider: str, kind: str, issues: list[ValidationIssue], response: Any
    ) -> None:
        self.provider = provider
        self.kind = kind
        self.issues = issues
        self.response = response
        super().__init__(
            f"{provider} response failed {kind} validation: "
            + "; ".join(issue.message for issue in issues)
        )


ReportStatus = Literal["valid", "missing", "invalid", "unreadable"]


@dataclass(frozen=True, slots=True)
class ReportInspection:
    """Validation state and decoded content for one expected report."""

    label: str
    path: Path
    status: ReportStatus
    content: Any = None


EXPECTED_REPORTS = (
    ("System inventory", DIAG_FILE),
    ("Performance diagnostics", PERFORMANCE_FILE),
    ("Security collection", SECURITY_FILE),
    ("Security analysis", SECURITY_ANALYSIS_FILE),
)


def inspect_analysis_reports(project_dir: Path | None = None) -> list[ReportInspection]:
    """Inspect every expected report without requiring any one report to exist."""
    root = project_root(project_dir) if project_dir else project_root()
    output_dir = output_directory(root)
    inspections = []
    for label, filename in EXPECTED_REPORTS:
        path = output_dir / filename.name
        if not path.exists():
            inspections.append(ReportInspection(label, path, "missing"))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            inspections.append(ReportInspection(label, path, "invalid"))
            continue
        except OSError:
            inspections.append(ReportInspection(label, path, "unreadable"))
            continue
        try:
            content = json.loads(text)
        except json.JSONDecodeError:
            inspections.append(ReportInspection(label, path, "invalid"))
            continue
        inspections.append(ReportInspection(label, path, "valid", content))
    return inspections


def discover_analysis_payload(
    project_dir: Path | None = None,
) -> tuple[dict[str, Any], list[Path], list[Path]]:
    """Discover valid normalized reports and separately identify missing or invalid inputs."""
    inspections = inspect_analysis_reports(project_dir)
    reports = {item.path.name: item.content for item in inspections if item.status == "valid"}
    missing = [item.path for item in inspections if item.status == "missing"]
    invalid = [item.path for item in inspections if item.status in {"invalid", "unreadable"}]
    if not reports:
        details = f"No valid analysis reports found in: {inspections[0].path.parent}"
        if invalid:
            details += "; invalid: " + ", ".join(path.name for path in invalid)
        raise MissingReportError(details)
    return {"reports": reports}, missing, invalid


def load_analysis_payload(project_dir: Path | None = None) -> dict[str, Any]:
    """Load the valid normalized report payload."""
    payload, _, _ = discover_analysis_payload(project_dir)
    return payload


def validate_analysis(result: Any, *, provider: str) -> dict[str, Any]:
    """Validate and normalize the provider's structured response."""
    result = _with_provenance_defaults(result)
    structural = _structural_issues(result)
    if structural:
        raise AnalysisValidationError(provider, "structural", structural, result)
    semantic = semantic_validation_errors(result)
    if semantic:
        raise AnalysisValidationError(provider, "semantic", semantic, result)
    return {field: result[field] for field in ANALYSIS_SCHEMA["properties"] if field in result}


def validate_analysis_structure(result: Any, *, provider: str) -> dict[str, Any]:
    """Validate only the shared JSON structure, leaving semantics to the workflow."""
    result = _with_provenance_defaults(result)
    structural = _structural_issues(result)
    if structural:
        raise AnalysisValidationError(provider, "structural", structural, result)
    return result


def _with_provenance_defaults(result: Any) -> Any:
    """Upgrade older analysis objects conservatively before schema validation."""
    if not isinstance(result, dict):
        return result
    upgraded = deepcopy(result)
    upgraded.setdefault("correlations", [])
    upgraded.setdefault(
        "evidence_qualification",
        {
            "temporal_confidence": "low",
            "overall_assessment_confidence": upgraded.get("confidence", "low"),
        },
    )
    for concern in upgraded.get("active_concerns", []):
        if isinstance(concern, dict):
            concern.setdefault("evidence_refs", [])
            concern.setdefault("temporal_scope", "unknown")
    for observation in upgraded.get("observations", []):
        if isinstance(observation, dict):
            observation.setdefault("evidence_refs", [])
            observation.setdefault("temporal_scope", "unknown")
    return upgraded


def semantic_validation_errors(result: dict[str, Any]) -> list[ValidationIssue]:
    """Return every cross-field inconsistency in a structurally valid response."""
    issues: list[ValidationIssue] = []
    subsystems = result["subsystem_health"]
    for name, subsystem in subsystems.items():
        guest_kernel_partial = (
            name == "kernel"
            and subsystem["coverage"] == "partial"
            and "guest-visible" in subsystem["summary"].lower()
        )
        if (
            subsystem["status"] == "healthy"
            and subsystem["coverage"] != "sufficient"
            and not guest_kernel_partial
        ):
            issues.append(
                ValidationIssue(
                    f"subsystem_health.{name}.status",
                    "healthy_requires_sufficient_coverage",
                    f"{name.title()} cannot be healthy when coverage is {subsystem['coverage']}.",
                    "healthy",
                    "unknown or attention",
                )
            )
        non_metric_limitations = subsystem.get("coverage_limitations") or subsystem.get(
            "limitations", []
        )
        unexplained_incomplete_coverage = (
            subsystem["coverage"] != "sufficient"
            and not subsystem["missing_metrics"]
            and not non_metric_limitations
        )
        if unexplained_incomplete_coverage:
            issues.append(
                ValidationIssue(
                    f"subsystem_health.{name}.missing_metrics",
                    "incomplete_coverage_requires_missing_metrics",
                    f"{name.title()} must identify missing metrics when coverage is incomplete.",
                    [],
                    "one or more missing metric names",
                )
            )
    overall = result["overall_health"]
    concerns = result["active_concerns"]
    observations = result["observations"]
    hardening = any(
        action["category"] == "hardening_review" for action in result["recommended_actions"]
    )
    incomplete = any(item["coverage"] != "sufficient" for item in subsystems.values())
    if overall == "healthy" and (concerns or observations or hardening or incomplete):
        issues.append(
            ValidationIssue(
                "overall_health",
                "healthy_requires_clean_supported_assessment",
                "Overall health cannot be healthy with concerns, observations, or coverage gaps.",
                overall,
                "healthy_with_observations, attention_recommended, degraded, or unknown",
            )
        )
    if overall == "healthy_with_observations" and concerns:
        issues.append(
            ValidationIssue(
                "overall_health",
                "healthy_cannot_have_active_concerns",
                "Overall health cannot be healthy while active concerns exist.",
                overall,
                "attention_recommended or degraded",
            )
        )
    if overall == "attention_recommended" and not concerns:
        issues.append(
            ValidationIssue(
                "overall_health",
                "attention_requires_active_concern",
                "Attention recommended requires an active concern.",
                overall,
                "healthy_with_observations or unknown",
            )
        )
    if overall == "degraded" and not concerns:
        issues.append(
            ValidationIssue(
                "overall_health",
                "degraded_requires_active_concern",
                "Degraded health requires an active concern.",
                overall,
                "unknown or attention_recommended",
            )
        )
    if result["confidence"] == "high" and any(
        subsystem["coverage"] != "sufficient" for subsystem in subsystems.values()
    ):
        issues.append(
            ValidationIssue(
                "confidence",
                "high_confidence_requires_broad_coverage",
                "Confidence cannot be high when subsystem coverage is incomplete.",
                "high",
                "low or medium",
            )
        )
    window = result["assessment_scope"]["measurement_window"]
    duration = re.search(r"\b(\d+(?:\.\d+)?)\s*seconds?\b", window, re.IGNORECASE)
    if result["confidence"] == "high" and duration and float(duration.group(1)) < 60:
        issues.append(
            ValidationIssue(
                "confidence",
                "high_confidence_requires_adequate_duration",
                "Confidence cannot be high for a short measurement window.",
                "high",
                "low or medium",
            )
        )
    if any(subsystem["status"] == "degraded" for subsystem in subsystems.values()) and not any(
        concern["evidence"] for concern in concerns
    ):
        issues.append(
            ValidationIssue(
                "subsystem_health",
                "concern_status_requires_supporting_evidence",
                "Attention or degraded subsystem status requires supporting concern evidence.",
                "attention or degraded",
                "an active concern with evidence",
            )
        )
    if any(subsystem["status"] == "attention" for subsystem in subsystems.values()) and not (
        any(concern["evidence"] for concern in concerns)
        or any(observation["evidence"] for observation in observations)
    ):
        issues.append(
            ValidationIssue(
                "subsystem_health",
                "attention_requires_supporting_evidence",
                "Attention subsystem status requires concern or observation evidence.",
                "attention",
                "supporting concern or observation evidence",
            )
        )
    for index, concern in enumerate(concerns):
        if (
            concern["assessment"] in {"likely_issue", "confirmed_issue"}
            and len(concern["evidence"]) < 2
        ):
            issues.append(
                ValidationIssue(
                    f"active_concerns[{index}].evidence",
                    "issue_requires_correlated_evidence",
                    "Likely or confirmed issues require at least two correlated evidence items.",
                    concern["evidence"],
                    "at least two independent evidence items",
                )
            )
    cpu_concerns = [
        (index, concern) for index, concern in enumerate(concerns) if _is_cpu_concern(concern)
    ]
    cpu_evidence = _cpu_evidence_text(result)
    if (
        subsystems["cpu"]["status"] == "healthy"
        and _has_near_zero_idle(cpu_evidence)
        and _has_run_queue_above_capacity(cpu_evidence)
    ):
        issues.append(
            ValidationIssue(
                "subsystem_health.cpu.status",
                "cpu_healthy_conflicts_with_capacity_pressure",
                "CPU cannot be healthy when near-zero idle and run queue above capacity "
                "are observed.",
                "healthy",
                "attention or degraded",
            )
        )
    if cpu_concerns and subsystems["cpu"]["status"] == "healthy":
        issues.append(
            ValidationIssue(
                "subsystem_health.cpu.status",
                "cpu_healthy_conflicts_with_active_concern",
                "CPU cannot be healthy while an active CPU concern exists.",
                "healthy",
                "attention or degraded",
            )
        )
    for name, subsystem in subsystems.items():
        if name == "cpu" or subsystem["status"] != "healthy":
            continue
        if any(_concern_mentions_subsystem(concern, name) for concern in concerns):
            issues.append(
                ValidationIssue(
                    f"subsystem_health.{name}.status",
                    "healthy_conflicts_with_active_concern",
                    f"{name.title()} cannot be healthy while an active {name} concern exists.",
                    "healthy",
                    "attention or degraded",
                )
            )
    for index, concern in cpu_concerns:
        claims_issue = concern["assessment"] in {
            "likely_issue",
            "confirmed_issue",
        } or is_cpu_saturation_claim(concern)
        if claims_issue and not cpu_concern_has_pressure_evidence(concern):
            issues.append(
                ValidationIssue(
                    f"active_concerns[{index}]",
                    "cpu_saturation_requires_pressure_evidence",
                    "CPU saturation requires explicit scheduler or capacity-pressure evidence.",
                    concern["title"],
                    "run-queue, PSI, scheduling-delay, capacity-relative load, or impact evidence",
                )
            )
        if concern["assessment"] == "confirmed_issue" and not cpu_concern_has_workload_impact(
            concern
        ):
            issues.append(
                ValidationIssue(
                    f"active_concerns[{index}].assessment",
                    "confirmed_cpu_bottleneck_requires_impact",
                    "A confirmed CPU bottleneck requires measured workload or scheduling impact.",
                    "confirmed_issue",
                    "likely_issue unless measured impact is present",
                )
            )
    assessment = result["performance_assessment"].lower()
    positive_cpu_claim = _performance_claims_cpu_pressure(assessment)
    if subsystems["cpu"]["status"] == "healthy" and positive_cpu_claim:
        issues.append(
            ValidationIssue(
                "performance_assessment",
                "cpu_healthy_conflicts_with_pressure_assessment",
                "A healthy CPU status conflicts with a positive CPU pressure assessment.",
                result["performance_assessment"],
                "consistent CPU status and performance assessment",
            )
        )
    if not concerns and _summary_claims_active_problem(result["assessment_summary"]):
        issues.append(
            ValidationIssue(
                "assessment_summary",
                "summary_active_problem_requires_concern",
                "The assessment summary claims an active problem when no active concerns exist.",
                result["assessment_summary"],
                "a summary without active degradation or attention wording",
            )
        )
    if duration and float(duration.group(1)) <= 5 and not _has_repeated_sample_support(result):
        for path, text in _conclusion_texts(result):
            if re.search(r"\b(?:persistent|sustained|ongoing)\b", text, re.IGNORECASE):
                issues.append(
                    ValidationIssue(
                        path,
                        "short_sample_prohibits_persistence_claim",
                        "A five-second sample cannot support persistence wording without "
                        "repeated-sample evidence.",
                        text,
                        "language bounded to the sampled interval",
                    )
                )
    if (
        any(
            action["category"] == "immediate_remediation"
            for action in result["recommended_actions"]
        )
        and not concerns
    ):
        issues.append(
            ValidationIssue(
                "recommended_actions",
                "immediate_remediation_requires_active_concern",
                "Immediate remediation requires an active concern.",
                "immediate_remediation",
                "diagnostic_follow_up or hardening_review",
            )
        )
    return issues


def _is_cpu_concern(concern: dict[str, Any]) -> bool:
    text = " ".join([concern["title"], concern["description"], *concern["evidence"]]).lower()
    return "cpu" in text or "scheduler" in text


def _concern_mentions_subsystem(concern: dict[str, Any], subsystem: str) -> bool:
    text = " ".join([concern["title"], concern["description"], *concern["evidence"]]).lower()
    aliases = {"memory": ("memory", "swap", "reclaim")}
    return any(term in text for term in aliases.get(subsystem, (subsystem,)))


def is_cpu_saturation_claim(concern: dict[str, Any]) -> bool:
    """Return whether concern language asserts CPU saturation or contention."""
    text = f"{concern['title']} {concern['description']}".lower()
    return any(
        phrase in text
        for phrase in (
            "cpu saturation",
            "cpu bottleneck",
            "scheduler contention",
            "severe cpu pressure",
            "exhausted cpu capacity",
        )
    )


def cpu_concern_has_pressure_evidence(concern: dict[str, Any]) -> bool:
    """Require capacity-relative scheduler or direct workload-impact evidence."""
    text = " ".join(concern["evidence"]).lower()
    phrases = (
        "run queue exceeded",
        "run queue above",
        "run_queue_ratio > 1",
        "run_queue_ratio above 1",
        "runnable demand exceeded",
        "runnable demand above effective",
        "scheduler psi",
        "scheduling delay",
        "scheduler backlog",
        "queue growth",
        "effective cpu quota exceeded",
        "workload latency",
        "throughput impact",
        "deadline miss",
        "load ratio above 1",
    )
    if any(phrase in text for phrase in phrases):
        return True

    run_queue_ratios = re.findall(r"\brun_queue_ratio\s*=\s*(\d+(?:\.\d+)?)", text)
    if any(float(value) > 1.0 for value in run_queue_ratios):
        return True

    run_queue_depths = re.findall(
        r"\brun[ _-]?queue depth(?: average)?\s*(?:[=:]\s*)?"
        r"(\d+(?:\.\d+)?)\s+on\s+(\d+(?:\.\d+)?)\s+cpus?\b",
        text,
    )
    if any(float(depth) > float(cpus) for depth, cpus in run_queue_depths):
        return True

    psi_some_avg10 = re.findall(
        r"\b(?:psi|scheduler(?:[._ -]+(?:psi|pressure))?|cpu[._ -]+pressure)"
        r"[._ -]+some[._ -]+avg10\s*[=:]\s*(\d+(?:\.\d+)?)",
        text,
    )
    if any(float(value) > 0 for value in psi_some_avg10):
        return True

    load = re.search(r"load average\D+(\d+(?:\.\d+)?)", text)
    cpus = re.search(r"(\d+)\s+(?:logical|effective) cpus", text)
    return bool(load and cpus and float(load.group(1)) > int(cpus.group(1)))


def cpu_concern_has_workload_impact(concern: dict[str, Any]) -> bool:
    """Return whether evidence establishes direct workload or scheduling impact."""
    text = " ".join(concern["evidence"]).lower()
    direct_impact = any(
        phrase in text
        for phrase in (
            "workload latency",
            "application latency",
            "throughput loss",
            "throughput decreased",
            "throughput degradation",
            "scheduling delay",
            "deadline miss",
            "responsiveness degradation",
            "persistent scheduler backlog",
        )
    ) or bool(re.search(r"(?:latency|response time).*(?:increased|regressed|above baseline)", text))
    repeated = re.search(r"\b(\d+)\s+(?:of|/)\s*(\d+)\s+samples?\b", text)
    longer_pattern = bool(repeated and int(repeated.group(2)) >= 30)
    return direct_impact or longer_pattern


def _cpu_evidence_text(result: dict[str, Any]) -> str:
    cpu = result["subsystem_health"]["cpu"]
    parts = [cpu["summary"], result["performance_assessment"]]
    for group in (result["active_concerns"], result["observations"]):
        for item in group:
            parts.extend([item["title"], item["description"], *item["evidence"]])
    return " ".join(parts).lower()


def _has_near_zero_idle(text: str) -> bool:
    percentages = re.findall(
        r"(?:idle(?:_pct)?\s*[=:]?|cpu idle\s*[=:]?)\s*(\d+(?:\.\d+)?)\s*%", text
    )
    ratios = re.findall(r"cpu_idle_ratio\s*[=:]\s*(\d+(?:\.\d+)?)", text)
    return any(float(value) <= 2 for value in percentages) or any(
        float(value) <= 0.02 for value in ratios
    )


def _has_run_queue_above_capacity(text: str) -> bool:
    ratios = re.findall(r"run_queue_ratio\s*[=:]\s*(\d+(?:\.\d+)?)", text)
    return any(float(value) > 1 for value in ratios) or bool(
        re.search(
            r"run[_ -]?queue(?: ratio)?.*(?:above|exceed(?:ed|s)?)\s*(?:capacity|1(?:\.0+)?)", text
        )
    )


def _summary_claims_active_problem(summary: str) -> bool:
    return bool(
        re.search(
            r"\b(?:requires attention|attention is required|is degraded|"
            r"active (?:cpu )?bottleneck)\b",
            summary,
            re.IGNORECASE,
        )
    )


def _performance_claims_cpu_pressure(assessment: str) -> bool:
    pattern = re.compile(
        r"\b(?:cpu|scheduler) (?:pressure|saturation|contention|bottleneck) "
        r"(?:exists|occurred|was observed|was detected|is present)\b"
    )
    for sentence in re.split(r"(?<=[.!?])\s+", assessment):
        if not pattern.search(sentence):
            continue
        lowered = sentence.strip().lower()
        if lowered.startswith("no ") or re.search(
            r"\b(?:no|not|without)\b.*\b(?:pressure|saturation|contention|bottleneck)\b",
            lowered,
        ):
            continue
        return True
    return False


def _has_repeated_sample_support(result: dict[str, Any]) -> bool:
    text = _cpu_evidence_text(result)
    return bool(
        re.search(r"\b\d+\s+(?:of|/)\s*\d+\s+samples?\b", text)
        or re.search(r"\b(?:every|all|repeated)\s+(?:collected\s+)?samples?\b", text)
    )


def _conclusion_texts(result: dict[str, Any]) -> list[tuple[str, str]]:
    texts = [
        ("assessment_summary", result["assessment_summary"]),
        ("performance_assessment", result["performance_assessment"]),
        ("subsystem_health.cpu.summary", result["subsystem_health"]["cpu"]["summary"]),
    ]
    for index, concern in enumerate(result["active_concerns"]):
        texts.extend(
            [
                (f"active_concerns[{index}].title", concern["title"]),
                (f"active_concerns[{index}].description", concern["description"]),
            ]
        )
    return texts


def _structural_issues(result: Any) -> list[ValidationIssue]:
    try:
        _validate_schema_value(result, ANALYSIS_SCHEMA, "analysis")
    except ValueError as exc:
        return [ValidationIssue("analysis", "schema_mismatch", str(exc))]
    return []


def _validate_schema_value(value: Any, schema: dict[str, Any], path: str) -> None:
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be an object.")
        required = schema.get("required", [])
        missing = [field for field in required if field not in value]
        if missing:
            raise ValueError(f"{path} is missing {', '.join(missing)}.")
        if schema.get("additionalProperties") is False:
            unexpected = sorted(set(value) - set(schema.get("properties", {})))
            if unexpected:
                raise ValueError(f"{path} has unexpected fields: {', '.join(unexpected)}.")
        for name, item in value.items():
            child = schema.get("properties", {}).get(name)
            if child is not None:
                _validate_schema_value(item, child, f"{path}.{name}")
    elif expected == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be an array.")
        for index, item in enumerate(value):
            _validate_schema_value(item, schema["items"], f"{path}[{index}]")
    elif expected == "string" and not isinstance(value, str):
        raise ValueError(f"{path} must be a string.")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} has an unsupported value.")
