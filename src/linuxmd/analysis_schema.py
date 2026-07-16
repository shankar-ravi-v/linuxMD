"""Shared normalized schema for Linux health assessments."""

OVERALL_HEALTH_VALUES = {
    "healthy",
    "healthy_with_observations",
    "attention_recommended",
    "degraded",
    "unknown",
}
SUBSYSTEM_STATUS_VALUES = {"healthy", "attention", "degraded", "unknown"}
COVERAGE_VALUES = {"sufficient", "partial", "limited", "insufficient"}
WORKLOAD_VALUES = {"idle", "light", "active", "unknown"}
BASELINE_VALUES = {"none", "generic", "environment", "machine_historical", "workload"}
CONCERN_CATEGORIES = {
    "performance",
    "reliability",
    "security",
    "availability",
    "functionality",
}
SEVERITY_VALUES = {"low", "medium", "high", "critical"}
ASSESSMENT_VALUES = {"observation", "indication", "likely_issue", "confirmed_issue"}
CONFIDENCE_VALUES = {"low", "medium", "high"}
ACTION_CATEGORIES = {"immediate_remediation", "diagnostic_follow_up", "hardening_review"}
TEMPORAL_SCOPE_VALUES = {
    "instantaneous",
    "sampled_interval",
    "multi_sample_trend",
    "historical_event",
    "configuration_state",
    "environment_state",
    "unknown",
}
CORRELATION_IDS = {
    "cpu_contention_pattern",
    "storage_bottleneck_pattern",
    "network_pressure_pattern",
}
SUBSYSTEMS = ("cpu", "memory", "storage", "network", "kernel", "security")

SUBSYSTEM_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": sorted(SUBSYSTEM_STATUS_VALUES)},
        "summary": {"type": "string"},
        "coverage": {"type": "string", "enum": sorted(COVERAGE_VALUES)},
        "missing_metrics": {"type": "array", "items": {"type": "string"}},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "not_applicable": {"type": "array", "items": {"type": "string"}},
        "coverage_limitations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": [
                            "missing_tool",
                            "not_observable_in_environment",
                            "not_observable_with_current_privilege",
                            "permission_denied",
                            "unsupported",
                        ],
                    },
                    "item": {"type": "string"},
                },
                "required": ["type", "item"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["status", "summary", "coverage", "missing_metrics"],
    "additionalProperties": False,
}

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "overall_health": {"type": "string", "enum": sorted(OVERALL_HEALTH_VALUES)},
        "assessment_summary": {"type": "string"},
        "assessment_scope": {
            "type": "object",
            "properties": {
                "environment": {"type": "string"},
                "measurement_window": {"type": "string"},
                "workload_state": {"type": "string", "enum": sorted(WORKLOAD_VALUES)},
                "baseline": {"type": "string", "enum": sorted(BASELINE_VALUES)},
            },
            "required": ["environment", "measurement_window", "workload_state", "baseline"],
            "additionalProperties": False,
        },
        "subsystem_health": {
            "type": "object",
            "properties": {name: SUBSYSTEM_SCHEMA for name in SUBSYSTEMS},
            "required": list(SUBSYSTEMS),
            "additionalProperties": False,
        },
        "performance_assessment": {"type": "string"},
        "active_concerns": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "category": {"type": "string", "enum": sorted(CONCERN_CATEGORIES)},
                    "severity": {"type": "string", "enum": sorted(SEVERITY_VALUES)},
                    "assessment": {"type": "string", "enum": sorted(ASSESSMENT_VALUES)},
                    "description": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "temporal_scope": {
                        "type": "string",
                        "enum": sorted(TEMPORAL_SCOPE_VALUES),
                    },
                },
                "required": [
                    "title",
                    "category",
                    "severity",
                    "assessment",
                    "description",
                    "evidence",
                    "evidence_refs",
                    "temporal_scope",
                ],
                "additionalProperties": False,
            },
        },
        "observations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "temporal_scope": {
                        "type": "string",
                        "enum": sorted(TEMPORAL_SCOPE_VALUES),
                    },
                },
                "required": ["title", "description", "evidence", "evidence_refs", "temporal_scope"],
                "additionalProperties": False,
            },
        },
        "recommended_actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": sorted(ACTION_CATEGORIES)},
                    "action": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["category", "action", "rationale"],
                "additionalProperties": False,
            },
        },
        "confidence": {"type": "string", "enum": sorted(CONFIDENCE_VALUES)},
        "evidence_qualification": {
            "type": "object",
            "properties": {
                "temporal_confidence": {
                    "type": "string",
                    "enum": sorted(CONFIDENCE_VALUES),
                },
                "overall_assessment_confidence": {
                    "type": "string",
                    "enum": sorted(CONFIDENCE_VALUES),
                },
            },
            "required": ["temporal_confidence", "overall_assessment_confidence"],
            "additionalProperties": False,
        },
        "correlations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "correlation_id": {"type": "string", "enum": sorted(CORRELATION_IDS)},
                    "classification": {"type": "string", "enum": ["indication"]},
                    "signals": {"type": "array", "items": {"type": "string"}},
                    "temporal_scope": {
                        "type": "string",
                        "enum": sorted(TEMPORAL_SCOPE_VALUES),
                    },
                },
                "required": [
                    "correlation_id",
                    "classification",
                    "signals",
                    "temporal_scope",
                ],
                "additionalProperties": False,
            },
        },
        "generation": {
            "type": "object",
            "properties": {
                "mode": {"type": "string"},
                "provider_attempted": {"type": "string"},
                "provider_output_accepted": {"type": "boolean"},
                "fallback_reason": {"type": "string"},
            },
            "required": [
                "mode",
                "provider_attempted",
                "provider_output_accepted",
                "fallback_reason",
            ],
            "additionalProperties": False,
        },
    },
    "required": [
        "overall_health",
        "assessment_summary",
        "assessment_scope",
        "subsystem_health",
        "performance_assessment",
        "active_concerns",
        "observations",
        "recommended_actions",
        "confidence",
        "evidence_qualification",
        "correlations",
    ],
    "additionalProperties": False,
}

ANALYSIS_FIELDS = tuple(ANALYSIS_SCHEMA["required"])
