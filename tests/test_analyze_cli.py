"""CLI tests for deterministic diagnostic analysis."""

import json

import pytest
from typer.testing import CliRunner

from linuxmd.cli import app
from linuxmd.providers import PROVIDER_CONFIGS

runner = CliRunner()


def _health_analysis(*, concern: bool = False) -> dict:
    result = {
        "overall_health": "attention_recommended" if concern else "healthy",
        "assessment_summary": "The system appeared healthy during the sampled interval.",
        "assessment_scope": {
            "environment": "Linux host",
            "measurement_window": "60 seconds, 60 samples",
            "workload_state": "idle",
            "baseline": "none",
        },
        "subsystem_health": {
            name: {
                "status": "healthy",
                "summary": "No pressure was observed.",
                "coverage": "sufficient",
                "missing_metrics": [],
            }
            for name in ("cpu", "memory", "storage", "network", "kernel", "security")
        },
        "performance_assessment": (
            "No CPU, memory, storage, network, or scheduler bottleneck was detected during "
            "the supplied measurement window."
        ),
        "active_concerns": (
            [
                {
                    "title": "CPU pressure",
                    "category": "performance",
                    "severity": "medium",
                    "assessment": "likely_issue",
                    "description": "Correlated CPU pressure occurred during the interval.",
                    "evidence": [
                        "performance.json CPU utilization remained high",
                        "performance.json run queue exceeded logical CPUs",
                    ],
                }
            ]
            if concern
            else []
        ),
        "observations": [],
        "recommended_actions": (
            [
                {
                    "category": "diagnostic_follow_up",
                    "action": "Run vmstat 1.",
                    "rationale": "Confirm scheduler pressure over a longer interval.",
                }
            ]
            if concern
            else []
        ),
        "confidence": "medium",
    }
    if concern:
        result["subsystem_health"]["cpu"] = {
            "status": "attention",
            "summary": "CPU utilization and run-queue evidence indicate pressure.",
            "coverage": "sufficient",
            "missing_metrics": [],
        }
    return result


def _write_inputs(tmp_path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "diag.json").write_text(
        json.dumps({"schema_version": "1.0", "diagnostics": {"system": {}}}),
        encoding="utf-8",
    )
    (output / "performance.json").write_text(
        json.dumps({"schema_version": "1.1", "diagnostics": {"performance": {}}}),
        encoding="utf-8",
    )


@pytest.mark.parametrize("create_output", [False, True])
def test_analyze_reports_no_input_files(tmp_path, monkeypatch, create_output) -> None:
    if create_output:
        (tmp_path / "output").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LINUXMD_PROVIDER", raising=False)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert "No valid analysis reports are available" in result.output
    assert "missing" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("invalid", ["diag.json", "performance.json"])
def test_analyze_reports_invalid_json_but_uses_other_valid_inputs(
    tmp_path, monkeypatch, invalid
) -> None:
    _write_inputs(tmp_path)
    (tmp_path / "output" / invalid).write_text("{not json", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert "invalid" in result.output
    assert "Traceback" not in result.output


def test_analyze_fails_when_every_existing_report_is_invalid(tmp_path, monkeypatch) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "diag.json").write_text("not-json", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert "diag.json" in result.output
    assert "invalid" in result.output


@pytest.mark.parametrize("provider", [None, "", "   "])
def test_unconfigured_provider_validates_without_writing_analysis(
    tmp_path, monkeypatch, provider
) -> None:
    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    if provider is None:
        monkeypatch.delenv("LINUXMD_PROVIDER", raising=False)
    else:
        monkeypatch.setenv("LINUXMD_PROVIDER", provider)
    monkeypatch.delenv("LINUXMD_API_KEY", raising=False)
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *args, **kwargs: pytest.fail("unconfigured mode attempted network access"),
    )

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert "No LLM provider is configured" in result.output
    assert "System inventory" in result.output
    assert "Performance diagnostics" in result.output
    assert "openai" in result.output
    assert "gpt-5-mini" in result.output
    assert "https://api.openai.com/v1" in result.output
    assert "gemini" in result.output
    assert "gemini-2.5-flash" in result.output
    assert "https://generativelanguage.googleapis.com/v1beta/openai" in result.output
    assert "deepseek" in result.output
    assert "deepseek-v4-flash" in result.output
    assert "https://api.deepseek.com" in result.output
    assert "Optional overrides" in result.output
    assert "\n  mock\n" not in result.output
    assert not (tmp_path / "output" / "analysis.json").exists()


def test_explicit_mock_never_uses_api_key_network_or_analysis_file(tmp_path, monkeypatch) -> None:
    secret = "should-never-appear"
    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "mock")
    monkeypatch.setenv("LINUXMD_API_KEY", secret)

    def fail_network(*args, **kwargs):
        raise AssertionError("mock provider attempted a network request")

    monkeypatch.setattr("urllib.request.urlopen", fail_network)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert "Mock provider selected" in result.output
    assert "testing and development" in result.output
    assert secret not in result.output
    assert not (tmp_path / "output" / "analysis.json").exists()


def test_no_provider_preserves_existing_analysis(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    existing = tmp_path / "output" / "analysis.json"
    existing.write_text('{"provider":"openai","existing":true}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LINUXMD_PROVIDER", raising=False)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert json.loads(existing.read_text(encoding="utf-8"))["existing"] is True


def test_unreadable_report_is_displayed(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LINUXMD_PROVIDER", raising=False)
    original = __import__("pathlib").Path.read_text

    def read_text(path, *args, **kwargs):
        if path.name == "diag.json":
            raise PermissionError("denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr("pathlib.Path.read_text", read_text)
    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert "System inventory" in result.output
    assert "unreadable" in result.output


def test_real_provider_requires_api_key_without_network(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "openai")
    monkeypatch.delenv("LINUXMD_API_KEY", raising=False)

    def fail_network(*args, **kwargs):
        raise AssertionError("missing-key validation attempted a network request")

    monkeypatch.setattr("urllib.request.urlopen", fail_network)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert "LINUXMD_API_KEY is required" in result.output
    assert not (tmp_path / "output" / "analysis.json").exists()


def test_unsupported_provider_is_helpful(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "unknown")

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert "Unsupported LINUXMD_PROVIDER: unknown" in result.output


@pytest.mark.parametrize("provider_name", ["openai", "gemini", "deepseek"])
def test_analyze_sends_compact_payload_and_excludes_previous_analysis(
    tmp_path, monkeypatch, provider_name
) -> None:
    _write_inputs(tmp_path)
    output = tmp_path / "output"
    (output / "network.json").write_text(json.dumps({"interfaces": 2}), encoding="utf-8")
    (output / "security.json").write_text(json.dumps({"collector": "security"}), encoding="utf-8")
    (output / "security-analysis.json").write_text(
        json.dumps({"confidence": "low"}), encoding="utf-8"
    )
    (output / "analysis.json").write_text(json.dumps({"stale": True}), encoding="utf-8")
    captured = {}

    class CapturingProvider:
        def analyze(self, payload):
            captured["payload"] = payload
            return _health_analysis()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", provider_name)
    monkeypatch.setenv("LINUXMD_API_KEY", "test-key")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args: CapturingProvider())

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert captured["payload"]["metadata"]["source_reports"] == [
        "diag.json",
        "performance.json",
        "security-analysis.json",
        "security.json",
    ]
    serialized = json.dumps(captured["payload"])
    assert "network.json" not in serialized
    assert "analysis.json" not in captured["payload"]["metadata"]["source_reports"]
    assert "raw_command_results" not in serialized
    assert "Raw reports:" in result.output
    assert "Analysis payload:" in result.output
    assert "Reduction:" in result.output


def test_debug_writes_sanitized_compact_payload(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)

    class Provider:
        def analyze(self, payload):
            return _health_analysis()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "openai")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret-never-written")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args: Provider())

    result = runner.invoke(app, ["analyze", "--debug"])

    debug_payload = tmp_path / "output" / "debug" / "analysis-payload.json"
    assert result.exit_code == 0
    assert debug_payload.is_file()
    assert "secret-never-written" not in debug_payload.read_text(encoding="utf-8")
    assert "compacted section sizes" in result.output


@pytest.mark.parametrize("value", ["0", "invalid"])
def test_analyze_rejects_invalid_payload_limit(tmp_path, monkeypatch, value) -> None:
    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "openai")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret")
    monkeypatch.setenv("LINUXMD_MAX_PAYLOAD_KIB", value)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert "LINUXMD_MAX_PAYLOAD_KIB must be a positive integer" in result.output


def test_real_provider_prints_sections_and_writes_json(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)

    class Provider:
        def analyze(self, payload):
            return _health_analysis(concern=True)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "openai")
    monkeypatch.setenv("LINUXMD_API_KEY", "never-print-this")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args: Provider())

    result = runner.invoke(app, ["analyze"])

    saved = json.loads((tmp_path / "output" / "analysis.json").read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert "LinuxMD Health Assessment" in result.output
    assert "Overall health" in result.output
    assert "Active concerns" in result.output
    assert '"active_concerns"' not in result.output
    assert "never-print-this" not in result.output
    assert saved["overall_health"] == "attention_recommended"


@pytest.mark.parametrize("detailed", [False, True])
def test_rendered_and_saved_summary_remove_provider_environment_restatement(
    tmp_path, monkeypatch, detailed
) -> None:
    _write_inputs(tmp_path)
    diag_path = tmp_path / "output" / "diag.json"
    diag_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "diagnostics": {
                    "system": {
                        "operating_system": {
                            "distribution": {"name": "Ubuntu", "version_id": "24.04"},
                            "kernel_version": "6.6.87.2-microsoft-standard-WSL2",
                        },
                        "virtualization": {"environment": "wsl", "wsl": True},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    analysis = _health_analysis()
    analysis["overall_health"] = "unknown"
    analysis["assessment_summary"] = (
        "The system is a WSL2 guest running Ubuntu 24. 04 on Linux kernel 6. 6."
    )

    class Provider:
        def analyze(self, payload):
            return json.loads(json.dumps(analysis))

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "openai")
    monkeypatch.setenv("LINUXMD_API_KEY", "test-key")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args: Provider())

    args = ["analyze", "--detailed"] if detailed else ["analyze"]
    result = runner.invoke(app, args)
    saved = json.loads((tmp_path / "output" / "analysis.json").read_text(encoding="utf-8"))

    assert result.exit_code == 0
    assert "24. 04" not in result.output
    assert "6. 6" not in result.output
    assert "24. 04" not in json.dumps(saved)
    assert "6. 6" not in json.dumps(saved)
    assert saved["assessment_scope"]["environment"] == (
        "WSL2 guest on Ubuntu 24.04, kernel 6.6.87.2-microsoft-standard-WSL2"
    )
    assert saved["assessment_summary"].startswith("No active operational issues")


def test_detailed_output_normalizes_security_provenance_and_wording(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    output = tmp_path / "output"
    (output / "diag.json").write_text(
        json.dumps(
            {
                "diagnostics": {
                    "system": {
                        "operating_system": {
                            "distribution": {"name": "Ubuntu", "version_id": "24.04"},
                            "kernel_version": "6.6.87.2-microsoft-standard-WSL2",
                        },
                        "virtualization": {"environment": "wsl", "wsl": True},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (output / "security.json").write_text(
        json.dumps(
            {
                "kernel_hardening": {
                    "apparmor": {"supported": True, "enabled": False},
                    "sysctls": {"dmesg_restrict": "0"},
                },
                "platform_security": {
                    "secure_boot": {"state": "unavailable", "reason": "WSL2 guest"}
                },
                "virtualization_security": {"environment": "wsl2"},
            }
        ),
        encoding="utf-8",
    )
    analysis = _health_analysis()
    analysis["overall_health"] = "healthy_with_observations"
    analysis["assessment_summary"] = "No active compromise detected."
    analysis["observations"] = [
        {
            "title": "AppArmor disabled",
            "description": "AppArmor is disabled.",
            "evidence": ["AppArmor enabled=false"],
            "evidence_refs": ["performance.normalized_metrics.kernel.recent_warnings_errors"],
            "temporal_scope": "sampled_interval",
        },
        {
            "title": "Secure Boot unavailable in WSL2",
            "description": "Secure Boot is not observable in this WSL2 guest.",
            "evidence": ["secure boot unavailable"],
            "evidence_refs": [],
            "temporal_scope": "sampled_interval",
        },
        {
            "title": "Network listeners",
            "description": "10.255.255.254 is localhost-only.",
            "evidence": ["listener 10.255.255.254"],
            "evidence_refs": [],
            "temporal_scope": "sampled_interval",
        },
    ]

    class Provider:
        def analyze(self, payload):
            return json.loads(json.dumps(analysis))

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "deepseek")
    monkeypatch.setenv("LINUXMD_API_KEY", "test-key")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args: Provider())

    result = runner.invoke(app, ["analyze", "--detailed"])
    saved = json.loads((output / "analysis.json").read_text(encoding="utf-8"))

    assert result.exit_code == 0
    assert "No active compromise detected" not in result.output
    assert "No evidence of active compromise was found" in result.output
    assert "10.255.255.254 is localhost-only" not in result.output
    assert "security.kernel_hardening.apparmor.enabled" in result.output
    assert "performance.normalized_metrics.kernel.recent_warnings_errors" not in result.output
    assert saved["observations"][0]["temporal_scope"] == "configuration_state"
    assert saved["observations"][1]["temporal_scope"] == "environment_state"
    assert saved["subsystem_health"]["kernel"]["coverage"] == "partial"


def test_concise_and_detailed_use_identical_provider_payload_and_json(
    tmp_path, monkeypatch
) -> None:
    _write_inputs(tmp_path)
    calls = []
    analysis = _health_analysis()
    analysis["overall_health"] = "healthy_with_observations"
    for subsystem in ("storage", "network"):
        analysis["subsystem_health"][subsystem] = {
            "status": "unknown",
            "summary": "Telemetry was insufficient for a complete assessment.",
            "coverage": "insufficient",
            "missing_metrics": ["latency", "errors", "throughput"],
        }
    analysis["assessment_summary"] = (
        "The system appeared healthy during the collected interval. A historical crash was "
        "recorded without ongoing impact."
    )
    analysis["observations"] = [
        {
            "title": "Historical crash",
            "description": "No continuing impact was shown.",
            "evidence": ["diag.json kernel log timestamp=1"],
        }
    ]
    analysis["recommended_actions"] = [
        {
            "category": "diagnostic_follow_up",
            "action": "Install optional sysstat tools.",
            "rationale": "Expand storage telemetry.",
        },
        {
            "category": "hardening_review",
            "action": "Review AppArmor applicability.",
            "rationale": "Consider deployment role and threat model.",
        },
    ]

    class Provider:
        def analyze(self, payload):
            calls.append(payload)
            return analysis

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "openai")
    monkeypatch.setenv("LINUXMD_API_KEY", "test-key")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args: Provider())

    concise = runner.invoke(app, ["analyze"])
    concise_json = (tmp_path / "output" / "analysis.json").read_bytes()
    detailed = runner.invoke(app, ["analyze", "--detailed"])
    detailed_json = (tmp_path / "output" / "analysis.json").read_bytes()

    assert concise.exit_code == detailed.exit_code == 0
    assert calls[0] == calls[1]
    assert concise_json == detailed_json
    assert "Historical crash" not in concise.output
    assert "Evidence\n" not in concise.output
    assert "Missing:" not in concise.output
    assert "Install optional sysstat tools" not in concise.output
    assert "Review AppArmor applicability" not in concise.output
    assert "No immediate remediation is required." in concise.output
    assert "Historical crash" in detailed.output
    assert "Evidence" in detailed.output
    assert "Missing:" in detailed.output
    assert "Install optional sysstat tools" in detailed.output
    assert "Review AppArmor applicability" in detailed.output


def test_analyze_help_documents_detailed_option() -> None:
    result = runner.invoke(app, ["analyze", "--help"])

    assert result.exit_code == 0
    assert "--detailed" in result.output
    assert "historical observations" in result.output
    assert "--verbose" in result.output


def test_gemini_verbose_prints_resolved_endpoint_without_api_key(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return json.dumps(
                {"choices": [{"message": {"content": json.dumps(_health_analysis())}}]}
            ).encode("utf-8")

    def respond(request, **kwargs):
        captured["url"] = request.full_url
        captured["connect_timeout"] = kwargs["timeout"]
        return Response()

    secret = "gemini-key-never-print"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "gemini")
    monkeypatch.setenv("LINUXMD_API_KEY", secret)
    monkeypatch.setenv("LINUXMD_MODEL", "gemini-3.5-flash")
    monkeypatch.setenv(
        "LINUXMD_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/"
    )
    monkeypatch.setattr("urllib.request.urlopen", respond)

    result = runner.invoke(app, ["analyze", "--verbose"])

    endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    assert result.exit_code == 0
    assert captured["url"] == endpoint
    assert captured["connect_timeout"] == 30
    assert "Provider: gemini" in result.output
    assert "Model: gemini-3.5-flash" in result.output
    assert f"Endpoint: {endpoint}" in result.output
    assert "Connect timeout: 30 seconds" in result.output
    assert "Read timeout: 600 seconds" in result.output
    assert secret not in result.output


@pytest.mark.skip(reason="urllib adapter was replaced by one synchronous httpx request")
def test_openai_environment_read_timeout_applies_to_custom_base_url(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    configured_read_timeouts = []

    class Socket:
        def settimeout(self, value):
            configured_read_timeouts.append(value)

    class Response:
        fp = type("File", (), {"raw": type("Raw", (), {"_sock": Socket()})()})()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return json.dumps(
                {"choices": [{"message": {"content": json.dumps(_health_analysis())}}]}
            ).encode("utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "openai")
    monkeypatch.setenv("LINUXMD_API_KEY", "ollama")
    monkeypatch.setenv("LINUXMD_MODEL", "local-model")
    monkeypatch.setenv("LINUXMD_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("LINUXMD_TIMEOUT_SECONDS", "47.5")
    monkeypatch.setenv("LINUXMD_CONNECT_TIMEOUT_SECONDS", "12.5")
    connect_timeouts = []

    def respond(*args, **kwargs):
        connect_timeouts.append(kwargs["timeout"])
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", respond)

    result = runner.invoke(app, ["analyze", "--verbose"])

    assert result.exit_code == 0
    assert configured_read_timeouts == [47.5]
    assert connect_timeouts == [12.5]
    assert "Base URL: http://127.0.0.1:11434/v1" in result.output
    assert "Endpoint: http://127.0.0.1:11434/v1/chat/completions" in result.output
    assert "Model: local-model" in result.output
    assert "Connect timeout: 12.5 seconds" in result.output
    assert "Read timeout: 47.5 seconds" in result.output


def test_gemini_invalid_json_is_saved_without_repair_request(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    calls = 0

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return json.dumps(
                {"choices": [{"message": {"content": "not valid analysis json"}}]}
            ).encode("utf-8")

    def respond(request, **kwargs):
        nonlocal calls
        calls += 1
        return Response()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "gemini")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret")
    monkeypatch.setattr("urllib.request.urlopen", respond)

    result = runner.invoke(app, ["analyze"])

    raw = tmp_path / "output" / "analysis-provider-raw.txt"
    assert result.exit_code == 1
    assert calls == 1
    assert raw.read_text(encoding="utf-8") == "not valid analysis json"
    assert "could not be parsed" in result.output


def test_semantically_invalid_response_produces_successful_fallback_without_repair_interface(
    tmp_path, monkeypatch
) -> None:
    _write_inputs(tmp_path)
    invalid = _health_analysis()
    invalid["overall_health"] = "healthy"
    invalid["subsystem_health"]["memory"]["status"] = "attention"
    invalid["active_concerns"] = [
        {
            "title": "Memory pressure",
            "category": "performance",
            "severity": "medium",
            "assessment": "indication",
            "description": "Reclaim activity indicates current memory pressure.",
            "evidence": ["performance.json reclaim activity"],
        }
    ]
    calls = 0

    class Provider:
        def generate(self, payload):
            nonlocal calls
            calls += 1
            return invalid

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "deepseek")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args, **kwargs: Provider())

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert calls == 1
    assert "Warning:" in result.output
    assert (
        json.loads((tmp_path / "output" / "analysis-provider-invalid.json").read_text()) == invalid
    )
    assert json.loads((tmp_path / "output" / "analysis-provider-raw.txt").read_text()) == invalid
    final = json.loads((tmp_path / "output" / "analysis.json").read_text())
    assert final["generation"]["mode"] == "deterministic_fallback"


def test_coverage_normalization_metadata_is_written_after_one_request(
    tmp_path, monkeypatch
) -> None:
    _write_inputs(tmp_path)
    response = _health_analysis()
    response["overall_health"] = "healthy_with_observations"
    response["subsystem_health"]["cpu"].update(
        {"status": "healthy", "coverage": "limited", "missing_metrics": ["scheduler PSI"]}
    )
    calls = 0

    class Provider:
        def generate(self, payload):
            nonlocal calls
            calls += 1
            return response

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "deepseek")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args, **kwargs: Provider())

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert calls == 1
    saved = json.loads((tmp_path / "output" / "analysis.json").read_text())
    metadata = json.loads((tmp_path / "output" / "analysis-normalizations.json").read_text())
    assert saved["subsystem_health"]["cpu"]["status"] == "unknown"
    assert metadata["normalizations"][0]["path"] == "subsystem_health.cpu.status"


def test_temporal_wording_normalizes_locally_without_repair_call(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    response = _health_analysis()
    response["overall_health"] = "healthy_with_observations"
    response["subsystem_health"]["cpu"]["summary"] = (
        "PSI some avg10 0.22, but no sustained pressure."
    )
    calls = 0

    class Provider:
        def generate(self, payload):
            nonlocal calls
            calls += 1
            return response

        def repair(self, response, errors, evidence):
            pytest.fail("local normalization should avoid a repair request")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "deepseek")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args, **kwargs: Provider())

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert calls == 1
    saved = json.loads((tmp_path / "output" / "analysis.json").read_text())
    assert saved["subsystem_health"]["cpu"]["summary"] == (
        "PSI some avg10 0.22, but no pressure was observed during the sampled interval."
    )
    raw = json.loads((tmp_path / "output" / "analysis-provider-raw.txt").read_text())
    assert raw["subsystem_health"]["cpu"]["summary"].endswith("no sustained pressure.")


def test_one_successful_constrained_repair_writes_final_analysis(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    invalid = _health_analysis()
    invalid["overall_health"] = "healthy"
    invalid["subsystem_health"]["memory"]["status"] = "attention"
    invalid["active_concerns"] = [
        {
            "title": "Memory pressure",
            "category": "performance",
            "severity": "medium",
            "assessment": "indication",
            "description": "Reclaim was observed.",
            "evidence": ["memory reclaim metric"],
        }
    ]
    repaired = json.loads(json.dumps(invalid))
    repaired["overall_health"] = "attention_recommended"
    calls = []

    class Provider:
        def generate(self, payload):
            calls.append("generate")
            return invalid

        def repair(self, response, errors, evidence):
            calls.append("repair")
            return repaired

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "deepseek")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args, **kwargs: Provider())

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert calls == ["generate", "repair"]
    assert (
        json.loads((tmp_path / "output" / "analysis.json").read_text())["overall_health"]
        == "attention_recommended"
    )
    assert (tmp_path / "output" / "analysis-provider-repaired-raw.txt").is_file()


def test_failed_repair_writes_valid_fallback_and_warns(tmp_path, monkeypatch) -> None:
    _write_inputs(tmp_path)
    invalid = _health_analysis()
    invalid["overall_health"] = "healthy"
    invalid["subsystem_health"]["memory"]["status"] = "attention"
    invalid["active_concerns"] = [
        {
            "title": "Memory pressure",
            "category": "performance",
            "severity": "medium",
            "assessment": "indication",
            "description": "Reclaim was observed.",
            "evidence": ["memory reclaim metric"],
        }
    ]
    calls = []

    class Provider:
        def generate(self, payload):
            calls.append("generate")
            return invalid

        def repair(self, response, errors, evidence):
            calls.append("repair")
            return invalid

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "deepseek")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args, **kwargs: Provider())

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert calls == ["generate", "repair"]
    assert "Warning:" in result.output
    fallback = json.loads((tmp_path / "output" / "analysis.json").read_text())
    assert fallback["generation"]["mode"] == "deterministic_fallback"


def test_internal_fallback_validation_failure_preserves_previous_analysis(
    tmp_path, monkeypatch
) -> None:
    _write_inputs(tmp_path)
    existing = tmp_path / "output" / "analysis.json"
    previous = '{"previous_valid":true}\n'
    existing.write_text(previous, encoding="utf-8")
    invalid = _health_analysis()
    invalid["overall_health"] = "healthy"
    invalid["subsystem_health"]["memory"]["status"] = "attention"
    invalid["active_concerns"] = [
        {
            "title": "Memory concern",
            "category": "performance",
            "severity": "medium",
            "assessment": "indication",
            "description": "Memory pressure was indicated.",
            "evidence": ["reclaim activity"],
        }
    ]

    class Provider:
        def generate(self, payload):
            return invalid

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "deepseek")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args, **kwargs: Provider())
    monkeypatch.setattr(
        "linuxmd.analysis_repair.conservative_fallback", lambda *args, **kwargs: {"invalid": True}
    )

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert "internal deterministic fallback response failed" in result.output
    assert existing.read_text(encoding="utf-8") == previous
    assert (tmp_path / "output" / "analysis-provider-invalid.json").is_file()


@pytest.mark.skip(reason="automatic semantic repair was intentionally removed")
@pytest.mark.parametrize("provider_name", ["gemini", "deepseek"])
def test_failed_semantic_repair_preserves_analysis_and_debug_is_opt_in(
    tmp_path, monkeypatch, provider_name
) -> None:
    _write_inputs(tmp_path)
    existing = tmp_path / "output" / "analysis.json"
    existing.write_text('{"existing":true}\n', encoding="utf-8")
    invalid = _health_analysis()
    invalid["overall_health"] = "degraded"
    invalid["subsystem_health"]["storage"].update(
        {
            "status": "healthy",
            "coverage": "insufficient",
            "missing_metrics": ["latency"],
        }
    )

    class Provider:
        def generate(self, payload):
            return invalid

        def repair(self, response, errors, schema):
            return invalid

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", provider_name)
    monkeypatch.setenv("LINUXMD_API_KEY", "never-print-secret")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args: Provider())

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert (
        f"{PROVIDER_CONFIGS[provider_name].display_name} returned an internally inconsistent "
        "health assessment"
    ) in result.output
    assert "could not be repaired automatically" in result.output
    assert "never-print-secret" not in result.output
    assert existing.read_text(encoding="utf-8") == '{"existing":true}\n'
    assert not (tmp_path / "output" / "debug").exists()

    debug_result = runner.invoke(app, ["analyze", "--debug"])

    assert debug_result.exit_code == 1
    assert (tmp_path / "output" / "debug" / "analysis-invalid-response.json").is_file()
    errors = tmp_path / "output" / "debug" / "analysis-validation-errors.json"
    assert errors.is_file()
    assert "never-print-secret" not in errors.read_text(encoding="utf-8")


def test_network_progress_precedes_timeout_and_existing_analysis_survives(
    tmp_path, monkeypatch
) -> None:
    from linuxmd.analysis import ProviderRequestError

    _write_inputs(tmp_path)
    existing = tmp_path / "output" / "analysis.json"
    existing.write_text('{"existing":true}\n', encoding="utf-8")

    class Provider:
        def generate(self, payload):
            raise ProviderRequestError(
                "Gemini", "timeout", "Gemini request timed out after 12 seconds.", timeout=12
            )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "gemini")
    monkeypatch.setenv("LINUXMD_API_KEY", "secret-value")
    monkeypatch.setenv("LINUXMD_TIMEOUT_SECONDS", "12")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args: Provider())

    result = runner.invoke(app, ["analyze", "--debug"])

    assert result.exit_code == 1
    assert result.output.index("Sending") < result.output.index("timed out")
    assert "Waiting for Gemini response" in result.output
    assert "Provider: gemini" in result.output
    assert "Payload size:" in result.output
    assert "secret-value" not in result.output
    assert existing.read_text(encoding="utf-8") == '{"existing":true}\n'


@pytest.mark.parametrize("value", ["0", "-1", "", "abc", "nan", "inf"])
def test_timeout_environment_must_be_positive_number(tmp_path, monkeypatch, value) -> None:
    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "openai")
    monkeypatch.setenv("LINUXMD_TIMEOUT_SECONDS", value)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert "LINUXMD_TIMEOUT_SECONDS must be a positive number" in result.output


@pytest.mark.parametrize("value", ["0", "-1", "", "abc", "nan", "inf"])
def test_connect_timeout_environment_must_be_positive_number(tmp_path, monkeypatch, value) -> None:
    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "gemini")
    monkeypatch.setenv("LINUXMD_CONNECT_TIMEOUT_SECONDS", value)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert "LINUXMD_CONNECT_TIMEOUT_SECONDS must be a positive number" in result.output


@pytest.mark.skip(reason="provider attempt configuration was intentionally removed")
@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_max_attempts_environment_must_be_positive_integer(tmp_path, monkeypatch, value) -> None:
    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LINUXMD_PROVIDER", "gemini")
    monkeypatch.setenv("LINUXMD_PROVIDER_MAX_ATTEMPTS", value)

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 1
    assert "LINUXMD_PROVIDER_MAX_ATTEMPTS must be a positive integer" in result.output


def test_provider_guidance_is_derived_from_registry(tmp_path, monkeypatch) -> None:
    from linuxmd.providers import MockProvider, ProviderConfig

    _write_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LINUXMD_PROVIDER", raising=False)
    monkeypatch.setitem(
        __import__("linuxmd.cli", fromlist=["PROVIDER_CONFIGS"]).PROVIDER_CONFIGS,
        "future",
        ProviderConfig(
            display_name="Future",
            default_model="future-model",
            default_base_url="https://future.invalid/v1",
            requires_api_key=True,
            is_real_provider=True,
            provider_type=MockProvider,
        ),
    )

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert "future-model" in result.output
    assert "https://future.invalid/v1" in result.output


def test_analysis_output_resolves_to_project_root_from_subdirectory(tmp_path, monkeypatch) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    _write_inputs(tmp_path)
    nested = tmp_path / "src" / "linuxmd"
    nested.mkdir(parents=True)

    class Provider:
        def analyze(self, payload):
            return _health_analysis()

    monkeypatch.chdir(nested)
    monkeypatch.setenv("LINUXMD_PROVIDER", "openai")
    monkeypatch.setenv("LINUXMD_API_KEY", "test-key")
    monkeypatch.setattr("linuxmd.cli.create_provider", lambda *args: Provider())

    result = runner.invoke(app, ["analyze"])

    assert result.exit_code == 0
    assert (tmp_path / "output" / "analysis.json").is_file()
    assert not (nested / "output" / "analysis.json").exists()
