"""Command-line interface for LinuxMD."""

import json
import math
import os
import sys
from pathlib import Path
from time import perf_counter
from typing import Annotated

import typer

from linuxmd import __version__
from linuxmd.analysis import (
    AnalysisError,
    AnalysisValidationError,
    ProviderJSONDecodeError,
    ProviderRequestError,
    ReportInspection,
    inspect_analysis_reports,
)
from linuxmd.analysis_payload import PayloadLimits, build_analysis_payload
from linuxmd.analysis_repair import analyze_once
from linuxmd.diagnostics.writer import write_json
from linuxmd.health_report import format_health_assessment
from linuxmd.paths import output_directory, project_root
from linuxmd.providers import PROVIDER_CONFIGS, create_provider
from linuxmd.workflows import (
    ANALYSIS_FILE,
    SECURITY_ANALYSIS_FILE,
    StageResult,
    run_all_collections,
    run_performance_collection,
    run_registered_collectors,
    run_security_analysis,
    run_security_collection,
    run_system_collection,
)

app = typer.Typer(
    name="linuxmd",
    help="Collect and analyze Linux host diagnostics.",
    no_args_is_help=True,
)


def version_callback(value: bool) -> None:
    """Print the application version and exit."""
    if value:
        typer.echo(f"linuxmd {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = None,
) -> None:
    """Collect and analyze Linux host diagnostics."""


@app.command()
def system() -> None:
    """Collect Linux system inventory."""
    result = run_system_collection()
    _print_individual_result(result)
    _exit_for_result(result)


@app.command()
def performance(
    host: Annotated[
        str | None,
        typer.Option("--host", help="Remote Linux host; omit to run locally."),
    ] = None,
    user: Annotated[
        str | None,
        typer.Option("--user", help="Remote SSH user; SSH configuration is used if omitted."),
    ] = None,
    port: Annotated[
        int,
        typer.Option("--port", min=1, max=65535, help="Remote SSH port."),
    ] = 22,
    identity_file: Annotated[
        Path | None,
        typer.Option(
            "--identity-file",
            exists=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Private key passed to SSH; ssh-agent and SSH config also work.",
        ),
    ] = None,
    duration: Annotated[
        int,
        typer.Option("--duration", min=1, max=300, help="Per-command sample count in seconds."),
    ] = 5,
    timeout: Annotated[
        int,
        typer.Option("--timeout", min=1, help="Timeout in seconds for each command."),
    ] = 90,
) -> None:
    """Collect a bounded performance sample."""
    result = run_performance_collection(
        host=host,
        user=user,
        port=port,
        identity_file=identity_file,
        duration=duration,
        timeout=timeout,
    )
    _print_individual_result(result, detail=f"sampling duration: {duration}s")
    _exit_for_result(result)


@app.command()
def security() -> None:
    """Collect and analyze Linux security state."""
    collection = run_security_collection()
    analysis = run_security_analysis(
        collection.data if collection.status in {"success", "unsupported"} else None
    )
    _print_individual_result(collection)
    _print_individual_result(analysis)
    if collection.status == "failed" or analysis.status in {"failed", "skipped"}:
        raise typer.Exit(code=1)


@app.command()
def collect(
    all_collectors: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Run every registered collector, including optional and experimental collectors.",
        ),
    ] = False,
    duration: Annotated[
        int,
        typer.Option("--duration", min=1, max=300, help="Performance sample count in seconds."),
    ] = 5,
    timeout: Annotated[
        int,
        typer.Option("--timeout", min=1, help="Performance command timeout in seconds."),
    ] = 90,
) -> None:
    """Collect stable baseline diagnostics, or every registered collector with --all."""
    results = run_registered_collectors(
        include_all=all_collectors,
        duration=duration,
        timeout=timeout,
    )
    for result in results:
        _print_individual_result(result)
    failures = sum(result.status == "failed" for result in results)
    typer.echo(f"\nCompleted {len(results)} collectors with {failures} failures.")
    if failures:
        raise typer.Exit(code=1)


@app.command(name="all")
def all_command(
    duration: Annotated[
        int,
        typer.Option("--duration", min=1, max=300, help="Performance sample count in seconds."),
    ] = 5,
    timeout: Annotated[
        int,
        typer.Option("--timeout", min=1, help="Performance command timeout in seconds."),
    ] = 90,
) -> None:
    """Run all local collectors and deterministic analyzers."""
    results = run_all_collections(duration=duration, timeout=timeout)
    labels = {
        "system": "System",
        "performance": "Performance",
        "security_collection": "Security collection",
        "security_analysis": "Security analysis",
    }
    for result in results:
        paths = ", ".join(str(path) for path in result.output_paths)
        detail = paths or result.error or ""
        typer.echo(f"{labels.get(result.name, result.name):<20} {result.status:<11} {detail}")
    failures = sum(result.status == "failed" for result in results)
    typer.echo(f"\nCompleted {len(results)} stages with {failures} failures.")
    if failures:
        raise typer.Exit(code=1)


@app.command()
def analyze(
    detailed: Annotated[
        bool,
        typer.Option(
            "--detailed",
            help=(
                "Show historical observations, evidence, coverage gaps, and optional diagnostic "
                "and hardening recommendations."
            ),
        ),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Write sanitized invalid-response diagnostics on failure."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Show the resolved provider, model, and endpoint."),
    ] = False,
) -> None:
    """Analyze collected reports with the configured LLM provider."""
    configured_provider = os.environ.get("LINUXMD_PROVIDER", "").strip().lower()
    api_key = os.environ.get("LINUXMD_API_KEY")
    model = os.environ.get("LINUXMD_MODEL")
    base_url = os.environ.get("LINUXMD_BASE_URL")
    try:
        timeout_seconds = _positive_number_environment("LINUXMD_TIMEOUT_SECONDS", 600.0)
        connect_timeout_seconds = _positive_number_environment(
            "LINUXMD_CONNECT_TIMEOUT_SECONDS", 30.0
        )
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    inspections = inspect_analysis_reports()
    raw_payload = {
        "reports": {item.path.name: item.content for item in inspections if item.status == "valid"}
    }
    if not configured_provider or configured_provider == "mock":
        _print_analysis_preparation(inspections, explicit_mock=configured_provider == "mock")
        if not raw_payload["reports"]:
            typer.echo("\nError: No valid analysis reports are available.", err=True)
            raise typer.Exit(code=1)
        return

    try:
        _print_report_inspections(inspections)
        if not raw_payload["reports"]:
            raise AnalysisError("No valid analysis reports are available.")
        config = PROVIDER_CONFIGS.get(configured_provider)
        if config is None:
            raise AnalysisError(f"Unsupported LINUXMD_PROVIDER: {configured_provider}")
        selected_model = model.strip() if model and model.strip() else config.default_model
        limits = PayloadLimits.from_environment()
        payload, payload_stats = build_analysis_payload(raw_payload["reports"], limits)
        payload_kib = payload_stats.compacted_bytes / 1024
        typer.echo(f"Raw reports:       {payload_stats.raw_bytes / 1024:6.1f} KiB")
        typer.echo(f"Analysis payload:  {payload_kib:6.1f} KiB")
        typer.echo(f"Reduction:         {payload_stats.reduction_percent:6.1f}%\n")
        if debug:
            _print_payload_debug(payload_stats)
            _write_payload_debug(payload)
        provider = create_provider(
            configured_provider,
            api_key,
            model,
            base_url,
            timeout_seconds,
            connect_timeout_seconds,
        )
        if verbose or debug:
            typer.echo(f"Provider: {configured_provider}")
            typer.echo(f"Model: {selected_model}")
            endpoint = getattr(provider, "endpoint", None)
            resolved_base_url = getattr(provider, "base_url", None)
            if resolved_base_url:
                typer.echo(f"Base URL: {resolved_base_url}")
            if endpoint:
                typer.echo(f"Endpoint: {endpoint}")
            typer.echo(f"Payload size: {payload_kib:.1f} KiB")
            typer.echo(f"Connect timeout: {connect_timeout_seconds:g} seconds")
            typer.echo(f"Read timeout: {timeout_seconds:g} seconds")
            typer.echo()
        typer.echo(
            f"Sending {payload_kib:.1f} KiB to {config.display_name} using {selected_model}...",
            nl=True,
        )
        typer.echo(f"Waiting for {config.display_name} response...", nl=True)
        sys.stdout.flush()
        started = perf_counter()
        outcome = analyze_once(provider, payload, provider_name=configured_provider)
        elapsed = perf_counter() - started
        typer.echo(f"{config.display_name} response received in {elapsed:.1f} seconds.\n")
        if debug:
            typer.echo(
                "Debug: deterministic normalizations: "
                + json.dumps(list(outcome.normalization_notes), sort_keys=True)
            )
        if outcome.provider_original is not None:
            _write_provider_artifact(
                "analysis-provider-raw.txt", outcome.provider_original, pretty=False
            )
        if outcome.fallback_used and outcome.provider_original is not None:
            _write_provider_artifact(
                "analysis-provider-invalid.json", outcome.provider_original, pretty=True
            )
        if outcome.provider_repaired is not None:
            _write_provider_artifact(
                "analysis-provider-repaired-raw.txt", outcome.provider_repaired, pretty=False
            )
        if outcome.warning:
            typer.echo(f"Warning: {outcome.warning}", err=True)
        result = outcome.result
        if outcome.normalization_notes:
            normalization_path = output_directory() / "analysis-normalizations.json"
            normalization_path.parent.mkdir(parents=True, exist_ok=True)
            normalization_path.write_text(
                json.dumps(
                    {"normalizations": list(outcome.normalization_notes)},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        output = write_json(result, ANALYSIS_FILE)
    except ProviderJSONDecodeError as exc:
        if exc.raw_response is not None:
            raw_path = output_directory() / "analysis-provider-raw.txt"
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(exc.raw_response, encoding="utf-8")
            typer.echo(f"Raw provider response written to {_display_path(raw_path)}", err=True)
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except ProviderRequestError as exc:
        _print_provider_request_error(
            exc,
            model=selected_model or "unknown",
            payload_kib=payload_kib,
            debug=debug,
            elapsed=perf_counter() - started,
        )
        raise typer.Exit(code=1) from exc
    except AnalysisValidationError as exc:
        diagnostic_dir = output_directory()
        diagnostic_dir.mkdir(parents=True, exist_ok=True)
        raw_path = diagnostic_dir / "analysis-provider-raw.txt"
        invalid_path = diagnostic_dir / "analysis-provider-invalid.json"
        raw_path.write_text(
            json.dumps(exc.response, separators=(",", ":"), ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        invalid_path.write_text(
            json.dumps(exc.response, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        typer.echo(f"Error: {exc.provider} response failed {exc.kind} validation:", err=True)
        for issue in exc.issues:
            typer.echo(f"- {issue.path}: {issue.message}", err=True)
        typer.echo(f"Raw response written to {_display_path(raw_path)}", err=True)
        typer.echo(f"Parsed response written to {_display_path(invalid_path)}", err=True)
        raise typer.Exit(code=1) from exc
    except KeyboardInterrupt as exc:
        typer.echo("Analysis cancelled by user.", err=True)
        raise typer.Exit(code=130) from exc
    except AnalysisError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        typer.echo(f"Error: could not write analysis report: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    _print_real_analysis(result, configured_provider, selected_model, output, detailed=detailed)


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(project_root()))
    except ValueError:
        return str(path.resolve())


def _write_provider_artifact(filename: str, value: dict, *, pretty: bool) -> Path:
    path = output_directory() / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2 if pretty else None, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _print_analysis_preparation(
    inspections: list[ReportInspection], *, explicit_mock: bool
) -> None:
    typer.echo("LinuxMD analysis preparation\n")
    _print_report_inspections(inspections)
    if explicit_mock:
        typer.echo("Mock provider selected.\n")
        typer.echo(
            "No real diagnostic analysis was performed. This mode is intended for testing "
            "and development.\n"
        )
    else:
        typer.echo("No LLM provider is configured.\n")
        typer.echo(
            "The collected reports were validated, but no cross-report LLM diagnosis was "
            "performed.\n"
        )
    security_analysis = next(
        (item for item in inspections if item.path.name == SECURITY_ANALYSIS_FILE.name), None
    )
    if security_analysis and security_analysis.status == "valid":
        typer.echo("Deterministic results available:")
        typer.echo(f"  Security analysis: {_display_path(security_analysis.path)}\n")
    typer.echo("Available providers:\n")
    for name, config in PROVIDER_CONFIGS.items():
        if not config.is_real_provider:
            continue
        typer.echo(f"  {name}")
        typer.echo(f"    Default model:    {config.default_model}")
        typer.echo(f"    Default base URL: {config.default_base_url}\n")
        typer.echo(f"    export LINUXMD_PROVIDER={name}")
        typer.echo(f"    export LINUXMD_API_KEY=<your_{name}_api_key>\n")
    typer.echo("Optional overrides:")
    typer.echo("  export LINUXMD_MODEL=<provider_model>")
    typer.echo("  export LINUXMD_BASE_URL=<provider_base_url>\n")
    typer.echo("Then run:\n  uv run linuxmd analyze")


def _print_report_inspections(inspections: list[ReportInspection]) -> None:
    typer.echo("Reports discovered:")
    for item in inspections:
        typer.echo(f"  {item.label:<23} {item.status:<10} {_display_path(item.path)}")
    typer.echo()


def _print_real_analysis(
    result: dict,
    provider: str,
    model: str | None,
    output: Path,
    *,
    detailed: bool,
) -> None:
    typer.echo(
        format_health_assessment(
            result,
            provider=provider,
            model=model or "unknown",
            output_path=Path(_display_path(output)),
            detail_level="detailed" if detailed else "concise",
        )
    )


def _write_payload_debug(payload: dict) -> None:
    debug_dir = output_directory() / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    (debug_dir / "analysis-payload.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _print_payload_debug(stats) -> None:
    typer.echo("Debug: compacted section sizes:")
    for name, size in sorted(stats.section_bytes.items(), key=lambda item: item[1], reverse=True):
        typer.echo(f"  {name}: {size / 1024:.1f} KiB")
    typer.echo(
        f"Debug: log events retained/removed: "
        f"{stats.log_events_retained}/{stats.log_events_removed}"
    )
    typer.echo(
        f"Debug: process entries retained/removed: "
        f"{stats.processes_retained}/{stats.processes_removed}"
    )
    typer.echo(
        f"Debug: raw samples retained/summarized: "
        f"{stats.raw_samples_retained}/{stats.raw_samples_summarized}\n"
    )


def _positive_integer_environment(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        timeout = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer.") from exc
    if timeout <= 0:
        raise ValueError(f"{name} must be a positive integer.")
    return timeout


def _positive_number_environment(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        timeout = float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number.") from exc
    if not value.strip() or not math.isfinite(timeout) or not timeout > 0:
        raise ValueError(f"{name} must be a positive number.")
    return timeout


def _print_provider_request_error(
    error: ProviderRequestError,
    *,
    model: str,
    payload_kib: float,
    debug: bool,
    elapsed: float,
) -> None:
    typer.echo(f"Error: {error}", err=True)
    typer.echo(f"Provider: {error.provider.lower()}", err=True)
    typer.echo(f"Model: {model}", err=True)
    typer.echo(f"Payload size: {payload_kib:.1f} KiB", err=True)
    if debug:
        typer.echo("Debug diagnostics:", err=True)
        typer.echo(f"  endpoint: {error.endpoint}", err=True)
        typer.echo(f"  timeout: {error.timeout}", err=True)
        typer.echo(f"  HTTP status: {error.status}", err=True)
        typer.echo(f"  category: {error.category}", err=True)
        typer.echo(f"  elapsed seconds: {elapsed:.3f}", err=True)
        typer.echo(f"  exception class: {type(error).__name__}", err=True)


def _print_individual_result(result: StageResult, *, detail: str | None = None) -> None:
    paths = ", ".join(str(path) for path in result.output_paths)
    suffix = "; ".join(value for value in (paths, detail, result.error) if value)
    typer.echo(
        f"{result.name.replace('_', ' ').title()}: {result.status}{': ' + suffix if suffix else ''}"
    )


def _exit_for_result(result: StageResult) -> None:
    if result.status in {"failed", "skipped"}:
        raise typer.Exit(code=1)
