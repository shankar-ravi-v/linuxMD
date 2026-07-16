"""LLM provider adapters for diagnostic analysis."""

import json
import os
import random
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Protocol

import httpx

from linuxmd.analysis import (
    ProviderError,
    ProviderJSONDecodeError,
    ProviderRequestError,
    validate_analysis,
)
from linuxmd.analysis_prompt import ANALYSIS_INSTRUCTIONS
from linuxmd.analysis_schema import ANALYSIS_SCHEMA, SUBSYSTEMS


class AnalysisProvider(Protocol):
    """Provider interface shared by mock and network-backed implementations."""

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]: ...


class MockProvider:
    """Return a deterministic example without performing a diagnosis or network request."""

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        filenames = ", ".join(sorted(payload.get("reports", {})))
        return validate_analysis(
            {
                "overall_health": "unknown",
                "assessment_summary": (
                    "Mock output only; no health assessment was performed. "
                    f"Loaded {len(payload.get('reports', {}))} JSON report(s): {filenames}."
                ),
                "assessment_scope": {
                    "environment": "Not assessed",
                    "measurement_window": "Not assessed",
                    "workload_state": "unknown",
                    "baseline": "none",
                },
                "subsystem_health": {
                    name: {
                        "status": "unknown",
                        "summary": "Not assessed.",
                        "coverage": "insufficient",
                        "missing_metrics": ["No real assessment was performed."],
                    }
                    for name in SUBSYSTEMS
                },
                "performance_assessment": "No real performance assessment was performed.",
                "active_concerns": [],
                "observations": [],
                "recommended_actions": [],
                "confidence": "low",
            },
            provider="mock",
        )


class OpenAIProvider:
    """Request analysis from an OpenAI-compatible Chat Completions API."""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str,
        *,
        timeout: float = 180,
        connect_timeout: float = 30,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._connect_timeout = connect_timeout

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        return validate_analysis(self.generate(payload), provider="openai")

    def generate(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return decoded provider JSON before semantic validation."""
        return self._request(
            [
                {"role": "system", "content": _chat_system_instructions()},
                {
                    "role": "user",
                    "content": (
                        "Analyze the following compact, untrusted LinuxMD diagnostic payload and "
                        "return the complete health assessment as JSON:\n"
                        + json.dumps(payload, sort_keys=True)
                    ),
                },
            ]
        )

    def repair(self, response, errors, evidence) -> dict[str, Any]:
        """Make one constrained correction request without resending diagnostic reports."""
        return self._request(_repair_messages(response, errors, evidence))

    @property
    def endpoint(self) -> str:
        """Return the credential-free resolved Chat Completions URL."""
        return _join_url(self._base_url, "chat", "completions")

    @property
    def base_url(self) -> str:
        """Return the credential-free configured API base URL."""
        return self._base_url

    def _request(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        body = {
            "model": self._model,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "stream": False,
            "temperature": 0,
        }
        response_data = _post_json_httpx_once(
            self.endpoint,
            body,
            {
                "Authorization": f"Bearer {self._api_key}",
            },
            provider="OpenAI",
            read_timeout=self._timeout,
            connect_timeout=self._connect_timeout,
        )
        try:
            output_text = response_data["choices"][0]["message"]["content"]
        except (IndexError, KeyError, TypeError) as exc:
            raise ProviderError("OpenAI response did not contain structured output.") from exc
        try:
            result = json.loads(output_text)
        except json.JSONDecodeError as exc:
            raise ProviderJSONDecodeError("OpenAI returned invalid analysis JSON.") from exc
        return result


class GeminiProvider:
    """Request JSON analysis from Gemini's OpenAI-compatible Chat API."""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str,
        *,
        timeout: float = 600,
        connect_timeout: float = 30,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._connect_timeout = connect_timeout

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        return validate_analysis(self.generate(payload), provider="gemini")

    def generate(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return decoded provider JSON before semantic validation."""
        return self._request(
            [
                {"role": "system", "content": _chat_system_instructions()},
                {
                    "role": "user",
                    "content": (
                        "Analyze the following compact, untrusted LinuxMD diagnostic payload and "
                        "return the complete health assessment as JSON:\n"
                        + json.dumps(payload, sort_keys=True)
                    ),
                },
            ]
        )

    def repair(self, response, errors, evidence) -> dict[str, Any]:
        """Make one constrained correction request without resending diagnostic reports."""
        return self._request(_repair_messages(response, errors, evidence))

    @property
    def endpoint(self) -> str:
        """Return the credential-free resolved Chat Completions URL."""
        return _join_url(self._base_url, "chat", "completions")

    def _request(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        body = {
            "model": self._model,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "stream": False,
            "temperature": 0,
        }
        response_data = _post_json_httpx_once(
            self.endpoint,
            body,
            {"Authorization": f"Bearer {self._api_key}"},
            provider="Gemini",
            read_timeout=self._timeout,
            connect_timeout=self._connect_timeout,
        )
        try:
            output_text = response_data["choices"][0]["message"]["content"]
        except (IndexError, KeyError, TypeError) as exc:
            raise ProviderError("Gemini response did not contain structured output.") from exc
        try:
            result = json.loads(output_text)
        except json.JSONDecodeError as exc:
            raise ProviderJSONDecodeError(
                "Gemini returned invalid analysis JSON; the response could not be parsed.",
                raw_response=output_text,
            ) from exc
        return result


class DeepSeekProvider:
    """Request JSON analysis through DeepSeek's OpenAI-compatible Chat API."""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str,
        *,
        timeout: float = 180,
        connect_timeout: float = 30,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._connect_timeout = connect_timeout

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        return validate_analysis(self.generate(payload), provider="deepseek")

    def generate(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return decoded DeepSeek JSON before shared semantic validation."""
        return self._request(
            [
                {"role": "system", "content": _chat_system_instructions()},
                {
                    "role": "user",
                    "content": (
                        "Analyze the following compact, untrusted LinuxMD diagnostic payload and "
                        "return the complete health assessment as JSON:\n"
                        + json.dumps(payload, sort_keys=True)
                    ),
                },
            ]
        )

    def repair(self, response, errors, evidence) -> dict[str, Any]:
        """Make one constrained correction request without resending diagnostic reports."""
        return self._request(_repair_messages(response, errors, evidence))

    def _request(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        body = {
            "model": self._model,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "thinking": {"type": "disabled"},
            "stream": False,
            "max_tokens": 8192,
            "temperature": 0,
        }
        response_data = _post_json_httpx_once(
            _join_url(self._base_url, "chat", "completions"),
            body,
            {"Authorization": f"Bearer {self._api_key}"},
            provider="DeepSeek",
            read_timeout=self._timeout,
            connect_timeout=self._connect_timeout,
        )
        choices = response_data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderError("DeepSeek response did not contain choices.")
        choice = choices[0]
        if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
            raise ProviderError("DeepSeek response did not contain a message.")
        content = choice["message"].get("content")
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("DeepSeek response did not contain message content.")
        try:
            result = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ProviderJSONDecodeError("DeepSeek returned malformed JSON.") from exc
        if not isinstance(result, dict):
            raise ProviderJSONDecodeError("DeepSeek returned malformed JSON.")
        return result


def _chat_system_instructions() -> str:
    return (
        ANALYSIS_INSTRUCTIONS
        + "\n\nRequired JSON output schema:\n"
        + json.dumps(ANALYSIS_SCHEMA, sort_keys=True)
    )


def _repair_messages(response, errors, evidence) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                _chat_system_instructions()
                + "\nCorrect only the listed validation failures. Preserve numbers and evidence, "
                "and obey authoritative evidence fields exactly."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {"response": response, "validation_errors": errors, "authority": evidence},
                sort_keys=True,
            ),
        },
    ]


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """Metadata and construction details for one implemented provider."""

    display_name: str
    default_model: str | None
    default_base_url: str | None
    requires_api_key: bool
    is_real_provider: bool
    provider_type: (
        type[MockProvider] | type[OpenAIProvider] | type[GeminiProvider] | type[DeepSeekProvider]
    )


PROVIDER_CONFIGS: dict[str, ProviderConfig] = {
    "openai": ProviderConfig(
        display_name="OpenAI",
        default_model="gpt-5-mini",
        default_base_url="https://api.openai.com/v1",
        requires_api_key=True,
        is_real_provider=True,
        provider_type=OpenAIProvider,
    ),
    "gemini": ProviderConfig(
        display_name="Gemini",
        default_model="gemini-2.5-flash",
        default_base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        requires_api_key=True,
        is_real_provider=True,
        provider_type=GeminiProvider,
    ),
    "deepseek": ProviderConfig(
        display_name="DeepSeek",
        default_model="deepseek-v4-flash",
        default_base_url="https://api.deepseek.com",
        requires_api_key=True,
        is_real_provider=True,
        provider_type=DeepSeekProvider,
    ),
    "mock": ProviderConfig(
        display_name="Mock",
        default_model=None,
        default_base_url=None,
        requires_api_key=False,
        is_real_provider=False,
        provider_type=MockProvider,
    ),
}


def create_provider(
    name: str,
    api_key: str | None,
    model: str | None = None,
    base_url: str | None = None,
    timeout: float = 600,
    connect_timeout: float = 30,
) -> AnalysisProvider:
    """Create a configured provider without exposing its credentials."""
    normalized = name.strip().lower()
    config = PROVIDER_CONFIGS.get(normalized)
    if config is None:
        raise ProviderError(f"Unsupported LINUXMD_PROVIDER: {name}")
    if not config.is_real_provider:
        return config.provider_type()
    if config.requires_api_key and not api_key:
        raise ProviderError(f"LINUXMD_API_KEY is required when LINUXMD_PROVIDER={normalized}.")
    configured_model = model.strip() if model and model.strip() else config.default_model
    configured_base_url = (
        base_url.strip() if base_url and base_url.strip() else config.default_base_url
    )
    if configured_model is None or configured_base_url is None:
        raise ProviderError(f"Provider {normalized} has incomplete endpoint configuration.")
    kwargs = {"timeout": timeout, "connect_timeout": connect_timeout}
    return config.provider_type(api_key or "", configured_model, configured_base_url, **kwargs)


def _post_json_httpx_once(
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    provider: str,
    read_timeout: float,
    connect_timeout: float = 30,
) -> dict[str, Any]:
    """Perform exactly one HTTP request with independent timeout phases."""
    timeout = httpx.Timeout(
        connect=connect_timeout,
        read=read_timeout,
        write=60.0,
        pool=30.0,
    )
    debug = os.environ.get("LINUXMD_PROVIDER_DEBUG") == "1"
    started = perf_counter()
    started_at = _debug_timestamp()
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json=body, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        elapsed = perf_counter() - started
        details = _httpx_response_details(exc.response)
        status = exc.response.status_code
        _provider_debug(
            debug,
            started_at=started_at,
            ended_at=_debug_timestamp(),
            exception=type(exc).__name__,
            elapsed=elapsed,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            status=status,
            details=details,
        )
        category, message = _single_http_status_message(provider, status, details)
        raise ProviderRequestError(
            provider,
            category,
            message,
            status=status,
            timeout=read_timeout,
        ) from exc
    except (
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
    ) as exc:
        elapsed = perf_counter() - started
        category, phase_timeout, message = _httpx_timeout_error(
            provider, exc, connect_timeout, read_timeout
        )
        _provider_debug(
            debug,
            started_at=started_at,
            ended_at=_debug_timestamp(),
            exception=type(exc).__name__,
            elapsed=elapsed,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )
        raise ProviderRequestError(
            provider,
            category,
            message,
            timeout=phase_timeout,
        ) from exc
    except httpx.RequestError as exc:
        raise ProviderRequestError(
            provider,
            "network",
            f"{provider} network request failed ({type(exc).__name__}).",
        ) from exc

    try:
        parsed = response.json()
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProviderJSONDecodeError(
            f"{provider} response could not be parsed.", raw_response=response.text
        ) from exc
    if not isinstance(parsed, dict):
        raise ProviderJSONDecodeError(
            f"{provider} response could not be parsed.", raw_response=response.text
        )
    return parsed


def _single_http_status_message(
    provider: str, status: int, details: dict[str, Any] | None
) -> tuple[str, str]:
    detail = _safe_error_detail(details)
    if status == 429:
        return (
            "rate_limit",
            f"{provider} rate limit reached (HTTP 429). Please wait and run the command again.",
        )
    if status == 503:
        return (
            "temporary_failure",
            f"{provider} is temporarily unavailable (HTTP 503). "
            "Please run the command again later.",
        )
    if status == 404:
        message = f"{provider} model is unavailable (HTTP 404)."
        if detail:
            message = f"{message} Provider message: {detail}"
        return "not_found", message
    return _http_status_message(provider, status, details)


def _httpx_timeout_error(
    provider: str,
    error: httpx.TimeoutException,
    connect_timeout: float,
    read_timeout: float,
) -> tuple[str, float, str]:
    if isinstance(error, httpx.ConnectTimeout):
        return (
            "connection_timeout",
            connect_timeout,
            f"{provider} connection could not be established within {connect_timeout:g} seconds.",
        )
    if isinstance(error, httpx.ReadTimeout):
        return (
            "read_timeout",
            read_timeout,
            f"Provider did not complete the response within {read_timeout:g} seconds.",
        )
    if isinstance(error, httpx.WriteTimeout):
        return "write_timeout", 60.0, f"{provider} request upload timed out after 60 seconds."
    return "pool_timeout", 30.0, f"{provider} connection pool timed out after 30 seconds."


def _httpx_response_details(response: httpx.Response) -> dict[str, Any] | None:
    try:
        parsed = response.json()
    except (UnicodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _timed_http_attempt_summary(
    attempt: int, status: int, elapsed: float, details: dict[str, Any] | None
) -> str:
    base = _http_attempt_summary(attempt, status, details).removesuffix(".")
    return f"{base} after {elapsed:.1f} seconds."


def _httpx_retry_delay(response: httpx.Response, attempt: int, jitter: float) -> float:
    value = response.headers.get("Retry-After")
    try:
        if value is not None:
            return min(max(float(value), 0.0), 60.0)
    except ValueError:
        pass
    return _calculated_retry_delay(attempt=attempt, initial_delay=5.0, jitter=jitter)


def _http_status_message(
    provider: str, status: int, details: dict[str, Any] | None
) -> tuple[str, str]:
    messages = {
        400: ("invalid_request", f"{provider} rejected the request (HTTP 400)."),
        401: ("authentication", f"{provider} authentication failed (HTTP 401)."),
        403: ("authorization", f"{provider} authorization failed (HTTP 403)."),
        404: ("not_found", f"{provider} model or endpoint is unavailable (HTTP 404)."),
        429: ("rate_limit", f"{provider} rate limit exceeded (HTTP 429)."),
        500: ("temporary_failure", f"{provider} service temporarily unavailable (HTTP 500)."),
        502: ("temporary_failure", f"{provider} service temporarily unavailable (HTTP 502)."),
        503: ("temporary_failure", f"{provider} service temporarily unavailable (HTTP 503)."),
        504: ("temporary_failure", f"{provider} service temporarily unavailable (HTTP 504)."),
    }
    category, message = messages.get(
        status, ("http_error", f"{provider} request failed (HTTP {status}).")
    )
    detail = _safe_error_detail(details)
    if detail:
        message = f"{message} Provider message: {detail}"
    return category, message


def _provider_debug(
    enabled: bool,
    *,
    started_at: str,
    ended_at: str,
    exception: str,
    elapsed: float,
    connect_timeout: float,
    read_timeout: float,
    status: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    if not enabled:
        return
    print("Provider debug:", flush=True)
    print(f"  start timestamp: {started_at}", flush=True)
    print(f"  end timestamp: {ended_at}", flush=True)
    print(f"  exception: {exception}", flush=True)
    print(f"  elapsed seconds: {elapsed:.3f}", flush=True)
    print(
        f"  timeouts: connect={connect_timeout:g}, read={read_timeout:g}, write=60, pool=30",
        flush=True,
    )
    if status is not None:
        print(f"  HTTP status: {status}", flush=True)
    detail = _safe_error_detail(details)
    if detail:
        print(f"  provider message: {detail}", flush=True)


def _debug_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _post_json(
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    provider: str,
    read_timeout: float,
    connect_timeout: float = 30,
    max_attempts: int = 2,
    initial_retry_delay: float = 0.1,
    retry_jitter: float = 0.0,
) -> dict[str, Any]:
    """POST JSON and consistently translate transport and response failures."""
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    response_data = _send_with_retry(
        request,
        provider=provider,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        max_attempts=max_attempts,
        initial_retry_delay=initial_retry_delay,
        retry_jitter=retry_jitter,
    )
    if not isinstance(response_data, dict):
        raise ProviderError(f"{provider} returned a malformed response.")
    return response_data


def _send_with_retry(
    request: urllib.request.Request,
    *,
    provider: str,
    connect_timeout: float,
    read_timeout: float,
    max_attempts: int = 2,
    initial_retry_delay: float = 0.1,
    retry_jitter: float = 0.0,
) -> dict[str, Any]:
    transient = {429, 500, 502, 503, 504}
    failures: list[str] = []
    for attempt in range(max_attempts):
        try:
            with nullcontext():
                response = urllib.request.urlopen(request, timeout=connect_timeout)
                try:
                    with response:
                        _set_response_read_timeout(response, read_timeout)
                        response_bytes = response.read()
                except TimeoutError as exc:
                    raise _ProviderReadTimeout from exc
        except urllib.error.HTTPError as exc:
            details = _read_http_error(exc)
            failure = _http_attempt_summary(attempt + 1, exc.code, details)
            failures.append(failure)
            should_retry = exc.code in transient and attempt + 1 < max_attempts
            if provider == "Gemini" or should_retry:
                _print_http_attempt_failure(
                    provider,
                    attempt=attempt,
                    maximum=max_attempts,
                    status=exc.code,
                    details=details,
                )
            if should_retry:
                delay = _retry_delay(
                    exc,
                    attempt=attempt,
                    initial_delay=initial_retry_delay,
                    jitter=retry_jitter,
                )
                print(f"Retrying in {delay:.1f} seconds...", flush=True)
                time.sleep(delay)
            if should_retry:
                continue
            raise _http_error(
                provider,
                request.full_url,
                read_timeout,
                exc,
                retried=exc.code in transient,
                details=details,
                attempts=attempt + 1,
                attempt_failures=tuple(failures),
            ) from exc
        except _ProviderReadTimeout as exc:
            failures.append(
                f"Attempt {attempt + 1}: response timeout after {read_timeout:g} seconds."
            )
            if attempt + 1 < max_attempts:
                delay = _calculated_retry_delay(
                    attempt=attempt,
                    initial_delay=initial_retry_delay,
                    jitter=retry_jitter,
                )
                print(
                    f"{provider} attempt {attempt + 1} of {max_attempts} response timed out "
                    f"after {read_timeout:g} seconds.",
                    flush=True,
                )
                print(f"Retrying in {delay:.1f} seconds...", flush=True)
                time.sleep(delay)
                continue
            raise ProviderRequestError(
                provider,
                "read_timeout",
                f"{provider} did not complete its response within {read_timeout:g} seconds after "
                f"{max_attempts} attempts.",
                endpoint=request.full_url,
                timeout=read_timeout,
                retried=max_attempts > 1,
                attempt_failures=tuple(failures),
            ) from exc
        except TimeoutError as exc:
            failures.append(
                f"Attempt {attempt + 1}: connection timeout after {connect_timeout:g} seconds."
            )
            if attempt + 1 < max_attempts:
                delay = _calculated_retry_delay(
                    attempt=attempt,
                    initial_delay=initial_retry_delay,
                    jitter=retry_jitter,
                )
                print(
                    f"{provider} attempt {attempt + 1} of {max_attempts} connection timed "
                    f"out after {connect_timeout:g} seconds.",
                    flush=True,
                )
                print(f"Retrying in {delay:.1f} seconds...", flush=True)
                time.sleep(delay)
                continue
            raise ProviderRequestError(
                provider,
                "connection_timeout",
                f"{provider} connection could not be established within {connect_timeout:g} "
                "seconds; "
                "the provider could not be reached.",
                endpoint=request.full_url,
                timeout=connect_timeout,
                retried=max_attempts > 1,
                attempt_failures=tuple(failures),
            ) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                failures.append(
                    f"Attempt {attempt + 1}: connection timeout after {connect_timeout:g} seconds."
                )
                if attempt + 1 < max_attempts:
                    delay = _calculated_retry_delay(
                        attempt=attempt,
                        initial_delay=initial_retry_delay,
                        jitter=retry_jitter,
                    )
                    print(
                        f"{provider} attempt {attempt + 1} of {max_attempts} connection timed "
                        f"out after {connect_timeout:g} seconds.",
                        flush=True,
                    )
                    print(f"Retrying in {delay:.1f} seconds...", flush=True)
                    time.sleep(delay)
                    continue
                raise ProviderRequestError(
                    provider,
                    "connection_timeout",
                    f"{provider} connection could not be established within "
                    f"{connect_timeout:g} seconds; the provider could not be reached.",
                    endpoint=request.full_url,
                    timeout=connect_timeout,
                    retried=max_attempts > 1,
                    attempt_failures=tuple(failures),
                ) from exc
            raise _url_error(provider, request.full_url, connect_timeout, exc) from exc
        try:
            return json.loads(response_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProviderRequestError(
                provider,
                "malformed_response",
                f"{provider} returned a malformed response.",
                endpoint=request.full_url,
                timeout=read_timeout,
            ) from exc
    raise AssertionError("bounded retry loop exhausted unexpectedly")


class _ProviderReadTimeout(Exception):
    """Distinguish an established-connection read timeout from connection setup."""


def _http_attempt_summary(attempt: int, status: int, details: dict[str, Any] | None) -> str:
    provider_status = _provider_error_status(details)
    status_suffix = f" {provider_status}" if provider_status else ""
    detail = _safe_error_detail(details)
    detail_suffix = f" Provider message: {detail}" if detail else ""
    return f"Attempt {attempt}: HTTP {status}{status_suffix}.{detail_suffix}"


def _http_error(
    provider: str,
    endpoint: str,
    timeout: float,
    error: urllib.error.HTTPError,
    *,
    retried: bool,
    details: dict[str, Any] | None = None,
    attempts: int = 1,
    attempt_failures: tuple[str, ...] = (),
) -> ProviderRequestError:
    messages = {
        400: ("invalid_request", f"{provider} rejected the request (HTTP 400)."),
        401: ("authentication", f"{provider} authentication failed (HTTP 401)."),
        402: ("insufficient_balance", f"{provider} account has insufficient balance (HTTP 402)."),
        403: ("authorization", f"{provider} authorization failed (HTTP 403)."),
        404: ("not_found", f"{provider} model or endpoint is unavailable (HTTP 404)."),
        422: ("invalid_parameters", f"{provider} rejected invalid parameters (HTTP 422)."),
        429: ("rate_limit", f"{provider} rate limit exceeded (HTTP 429)."),
        500: ("temporary_failure", f"{provider} service temporarily unavailable (HTTP 500)."),
        502: ("temporary_failure", f"{provider} service temporarily unavailable (HTTP 502)."),
        503: ("temporary_failure", f"{provider} service temporarily unavailable (HTTP 503)."),
        504: ("temporary_failure", f"{provider} service temporarily unavailable (HTTP 504)."),
    }
    category, message = messages.get(
        error.code, ("http_error", f"{provider} request failed (HTTP {error.code}).")
    )
    if provider == "Gemini" and error.code == 503 and attempts >= 3:
        message = (
            f"Gemini is temporarily overloaded after {attempts} attempts. Please try again later "
            "or select another model."
        )
    elif provider == "Gemini" and error.code == 429 and attempts >= 3:
        message = f"Gemini rate or quota limit reached after {attempts} attempts."
    detail = _safe_error_detail(details)
    if detail and error.code in {400, 422, 429, 500, 502, 503, 504}:
        message = f"{message} Provider message: {detail}"
    return ProviderRequestError(
        provider,
        category,
        message,
        status=error.code,
        endpoint=endpoint,
        timeout=timeout,
        retried=retried,
        attempt_failures=attempt_failures,
    )


def _url_error(
    provider: str, endpoint: str, timeout: float, error: urllib.error.URLError
) -> ProviderRequestError:
    reason = error.reason
    host = urllib.parse.urlsplit(endpoint).hostname or "provider host"
    if isinstance(reason, socket.gaierror):
        category, message = "dns", f"DNS resolution failed for {host}."
    elif isinstance(reason, ssl.SSLError):
        category, message = "tls", f"TLS or certificate validation failed for {host}."
    elif isinstance(reason, ConnectionRefusedError):
        category, message = "connection_refused", f"Connection to {host} was refused."
    elif isinstance(reason, ConnectionResetError):
        category, message = "connection_reset", f"Connection to {host} was reset."
    elif isinstance(reason, TimeoutError):
        category = "connection_timeout"
        message = (
            f"{provider} connection timed out after {timeout} seconds; "
            "the provider could not be reached."
        )
    else:
        category, message = "network", f"{provider} network request failed."
    return ProviderRequestError(provider, category, message, endpoint=endpoint, timeout=timeout)


def _retry_delay(
    error: urllib.error.HTTPError,
    *,
    attempt: int = 0,
    initial_delay: float = 0.1,
    jitter: float = 0.0,
) -> float:
    value = error.headers.get("Retry-After") if error.headers else None
    try:
        if value is not None:
            return min(max(float(value), 0.0), 60.0)
    except ValueError:
        pass
    return _calculated_retry_delay(
        attempt=attempt,
        initial_delay=initial_delay,
        jitter=jitter,
    )


def _calculated_retry_delay(*, attempt: int, initial_delay: float, jitter: float) -> float:
    del initial_delay
    schedule = (5.0, 15.0, 30.0)
    return schedule[min(attempt, len(schedule) - 1)] + random.uniform(0.0, max(jitter, 0.5))


def _print_http_attempt_failure(
    provider: str,
    *,
    attempt: int,
    maximum: int,
    status: int,
    details: dict[str, Any] | None,
) -> None:
    provider_status = _provider_error_status(details)
    suffix = f" {provider_status}" if provider_status else ""
    print(
        f"{provider} attempt {attempt + 1} of {maximum} failed: HTTP {status}{suffix}.",
        flush=True,
    )
    safe_message = _safe_error_detail(details)
    if safe_message:
        print(f"{provider} provider message: {safe_message}", flush=True)


def _provider_error_status(details: dict[str, Any] | None) -> str | None:
    if not details or not isinstance(details.get("error"), dict):
        return None
    status = details["error"].get("status")
    if not isinstance(status, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", status):
        return None
    return status


def _set_response_read_timeout(response: Any, timeout: float) -> None:
    """Apply a read timeout to urllib's established response socket when accessible."""
    fp = getattr(response, "fp", None)
    candidates = (
        getattr(getattr(fp, "raw", None), "_sock", None),
        getattr(getattr(getattr(fp, "fp", None), "raw", None), "_sock", None),
    )
    for sock in candidates:
        if sock is not None and hasattr(sock, "settimeout"):
            sock.settimeout(timeout)
            return


def _read_http_error(error: urllib.error.HTTPError) -> dict[str, Any] | None:
    """Parse provider error JSON when available without exposing it in user messages."""
    try:
        body = error.read().decode("utf-8")
        parsed = json.loads(body)
    except (AttributeError, OSError, UnicodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _safe_error_detail(details: dict[str, Any] | None) -> str | None:
    if not details:
        return None
    error = details.get("error")
    candidate = error.get("message") if isinstance(error, dict) else details.get("message")
    if not isinstance(candidate, str):
        return None
    sanitized = re.sub(r"(?i)bearer\s+\S+", "Bearer [redacted]", candidate)
    sanitized = re.sub(
        r"(?i)(?:api[_ -]?key|token|authorization)\s*[:=]\s*\S+",
        "credential=[redacted]",
        sanitized,
    )
    return " ".join(sanitized.split())[:240] or None


def _join_url(base_url: str, *parts: str) -> str:
    """Join URL path components without introducing duplicate separators."""
    return "/".join([base_url.rstrip("/"), *(part.strip("/") for part in parts)])
