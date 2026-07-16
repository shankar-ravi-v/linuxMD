# LLM Providers

LinuxMD supports OpenAI, Gemini, DeepSeek, and a non-network mock mode for development.

| Provider | Default model | Default base URL |
| --- | --- | --- |
| OpenAI | `gpt-5-mini` | `https://api.openai.com/v1` |
| Gemini | `gemini-2.5-flash` | `https://generativelanguage.googleapis.com/v1beta/openai` |
| DeepSeek | `deepseek-v4-flash` | `https://api.deepseek.com` |

## Environment variables

- `LINUXMD_PROVIDER`: `openai`, `gemini`, or `deepseek`
- `LINUXMD_API_KEY`: provider credential
- `LINUXMD_MODEL`: optional model override
- `LINUXMD_BASE_URL`: optional compatible endpoint override
- `LINUXMD_TIMEOUT_SECONDS`: read timeout, default `600`
- `LINUXMD_CONNECT_TIMEOUT_SECONDS`: connection timeout, default `30`
- `LINUXMD_PROVIDER_DEBUG=1`: sanitized transport diagnostics

Timeout values must be positive numbers. Provider requests use a 30-second connect timeout,
600-second default read timeout, 60-second write timeout, and 30-second pool timeout where
supported.

## Bash, zsh, or WSL

```console
export LINUXMD_PROVIDER=gemini
export LINUXMD_API_KEY=<your_api_key>
export LINUXMD_MODEL=gemini-2.5-flash
uv run linuxmd analyze --detailed
```

## PowerShell

```powershell
$env:LINUXMD_PROVIDER = "deepseek"
$env:LINUXMD_API_KEY = "<your_api_key>"
$env:LINUXMD_MODEL = "deepseek-v4-flash"
uv run linuxmd analyze --detailed
```

Use `LINUXMD_BASE_URL` for OpenAI-compatible custom endpoints. LinuxMD never prints API keys or
authorization headers. `--verbose` shows credential-free endpoint and timeout information;
`--debug` writes sanitized payload and failure diagnostics.

Provider transport is synchronous. HTTP and network failures are reported rather than converted
into evidence, and LinuxMD does not automatically retry provider requests. Structured provider
output passes deterministic overlay, normalization, and validation before `analysis.json` is
replaced.
