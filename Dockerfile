# syntax=docker/dockerfile:1

FROM ghcr.io/astral-sh/uv:0.11.28 AS uv

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY --from=uv /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

RUN useradd --create-home --uid 10001 linuxmd \
    && mkdir /data \
    && chown linuxmd:linuxmd /data

USER linuxmd
WORKDIR /data
ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["linuxmd"]
CMD ["all"]
