FROM python:3.13-slim

# Required by PyCharm Gateway to download the remote IDE backend
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Add corporate root CA if present (needed when behind SSL inspection proxy)
COPY --chown=root:root .devcontainer/corporate-ca.crt* /usr/local/share/ca-certificates/
RUN update-ca-certificates

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first (for better caching)
COPY pyproject.toml uv.lock ./
COPY src ./src
COPY README.md ./

# Install all deps including dev, plus debugpy for PyCharm remote debugging
RUN uv sync && uv pip install debugpy

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app \
    && mkdir -p /home/appuser/.local/share/python_keyring \
    && chown -R appuser:appuser /home/appuser/.local
USER appuser

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring
