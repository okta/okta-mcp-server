FROM python:3.13-slim

LABEL Title="Okta MCP Server" \
      Description="Model Context Protocol server for Okta API integration" \
      Authors="Okta" \
      Licenses="Apache-2.0" \
      Version="1.0.0" \
      Maintainer="Okta"

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY zscaler-root.crt /usr/local/share/ca-certificates/zscaler.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler.crt && update-ca-certificates
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV UV_SSL_FILE=/etc/ssl/certs/ca-certificates.crt

# Copy dependency files first (for better caching)
COPY pyproject.toml uv.lock ./

COPY src ./src

# Copy README.md if it exists (needed by some builds)
COPY README.md ./

RUN uv sync --no-dev

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
USER appuser

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
# Use file-based keyring backend for Docker (no system keyring available)
ENV PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring

ENV NODE_USE_SYSTEM_CA=1
# Run the server using the console script entry point
ENTRYPOINT ["okta-mcp-server"]
