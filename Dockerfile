FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

LABEL Title="Okta Open Source MCP Server" \
      Description="Model Context Protocol server for Okta API integration" \
      Authors="Okta" \
      Licenses="Apache-2.0" \
      Version="1.0.0" \
      Maintainer="Okta"

# Install uv
# Digest pin is the latest uv release as of writing; it still bundles vulnerable quick-xml 0.39.2
# (RUSTSEC-2026-0194/0195) pending https://github.com/astral-sh/uv/pull/20583 — re-pin once that ships.
COPY --from=ghcr.io/astral-sh/uv:0.11.30@sha256:93b61e21202b1dab861092748e46bbd6e0e41dd84f59b9174efd2353186e1b47 /uv /usr/local/bin/uv

WORKDIR /app

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

# Run the server using the console script entry point
ENTRYPOINT ["okta-mcp-server"]
