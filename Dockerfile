FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

LABEL Title="Okta Open Source MCP Server" \
      Description="Model Context Protocol server for Okta API integration" \
      Authors="Okta" \
      Licenses="Apache-2.0" \
      Version="1.0.0" \
      Maintainer="Okta"

# Install uv (0.11.31+ carries the quick-xml 0.41.0 fix for RUSTSEC-2026-0194/0195)
COPY --from=ghcr.io/astral-sh/uv:0.11.31@sha256:ecd4de2f060c64bea0ff8ecb182ddf46ba3fcccdc8a60cfdbaf20d1a047d7437 /uv /usr/local/bin/uv

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
