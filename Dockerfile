FROM python:3.13-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first (for better caching)
COPY pyproject.toml uv.lock ./

COPY src ./src

# Copy README.md if it exists (needed by some builds)
COPY README.md ./

RUN uv sync --no-dev

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Run the server using the console script entry point
ENTRYPOINT ["okta-mcp-server"]
