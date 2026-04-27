# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

`uv` is at `{home}/.local/bin/uv` (not on PATH in non-interactive shells — always use the full path).

```bash
# Install dependencies
{home}/.local/bin/uv sync

# Run all tests
{home}/.local/bin/uv run pytest

# Run a single test file
{home}/.local/bin/uv run pytest tests/test_auth_manager.py -v

# Run a single test by name
{home}/.local/bin/uv run pytest tests/test_auth_manager.py::TestTokenRefresh::test_refresh_success -v

# Lint
{home}/.local/bin/uv run ruff check .

# Format / auto-fix
{home}/.local/bin/uv run ruff check --fix . && {home}/.local/bin/uv run ruff format .

# Run the server (requires env vars)
{home}/.local/bin/uv run okta-mcp-server
```

## Architecture

This is a **FastMCP server** that exposes Okta Admin Management API operations as MCP tools, allowing LLM agents to manage an Okta organization.

### Request lifecycle

```
MCP Client → FastMCP (server.py) → tool function (tools/**/*.py)
                                       ↓
                                   get_okta_client()  ← validates/refreshes token
                                       ↓
                                   Okta SDK (okta library)
```

On startup, `server.py` runs `okta_authorisation_flow` (an async context manager used as the FastMCP lifespan). It creates `OktaAuthManager`, authenticates, and yields `OktaAppContext` — which is available in every tool via `ctx.request_context.lifespan_context.okta_auth_manager`.

### Tool registration

Tools are registered by importing their modules inside `main()` in `server.py`. Each module calls `@mcp.tool()` decorators at import time, which registers the function with the shared `mcp` instance (a module-level singleton in `server.py`). New tools must be imported in `main()` to be registered.

### Auth (`utils/auth/auth_manager.py`)

`OktaAuthManager` supports three flows:
- **Device Authorization Grant** (default): interactive, browser-based; tokens stored in OS keyring
- **Private Key JWT** (`OKTA_PRIVATE_KEY` + `OKTA_KEY_ID` set): browserless, no refresh token
- **XAA / RFC 8693 Token Exchange** (planned): enterprise cross-app access via identity assertion JWT

Tokens are stored in the OS keyring under service name `"OktaAuthManager"` with keys `"api_token"` and `"refresh_token"`. Docker requires `PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring` and a persistent volume.

### Destructive operations and elicitation

All delete/deactivate tools call `elicit_or_fallback()` from `utils/elicitation.py` before executing. This uses `ctx.elicit()` to show a structured confirmation dialog. If the client doesn't support elicitation, it returns a `fallback_response` dict that the LLM relays to the user (legacy two-step flow). Schemas are `DeleteConfirmation` and `DeactivateConfirmation` (both have a single `confirm: bool` field).

### Input validation

The `@validate_ids()` decorator in `utils/validation.py` wraps tool functions and rejects IDs containing path traversal sequences (`../`, `\`, `%2f`, etc.) or query/fragment injection (`?`, `#`). Apply it to any tool that accepts a user-supplied Okta ID.

### Pagination

`utils/pagination.py` provides `build_query_params()`, `paginate_all_results()`, and `create_paginated_response()`. Tools expose `after` (cursor), `limit` (20–100), and `fetch_all` parameters. Responses include `has_more`, `next_cursor`, and `total_fetched`.

## Testing patterns

pytest-asyncio is configured in strict mode. Async test functions need `@pytest.mark.asyncio`.

`conftest.py` provides:
- `FakeOktaAuthManager` / `FakeLifespanContext` — lightweight stubs; no real auth
- `ctx_elicit_accept_true/false`, `ctx_elicit_decline`, `ctx_elicit_cancel`, `ctx_no_elicitation`, `ctx_elicit_exception`, `ctx_elicit_mcp_error_method_not_found`, `ctx_elicit_mcp_error_other` — pre-built context mocks for elicitation scenarios
- `mock_okta_client` — `AsyncMock` with all destructive Okta SDK methods pre-configured to return `(None, None)`

Patch targets use the module namespace, e.g.:
```python
patch("okta_mcp_server.utils.auth.auth_manager.requests")
patch("okta_mcp_server.utils.auth.auth_manager.keyring")
patch("okta_mcp_server.utils.auth.auth_manager.jwt")
```

## Linting

Ruff (`.ruff.toml`): line length 119, double quotes, 4-space indent. Rules: `F` (Pyflakes), `E` (pycodestyle), `I` (isort), `RUF`. CI enforces this via `.github/workflows/ruff-check.yml`.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `OKTA_ORG_URL` | yes | Okta org URL (https:// prefix added if missing) |
| `OKTA_CLIENT_ID` | yes | OAuth2 client ID |
| `OKTA_SCOPES` | yes | Space-separated API scopes |
| `OKTA_PRIVATE_KEY` | no | PEM private key — enables browserless auth |
| `OKTA_KEY_ID` | no | Key ID (KID) for the private key |
| `OKTA_LOG_LEVEL` | no | Log level, default `INFO` |
| `OKTA_LOG_FILE` | no | Path for rotating log file (5-day retention) |
| `PYTHON_KEYRING_BACKEND` | Docker only | Set to `keyrings.alt.file.PlaintextKeyring` |

## Feature and Bug Fix Implementation
- every feature and bug fix must be documented in the ./doc/changes/ directory with the following constraints: 1. File format DATATIME-<short feature description>.md 2. The file must contain the following sections: a. Purpose [of the change] b. Impact [to the existing functionality] c. Implementation [overview] d. Test [overview, including code coverage for files with new changes]
- update CHANGELOG.md with a short feature description and a link to the appropriate file in ./doc/changes/ . Unless otherwise specified, put the updates under a date heading in the format of ## <Month name>, <Year>