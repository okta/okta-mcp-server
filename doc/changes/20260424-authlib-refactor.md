# Authlib Refactor & DevContainer Support

## Purpose

Replace hand-rolled OAuth 2.0 implementations in `OktaAuthManager` with
authlib primitives. This is tech-debt cleanup that unblocks adding the ID-JAG
grant for Cross-App Access (XAA) without further custom OAuth plumbing. The
full refactor plan is documented in `doc/AUTHLIB_REFACTOR_PLAN.md`.

Additionally, add a devcontainer configuration and fix Docker keyring volume
ownership so the project can be developed and debugged inside containers
(PyCharm Gateway / VS Code Remote).

## Impact

- **Public API unchanged.** `OktaAuthManager.__init__`, `authenticate`,
  `is_valid_token`, `refresh_access_token`, and `clear_tokens` keep identical
  signatures. Env-var and keyring contracts are preserved.
- **Dependency change:** `authlib>=1.3.0` added; `pyjwt` is no longer
  imported (authlib handles JWT signing internally via `cryptography`).
- **Browserless flow:** `_get_client_assertion` removed; replaced by authlib
  `OAuth2Session` with `PrivateKeyJWT` client auth method.
- **Token refresh:** `refresh_access_token` now uses `OAuth2Session.refresh_token`
  instead of a manual `requests.post`.
- **Device flow polling:** Added handling for two previously missing RFC 8628
  error codes: `slow_down` (backs off interval) and `expired_token` (aborts).
- **Docker:** Keyring volume now mounts to `/home/appuser/` (not `/root/`),
  matching the non-root user. Dockerfile creates the keyring directory with
  correct ownership. `docker-compose.yml` declares the named volume and sets
  the image name.
- **DevContainer:** New `.devcontainer/` with Dockerfile and
  `devcontainer.json` for containerised development with PyCharm or VS Code.

## Implementation

### auth_manager.py

- Removed `_get_client_assertion` (manual JWT minting via `pyjwt`).
- `_browserless_authenticate` now creates an `OAuth2Session` configured with
  `token_endpoint_auth_method="private_key_jwt"`, registers a `PrivateKeyJWT`
  instance with the `kid` header, and calls `session.fetch_token`.
- `refresh_access_token` now creates an `OAuth2Session` with
  `token_endpoint_auth_method="none"` and calls `session.refresh_token`.
- `_poll_for_token` now handles `slow_down` (exponential back-off on the
  polling interval) and `expired_token` (returns `None`).
- Exception handling simplified: broad `except Exception` catches authlib and
  network errors in both flows, logged with a single message.

### pyproject.toml

- Added `authlib>=1.3.0` to dependencies.
- Added `pytest-cov>=6.0.0` to dev dependencies.
- Added `[tool.pytest.ini_options]` with `asyncio_mode = "strict"` and a
  filter to suppress `AuthlibDeprecationWarning`.
- Added `[tool.coverage.run]` and `[tool.coverage.report]` configuration.

### Docker / DevContainer

- `Dockerfile`: creates `/home/appuser/.local/share/python_keyring` with
  correct ownership.
- `docker-compose.yml`: keyring volume target changed from `/root/` to
  `/home/appuser/`, image name set, top-level `volumes:` block added.
- `.devcontainer/Dockerfile`: Python 3.13-slim image with `uv`, optional
  corporate CA cert, `debugpy`, non-root user.
- `.devcontainer/devcontainer.json`: PyCharm Gateway settings, keyring
  volume mount, port forwarding.

### .gitignore

- Added `.devcontainer/corporate-ca.crt` (machine-specific cert).
- Added `/.claude/settings.local.json`.

## Test

New test file `tests/test_auth_manager.py` (759 lines) providing comprehensive
unit-test coverage for `OktaAuthManager`:

- **TestInit:** env-var validation, `https://` prefix normalisation, default
  and custom scope merging, browserless flag detection.
- **TestBrowserlessAuth:** authlib `OAuth2Session` + `PrivateKeyJWT` wiring,
  success path (token stored in keyring), missing-token response, exception
  handling.
- **TestDeviceFlowAuth:** device authorisation initiation, successful token
  polling, `authorization_pending` retry, `slow_down` back-off,
  `access_denied` and `expired_token` terminal errors, HTTP failure, browser
  open and user code display.
- **TestTokenRefresh:** successful refresh with new refresh token rotation,
  refresh without rotation, missing refresh token, failure handling.
- **TestIsValidToken:** token within / beyond expiry window, fresh token,
  keyring miss (no token stored).
- **TestClearTokens:** keyring deletion of both `api_token` and
  `refresh_token`.
- **TestAuthenticate:** integration-level async tests for device-flow and
  browserless dispatch, plus failure-to-authenticate path.

All external I/O is mocked (`requests`, `keyring`, `OAuth2Session`,
`PrivateKeyJWT`, `webbrowser`, `time`).

### Code Coverage

| File | Stmts | Miss | Branch | BrPart | Cover |
|---|---|---|---|---|---|
| `src/okta_mcp_server/utils/auth/auth_manager.py` | 205 | 6 | 46 | 6 | **95%** |

43 tests, all passing. Uncovered lines: 88, 202-204, 252, 278 (edge-case
error paths in device-flow initiation and re-authentication fallback).
