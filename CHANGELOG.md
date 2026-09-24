# Changelog
All notable changes to this project will be documented in this file.

## v1.1.7

### Security
- Raised transitive dependency floors in `[tool.uv] constraint-dependencies` to clear four Dependabot security advisories against pinned entries in `uv.lock` ([#121](https://github.com/okta/okta-mcp-server/pull/121)). None of the flagged packages are declared in `[project] dependencies` — they are pulled in through our direct deps — so the fix follows the v1.1.5 pattern of bounding transitive packages via `constraint-dependencies` and re-resolving once, making the floor durable against a future `uv lock` regression:
  - `aiohttp>=3.14.3` — reached via `okta` (its async HTTP layer).
  - `anyio>=4.15.1` — reached via `mcp` directly, and transitively through `httpx`, `starlette`, and `sse-starlette`.
  - `pygments>=2.21.0` — reached via `rich` ← `typer` ← `mcp[cli]` (ships in the runtime image); also a `pytest` dependency in the dev group.
  - `cryptography>=50.0.0` (was `>=48.0.1`) — reached via `jwcrypto` ← `okta` and `pyjwt[crypto]` ← `mcp`.
  - Re-resolving updates `aiohttp` 3.14.1 → 3.14.3, `anyio` 4.9.0 → 4.15.1, `cryptography` 49.0.0 → 50.0.1, and `pygments` 2.19.1 → 2.21.0. Also drops `sniffio` 1.3.1 (no longer required by `anyio` ≥ 4.15), taking the locked graph from 77 → 76 packages. No source changes; full test suite passes unchanged.

### Improvements
- Upgraded the Okta Python SDK from **3.4.4 → 3.4.6** to pick up two upstream spec fixes:
  - **3.4.6** ([okta-sdk-python#580](https://github.com/okta/okta-sdk-python/pull/580)) — relaxed the last five over-strict `required` boolean constraints on `SamlApplicationSettingsSignOn` (`allowMultipleAcsEndpoints`, `assertionSigned`, `honorForceAuthn`, `requestCompressed`, `responseSigned`). App Catalog / OIN SAML applications legitimately omit these on `GET`, so a single such app was raising `ValidationError` and failing entire paginated pages of `list_applications`. Completes the read-side fix started in SDK 3.4.3. Directly benefits the `list_applications` MCP tool and the new OIN catalog tools shipped in v1.1.6.
  - **3.4.5** ([okta-sdk-python#575](https://github.com/okta/okta-sdk-python/pull/575)) — resolved a name collision where OpenAPI Generator promoted the inline `User.type` object into a `UserType` class that shadowed the real `components/schemas/UserType`, causing `/api/v1/meta/types/user/*` responses to silently drop every field except `id`. The spec now defines a dedicated `UserTypeRef` for `User.type` and `UserType` carries its full field set (`name`, `displayName`, `description`, `created`, `createdBy`, `default`, `lastUpdated`, `lastUpdatedBy`, `_links`). Note: the Python-level type of `User.type` changed from `UserType` to `UserTypeRef` upstream, but wire-format JSON is unchanged and no MCP tool relies on the Python type annotation, so tool signatures and response shapes are unaffected.
  - Full test suite passes unchanged.

## v1.1.6

### Features
- Added `list_user_groups` to list every group a given user is a member of ([#115](https://github.com/okta/okta-mcp-server/pull/115)). The Okta endpoint returns the user's full group membership in a single response and does not paginate, so the tool exposes no pagination parameters — use `list_groups` for an org-wide listing. Introduces a new **User Resources** tool family at `tools/user_resources/`.
- Added Okta Integration Network (OIN) catalog tools — `list_catalog_apps` and `get_catalog_app` (`okta.apps.read`) to browse the catalog and read an app definition with its provisioning schema, plus `install_oin_app` (`okta.apps.manage`) to install an instance ([#75](https://github.com/okta/okta-mcp-server/pull/75)). Outbound SCIM provisioning only works on an instance of a provisioning-capable catalog app: the capability is fixed by the catalog definition at install time and cannot be added to a plain custom SAML/OIDC app afterwards. `create_application` cannot install one because the typed SDK strips the catalog `name` key from the request body, so `install_oin_app` issues the request directly.

### Improvements
- `list_catalog_apps` supports `q` keyword filtering and `after` / `limit` / `fetch_all` pagination against an endpoint that paginates (default page size **20**) but, unlike the rest of the Okta API, sends no `Link: rel="next"` header — the cursor is synthesized from the last entry's catalog `name`, `fetch_all` dedups by name so a misbehaving cursor cannot duplicate entries or loop, and an early stop reports `stopped_early` with a resume cursor instead of implying the walk completed ([#75](https://github.com/okta/okta-mcp-server/pull/75)).
- Added `tests/test_oin_catalog.py` (18 tests) and `tests/test_user_resources.py` (9 tests). Suite total: **529 → 556 tests**, all passing.

### Documentation
- Documented the four new tools in the README supported-tools tables and scope matrix. Tool total: **109 → 113**.

## v1.1.5

### Security
- Bumped vulnerable dependencies and pinned the Docker base images by digest to raise the Docker Scout health score of the published `mcp/okta-mcp-server` image ([#94](https://github.com/okta/okta-mcp-server/pull/94)):
  - Raised the `mcp[cli]` SDK floor to **1.28.1**.
  - Added `[tool.uv]` `constraint-dependencies` floors for `urllib3>=2.7.0`, `cryptography>=48.0.1`, `starlette>=1.3.1`, `python-multipart>=0.0.31`, `click>=8.3.3`, `jaraco.context>=6.1.0`, `python-dotenv>=1.2.2`, and `idna>=3.15` to close the CVEs Docker Scout flagged transitively.
  - Pinned both Dockerfile base images by digest for reproducibility: `python:3.13-slim` and `ghcr.io/astral-sh/uv:0.11.31` (uv 0.11.31 carries the quick-xml 0.41.0 fix for RUSTSEC-2026-0194/0195).
  - Result: Docker Scout Critical/High/Medium dropped from 1/21/13 to only the residual base-image `perl` CVEs (no upstream fix available yet). All 529 existing tests pass unchanged.

### Improvements
- Upgraded the `pytest` dev dependency floor to **9.0.3**.

### Documentation
- Updated the logo thumbnail image ([#97](https://github.com/okta/okta-mcp-server/pull/97)).

## v1.1.4

### Documentation
- Renamed the self-hosted server to **"Okta Open Source MCP Server"** and updated all existing references from "Okta MCP Server" to "Okta Open Source MCP Server" ([#91](https://github.com/okta/okta-mcp-server/pull/91)).

### Bug Fixes
- Standardized MCP tool responses to valid JSON per RFC 8259 across all 109 tools; fixes [#14](https://github.com/okta/okta-mcp-server/issues/14). Tool responses no longer leak raw Python `repr` for `ApplicationSignOnMode.SAML_2_0`, `OktaAPIResponse` objects, SDK tuples, or other non-JSON types.
- Standardized error return shape for `@validate_ids` / `@validate_os_version_params` and every tool that previously emitted `[f"Error: {e}"]` — errors are now returned as `[{"error": "..."}]` / `[{"exception": "..."}]` so callers always parse valid JSON.
- Fixed `create_custom_domain` and `create_email_domain` to handle Okta's 204 / empty-body response by refetching the newly created resource via `list_custom_domains` / `list_email_domains`. FQDN comparison is case-insensitive per RFC 1035, applied consistently across **both** the pre-create duplicate check and the post-create refetch lookup in **both** tools (all four comparisons were audited; the email-domains fallback and both modules' duplicate-check loops were previously case-sensitive).
- Fixed the `create_email_customization` duplicate-language pre-check in `custom_templates.py` to compare BCP 47 (RFC 5646) language tags case-insensitively, matching the FQDN fix above.
- Extended the `(None, response, None)` empty-body guard — previously applied only to the customization tool family — to every other `get_*`/`create_*`/`update_*`/`replace_*`/`verify_*` tool that unpacks an Okta SDK 3-tuple and dereferences the result: `applications.py` (`get_application`, `create_application`, `update_application`), `groups.py` (`get_group`, `create_group`, `update_group`), `users.py` (`get_user`, `create_user`, `update_user`), `policies.py` (all 6 of `get_policy`, `create_policy`, `update_policy`, `get_policy_rule`, `create_policy_rule`, `update_policy_rule`), `device_assurance.py` (`get_device_assurance_policy`, `create_device_assurance_policy`, `replace_device_assurance_policy` — the latter two previously returned bare `None` instead of an error dict), and `custom_domains.py` (`verify_custom_domain`). Two of these (`groups.create_group`, `users.create_user`) previously crashed with an unguarded `AttributeError` on `group.id` / `user.id` when the SDK quirk fired, masked into a confusing `{"exception": "'NoneType' object has no attribute 'id'"}`.
- Fixed the dynamically-registered scope-info stub tools in `utils/scope_stubs.py` (registered via `mcp.tool()(stub_fn)` rather than `@mcp.tool()` decorator syntax) to also pass through `@json_response` — previously the only MCP-tool-registered callables in the server that bypassed the single JSON boundary.

### Improvements
- Added `okta_mcp_server.utils.serialization` as the single normalization boundary for tool returns. `to_jsonable()` flattens Pydantic v2 models (`model_dump(by_alias=True, exclude_none=True, mode="json")`), Okta SDK v2 models (`to_dict()`), `Enum` values (`.value`), and drops transport-only `OktaAPIResponse` / `ApiResponse` objects. `Enum` unwrapping is checked before the scalar branch so `(str, Enum)` / `(int, Enum)` mixins (e.g. `ApplicationSignOnMode`) serialize to their `.value`.
- Added `@json_response` decorator, applied innermost on every `@mcp.tool` so every response passes through the canonical serializer exactly once. Note: the decorator catches *any* exception raised while running the wrapped tool, not only a serialization failure — see the module and decorator docstrings in `serialization.py` for the resulting `isError=False` tradeoff.
- Added `okta_mcp_server.utils.serialization.none_body_error()`, a shared helper for the `(None, response, None)` guard above — builds the `{"error": "..."}` envelope and logs a warning in one call instead of repeating the same six lines at every call site.
- Added a structured failure envelope (`{"ok": false, "error": {...}, "status_code": null, "raw": {}}`) returned when serialization itself raises, so callers always receive valid JSON. The full traceback is written to the server log via `logger.exception`; the last 4096 chars can additionally be surfaced to the caller as `raw.traceback_tail` by setting `OKTA_MCP_INCLUDE_RAW=1` (accepted truthy values: `1`, `true`, `yes`, `on`). Default is off to avoid leaking server-side stack frames to MCP clients.
- Centralized JSON normalization in `create_paginated_response()` — the paginated payload is returned untouched and flattened once by the outer `@json_response` decorator, removing the redundant lazy import back into `serialization.py`.
- Removed redundant per-tool `_serialize_*` helpers in `brands.py`, `custom_domains.py`, `email_domains.py`, and `themes.py`. `custom_templates.py` intentionally retains its local `_serialize()` helper because the SDK's `to_dict()` drops server-readOnly preview fields (e.g. `EmailPreview.body`, `.subject`) that `model_dump()` preserves. `custom_pages.py` retains its helper to preserve the legacy `{}` return for legitimate empty-body responses on preview endpoints; the helper now uses `mode="json"` so nested `datetime` / `UUID` / `Enum` fields still meet the RFC 3339 guarantee.
- Reworked `create_device_assurance_policy` and `replace_device_assurance_policy` so `policy_data` is typed as `Dict[str, Any]` at the FastMCP boundary and any `PolicyDataInput` validation error is surfaced as `{"error": "..."}` instead of leaking a plain-text `pydantic.ValidationError`.
- Added `tests/test_serialization.py` (44 tests), `tests/test_custom_domains.py` (7 tests), `tests/test_none_body_guards.py` (28 tests, covering all None-body guards across 9 modules), and `tests/test_scope_stubs.py` (4 tests). Extended `tests/test_device_assurance.py` (136 tests total) and `tests/test_custom_templates.py` (51 tests total).

## v1.1.3

### Bug Fixes
- Upgraded Okta SDK from **3.4.1 → 3.4.4** to fix an upstream deserialization error on `GET /api/v1/policies/{policyId}/rules`. The 3.4.1 SDK modeled the `AccessPolicyConstraint.methods` / `AccessPolicyConstraint.types` enums as uppercase-only (`PASSWORD`, `PUSH`, `SECURITY_KEY`, …), while the live API returns lowercase values (`password`, `push`, `security_key`, …), causing the `list_policy_rules` MCP tool to fail on Access Policy rules that carry authenticator constraints.

## v1.1.2

### Features
- PyPI Release changes

## v1.1.1

### Features
- GA Release changes

## v1.1.0

### Features
- Added Device Assurance Policy tools (`list_device_assurance_policies`, `get_device_assurance_policy`, `create_device_assurance_policy`, `replace_device_assurance_policy`, `delete_device_assurance_policy`) with support for Android, iOS, macOS, Windows, and ChromeOS platforms.
- Upgraded Okta SDK dependency to v3.4.1.
- Added customization tools for brands, custom domains, custom pages, custom templates, email domains, and themes.
- Added scope-based tool loading — tools are now dynamically enabled based on the OAuth scopes available to the configured API token.
- Added `login_failures` system log tool for querying recent authentication failures.

### Bug Fixes
- Fixed pagination bug introduced by Okta SDK v3 upgrade.
- Fixed `add_user_to_group` to be idempotent (no longer errors if user is already a member).
- Fixed `get_logs` to support filtering by `DENY` outcome.
- Added `fetch_all` support to `list_applications`.

### Improvements
- Pagination improvements with better handling of large result sets.

## v1.0.0

- Initial release of the self hosted okta-mcp-server.
