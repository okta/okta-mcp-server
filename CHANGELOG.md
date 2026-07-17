# Changelog
All notable changes to this project will be documented in this file.

## Unreleased

### Bug Fixes
- Standardized MCP tool responses to valid JSON per RFC 8259 across all 109 tools; fixes [#14](https://github.com/okta/okta-mcp-server/issues/14). Tool responses no longer leak raw Python `repr` for `ApplicationSignOnMode.SAML_2_0`, `OktaAPIResponse` objects, SDK tuples, or other non-JSON types.
- Standardized error return shape for `@validate_ids` / `@validate_os_version_params` and every tool that previously emitted `[f"Error: {e}"]` — errors are now returned as `[{"error": "..."}]` / `[{"exception": "..."}]` so callers always parse valid JSON.
- Fixed `create_custom_domain` to handle Okta's 204 / empty-body response by refetching the newly created domain via `list_custom_domains`, with case-insensitive FQDN matching per RFC 1035.
- Fixed customization getters and setters (`get_brand`, `create_brand`, `replace_brand`, `get_custom_domain`, `replace_custom_domain`, `replace_email_domain`, `get_brand_theme`, `replace_brand_theme`) to return an actionable `{"error": "..."}` dict when the SDK returns `(None, response, None)` instead of silently emitting `null`.

### Improvements
- Added `okta_mcp_server.utils.serialization` as the single normalization boundary for tool returns. `to_jsonable()` flattens Pydantic v2 models (`model_dump(by_alias=True, exclude_none=True, mode="json")`), Okta SDK v2 models (`to_dict()`), `Enum` values (`.value`), and drops transport-only `OktaAPIResponse` / `ApiResponse` objects. `Enum` unwrapping is checked before the scalar branch so `(str, Enum)` / `(int, Enum)` mixins (e.g. `ApplicationSignOnMode`) serialize to their `.value`.
- Added `@json_response` decorator, applied innermost on every `@mcp.tool` so every response passes through the canonical serializer exactly once.
- Added a structured failure envelope (`{"ok": false, "error": {...}, "status_code": null, "raw": {}}`) returned when serialization itself raises, so callers always receive valid JSON. The full traceback is written to the server log via `logger.exception`; the last 4096 chars can additionally be surfaced to the caller as `raw.traceback_tail` by setting `OKTA_MCP_INCLUDE_RAW=1` (accepted truthy values: `1`, `true`, `yes`, `on`). Default is off to avoid leaking server-side stack frames to MCP clients.
- Centralized JSON normalization in `create_paginated_response()` — the paginated payload is returned untouched and flattened once by the outer `@json_response` decorator, removing the redundant lazy import back into `serialization.py`.
- Removed redundant per-tool `_serialize_*` helpers in `brands.py`, `custom_domains.py`, `email_domains.py`, and `themes.py`. `custom_templates.py` intentionally retains its local `_serialize()` helper because the SDK's `to_dict()` drops server-readOnly preview fields (e.g. `EmailPreview.body`, `.subject`) that `model_dump()` preserves. `custom_pages.py` retains its helper to preserve the legacy `{}` return for legitimate empty-body responses on preview endpoints; the helper now uses `mode="json"` so nested `datetime` / `UUID` / `Enum` fields still meet the RFC 3339 guarantee.
- Reworked `create_device_assurance_policy` and `replace_device_assurance_policy` so `policy_data` is typed as `Dict[str, Any]` at the FastMCP boundary and any `PolicyDataInput` validation error is surfaced as `{"error": "..."}` instead of leaking a plain-text `pydantic.ValidationError`.
- Added `tests/test_serialization.py` (42 tests), `tests/test_custom_domains.py` (7 tests), and `tests/test_none_body_guards.py` (10 tests). Extended `tests/test_device_assurance.py` with 12 tests covering non-dict / extra-field / `osVersion`-in-policy_data validation for both create and replace paths.

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
