# Changelog
All notable changes to this project will be documented in this file.

## Unreleased

### Bug Fixes
- Standardized MCP tool responses to valid JSON per RFC 8259 across all 108 tools; fixes [#14](https://github.com/okta/okta-mcp-server/issues/14). Tool responses no longer leak raw Python `repr` for `ApplicationSignOnMode.SAML_2_0`, `OktaAPIResponse` objects, SDK tuples, or other non-JSON types.

### Improvements
- Added `okta_mcp_server.utils.serialization` as the single normalization boundary for tool returns. `to_jsonable()` flattens Pydantic v2 models (`model_dump(by_alias=True, exclude_none=True, mode="json")`), Okta SDK v2 models (`to_dict()`), `Enum` values (`.value`), and drops transport-only `OktaAPIResponse` / `ApiResponse` objects.
- Added `@json_response` decorator, applied innermost on every `@mcp.tool` so every response passes through the canonical serializer exactly once.
- Added a structured failure envelope (`{"ok": false, "error": {...}, "status_code": null, "raw": {"traceback_tail": "..."}}`) returned when serialization itself raises, so callers always receive valid JSON.
- Centralized JSON normalization in `create_paginated_response()`, removing redundant per-tool serialization in `policies`, `device_assurance`, and `custom_domains`.
- Added `tests/test_serialization.py` (32 tests) covering scalars, enums, Pydantic v2 flattening, transport-response drop, cycle handling, the fail-safe envelope, decorator metadata preservation, and the unittest.mock short-circuit.

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
