# Changelog
All notable changes to this project will be documented in this file.

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
