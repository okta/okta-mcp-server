# Changelog
All notable changes to this project will be documented in this file.

## v1.1.0

### Added
- **MCP Elicitation Support:** Destructive operations (delete, deactivate) now prompt the user for interactive confirmation via the MCP Elicitation API before proceeding.
  - `delete_group`, `delete_application`, `delete_policy`, `delete_policy_rule` — ask for explicit confirmation before deletion.
  - `deactivate_user`, `delete_deactivated_user` — ask for explicit confirmation before deactivation/deletion.
- **Elicitation utility module** (`utils/elicitation.py`) — shared schemas (`DeleteConfirmation`, `DeactivateConfirmation`), capability detection (`supports_elicitation`), and a robust `elicit_or_fallback` helper.
- **Backward-compatible fallback** — when an MCP client does not support elicitation, the tools return a JSON payload describing the confirmation step the LLM must relay to the user.
- **Comprehensive test suite** — 74 unit tests covering all elicitation flows (accept, decline, cancel, fallback, API errors, and exceptions) across all tool modules.

### Changed
- Upgraded MCP Python SDK from `1.9.2` to `1.26.0`.
- `confirm_delete_group` and `confirm_delete_application` are now **deprecated** — the new elicitation-based flow replaces the two-step confirm pattern.
- `delete_policy` and `delete_policy_rule` now wrap `get_okta_client` inside the `try/except` block for consistent error handling.

## v1.0.0

- Initial release of the self hosted okta-mcp-server.
