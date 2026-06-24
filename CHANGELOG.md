# Changelog
All notable changes to this project will be documented in this file.

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
