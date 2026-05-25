# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""OAuth 2.0 scope registry for the Okta MCP Server.

``TOOL_SCOPE_REGISTRY`` is the **single source of truth** that maps every MCP
tool name to the minimum OAuth 2.0 scope required to call it.  It is used by:

- ``scope_guard.prune_tools_by_scope`` — removes unavailable tools at startup.
- Tests that verify every registered tool has a declared scope.

Scope naming convention:
    ``okta.<resource>.read``    — GET operations (read-only).
    ``okta.<resource>.manage``  — POST / PUT / DELETE operations (write).
    A token with ``*.manage`` implicitly covers ``*.read`` for the same resource.

Reference: https://developer.okta.com/docs/api/oauth2
"""

# Dict[tool_name, required_scope]
# Tool names must match the Python function name exactly (FastMCP registers
# tools under the function name by default).
TOOL_SCOPE_REGISTRY: dict[str, str] = {
    # ------------------------------------------------------------------
    # Users  (src/okta_mcp_server/tools/users/users.py)
    # ------------------------------------------------------------------
    "list_users":                           "okta.users.read",
    "get_user":                             "okta.users.read",
    "get_user_profile_attributes":          "okta.users.read",
    "create_user":                          "okta.users.manage",
    "update_user":                          "okta.users.manage",
    "deactivate_user":                      "okta.users.manage",
    "delete_deactivated_user":              "okta.users.manage",
    # ------------------------------------------------------------------
    # Groups  (src/okta_mcp_server/tools/groups/groups.py)
    # ------------------------------------------------------------------
    "list_groups":                          "okta.groups.read",
    "get_group":                            "okta.groups.read",
    "list_group_users":                     "okta.groups.read",
    "list_group_apps":                      "okta.groups.read",
    "create_group":                         "okta.groups.manage",
    "update_group":                         "okta.groups.manage",
    "delete_group":                         "okta.groups.manage",
    "confirm_delete_group":                 "okta.groups.manage",
    "add_user_to_group":                    "okta.groups.manage",
    "remove_user_from_group":               "okta.groups.manage",
    # ------------------------------------------------------------------
    # Applications  (src/okta_mcp_server/tools/applications/applications.py)
    # ------------------------------------------------------------------
    "list_applications":                    "okta.apps.read",
    "get_application":                      "okta.apps.read",
    "create_application":                   "okta.apps.manage",
    "update_application":                   "okta.apps.manage",
    "delete_application":                   "okta.apps.manage",
    "confirm_delete_application":           "okta.apps.manage",
    "activate_application":                 "okta.apps.manage",
    "deactivate_application":               "okta.apps.manage",
    # ------------------------------------------------------------------
    # Policies  (src/okta_mcp_server/tools/policies/policies.py)
    # ------------------------------------------------------------------
    "list_policies":                        "okta.policies.read",
    "get_policy":                           "okta.policies.read",
    "list_policy_rules":                    "okta.policies.read",
    "get_policy_rule":                      "okta.policies.read",
    "create_policy":                        "okta.policies.manage",
    "update_policy":                        "okta.policies.manage",
    "delete_policy":                        "okta.policies.manage",
    "activate_policy":                      "okta.policies.manage",
    "deactivate_policy":                    "okta.policies.manage",
    "create_policy_rule":                   "okta.policies.manage",
    "update_policy_rule":                   "okta.policies.manage",
    "delete_policy_rule":                   "okta.policies.manage",
    "activate_policy_rule":                 "okta.policies.manage",
    "deactivate_policy_rule":               "okta.policies.manage",
    # ------------------------------------------------------------------
    # Device Assurance  (src/okta_mcp_server/tools/device_assurance/device_assurance.py)
    # ------------------------------------------------------------------
    "list_device_assurance_policies":       "okta.deviceAssurance.read",
    "get_device_assurance_policy":          "okta.deviceAssurance.read",
    "create_device_assurance_policy":       "okta.deviceAssurance.manage",
    "replace_device_assurance_policy":      "okta.deviceAssurance.manage",
    "delete_device_assurance_policy":       "okta.deviceAssurance.manage",
    # ------------------------------------------------------------------
    # System Logs  (src/okta_mcp_server/tools/system_logs/system_logs.py)
    #              (src/okta_mcp_server/tools/system_logs/login_failures.py)
    # ------------------------------------------------------------------
    "get_logs":                             "okta.logs.read",
    "get_login_failures":                   "okta.logs.read",
    # ------------------------------------------------------------------
    # Brands  (src/okta_mcp_server/tools/customization/brands/brands.py)
    # ------------------------------------------------------------------
    "list_brands":                          "okta.brands.read",
    "get_brand":                            "okta.brands.read",
    "list_brand_domains":                   "okta.brands.read",
    "create_brand":                         "okta.brands.manage",
    "replace_brand":                        "okta.brands.manage",
    "delete_brand":                         "okta.brands.manage",
    # ------------------------------------------------------------------
    # Themes  (src/okta_mcp_server/tools/customization/themes/themes.py)
    # ------------------------------------------------------------------
    "list_brand_themes":                    "okta.brands.read",
    "get_brand_theme":                      "okta.brands.read",
    "replace_brand_theme":                  "okta.brands.manage",
    "upload_brand_theme_logo":              "okta.brands.manage",
    "delete_brand_theme_logo":              "okta.brands.manage",
    "upload_brand_theme_favicon":           "okta.brands.manage",
    "delete_brand_theme_favicon":           "okta.brands.manage",
    "upload_brand_theme_background_image":  "okta.brands.manage",
    "delete_brand_theme_background_image":  "okta.brands.manage",
    # ------------------------------------------------------------------
    # Custom Pages  (src/okta_mcp_server/tools/customization/custom_pages/custom_pages.py)
    # ------------------------------------------------------------------
    "get_error_page_resources":             "okta.brands.read",
    "get_customized_error_page":            "okta.brands.read",
    "get_default_error_page":               "okta.brands.read",
    "get_preview_error_page":               "okta.brands.read",
    "get_sign_in_page_resources":           "okta.brands.read",
    "get_customized_sign_in_page":          "okta.brands.read",
    "get_default_sign_in_page":             "okta.brands.read",
    "get_preview_sign_in_page":             "okta.brands.read",
    "list_sign_in_widget_versions":         "okta.brands.read",
    "get_sign_out_page_settings":           "okta.brands.read",
    "replace_customized_error_page":        "okta.brands.manage",
    "delete_customized_error_page":         "okta.brands.manage",
    "replace_preview_error_page":           "okta.brands.manage",
    "delete_preview_error_page":            "okta.brands.manage",
    "replace_customized_sign_in_page":      "okta.brands.manage",
    "delete_customized_sign_in_page":       "okta.brands.manage",
    "replace_preview_sign_in_page":         "okta.brands.manage",
    "delete_preview_sign_in_page":          "okta.brands.manage",
    "replace_sign_out_page_settings":       "okta.brands.manage",
    # ------------------------------------------------------------------
    # Email Templates & Customizations
    # (src/okta_mcp_server/tools/customization/custom_templates/custom_templates.py)
    # Note: These endpoints require okta.templates.* scopes, NOT okta.brands.*
    # ------------------------------------------------------------------
    "list_email_templates":                 "okta.templates.read",
    "get_email_template":                   "okta.templates.read",
    "list_email_customizations":            "okta.templates.read",
    "get_email_customization":              "okta.templates.read",
    "get_email_customization_preview":      "okta.templates.read",
    "get_email_default_content":            "okta.templates.read",
    "get_email_default_content_preview":    "okta.templates.read",
    "get_email_settings":                   "okta.templates.read",
    "create_email_customization":           "okta.templates.manage",
    "replace_email_customization":          "okta.templates.manage",
    "delete_email_customization":           "okta.templates.manage",
    "delete_all_email_customizations":      "okta.templates.manage",
    "replace_email_settings":               "okta.templates.manage",
    "send_test_email":                      "okta.templates.manage",
    # ------------------------------------------------------------------
    # Custom Domains
    # (src/okta_mcp_server/tools/customization/custom_domains/custom_domains.py)
    # ------------------------------------------------------------------
    "list_custom_domains":                  "okta.domains.read",
    "get_custom_domain":                    "okta.domains.read",
    "create_custom_domain":                 "okta.domains.manage",
    "replace_custom_domain":                "okta.domains.manage",
    "delete_custom_domain":                 "okta.domains.manage",
    "upsert_custom_domain_certificate":     "okta.domains.manage",
    "verify_custom_domain":                 "okta.domains.manage",
    # ------------------------------------------------------------------
    # Email Domains
    # (src/okta_mcp_server/tools/customization/email_domains/email_domains.py)
    # ------------------------------------------------------------------
    "list_email_domains":                   "okta.emailDomains.read",
    "get_email_domain":                     "okta.emailDomains.read",
    "create_email_domain":                  "okta.emailDomains.manage",
    "replace_email_domain":                 "okta.emailDomains.manage",
    "delete_email_domain":                  "okta.emailDomains.manage",
    "verify_email_domain":                  "okta.emailDomains.manage",
}
