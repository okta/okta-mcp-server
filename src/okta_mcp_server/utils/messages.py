# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Centralised user-facing confirmation messages for elicitation prompts.

All messages are string templates using ``str.format()`` placeholders so
they can be rendered with resource-specific identifiers at call time.

Keeping them in one place makes future localisation straightforward —
swap this module for a locale-aware loader without touching tool code.
"""

# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

DELETE_GROUP = (
    "Are you sure you want to delete group {group_id}? "
    "This action cannot be undone."
)

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------

DELETE_APPLICATION = (
    "Are you sure you want to delete application {app_id}? "
    "This action cannot be undone."
)

DEACTIVATE_APPLICATION = (
    "Are you sure you want to deactivate application {app_id}? "
    "The application will become unavailable to all assigned users."
)

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

DEACTIVATE_USER = (
    "Are you sure you want to deactivate user {user_id}? "
    "The user will lose access to all applications."
)

DELETE_USER = (
    "Are you sure you want to permanently delete user {user_id}? "
    "This action cannot be undone."
)

# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

DELETE_POLICY = (
    "Are you sure you want to delete policy {policy_id}? "
    "This action cannot be undone."
)

DEACTIVATE_POLICY = (
    "Are you sure you want to deactivate policy {policy_id}?"
)

DELETE_POLICY_RULE = (
    "Are you sure you want to delete rule {rule_id} from policy {policy_id}? "
    "This action cannot be undone."
)

DEACTIVATE_POLICY_RULE = (
    "Are you sure you want to deactivate rule {rule_id} "
    "in policy {policy_id}?"
)

# ---------------------------------------------------------------------------
# Device Assurance
# ---------------------------------------------------------------------------

DELETE_DEVICE_ASSURANCE_POLICY = (
    "Are you sure you want to delete device assurance policy {policy_id}? "
    "This action cannot be undone."
)

# ---------------------------------------------------------------------------
# Brands (Customization)
# ---------------------------------------------------------------------------

DELETE_BRAND = (
    "Are you sure you want to delete brand {brand_id}? "
    "This action cannot be undone."
)

# ---------------------------------------------------------------------------
# Custom Domains (Customization)
# ---------------------------------------------------------------------------

DELETE_CUSTOM_DOMAIN = (
    "Are you sure you want to delete custom domain {domain_id}? "
    "This action cannot be undone."
)

# ---------------------------------------------------------------------------
# Themes (Customization)
# ---------------------------------------------------------------------------

DELETE_THEME_LOGO = (
    "Are you sure you want to delete the custom logo for theme {theme_id}? "
    "The theme will revert to the default Okta logo."
)

DELETE_THEME_FAVICON = (
    "Are you sure you want to delete the custom favicon for theme {theme_id}? "
    "The theme will revert to the default Okta favicon."
)

DELETE_THEME_BACKGROUND_IMAGE = (
    "Are you sure you want to delete the background image for theme {theme_id}? "
    "Touchpoint variants that use BACKGROUND_IMAGE will fall back to their default appearance."
)

# ---------------------------------------------------------------------------
# Custom Pages (Customization)
# ---------------------------------------------------------------------------
DELETE_CUSTOMIZED_ERROR_PAGE = (
    "Are you sure you want to delete the customized error page for brand {brand_id}? "
    "The default error page will appear in your live environment."
)

DELETE_PREVIEW_ERROR_PAGE = (
    "Are you sure you want to delete the preview error page for brand {brand_id}?"
)

DELETE_CUSTOMIZED_SIGN_IN_PAGE = (
    "Are you sure you want to delete the customized sign-in page for brand {brand_id}? "
    "The default sign-in page will appear in your live environment."
)

DELETE_PREVIEW_SIGN_IN_PAGE = (
    "Are you sure you want to delete the preview sign-in page for brand {brand_id}?"
)

# ---------------------------------------------------------------------------
# Custom Email Templates (Customization)
# ---------------------------------------------------------------------------

DELETE_EMAIL_CUSTOMIZATION = (
    "Are you sure you want to delete the {language} customization "
    "(ID: {customization_id}) for the {template_name} email template? "
    "This action cannot be undone."
)

DELETE_ALL_EMAIL_CUSTOMIZATIONS = (
    "Are you sure you want to delete ALL customizations for the {template_name} "
    "email template on brand {brand_id}? "
    "Every language variant will be removed and cannot be recovered."
)

# ---------------------------------------------------------------------------
# Email Domains
# ---------------------------------------------------------------------------

DELETE_EMAIL_DOMAIN = (
    "Are you sure you want to delete the email domain {domain!r} (ID: {email_domain_id})? "
    "Any brands using this domain will revert to the default Okta sender address. "
    "This action cannot be undone."
)
