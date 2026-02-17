# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
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
