# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
# file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import re
from pathlib import Path

from okta_mcp_server.server import mcp
from okta_mcp_server.tools.applications import applications  # noqa: F401


def test_list_application_groups_schema_defaults_to_expanded_groups():
    tool = mcp._tool_manager._tools["list_application_groups"]
    schema = tool.parameters

    assert schema["required"] == ["app_id"]
    assert schema["properties"]["expand_group"]["default"] is True
    assert "assigned groups" in tool.description.lower()
    assert "assignment profile" in tool.description.lower()


def test_list_application_users_schema_is_filtered_and_minimized():
    tool = mcp._tool_manager._tools["list_application_users"]
    schema = tool.parameters

    assert schema["required"] == ["app_id"]
    assert schema["properties"]["okta_login_suffix"]["default"] is None
    assert schema["properties"]["app_username_suffix"]["default"] is None
    assert "complete, minimized" in tool.description.lower()
    assert "excludes full okta and application profiles" in tool.description.lower()


def test_get_application_docs_direct_assignment_lookups_to_dedicated_endpoints():
    description = mcp._tool_manager._tools["get_application"].description

    assert re.search(r'Do not use\s+``expand="groups"``', description)
    assert "/api/v1/apps/{app_id}/groups" in description
    assert re.search(
        r"Prefer GET\s+``/api/v1/apps/\{app_id\}/users/\{user_id\}``.*"
        r'instead of ``expand="user/\{user_id\}"``',
        description,
        re.DOTALL,
    )


def test_list_applications_docs_explain_expand_constraints_and_assignment_endpoints():
    description = mcp._tool_manager._tools["list_applications"].description

    assert 'filter=user.id eq "{user_id}"' in description
    assert "For reliable assignment lookups, use the dedicated" in description
    assert "/api/v1/apps/{app_id}/groups" in description
    assert "/api/v1/apps/{app_id}/users/{user_id}" in description


def test_readme_repeats_negative_expand_guidance_and_dedicated_endpoints():
    readme = (Path(__file__).parents[1] / "README.md").read_text()

    assert 'Do not use `get_application(..., expand="groups")`' in readme
    assert "`list_application_groups(app_id, expand_group=true)`" in readme
    assert "`GET /api/v1/apps/{app_id}/groups?limit=200&expand=group`" in readme
    apps_scope_row = next(
        line for line in readme.splitlines() if line.startswith("| `okta.apps.read` |")
    )
    assert "`list_application_groups`" in apps_scope_row
    assert "`list_application_users`" in apps_scope_row
    assert "`group_name`" in readme
    assert "`assignment_profile`" in readme
    assert "`list_application_users`" in readme
    assert "`GET /api/v1/apps/{app_id}/users?limit=500&expand=user`" in readme
    assert "full embedded user profiles" in readme
    assert "prefer `GET /api/v1/apps/{app_id}/users/{user_id}`" in readme
