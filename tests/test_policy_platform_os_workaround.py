# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the platform OS type workaround applied when ``tools.policies.policies`` is imported.

The pinned okta SDK's ``PolicyPlatformOperatingSystemType`` enum does not include ``LINUX``, so any
policy rule with a Linux platform condition made ``list_policy_rules`` / ``get_policy_rule`` fail with
a pydantic ``ValidationError`` (okta/okta-mcp-server#125). Importing the policies module relaxes the
``type`` field to a plain string so the SDK can deserialize such rules.
"""

from okta.models.platform_condition_evaluator_platform_operating_system import (
    PlatformConditionEvaluatorPlatformOperatingSystem,
)
from okta.models.policy_rule import PolicyRule

import okta_mcp_server.tools.policies.policies  # noqa: F401  (applies the workaround at import time)


def _access_policy_rule(os_type: str) -> dict:
    return {
        "id": "rul0000000000000000a",
        "name": f"{os_type} devices",
        "type": "ACCESS_POLICY",
        "status": "ACTIVE",
        "priority": 1,
        "system": False,
        "conditions": {"platform": {"include": [{"type": "DESKTOP", "os": {"type": os_type}}], "exclude": []}},
        "actions": {"appSignOn": {"access": "ALLOW"}},
    }


def test_linux_os_type_is_accepted_by_the_platform_os_model():
    model = PlatformConditionEvaluatorPlatformOperatingSystem.from_dict({"type": "LINUX"})
    assert model.type == "LINUX"


def test_policy_rule_with_linux_platform_condition_deserializes():
    # PolicyRule.from_dict is the entry point the SDK uses for list_policy_rules / get_policy_rule responses.
    rule = PolicyRule.from_dict(_access_policy_rule("LINUX"))
    assert rule.conditions.platform.include[0].os.type == "LINUX"
    assert rule.to_dict()["conditions"]["platform"]["include"][0]["os"]["type"] == "LINUX"


def test_known_os_types_still_round_trip():
    rule = PolicyRule.from_dict(_access_policy_rule("WINDOWS"))
    assert rule.to_dict()["conditions"]["platform"]["include"][0]["os"]["type"] == "WINDOWS"
