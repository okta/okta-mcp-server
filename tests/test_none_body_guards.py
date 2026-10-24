# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the None-body guards added in the PR #90 review-response commit,
and in the follow-up fresh-review pass that swept the same bug class across
the rest of the tool surface.

Every tool that unpacks an Okta SDK ``(result, response, err)`` 3-tuple can
hit ``(None, response, None)`` -- a nominally successful call whose result
payload is ``None``.  Tools that used to hide this behind a per-module
``_serialize_x`` helper, or simply never checked for it, now return an
actionable error dict via ``utils.serialization.none_body_error``. These
tests lock the contract in place so a future refactor cannot silently
regress the caller-visible response to ``null``/``{}``/a crash.

Covered branches:
    brands.get_brand              (empty-body -> error dict)
    brands.create_brand           (empty-body -> error dict)
    brands.replace_brand          (empty-body -> error dict)
    custom_domains.get_custom_domain
    custom_domains.replace_custom_domain
    custom_domains.verify_custom_domain
    email_domains.get_email_domain
    email_domains.create_email_domain            (empty-body -> error dict)
    email_domains.create_email_domain            (case-insensitive FQDN refetch match)
    email_domains.replace_email_domain
    email_domains.verify_email_domain            (both verify and fallback GET fail)
    themes.get_brand_theme
    themes.replace_brand_theme
    applications.get_application
    applications.create_application
    applications.update_application
    groups.get_group
    groups.create_group           (previously crashed with AttributeError on group.id)
    groups.update_group
    users.get_user
    users.create_user             (previously crashed with AttributeError on user.id)
    users.update_user
    policies.get_policy
    policies.create_policy
    policies.update_policy
    policies.get_policy_rule
    policies.create_policy_rule
    policies.update_policy_rule
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.applications.applications import (
    create_application,
    get_application,
    update_application,
)
from okta_mcp_server.tools.customization.brands.brands import (
    create_brand,
    get_brand,
    replace_brand,
)
from okta_mcp_server.tools.customization.custom_domains.custom_domains import (
    get_custom_domain,
    replace_custom_domain,
    verify_custom_domain,
)
from okta_mcp_server.tools.customization.email_domains.email_domains import (
    create_email_domain,
    get_email_domain,
    replace_email_domain,
    verify_email_domain,
)
from okta_mcp_server.tools.customization.themes.themes import (
    get_brand_theme,
    replace_brand_theme,
)
from okta_mcp_server.tools.groups.groups import create_group, get_group, update_group
from okta_mcp_server.tools.policies.policies import (
    create_policy,
    create_policy_rule,
    get_policy,
    get_policy_rule,
    update_policy,
    update_policy_rule,
)
from okta_mcp_server.tools.users.users import create_user, get_user, update_user


BRAND_ID = "bnd114iNkrcN6aR680g4"
DOMAIN_ID = "OcDz6iRyjkaCTXkdo0g3"
EMAIL_DOMAIN_ID = "OeD1a2b3c4d5"
THEME_ID = "thd1a2b3c4d5"
APP_ID = "0oaABCDEfghIJKLmnop1"
GROUP_ID = "00gABCDEfghIJKLmnop1"
USER_ID = "00uABCDEfghIJKLmnop1"
POLICY_ID = "rstABCDEfghIJKLmnop1"
RULE_ID = "ruleABCDEfghIJKLmnop"


def _assert_error_dict(result, *, must_contain: str) -> None:
    """Common contract for a None-body guard: dict with a non-null error string
    that references the follow-up tool the caller should use."""
    assert isinstance(result, dict), (
        f"Expected dict from None-body guard, got {type(result).__name__}: {result!r}"
    )
    assert "error" in result, f"Expected 'error' key, got: {result!r}"
    assert isinstance(result["error"], str) and result["error"], (
        f"'error' must be a non-empty string, got: {result['error']!r}"
    )
    assert must_contain in result["error"], (
        f"Expected error message to reference {must_contain!r}, got: {result['error']!r}"
    )


class TestBrandsNoneBodyGuards:
    """PR #90 review issue 5: get/create/replace_brand must never leak ``null``
    to the caller when the SDK returns ``(None, response, None)``."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.customization.brands.brands.get_okta_client")
    async def test_get_brand_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_brand.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_brand(ctx=ctx_no_elicitation, brand_id=BRAND_ID)

        _assert_error_dict(result, must_contain="list_brands()")
        assert BRAND_ID in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.customization.brands.brands.get_okta_client")
    async def test_create_brand_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        # Pre-check list is empty (no duplicate).  Two calls: initial list +
        # any follow-up.  Use a return_value to cover both.
        client.list_brands.return_value = ([], MagicMock(), None)
        client.create_brand.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_brand(ctx=ctx_no_elicitation, name="Empty Brand")

        _assert_error_dict(result, must_contain="list_brands()")
        assert "Empty Brand" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.customization.brands.brands.get_okta_client")
    async def test_replace_brand_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.replace_brand.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await replace_brand(
            ctx=ctx_no_elicitation,
            brand_id=BRAND_ID,
            name="Renamed Brand",
        )

        _assert_error_dict(result, must_contain="get_brand()")
        assert BRAND_ID in result["error"]


class TestCustomDomainsNoneBodyGuards:
    """PR #90 review issue 5 for the custom_domains module."""

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.custom_domains.custom_domains.get_okta_client"
    )
    async def test_get_custom_domain_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_custom_domain.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_custom_domain(
            ctx=ctx_no_elicitation, domain_id=DOMAIN_ID
        )

        _assert_error_dict(result, must_contain="list_custom_domains()")
        assert DOMAIN_ID in result["error"]

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.custom_domains.custom_domains.get_okta_client"
    )
    async def test_replace_custom_domain_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.replace_custom_domain.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await replace_custom_domain(
            ctx=ctx_no_elicitation,
            domain_id=DOMAIN_ID,
            brand_id=BRAND_ID,
        )

        _assert_error_dict(result, must_contain="get_custom_domain()")
        assert DOMAIN_ID in result["error"]


class TestEmailDomainsNoneBodyGuards:
    """PR #90 review issue 5 for the email_domains module.

    ``replace_email_domain`` received a new guard in the last review-response
    commit.  ``create_email_domain``, ``get_email_domain``, and
    ``verify_email_domain`` carried explicit ``if x is None`` checks from
    earlier work; these tests lock the entire family of guards down so a
    future refactor cannot silently regress any of them to ``null``.
    """

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.email_domains.email_domains.get_okta_client"
    )
    async def test_get_email_domain_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_email_domain.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_email_domain(
            ctx=ctx_no_elicitation, email_domain_id=EMAIL_DOMAIN_ID
        )

        _assert_error_dict(result, must_contain="list_email_domains()")
        assert EMAIL_DOMAIN_ID in result["error"]

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.email_domains.email_domains.get_okta_client"
    )
    async def test_replace_email_domain_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.replace_email_domain.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await replace_email_domain(
            ctx=ctx_no_elicitation,
            email_domain_id=EMAIL_DOMAIN_ID,
            display_name="Acme",
            user_name="hello",
        )

        _assert_error_dict(result, must_contain="get_email_domain()")
        assert EMAIL_DOMAIN_ID in result["error"]

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.email_domains.email_domains.get_okta_client"
    )
    async def test_create_email_domain_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        # SDK returns (None, response, None); the tool then falls back to
        # ``list_email_domains`` to find the newly-created record.  Return an
        # empty list from the fallback so the tool cannot locate it and must
        # emit its explicit error dict.
        client.create_email_domain.return_value = (None, MagicMock(), None)
        client.list_email_domains.return_value = ([], MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_email_domain(
            ctx=ctx_no_elicitation,
            brand_id=BRAND_ID,
            domain="example.com",
            display_name="Acme",
            user_name="noreply",
        )

        assert isinstance(result, dict)
        assert "error" in result
        assert isinstance(result["error"], str) and result["error"]
        # Message should tell the caller how to confirm the domain state.
        assert "list_email_domains" in result["error"] or "get_email_domain" in result["error"]

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.email_domains.email_domains.get_okta_client"
    )
    async def test_create_email_domain_refetch_case_insensitive_match(
        self, mock_get_client, ctx_no_elicitation
    ):
        """Mirror of test_custom_domains.test_refetch_case_insensitive_match:
        the create_email_domain fallback lookup must match FQDNs
        case-insensitively per RFC 1035, the same fix already applied to
        create_custom_domain's identical fallback."""
        stored_fqdn = "Mail.Example.COM"
        requested_fqdn = "mail.example.com"

        stored = MagicMock()
        stored.domain = stored_fqdn
        stored.id = "OeD9z8y7x6"
        # to_dict powers the @json_response boundary in the tool.
        stored.to_dict.return_value = {"id": stored.id, "domain": stored_fqdn}

        client = AsyncMock()
        client.create_email_domain.return_value = (None, MagicMock(), None)
        # First call is the pre-create duplicate check (must see no match so
        # the tool proceeds to create); second call is the post-create
        # refetch fallback (must see the case-differing match).
        client.list_email_domains.side_effect = [
            ([], MagicMock(), None),
            ([stored], MagicMock(), None),
        ]
        mock_get_client.return_value = client

        result = await create_email_domain(
            ctx=ctx_no_elicitation,
            brand_id=BRAND_ID,
            domain=requested_fqdn,
            display_name="Acme",
            user_name="noreply",
        )

        assert result == {"id": stored.id, "domain": stored_fqdn}

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.email_domains.email_domains.get_okta_client"
    )
    async def test_verify_email_domain_both_calls_fail_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        # Both verify and the fallback GET fail -> the tool surfaces the
        # original verify error as a JSON dict rather than leaking ``None``
        # or the SDK's raw exception object.
        client = AsyncMock()
        client.verify_email_domain.return_value = (None, MagicMock(), "verify failed")
        client.get_email_domain.return_value = (None, MagicMock(), "fetch failed")
        mock_get_client.return_value = client

        result = await verify_email_domain(
            ctx=ctx_no_elicitation, email_domain_id=EMAIL_DOMAIN_ID
        )

        assert isinstance(result, dict)
        assert "error" in result
        assert isinstance(result["error"], str) and result["error"]


class TestThemesNoneBodyGuards:
    """PR #90 review issue 5 for the themes module."""

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.themes.themes.get_okta_client"
    )
    async def test_get_brand_theme_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_brand_theme.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_brand_theme(
            ctx=ctx_no_elicitation, brand_id=BRAND_ID, theme_id=THEME_ID
        )

        _assert_error_dict(result, must_contain="list_brand_themes(")
        assert THEME_ID in result["error"]
        assert BRAND_ID in result["error"]

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.themes.themes.get_okta_client"
    )
    async def test_replace_brand_theme_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.replace_brand_theme.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await replace_brand_theme(
            ctx=ctx_no_elicitation,
            brand_id=BRAND_ID,
            theme_id=THEME_ID,
            primary_color_hex="#000000",
            secondary_color_hex="#FFFFFF",
            sign_in_page_touch_point_variant="OKTA_DEFAULT",
            end_user_dashboard_touch_point_variant="OKTA_DEFAULT",
            error_page_touch_point_variant="OKTA_DEFAULT",
            email_template_touch_point_variant="OKTA_DEFAULT",
        )

        _assert_error_dict(result, must_contain="get_brand_theme()")
        assert THEME_ID in result["error"]


class TestVerifyCustomDomainNoneBodyGuard:
    """Fresh-review finding: verify_custom_domain used getattr(verified,
    'validation_status', None) defensively for logging but then returned
    the (possibly None) result directly -- missed in every prior review
    round even though this module got the most attention of any in the PR."""

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.custom_domains.custom_domains.get_okta_client"
    )
    async def test_verify_custom_domain_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_custom_domain.return_value = (None, MagicMock(), None)
        client.verify_domain.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await verify_custom_domain(
            ctx=ctx_no_elicitation, domain_id=DOMAIN_ID
        )

        _assert_error_dict(result, must_contain="get_custom_domain()")
        assert DOMAIN_ID in result["error"]


class TestApplicationsNoneBodyGuards:
    """Fresh-review finding: applications.py's get/create/update never
    checked for the Okta SDK's (None, response, None) quirk at all."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_get_application_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_application.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_application(ctx=ctx_no_elicitation, app_id=APP_ID)

        _assert_error_dict(result, must_contain="list_applications()")
        assert APP_ID in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_create_application_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.create_application.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_application(
            ctx=ctx_no_elicitation,
            app_config={"name": "bookmark", "label": "Test App", "signOnMode": "BOOKMARK", "settings": {"app": {"url": "https://example.com"}}},
        )

        _assert_error_dict(result, must_contain="list_applications()")

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_update_application_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.replace_application.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await update_application(
            ctx=ctx_no_elicitation,
            app_id=APP_ID,
            app_config={"name": "bookmark", "label": "Test App", "signOnMode": "BOOKMARK", "settings": {"app": {"url": "https://example.com"}}},
        )

        _assert_error_dict(result, must_contain="get_application()")
        assert APP_ID in result["error"]


class TestGroupsNoneBodyGuards:
    """Fresh-review finding: groups.py's get/create/update never checked for
    the SDK quirk. create_group additionally crashed with AttributeError on
    `group.id` when the quirk fired, masked into a confusing
    {"exception": "'NoneType' object has no attribute 'id'"}."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.groups.groups.get_okta_client")
    async def test_get_group_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_group.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_group(ctx=ctx_no_elicitation, group_id=GROUP_ID)

        assert isinstance(result, list) and len(result) == 1
        _assert_error_dict(result[0], must_contain="list_groups()")
        assert GROUP_ID in result[0]["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.groups.groups.get_okta_client")
    async def test_create_group_none_body_returns_error_dict_not_crash(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.add_group.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_group(
            ctx=ctx_no_elicitation, profile={"name": "Engineering"}
        )

        assert isinstance(result, list) and len(result) == 1
        _assert_error_dict(result[0], must_contain="list_groups()")
        assert "exception" not in result[0], (
            "create_group must not crash with AttributeError on group.id "
            "when the SDK returns (None, response, None)."
        )

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.groups.groups.get_okta_client")
    async def test_update_group_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.replace_group.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await update_group(
            ctx=ctx_no_elicitation, group_id=GROUP_ID, profile={"name": "Engineering"}
        )

        assert isinstance(result, list) and len(result) == 1
        _assert_error_dict(result[0], must_contain="get_group()")
        assert GROUP_ID in result[0]["error"]


class TestUsersNoneBodyGuards:
    """Fresh-review finding: users.py's get/create/update never checked for
    the SDK quirk. create_user additionally crashed with AttributeError on
    `user.id` when the quirk fired."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_get_user_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_user.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_user(ctx=ctx_no_elicitation, user_id=USER_ID)

        assert isinstance(result, list) and len(result) == 1
        _assert_error_dict(result[0], must_contain="list_users()")
        assert USER_ID in result[0]["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_create_user_none_body_returns_error_dict_not_crash(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.create_user.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_user(
            ctx=ctx_no_elicitation,
            profile={"login": "jdoe@example.com", "email": "jdoe@example.com"},
        )

        assert isinstance(result, list) and len(result) == 1
        _assert_error_dict(result[0], must_contain="list_users()")
        assert "exception" not in result[0], (
            "create_user must not crash with AttributeError on user.id "
            "when the SDK returns (None, response, None)."
        )

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_update_user_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.update_user.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await update_user(
            ctx=ctx_no_elicitation, user_id=USER_ID, profile={"firstName": "Jane"}
        )

        assert isinstance(result, list) and len(result) == 1
        _assert_error_dict(result[0], must_contain="get_user()")
        assert USER_ID in result[0]["error"]


class TestPoliciesNoneBodyGuards:
    """Fresh-review finding: none of the six singular policy/rule CRUD tools
    checked for the SDK quirk -- all six returned bare None as a
    'successful' result."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_get_policy_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_policy.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_policy(ctx=ctx_no_elicitation, policy_id=POLICY_ID)

        _assert_error_dict(result, must_contain="list_policies(")
        assert POLICY_ID in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_create_policy_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.create_policy.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_policy(
            ctx=ctx_no_elicitation,
            policy_data={"type": "PASSWORD", "name": "Test Policy"},
        )

        _assert_error_dict(result, must_contain="list_policies(")

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_update_policy_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.replace_policy.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await update_policy(
            ctx=ctx_no_elicitation,
            policy_id=POLICY_ID,
            policy_data={"type": "PASSWORD", "name": "Test Policy"},
        )

        _assert_error_dict(result, must_contain="get_policy()")
        assert POLICY_ID in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_get_policy_rule_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_policy_rule.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_policy_rule(
            ctx=ctx_no_elicitation, policy_id=POLICY_ID, rule_id=RULE_ID
        )

        _assert_error_dict(result, must_contain="list_policy_rules(")
        assert RULE_ID in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_create_policy_rule_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.create_policy_rule.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_policy_rule(
            ctx=ctx_no_elicitation,
            policy_id=POLICY_ID,
            rule_data={"name": "Test Rule", "type": "PASSWORD"},
        )

        _assert_error_dict(result, must_contain="list_policy_rules(")

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_update_policy_rule_none_body_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.replace_policy_rule.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await update_policy_rule(
            ctx=ctx_no_elicitation,
            policy_id=POLICY_ID,
            rule_id=RULE_ID,
            rule_data={"name": "Test Rule", "type": "PASSWORD"},
        )

        _assert_error_dict(result, must_contain="get_policy_rule()")
        assert RULE_ID in result["error"]
