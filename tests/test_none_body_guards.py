# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the None-body guards added in the PR #90 review-response commit.

Each customization tool that used to hide ``(None, response, None)`` SDK
tuples behind a per-module ``_serialize_x`` helper now returns an actionable
error dict.  These tests lock the new contract in place so a future refactor
cannot silently regress the caller-visible response to ``null`` or ``{}``.

Covered branches:
    brands.get_brand              (empty-body -> error dict)
    brands.create_brand           (empty-body -> error dict)
    brands.replace_brand          (empty-body -> error dict)
    custom_domains.get_custom_domain
    custom_domains.replace_custom_domain
    email_domains.replace_email_domain
    themes.get_brand_theme
    themes.replace_brand_theme
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.customization.brands.brands import (
    create_brand,
    get_brand,
    replace_brand,
)
from okta_mcp_server.tools.customization.custom_domains.custom_domains import (
    get_custom_domain,
    replace_custom_domain,
)
from okta_mcp_server.tools.customization.email_domains.email_domains import (
    create_email_domain,
    replace_email_domain,
    verify_email_domain,
)
from okta_mcp_server.tools.customization.themes.themes import (
    get_brand_theme,
    replace_brand_theme,
)


BRAND_ID = "bnd114iNkrcN6aR680g4"
DOMAIN_ID = "OcDz6iRyjkaCTXkdo0g3"
EMAIL_DOMAIN_ID = "OeD1a2b3c4d5"
THEME_ID = "thd1a2b3c4d5"


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
    commit.  ``create_email_domain`` and ``verify_email_domain`` carried
    explicit ``if x is None`` checks from earlier work; these tests lock the
    entire family of guards down so a future refactor cannot silently
    regress any of them to ``null``.
    """

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

        _assert_error_dict(result, must_contain="list_brand_themes()")
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
