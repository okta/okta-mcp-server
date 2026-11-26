# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for sign-in page ``widget_customizations`` handling.

Okta rejects a sign-in page whose ``widgetCustomizations`` is empty ("cannot
be left blank"). Previously ``{}`` was documented as "keep all defaults" and
omitting the parameter as "an empty object is sent", but in fact both left
the field out of the request, so Okta rejected it. These tests cover, for
both the customized and the preview replace tools:

1. ``{}`` (or a dict with no recognised fields) → clear error, no API call.
2. Omitted → current page is fetched and its customizations are kept.
3. Omitted, but the current page has none or cannot be read → clear error,
   no replace call.
4. Explicit dict → sent as given, no extra GET.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from okta.models.sign_in_page import SignInPage
from okta.models.sign_in_page_all_of_widget_customizations import SignInPageAllOfWidgetCustomizations

from okta_mcp_server.tools.customization.custom_pages.custom_pages import (
    replace_customized_sign_in_page,
    replace_preview_sign_in_page,
)

BRAND_ID = "bnd1a2b3c4d5e6f7g8h9"
PATCH_TARGET = "okta_mcp_server.tools.customization.custom_pages.custom_pages.get_okta_client"

# (tool, SDK getter name, SDK replace name) for both page variants.
VARIANTS = [
    pytest.param(
        replace_customized_sign_in_page,
        "get_customized_sign_in_page",
        "replace_customized_sign_in_page",
        id="customized",
    ),
    pytest.param(
        replace_preview_sign_in_page,
        "get_preview_sign_in_page",
        "replace_preview_sign_in_page",
        id="preview",
    ),
]


def _page(widget_customizations=None) -> SignInPage:
    return SignInPage(page_content="<html/>", widget_version="^7", widget_customizations=widget_customizations)


def _client(getter: str, replacer: str, current_page=None, get_err=None) -> AsyncMock:
    client = AsyncMock()
    getattr(client, getter).return_value = (current_page, MagicMock(), get_err)
    getattr(client, replacer).return_value = (_page(), MagicMock(), None)
    return client


def _sent_body(client: AsyncMock, replacer: str) -> dict:
    brand_id, sign_in_page = getattr(client, replacer).call_args.args
    assert brand_id == BRAND_ID
    return sign_in_page.to_dict()


@pytest.mark.parametrize(("tool", "getter", "replacer"), VARIANTS)
class TestWidgetCustomizations:
    @pytest.mark.asyncio
    @patch(PATCH_TARGET)
    async def test_empty_dict_is_rejected_before_any_api_call(
        self, mock_get_client, tool, getter, replacer, ctx_no_elicitation
    ):
        client = _client(getter, replacer)
        mock_get_client.return_value = client

        result = await tool(ctx=ctx_no_elicitation, brand_id=BRAND_ID, widget_customizations={})

        assert "error" in result
        assert "widget_customizations cannot be empty" in result["error"]
        getattr(client, getter).assert_not_called()
        getattr(client, replacer).assert_not_called()

    @pytest.mark.asyncio
    @patch(PATCH_TARGET)
    async def test_dict_without_recognised_fields_is_rejected(
        self, mock_get_client, tool, getter, replacer, ctx_no_elicitation
    ):
        client = _client(getter, replacer)
        mock_get_client.return_value = client

        result = await tool(ctx=ctx_no_elicitation, brand_id=BRAND_ID, widget_customizations={"bogus_field": "x"})

        assert "error" in result
        assert "no recognised fields" in result["error"]
        assert "bogus_field" in result["error"]
        getattr(client, replacer).assert_not_called()

    @pytest.mark.asyncio
    @patch(PATCH_TARGET)
    async def test_explicit_dict_is_sent_without_fetching_current_page(
        self, mock_get_client, tool, getter, replacer, ctx_no_elicitation
    ):
        client = _client(getter, replacer)
        mock_get_client.return_value = client

        await tool(
            ctx=ctx_no_elicitation,
            brand_id=BRAND_ID,
            widget_customizations={"sign_in_label": "Log in", "show_user_identifier": True},
        )

        getattr(client, getter).assert_not_called()
        body = _sent_body(client, replacer)
        assert body["widgetCustomizations"] == {"signInLabel": "Log in", "showUserIdentifier": True}

    @pytest.mark.asyncio
    @patch(PATCH_TARGET)
    async def test_omitted_keeps_current_widget_customizations(
        self, mock_get_client, tool, getter, replacer, ctx_no_elicitation
    ):
        current = SignInPageAllOfWidgetCustomizations(sign_in_label="Existing label", help_url="https://help")
        client = _client(getter, replacer, current_page=_page(current))
        mock_get_client.return_value = client

        await tool(ctx=ctx_no_elicitation, brand_id=BRAND_ID, page_content="<html>new</html>")

        getattr(client, getter).assert_awaited_once_with(BRAND_ID)
        body = _sent_body(client, replacer)
        assert body["widgetCustomizations"] == {"signInLabel": "Existing label", "helpUrl": "https://help"}
        assert body["pageContent"] == "<html>new</html>"

    @pytest.mark.asyncio
    @patch(PATCH_TARGET)
    @pytest.mark.parametrize(
        "current_page",
        [None, _page(None), _page(SignInPageAllOfWidgetCustomizations())],
        ids=["no-page", "no-customizations", "empty-customizations"],
    )
    async def test_omitted_without_current_customizations_returns_error(
        self, mock_get_client, current_page, tool, getter, replacer, ctx_no_elicitation
    ):
        client = _client(getter, replacer, current_page=current_page)
        mock_get_client.return_value = client

        result = await tool(ctx=ctx_no_elicitation, brand_id=BRAND_ID)

        assert "error" in result
        assert "current page has no widget customizations" in result["error"]
        getattr(client, replacer).assert_not_called()

    @pytest.mark.asyncio
    @patch(PATCH_TARGET)
    async def test_omitted_and_current_page_unreadable_returns_error(
        self, mock_get_client, tool, getter, replacer, ctx_no_elicitation
    ):
        client = _client(getter, replacer, get_err=Exception("HTTP 404 E0000007 Not found"))
        mock_get_client.return_value = client

        result = await tool(ctx=ctx_no_elicitation, brand_id=BRAND_ID)

        assert "error" in result
        assert "reading the current page failed" in result["error"]
        assert "E0000007" in result["error"]
        getattr(client, replacer).assert_not_called()
