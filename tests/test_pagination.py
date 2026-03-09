# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for pagination utilities and fetch_all=True branches in all four affected tools.

Covers the Gap #4 review comment: paginate_all_results() and all four callers
(list_users, list_groups, list_group_users, get_logs) must handle SDK v3
ApiResponse objects correctly via the Link-header cursor loop.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.utils.pagination import (
    extract_after_cursor,
    paginate_all_results,
    create_paginated_response,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_v3_response(after_cursor: str | None = None, items: list | None = None):
    """Return a minimal SDK v3 ApiResponse-like mock.

    Args:
        after_cursor: If provided, a ``Link`` header with rel="next" and the
            given ``after`` query parameter is added.
        items: Ignored here; kept for clarity at call-sites.
    """
    response = MagicMock()
    # v3 responses do NOT have has_next / next
    del response.has_next
    del response.next

    if after_cursor:
        link_value = (
            f'<https://test.okta.com/api/v1/users?after={after_cursor}&limit=20>; rel="next"'
        )
        response.headers = {"Link": link_value}
    else:
        response.headers = {}
    return response


def _make_v2_response(has_next: bool = False, next_url: str | None = None):
    """Return a minimal SDK v2 OktaAPIResponse-like mock."""
    response = MagicMock()
    response.has_next = MagicMock(return_value=has_next)
    response._next = next_url
    return response


def _make_items(n: int, prefix: str = "item") -> list:
    return [MagicMock(name=f"{prefix}_{i}") for i in range(n)]


# ---------------------------------------------------------------------------
# extract_after_cursor — SDK v3 path
# ---------------------------------------------------------------------------

class TestExtractAfterCursorV3:
    def test_extracts_cursor_from_link_header(self):
        response = _make_v3_response(after_cursor="abc123")
        assert extract_after_cursor(response) == "abc123"

    def test_returns_none_when_no_link_header(self):
        response = _make_v3_response(after_cursor=None)
        assert extract_after_cursor(response) is None

    def test_returns_none_when_link_header_has_no_next_rel(self):
        response = MagicMock()
        del response.has_next
        response.headers = {'Link': '<https://example.com/prev>; rel="prev"'}
        assert extract_after_cursor(response) is None

    def test_returns_none_for_none_response(self):
        assert extract_after_cursor(None) is None

    def test_handles_lowercase_link_header_key(self):
        response = MagicMock()
        del response.has_next
        response.headers = {
            "link": '<https://test.okta.com/api/v1/users?after=xyz>; rel="next"'
        }
        assert extract_after_cursor(response) == "xyz"

    def test_handles_multiple_link_rels(self):
        response = MagicMock()
        del response.has_next
        response.headers = {
            "Link": (
                '<https://test.okta.com/api/v1/users?after=cursor99>; rel="next", '
                '<https://test.okta.com/api/v1/users>; rel="self"'
            )
        }
        assert extract_after_cursor(response) == "cursor99"


# ---------------------------------------------------------------------------
# extract_after_cursor — SDK v2 path
# ---------------------------------------------------------------------------

class TestExtractAfterCursorV2:
    def test_extracts_cursor_from_next_url(self):
        response = _make_v2_response(
            has_next=True,
            next_url="/api/v1/users?after=v2cursor&limit=200",
        )
        assert extract_after_cursor(response) == "v2cursor"

    def test_returns_none_when_has_next_false(self):
        response = _make_v2_response(has_next=False)
        assert extract_after_cursor(response) is None

    def test_returns_none_when_no_next_url(self):
        response = _make_v2_response(has_next=True, next_url=None)
        assert extract_after_cursor(response) is None


# ---------------------------------------------------------------------------
# paginate_all_results — SDK v3 path (next_page_fn provided)
# ---------------------------------------------------------------------------

class TestPaginateAllResultsV3:
    @pytest.mark.asyncio
    async def test_single_page_no_next_cursor(self):
        """When there is no next cursor, only the initial page is returned."""
        initial_response = _make_v3_response(after_cursor=None)
        initial_items = _make_items(5)

        all_items, info = await paginate_all_results(
            initial_response,
            initial_items,
            next_page_fn=AsyncMock(),  # should never be called
        )

        assert all_items == initial_items
        assert info["pages_fetched"] == 1
        assert info["stopped_early"] is False
        assert info["stop_reason"] is None

    @pytest.mark.asyncio
    async def test_multi_page_fetches_all_pages(self):
        """Two pages of results are stitched together correctly."""
        page1_items = _make_items(5, "page1")
        page2_items = _make_items(3, "page2")

        # Response for page 1 has a next cursor; page 2 has none
        resp1 = _make_v3_response(after_cursor="cursor_for_page2")
        resp2 = _make_v3_response(after_cursor=None)

        next_page_fn = AsyncMock(return_value=(page2_items, resp2, None))

        all_items, info = await paginate_all_results(
            resp1,
            page1_items,
            next_page_fn=next_page_fn,
        )

        next_page_fn.assert_awaited_once_with("cursor_for_page2")
        assert all_items == page1_items + page2_items
        assert info["pages_fetched"] == 2
        assert info["total_items"] == 8
        assert info["stopped_early"] is False

    @pytest.mark.asyncio
    async def test_three_pages(self):
        page1 = _make_items(3, "p1")
        page2 = _make_items(3, "p2")
        page3 = _make_items(2, "p3")

        resp1 = _make_v3_response(after_cursor="c2")
        resp2 = _make_v3_response(after_cursor="c3")
        resp3 = _make_v3_response(after_cursor=None)

        next_page_fn = AsyncMock(side_effect=[
            (page2, resp2, None),
            (page3, resp3, None),
        ])

        all_items, info = await paginate_all_results(resp1, page1, next_page_fn=next_page_fn)

        assert len(all_items) == 8
        assert info["pages_fetched"] == 3
        assert info["stopped_early"] is False

    @pytest.mark.asyncio
    async def test_stops_at_max_pages(self):
        """Pagination stops at max_pages and sets stopped_early=True."""
        # Each response always has a next cursor → infinite pages
        resp_with_cursor = _make_v3_response(after_cursor="always_more")
        page_items = _make_items(5)

        next_page_fn = AsyncMock(return_value=(page_items, resp_with_cursor, None))

        all_items, info = await paginate_all_results(
            resp_with_cursor,
            page_items,
            max_pages=3,
            next_page_fn=next_page_fn,
        )

        assert info["pages_fetched"] == 3
        assert info["stopped_early"] is True
        assert "maximum page limit" in info["stop_reason"]
        assert len(all_items) == 15  # 3 pages × 5 items

    @pytest.mark.asyncio
    async def test_api_error_mid_pagination_returns_partial_results(self):
        """When the API returns an error mid-way, partial results are returned."""
        page1_items = _make_items(5, "p1")
        resp1 = _make_v3_response(after_cursor="c2")

        next_page_fn = AsyncMock(return_value=(None, MagicMock(), "Okta API error"))

        all_items, info = await paginate_all_results(
            resp1,
            page1_items,
            next_page_fn=next_page_fn,
        )

        assert all_items == page1_items  # only first page
        assert info["stopped_early"] is True
        assert "API error" in info["stop_reason"]

    @pytest.mark.asyncio
    async def test_exception_during_fetch_page_returns_partial_results(self):
        """An exception during a page fetch stops pagination gracefully."""
        page1_items = _make_items(4, "p1")
        resp1 = _make_v3_response(after_cursor="c2")

        next_page_fn = AsyncMock(side_effect=RuntimeError("network failure"))

        all_items, info = await paginate_all_results(
            resp1,
            page1_items,
            next_page_fn=next_page_fn,
        )

        assert all_items == page1_items
        assert info["stopped_early"] is True
        assert "Exception" in info["stop_reason"]

    @pytest.mark.asyncio
    async def test_empty_next_page_stops_loop(self):
        """If the next page returns no items, pagination terminates cleanly."""
        page1_items = _make_items(5, "p1")
        resp1 = _make_v3_response(after_cursor="c2")
        resp2 = _make_v3_response(after_cursor="c3")  # has cursor but empty items

        next_page_fn = AsyncMock(return_value=([], resp2, None))

        all_items, info = await paginate_all_results(
            resp1,
            page1_items,
            next_page_fn=next_page_fn,
        )

        assert all_items == page1_items
        assert info["pages_fetched"] == 1
        assert info["stopped_early"] is False

    @pytest.mark.asyncio
    async def test_initial_empty_items(self):
        """An empty initial page still participates in pagination correctly."""
        resp1 = _make_v3_response(after_cursor="c2")
        page2_items = _make_items(3, "p2")
        resp2 = _make_v3_response(after_cursor=None)

        next_page_fn = AsyncMock(return_value=(page2_items, resp2, None))

        all_items, info = await paginate_all_results(
            resp1,
            [],
            next_page_fn=next_page_fn,
        )

        assert all_items == page2_items
        assert info["pages_fetched"] == 2


# ---------------------------------------------------------------------------
# paginate_all_results — SDK v2 fallback path (no next_page_fn)
# ---------------------------------------------------------------------------

class TestPaginateAllResultsV2Fallback:
    @pytest.mark.asyncio
    async def test_v2_multi_page_pagination(self):
        page1 = _make_items(5, "p1")
        page2 = _make_items(3, "p2")

        resp = _make_v2_response(has_next=True)
        # .next() called once, then has_next returns False
        resp.has_next.side_effect = [True, False]
        resp.next = AsyncMock(return_value=(page2, None))

        all_items, info = await paginate_all_results(resp, page1)

        assert all_items == page1 + page2
        assert info["pages_fetched"] == 2
        assert info["stopped_early"] is False

    @pytest.mark.asyncio
    async def test_v2_no_next_page(self):
        page1 = _make_items(5)
        resp = _make_v2_response(has_next=False)

        all_items, info = await paginate_all_results(resp, page1)

        assert all_items == page1
        assert info["pages_fetched"] == 1

    @pytest.mark.asyncio
    async def test_v2_api_error_mid_pagination(self):
        page1 = _make_items(3)
        resp = _make_v2_response(has_next=True)
        resp.has_next.return_value = True
        resp.next = AsyncMock(return_value=(None, "v2 error"))

        all_items, info = await paginate_all_results(resp, page1)

        assert all_items == page1
        assert info["stopped_early"] is True
        assert "API error" in info["stop_reason"]


# ---------------------------------------------------------------------------
# create_paginated_response
# ---------------------------------------------------------------------------

class TestCreatePaginatedResponse:
    def test_single_page_no_fetch_all(self):
        items = _make_items(5)
        resp = _make_v3_response(after_cursor="abc")
        result = create_paginated_response(items, resp, fetch_all_used=False)

        assert result["total_fetched"] == 5
        assert result["fetch_all_used"] is False
        assert result["has_more"] is True
        assert result["next_cursor"] == "abc"

    def test_fetch_all_suppresses_has_more(self):
        items = _make_items(10)
        resp = _make_v3_response(after_cursor="xyz")
        result = create_paginated_response(items, resp, fetch_all_used=True)

        assert result["fetch_all_used"] is True
        assert result["has_more"] is False
        assert result["next_cursor"] is None

    def test_includes_pagination_info_when_provided(self):
        items = _make_items(3)
        resp = _make_v3_response()
        info = {"pages_fetched": 5, "total_items": 100, "stopped_early": True, "stop_reason": "limit"}
        result = create_paginated_response(items, resp, fetch_all_used=True, pagination_info=info)

        assert result["pagination_info"] == info

    def test_no_pagination_info_key_when_not_provided(self):
        items = _make_items(2)
        resp = _make_v3_response()
        result = create_paginated_response(items, resp, fetch_all_used=False)

        assert "pagination_info" not in result


# ---------------------------------------------------------------------------
# Tool integration: fetch_all=True guard + paginate_all_results call
# Tests for list_users, list_groups, list_group_users, get_logs
# ---------------------------------------------------------------------------

def _make_ctx_with_client(client):
    """Build a minimal Context mock wired to the given Okta client mock."""
    manager = MagicMock()
    ctx = MagicMock()
    ctx.request_context.lifespan_context.okta_auth_manager = manager
    return ctx, manager


class TestListUsersFetchAll:
    @pytest.mark.asyncio
    async def test_fetch_all_true_paginates_all_pages(self):
        """list_users with fetch_all=True stitches multiple pages together."""
        from okta_mcp_server.tools.users.users import list_users

        page1_users = _make_items(3, "user")
        for u in page1_users:
            u.profile = MagicMock()
            u.id = "id"

        page2_users = _make_items(2, "user")
        for u in page2_users:
            u.profile = MagicMock()
            u.id = "id"

        resp1 = _make_v3_response(after_cursor="c2")
        resp2 = _make_v3_response(after_cursor=None)

        client = AsyncMock()
        client.list_users.side_effect = [
            (page1_users, resp1, None),
            (page2_users, resp2, None),
        ]

        ctx, manager = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.users.users.get_okta_client", return_value=client):
            result = await list_users(ctx, fetch_all=True, limit=3)

        assert result["fetch_all_used"] is True
        assert result["total_fetched"] == 5
        assert result["pagination_info"]["pages_fetched"] == 2
        assert result["pagination_info"]["stopped_early"] is False

    @pytest.mark.asyncio
    async def test_fetch_all_false_returns_single_page(self):
        """list_users with fetch_all=False returns only the first page."""
        from okta_mcp_server.tools.users.users import list_users

        users = _make_items(5, "user")
        for u in users:
            u.profile = MagicMock()
            u.id = "id"

        resp = _make_v3_response(after_cursor="more")
        client = AsyncMock()
        client.list_users.return_value = (users, resp, None)

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.users.users.get_okta_client", return_value=client):
            result = await list_users(ctx, fetch_all=False)

        assert result["fetch_all_used"] is False
        assert result["total_fetched"] == 5
        assert result["has_more"] is True
        assert result["next_cursor"] == "more"
        # list_users was only called once — no pagination
        assert client.list_users.call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_all_true_single_page_no_next_cursor(self):
        """fetch_all=True on a single-page result: no extra requests made."""
        from okta_mcp_server.tools.users.users import list_users

        users = _make_items(4, "user")
        for u in users:
            u.profile = MagicMock()
            u.id = "id"

        resp = _make_v3_response(after_cursor=None)
        client = AsyncMock()
        client.list_users.return_value = (users, resp, None)

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.users.users.get_okta_client", return_value=client):
            result = await list_users(ctx, fetch_all=True)

        # Guard condition: no next cursor → no pagination attempted
        assert client.list_users.call_count == 1
        assert result["total_fetched"] == 4


class TestListGroupsFetchAll:
    @pytest.mark.asyncio
    async def test_fetch_all_true_paginates_all_pages(self):
        from okta_mcp_server.tools.groups.groups import list_groups

        page1 = _make_items(2, "grp")
        page2 = _make_items(2, "grp")

        resp1 = _make_v3_response(after_cursor="g2")
        resp2 = _make_v3_response(after_cursor=None)

        client = AsyncMock()
        client.list_groups.side_effect = [
            (page1, resp1, None),
            (page2, resp2, None),
        ]

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.groups.groups.get_okta_client", return_value=client):
            result = await list_groups(ctx, fetch_all=True, limit=2)

        assert result["fetch_all_used"] is True
        assert result["total_fetched"] == 4
        assert result["pagination_info"]["pages_fetched"] == 2

    @pytest.mark.asyncio
    async def test_fetch_all_false_returns_single_page(self):
        from okta_mcp_server.tools.groups.groups import list_groups

        groups = _make_items(3, "grp")
        resp = _make_v3_response(after_cursor="gc")
        client = AsyncMock()
        client.list_groups.return_value = (groups, resp, None)

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.groups.groups.get_okta_client", return_value=client):
            result = await list_groups(ctx, fetch_all=False)

        assert result["fetch_all_used"] is False
        assert result["total_fetched"] == 3
        assert client.list_groups.call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_all_true_max_pages_stops_early(self):
        from okta_mcp_server.tools.groups.groups import list_groups

        page_items = _make_items(5, "grp")
        resp_with_cursor = _make_v3_response(after_cursor="always_more")

        client = AsyncMock()
        # Always return a new page with a cursor
        client.list_groups.return_value = (page_items, resp_with_cursor, None)

        ctx, _ = _make_ctx_with_client(client)

        with (
            patch("okta_mcp_server.tools.groups.groups.get_okta_client", return_value=client),
            patch("okta_mcp_server.utils.pagination.paginate_all_results") as mock_paginate,
        ):
            mock_paginate.return_value = (
                page_items * 3,
                {"pages_fetched": 3, "total_items": 15, "stopped_early": True,
                 "stop_reason": "Reached maximum page limit (3)"},
            )
            result = await list_groups(ctx, fetch_all=True, limit=5)

        assert result["pagination_info"]["stopped_early"] is True


class TestListGroupUsersFetchAll:
    @pytest.mark.asyncio
    async def test_fetch_all_true_paginates_all_pages(self):
        from okta_mcp_server.tools.groups.groups import list_group_users

        page1 = _make_items(3, "usr")
        page2 = _make_items(2, "usr")

        resp1 = _make_v3_response(after_cursor="uc2")
        resp2 = _make_v3_response(after_cursor=None)

        client = AsyncMock()
        client.list_group_users.side_effect = [
            (page1, resp1, None),
            (page2, resp2, None),
        ]

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.groups.groups.get_okta_client", return_value=client):
            result = await list_group_users("grp1", ctx, fetch_all=True, limit=3)

        assert result["fetch_all_used"] is True
        assert result["total_fetched"] == 5
        assert result["pagination_info"]["pages_fetched"] == 2

    @pytest.mark.asyncio
    async def test_fetch_all_false_returns_single_page(self):
        from okta_mcp_server.tools.groups.groups import list_group_users

        users = _make_items(4, "usr")
        resp = _make_v3_response(after_cursor="uc")
        client = AsyncMock()
        client.list_group_users.return_value = (users, resp, None)

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.groups.groups.get_okta_client", return_value=client):
            result = await list_group_users("grp1", ctx, fetch_all=False)

        assert result["fetch_all_used"] is False
        assert result["total_fetched"] == 4
        assert client.list_group_users.call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_all_passes_group_id_to_each_page(self):
        """The group_id must be forwarded unchanged to every paginated request."""
        from okta_mcp_server.tools.groups.groups import list_group_users

        group_id = "00gABCDEFG"
        page1 = _make_items(2, "usr")
        page2 = _make_items(1, "usr")

        resp1 = _make_v3_response(after_cursor="uc2")
        resp2 = _make_v3_response(after_cursor=None)

        client = AsyncMock()
        client.list_group_users.side_effect = [
            (page1, resp1, None),
            (page2, resp2, None),
        ]

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.groups.groups.get_okta_client", return_value=client):
            await list_group_users(group_id, ctx, fetch_all=True)

        # Both calls should use the same group_id
        for call in client.list_group_users.call_args_list:
            assert call.args[0] == group_id


class TestGetLogsFetchAll:
    @pytest.mark.asyncio
    async def test_fetch_all_true_paginates_all_pages(self):
        from okta_mcp_server.tools.system_logs.system_logs import get_logs

        page1 = _make_items(3, "log")
        page2 = _make_items(2, "log")

        resp1 = _make_v3_response(after_cursor="lc2")
        resp2 = _make_v3_response(after_cursor=None)

        client = AsyncMock()
        client.list_log_events.side_effect = [
            (page1, resp1, None),
            (page2, resp2, None),
        ]

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.system_logs.system_logs.get_okta_client", return_value=client):
            result = await get_logs(ctx, fetch_all=True, limit=3)

        assert result["fetch_all_used"] is True
        assert result["total_fetched"] == 5
        assert result["pagination_info"]["pages_fetched"] == 2

    @pytest.mark.asyncio
    async def test_fetch_all_false_returns_single_page(self):
        from okta_mcp_server.tools.system_logs.system_logs import get_logs

        logs = _make_items(5, "log")
        resp = _make_v3_response(after_cursor="lc")
        client = AsyncMock()
        client.list_log_events.return_value = (logs, resp, None)

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.system_logs.system_logs.get_okta_client", return_value=client):
            result = await get_logs(ctx, fetch_all=False)

        assert result["fetch_all_used"] is False
        assert result["total_fetched"] == 5
        assert client.list_log_events.call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_all_true_single_page_no_cursor(self):
        """get_logs with fetch_all=True but only one page of results."""
        from okta_mcp_server.tools.system_logs.system_logs import get_logs

        logs = _make_items(2, "log")
        resp = _make_v3_response(after_cursor=None)
        client = AsyncMock()
        client.list_log_events.return_value = (logs, resp, None)

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.system_logs.system_logs.get_okta_client", return_value=client):
            result = await get_logs(ctx, fetch_all=True)

        assert client.list_log_events.call_count == 1
        assert result["total_fetched"] == 2

    @pytest.mark.asyncio
    async def test_empty_results_with_fetch_all(self):
        """get_logs with fetch_all=True and zero results returns empty list."""
        from okta_mcp_server.tools.system_logs.system_logs import get_logs

        resp = _make_v3_response(after_cursor=None)
        client = AsyncMock()
        client.list_log_events.return_value = ([], resp, None)

        ctx, _ = _make_ctx_with_client(client)

        with patch("okta_mcp_server.tools.system_logs.system_logs.get_okta_client", return_value=client):
            result = await get_logs(ctx, fetch_all=True)

        assert result["total_fetched"] == 0
        assert result["fetch_all_used"] is True


# ---------------------------------------------------------------------------
# Guard condition: v3 ApiResponse never has has_next attr
# ---------------------------------------------------------------------------

class TestGuardCondition:
    """Verify that the guard uses extract_after_cursor(), NOT hasattr(response, 'has_next')."""

    def test_v3_response_has_no_has_next(self):
        """SDK v3 ApiResponse objects must NOT have a has_next attribute."""
        resp = _make_v3_response(after_cursor="abc")
        assert not hasattr(resp, "has_next"), (
            "v3 ApiResponse must not have has_next; "
            "the old guard condition would silently skip pagination"
        )

    def test_extract_after_cursor_works_on_v3_response(self):
        """extract_after_cursor() must work on a v3 ApiResponse with a Link header."""
        resp = _make_v3_response(after_cursor="abc123")
        assert extract_after_cursor(resp) == "abc123"

    def test_extract_after_cursor_returns_none_on_v3_no_cursor(self):
        """extract_after_cursor() must return None on a v3 response without Link."""
        resp = _make_v3_response(after_cursor=None)
        assert extract_after_cursor(resp) is None
