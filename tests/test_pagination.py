# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for okta_mcp_server.utils.pagination"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from okta_mcp_server.utils.pagination import (
    build_query_params,
    create_paginated_response,
    extract_after_cursor,
    paginate_all_results,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(has_next: bool = False, next_url: str | None = None):
    """Create a mock OktaAPIResponse."""
    resp = MagicMock()
    resp.has_next.return_value = has_next
    resp._next = next_url
    return resp


# ---------------------------------------------------------------------------
# extract_after_cursor
# ---------------------------------------------------------------------------


class TestExtractAfterCursor:
    def test_returns_none_for_none_response(self):
        assert extract_after_cursor(None) is None

    def test_returns_none_when_no_has_next(self):
        resp = MagicMock(spec=[])  # no has_next attr
        assert extract_after_cursor(resp) is None

    def test_returns_none_when_has_next_false(self):
        resp = _mock_response(has_next=False)
        assert extract_after_cursor(resp) is None

    def test_extracts_cursor_from_next_url(self):
        resp = _mock_response(
            has_next=True,
            next_url="/api/v1/users?after=00u1abc123&limit=200",
        )
        assert extract_after_cursor(resp) == "00u1abc123"

    def test_returns_none_when_no_after_param(self):
        resp = _mock_response(
            has_next=True,
            next_url="/api/v1/users?limit=200",
        )
        assert extract_after_cursor(resp) is None

    def test_returns_none_when_next_is_none(self):
        resp = _mock_response(has_next=True, next_url=None)
        assert extract_after_cursor(resp) is None

    def test_handles_malformed_url_gracefully(self):
        resp = _mock_response(has_next=True, next_url="not-a-url")
        # Should not raise
        result = extract_after_cursor(resp)
        assert result is None


# ---------------------------------------------------------------------------
# build_query_params
# ---------------------------------------------------------------------------


class TestBuildQueryParams:
    def test_empty_params(self):
        assert build_query_params() == {}

    def test_search_only(self):
        result = build_query_params(search='profile.email eq "a@b.com"')
        assert result == {"search": 'profile.email eq "a@b.com"'}

    def test_all_params(self):
        result = build_query_params(
            search="s",
            filter="f",
            q="q",
            after="cursor123",
            limit=50,
        )
        assert result == {
            "search": "s",
            "filter": "f",
            "q": "q",
            "after": "cursor123",
            "limit": "50",
        }

    def test_empty_strings_excluded(self):
        result = build_query_params(search="", filter=None, q=None)
        assert result == {}

    def test_kwargs_forwarded(self):
        result = build_query_params(since="2024-01-01", until="2024-02-01")
        assert result == {"since": "2024-01-01", "until": "2024-02-01"}

    def test_kwargs_none_excluded(self):
        result = build_query_params(since=None)
        assert result == {}


# ---------------------------------------------------------------------------
# create_paginated_response
# ---------------------------------------------------------------------------


class TestCreatePaginatedResponse:
    def test_basic_response_structure(self):
        resp = _mock_response(has_next=False)
        result = create_paginated_response(["item1", "item2"], resp)
        assert result["items"] == ["item1", "item2"]
        assert result["total_fetched"] == 2
        assert result["has_more"] is False
        assert result["next_cursor"] is None
        assert result["fetch_all_used"] is False

    def test_has_more_with_cursor(self):
        resp = _mock_response(
            has_next=True,
            next_url="/api/v1/users?after=abc123",
        )
        result = create_paginated_response(["item"], resp)
        assert result["has_more"] is True
        assert result["next_cursor"] == "abc123"

    def test_fetch_all_used_skips_cursor(self):
        resp = _mock_response(has_next=True)
        result = create_paginated_response(
            ["item"], resp, fetch_all_used=True
        )
        assert result["fetch_all_used"] is True
        assert result["has_more"] is False
        assert result["next_cursor"] is None

    def test_empty_items(self):
        resp = _mock_response()
        result = create_paginated_response([], resp)
        assert result["total_fetched"] == 0
        assert result["items"] == []

    def test_pagination_info_included(self):
        resp = _mock_response()
        info = {"pages_fetched": 3, "total_items": 150}
        result = create_paginated_response(
            ["item"], resp, pagination_info=info
        )
        assert result["pagination_info"] == info

    def test_none_response(self):
        result = create_paginated_response(["item"], None)
        assert result["has_more"] is False


# ---------------------------------------------------------------------------
# paginate_all_results
# ---------------------------------------------------------------------------


class TestPaginateAllResults:
    async def test_single_page_no_next(self):
        resp = _mock_response(has_next=False)
        items, info = await paginate_all_results(resp, ["a", "b"])
        assert items == ["a", "b"]
        assert info["pages_fetched"] == 1
        assert info["total_items"] == 2
        assert info["stopped_early"] is False

    async def test_multi_page(self):
        page2_resp = _mock_response(has_next=False)
        resp = _mock_response(has_next=True)
        resp.next = AsyncMock(return_value=(["c", "d"], None))
        # After first .next() call, has_next should return False
        resp.has_next.side_effect = [True, False]

        items, info = await paginate_all_results(
            resp, ["a", "b"], delay_between_requests=0
        )
        assert items == ["a", "b", "c", "d"]
        assert info["pages_fetched"] == 2
        assert info["total_items"] == 4

    async def test_max_pages_limit(self):
        resp = _mock_response(has_next=True)
        resp.next = AsyncMock(return_value=(["x"], None))
        # Always has_next = True to trigger max_pages
        resp.has_next.return_value = True

        items, info = await paginate_all_results(
            resp, ["a"], max_pages=3, delay_between_requests=0
        )
        assert info["pages_fetched"] == 3
        assert info["stopped_early"] is True
        assert "maximum page limit" in info["stop_reason"]

    async def test_error_on_next_page(self):
        resp = _mock_response(has_next=True)
        resp.has_next.side_effect = [True, False]
        resp.next = AsyncMock(return_value=(None, "API error"))

        items, info = await paginate_all_results(
            resp, ["a"], delay_between_requests=0
        )
        assert items == ["a"]
        assert info["stopped_early"] is True
        assert "API error" in info["stop_reason"]

    async def test_exception_during_pagination(self):
        resp = _mock_response(has_next=True)
        resp.has_next.side_effect = [True, False]
        resp.next = AsyncMock(side_effect=RuntimeError("network"))

        items, info = await paginate_all_results(
            resp, ["a"], delay_between_requests=0
        )
        assert items == ["a"]
        assert info["stopped_early"] is True

    async def test_none_response(self):
        items, info = await paginate_all_results(None, ["a"])
        assert items == ["a"]
        assert info["pages_fetched"] == 1

    async def test_response_without_has_next(self):
        resp = MagicMock(spec=[])  # no has_next
        items, info = await paginate_all_results(resp, ["a"])
        assert items == ["a"]

    async def test_empty_next_page_stops(self):
        resp = _mock_response(has_next=True)
        resp.has_next.side_effect = [True, False]
        resp.next = AsyncMock(return_value=([], None))

        items, info = await paginate_all_results(
            resp, ["a"], delay_between_requests=0
        )
        assert items == ["a"]
