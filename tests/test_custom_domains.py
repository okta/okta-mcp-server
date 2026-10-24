# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the ``create_custom_domain`` refetch fallback.

PR #90 review flagged the 204/empty-body → ``list_custom_domains`` refetch
path in ``custom_domains.py`` as having no direct test coverage.  These tests
cover:

1. Refetch succeeds and the matching domain is returned (happy path).
2. Case-insensitive FQDN comparison (RFC 1035).
3. Refetch itself fails → error dict propagates.
4. Refetch succeeds but the created domain is not present → error dict.
5. Baseline: SDK returns the created object → refetch never runs.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.customization.custom_domains.custom_domains import (
    create_custom_domain,
)


DOMAIN = "login.example.com"


def _make_domain(fqdn: str, domain_id: str = "OcD1a2b3c4d5"):
    """Build a lightweight stand-in for an Okta ``DomainResponse`` model."""
    m = MagicMock()
    m.domain = fqdn
    m.id = domain_id
    # to_dict powers the @json_response boundary in the tool.
    m.to_dict.return_value = {"id": domain_id, "domain": fqdn}
    return m


def _make_list_response(domains):
    """Build a stand-in for the SDK's list-domains response object."""
    resp = MagicMock()
    resp.domains = domains
    return resp


class TestCreateCustomDomainRefetchFallback:
    """204/empty-body branch: SDK returns (None, response, None)."""

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.custom_domains.custom_domains.get_okta_client"
    )
    async def test_refetch_returns_matching_domain(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        # Pre-check list: empty (no duplicate).
        # Post-create refetch list: contains the freshly-created domain.
        client.list_custom_domains.side_effect = [
            (_make_list_response([]), MagicMock(), None),
            (_make_list_response([_make_domain(DOMAIN)]), MagicMock(), None),
        ]
        # SDK create returns (None, response, None) — the 204 case.
        client.create_custom_domain.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_custom_domain(
            ctx=ctx_no_elicitation,
            domain=DOMAIN,
            certificate_source_type="MANUAL",
        )

        assert isinstance(result, dict)
        assert result.get("domain") == DOMAIN
        # Two list calls: dedup pre-check + refetch fallback.
        assert client.list_custom_domains.await_count == 2

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.custom_domains.custom_domains.get_okta_client"
    )
    async def test_refetch_case_insensitive_match(
        self, mock_get_client, ctx_no_elicitation
    ):
        # Reviewer flagged that the naive comparison would miss an Okta-stored
        # domain that differs only in letter case.  FQDNs are case-insensitive
        # per RFC 1035, so the tool must match on ``.lower()``.
        stored_fqdn = "Login.Example.COM"
        requested_fqdn = "login.example.com"

        client = AsyncMock()
        client.list_custom_domains.side_effect = [
            (_make_list_response([]), MagicMock(), None),
            (_make_list_response([_make_domain(stored_fqdn)]), MagicMock(), None),
        ]
        client.create_custom_domain.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_custom_domain(
            ctx=ctx_no_elicitation,
            domain=requested_fqdn,
            certificate_source_type="MANUAL",
        )

        assert isinstance(result, dict)
        # to_dict output carries the stored (mixed-case) FQDN — that's fine;
        # the important guarantee is that the caller got a resolved object
        # back rather than an error.
        assert "error" not in result
        assert result.get("domain") == stored_fqdn

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.custom_domains.custom_domains.get_okta_client"
    )
    async def test_refetch_failure_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.list_custom_domains.side_effect = [
            (_make_list_response([]), MagicMock(), None),
            # Refetch returns an error.
            (None, MagicMock(), "list failed"),
        ]
        client.create_custom_domain.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_custom_domain(
            ctx=ctx_no_elicitation,
            domain=DOMAIN,
            certificate_source_type="MANUAL",
        )

        assert isinstance(result, dict)
        assert "error" in result
        assert "list_custom_domains failed" in result["error"]
        assert DOMAIN in result["error"]

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.custom_domains.custom_domains.get_okta_client"
    )
    async def test_refetch_missing_domain_returns_error_dict(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.list_custom_domains.side_effect = [
            (_make_list_response([]), MagicMock(), None),
            # Refetch succeeded but the created domain is not in the list.
            (_make_list_response([_make_domain("other.example.com")]), MagicMock(), None),
        ]
        client.create_custom_domain.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_custom_domain(
            ctx=ctx_no_elicitation,
            domain=DOMAIN,
            certificate_source_type="MANUAL",
        )

        assert isinstance(result, dict)
        assert "error" in result
        assert "was not returned by list_custom_domains" in result["error"]
        assert DOMAIN in result["error"]


class TestCreateCustomDomainBaseline:
    """Guardrail: happy-path create must NOT fire the refetch fallback."""

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.custom_domains.custom_domains.get_okta_client"
    )
    async def test_created_object_returned_without_refetch(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.list_custom_domains.return_value = (
            _make_list_response([]),
            MagicMock(),
            None,
        )
        # SDK returns the created object directly.
        client.create_custom_domain.return_value = (
            _make_domain(DOMAIN),
            MagicMock(),
            None,
        )
        mock_get_client.return_value = client

        result = await create_custom_domain(
            ctx=ctx_no_elicitation,
            domain=DOMAIN,
            certificate_source_type="MANUAL",
        )

        assert isinstance(result, dict)
        assert result.get("domain") == DOMAIN
        # Only the pre-check list call — no refetch.
        assert client.list_custom_domains.await_count == 1

    @pytest.mark.asyncio
    @patch(
        "okta_mcp_server.tools.customization.custom_domains.custom_domains.get_okta_client"
    )
    async def test_duplicate_domain_short_circuits_before_create(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.list_custom_domains.return_value = (
            _make_list_response([_make_domain(DOMAIN)]),
            MagicMock(),
            None,
        )
        mock_get_client.return_value = client

        result = await create_custom_domain(
            ctx=ctx_no_elicitation,
            domain=DOMAIN,
            certificate_source_type="MANUAL",
        )

        assert isinstance(result, dict)
        assert "error" in result
        assert "already exists" in result["error"]
        client.create_custom_domain.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_invalid_certificate_source_type_returns_error(
        self, ctx_no_elicitation
    ):
        result = await create_custom_domain(
            ctx=ctx_no_elicitation,
            domain=DOMAIN,
            certificate_source_type="BOGUS",
        )

        assert isinstance(result, dict)
        assert "error" in result
        assert "certificate_source_type" in result["error"]
