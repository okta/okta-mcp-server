# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Shared fixtures for Okta MCP Server tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.utils.elicitation import (
    DeleteConfirmation,
    DeactivateConfirmation,
)


# ---------------------------------------------------------------------------
# Fake Okta auth / lifespan context
# ---------------------------------------------------------------------------

@dataclass
class FakeOktaAuthManager:
    """Minimal stand-in for OktaAuthManager."""
    org_url: str = "https://test.okta.com"

    async def is_valid_token(self):
        return True

    async def authenticate(self):
        pass

    def clear_tokens(self):
        pass


@dataclass
class FakeLifespanContext:
    """Minimal stand-in for the lifespan context yielded by the server."""
    okta_auth_manager: FakeOktaAuthManager


# ---------------------------------------------------------------------------
# Elicitation result helpers
# ---------------------------------------------------------------------------

def _make_accepted_result(confirm: bool):
    """Simulate an ``AcceptedElicitation`` with a ``confirm`` field."""
    data = MagicMock()
    data.confirm = confirm
    result = MagicMock()
    result.action = "accept"
    result.data = data
    return result


def _make_declined_result():
    result = MagicMock()
    result.action = "decline"
    result.data = None
    return result


def _make_cancelled_result():
    result = MagicMock()
    result.action = "cancel"
    result.data = None
    return result


# ---------------------------------------------------------------------------
# Context fixtures
# ---------------------------------------------------------------------------

def _build_ctx(*, elicitation_supported: bool = True, elicit_return=None, elicit_side_effect=None):
    """Build a fake ``Context`` suitable for tool tests.

    Parameters
    ----------
    elicitation_supported:
        If ``True`` the fake client advertises the elicitation capability.
    elicit_return:
        Value returned by ``ctx.elicit()``.
    elicit_side_effect:
        Exception (or callable) raised by ``ctx.elicit()``.
    """
    # --- session & capabilities ---
    capabilities = MagicMock()
    if elicitation_supported:
        capabilities.elicitation = {}  # truthy → supported
    else:
        capabilities.elicitation = None  # falsy → not supported

    client_params = MagicMock()
    client_params.capabilities = capabilities

    session = MagicMock()
    session.client_params = client_params

    # --- request_context ---
    request_context = MagicMock()
    request_context.session = session
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager(),
    )

    # --- ctx ---
    ctx = MagicMock()
    ctx.request_context = request_context

    # ctx.elicit is async
    elicit_mock = AsyncMock()
    if elicit_side_effect:
        elicit_mock.side_effect = elicit_side_effect
    elif elicit_return is not None:
        elicit_mock.return_value = elicit_return
    ctx.elicit = elicit_mock

    return ctx


@pytest.fixture()
def ctx_elicit_accept_true():
    """Context where elicitation is supported and user accepts with confirm=True."""
    return _build_ctx(elicit_return=_make_accepted_result(confirm=True))


@pytest.fixture()
def ctx_elicit_accept_false():
    """Context where elicitation is supported and user accepts with confirm=False."""
    return _build_ctx(elicit_return=_make_accepted_result(confirm=False))


@pytest.fixture()
def ctx_elicit_decline():
    """Context where elicitation is supported and user declines."""
    return _build_ctx(elicit_return=_make_declined_result())


@pytest.fixture()
def ctx_elicit_cancel():
    """Context where elicitation is supported and user cancels."""
    return _build_ctx(elicit_return=_make_cancelled_result())


@pytest.fixture()
def ctx_no_elicitation():
    """Context where the client does NOT support elicitation."""
    return _build_ctx(elicitation_supported=False)


@pytest.fixture()
def ctx_elicit_exception():
    """Context where elicitation is supported but ctx.elicit() raises."""
    return _build_ctx(
        elicitation_supported=True,
        elicit_side_effect=Exception("elicitation not implemented"),
    )


# ---------------------------------------------------------------------------
# Okta client mock helper
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_okta_client():
    """Return a ``MagicMock`` with async Okta client methods pre-configured."""
    client = AsyncMock()
    # Defaults: success, no error
    client.delete_group.return_value = (None, None)
    client.delete_application.return_value = (None, None)
    client.delete_policy.return_value = (None, None)
    client.delete_policy_rule.return_value = (None, None)
    client.deactivate_user.return_value = (None, None)
    client.deactivate_or_delete_user.return_value = (None, None)
    return client
