# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for okta_mcp_server.utils.elicitation."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from okta_mcp_server.utils.elicitation import (
    DeactivateConfirmation,
    DeleteConfirmation,
    ElicitationOutcome,
    elicit_or_fallback,
    supports_elicitation,
)


# ---- Schema tests ---------------------------------------------------------

class TestDeleteConfirmationSchema:
    def test_explicit_true(self):
        obj = DeleteConfirmation(confirm=True)
        assert obj.confirm is True

    def test_json_schema_has_description(self):
        schema = DeleteConfirmation.model_json_schema()
        assert "confirm" in schema["properties"]
        assert "description" in schema["properties"]["confirm"]

    def test_only_primitive_fields(self):
        """Elicitation schemas must only contain primitive types."""
        for name, field in DeleteConfirmation.model_fields.items():
            assert field.annotation in (bool, str, int, float), (
                f"Field {name} has non-primitive type {field.annotation}"
            )


class TestDeactivateConfirmationSchema:
    def test_explicit_true(self):
        obj = DeactivateConfirmation(confirm=True)
        assert obj.confirm is True


# ---- supports_elicitation -------------------------------------------------

class TestSupportsElicitation:
    def test_returns_true_when_capability_present(self, ctx_elicit_accept_true):
        assert supports_elicitation(ctx_elicit_accept_true) is True

    def test_returns_false_when_capability_absent(self, ctx_no_elicitation):
        assert supports_elicitation(ctx_no_elicitation) is False

    def test_returns_false_when_session_missing(self):
        ctx = MagicMock()
        ctx.request_context.session = None
        assert supports_elicitation(ctx) is False

    def test_returns_false_when_client_params_missing(self):
        ctx = MagicMock()
        ctx.request_context.session.client_params = None
        assert supports_elicitation(ctx) is False

    def test_returns_false_when_capabilities_missing(self):
        ctx = MagicMock()
        ctx.request_context.session.client_params.capabilities = None
        assert supports_elicitation(ctx) is False

    def test_returns_false_on_exception(self):
        ctx = MagicMock()
        ctx.request_context = property(lambda self: (_ for _ in ()).throw(RuntimeError))
        # Any exception → False
        assert supports_elicitation(ctx) is False


# ---- elicit_or_fallback ---------------------------------------------------

class TestElicitOrFallback:
    @pytest.mark.asyncio
    async def test_accept_confirmed(self, ctx_elicit_accept_true):
        outcome = await elicit_or_fallback(
            ctx_elicit_accept_true, "Delete?", DeleteConfirmation
        )
        assert outcome.confirmed is True
        assert outcome.used_elicitation is True
        assert outcome.fallback_response is None

    @pytest.mark.asyncio
    async def test_accept_not_confirmed(self, ctx_elicit_accept_false):
        outcome = await elicit_or_fallback(
            ctx_elicit_accept_false, "Delete?", DeleteConfirmation
        )
        assert outcome.confirmed is False
        assert outcome.used_elicitation is True

    @pytest.mark.asyncio
    async def test_decline(self, ctx_elicit_decline):
        outcome = await elicit_or_fallback(
            ctx_elicit_decline, "Delete?", DeleteConfirmation
        )
        assert outcome.confirmed is False
        assert outcome.used_elicitation is True

    @pytest.mark.asyncio
    async def test_cancel(self, ctx_elicit_cancel):
        outcome = await elicit_or_fallback(
            ctx_elicit_cancel, "Delete?", DeleteConfirmation
        )
        assert outcome.confirmed is False
        assert outcome.used_elicitation is True

    @pytest.mark.asyncio
    async def test_fallback_when_not_supported(self, ctx_no_elicitation):
        outcome = await elicit_or_fallback(
            ctx_no_elicitation, "Delete?", DeleteConfirmation
        )
        assert outcome.confirmed is False
        assert outcome.used_elicitation is False
        assert outcome.fallback_response is not None
        assert outcome.fallback_response["confirmation_required"] is True

    @pytest.mark.asyncio
    async def test_fallback_with_custom_payload(self, ctx_no_elicitation):
        custom = {"custom_key": "custom_value"}
        outcome = await elicit_or_fallback(
            ctx_no_elicitation, "Delete?", DeleteConfirmation, fallback_payload=custom
        )
        assert outcome.fallback_response == custom

    @pytest.mark.asyncio
    async def test_fallback_on_exception(self, ctx_elicit_exception):
        outcome = await elicit_or_fallback(
            ctx_elicit_exception, "Delete?", DeleteConfirmation
        )
        assert outcome.confirmed is False
        assert outcome.used_elicitation is False
        assert outcome.fallback_response is not None

    @pytest.mark.asyncio
    async def test_deactivate_schema(self, ctx_elicit_accept_true):
        outcome = await elicit_or_fallback(
            ctx_elicit_accept_true, "Deactivate?", DeactivateConfirmation
        )
        assert outcome.confirmed is True
        assert outcome.used_elicitation is True

    # -- auto_confirm_on_fallback tests --

    @pytest.mark.asyncio
    async def test_auto_confirm_when_not_supported(self, ctx_no_elicitation):
        outcome = await elicit_or_fallback(
            ctx_no_elicitation, "Delete?", DeleteConfirmation,
            auto_confirm_on_fallback=True,
        )
        assert outcome.confirmed is True
        assert outcome.used_elicitation is False
        assert outcome.fallback_response is None

    @pytest.mark.asyncio
    async def test_auto_confirm_on_exception(self, ctx_elicit_exception):
        outcome = await elicit_or_fallback(
            ctx_elicit_exception, "Delete?", DeleteConfirmation,
            auto_confirm_on_fallback=True,
        )
        assert outcome.confirmed is True
        assert outcome.used_elicitation is False
        assert outcome.fallback_response is None

    @pytest.mark.asyncio
    async def test_auto_confirm_false_still_returns_payload(self, ctx_no_elicitation):
        """Default auto_confirm_on_fallback=False preserves original behaviour."""
        outcome = await elicit_or_fallback(
            ctx_no_elicitation, "Delete?", DeleteConfirmation,
            auto_confirm_on_fallback=False,
        )
        assert outcome.confirmed is False
        assert outcome.used_elicitation is False
        assert outcome.fallback_response is not None
        assert outcome.fallback_response["confirmation_required"] is True

    # -- McpError handling tests --

    @pytest.mark.asyncio
    async def test_mcp_error_method_not_found_fallback(self, ctx_elicit_mcp_error_method_not_found):
        """McpError with METHOD_NOT_FOUND falls back gracefully."""
        outcome = await elicit_or_fallback(
            ctx_elicit_mcp_error_method_not_found, "Delete?", DeleteConfirmation
        )
        assert outcome.confirmed is False
        assert outcome.used_elicitation is False
        assert outcome.fallback_response is not None
        assert outcome.fallback_response["confirmation_required"] is True

    @pytest.mark.asyncio
    async def test_mcp_error_method_not_found_auto_confirm(self, ctx_elicit_mcp_error_method_not_found):
        """McpError with METHOD_NOT_FOUND auto-confirms when configured."""
        outcome = await elicit_or_fallback(
            ctx_elicit_mcp_error_method_not_found, "Delete?", DeleteConfirmation,
            auto_confirm_on_fallback=True,
        )
        assert outcome.confirmed is True
        assert outcome.used_elicitation is False
        assert outcome.fallback_response is None

    @pytest.mark.asyncio
    async def test_mcp_error_other_code_fallback(self, ctx_elicit_mcp_error_other):
        """McpError with non-METHOD_NOT_FOUND code falls back gracefully."""
        outcome = await elicit_or_fallback(
            ctx_elicit_mcp_error_other, "Delete?", DeleteConfirmation
        )
        assert outcome.confirmed is False
        assert outcome.used_elicitation is False
        assert outcome.fallback_response is not None

    @pytest.mark.asyncio
    async def test_mcp_error_other_code_auto_confirm(self, ctx_elicit_mcp_error_other):
        """McpError with non-METHOD_NOT_FOUND code auto-confirms when configured."""
        outcome = await elicit_or_fallback(
            ctx_elicit_mcp_error_other, "Delete?", DeleteConfirmation,
            auto_confirm_on_fallback=True,
        )
        assert outcome.confirmed is True
        assert outcome.used_elicitation is False
        assert outcome.fallback_response is None
