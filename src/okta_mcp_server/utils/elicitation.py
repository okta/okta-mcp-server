# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Elicitation utilities for the Okta MCP server.

Provides shared Pydantic schemas, capability detection, and a fallback-aware
helper for requesting user confirmation before destructive operations via the
MCP elicitation protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from loguru import logger
from mcp.server.elicitation import AcceptedElicitation, CancelledElicitation, DeclinedElicitation
from mcp.server.fastmcp import Context
from mcp.shared.exceptions import McpError
from mcp.types import METHOD_NOT_FOUND
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared Pydantic schemas for elicitation prompts
# ---------------------------------------------------------------------------

class DeleteConfirmation(BaseModel):
    """Schema presented to the user when a deletion is requested."""

    confirm: bool = Field(
        default=False,
        description="Set to true to confirm the deletion. This action cannot be undone.",
    )


class DeactivateConfirmation(BaseModel):
    """Schema presented to the user when a deactivation is requested."""

    confirm: bool = Field(
        default=False,
        description="Set to true to confirm the deactivation.",
    )


# ---------------------------------------------------------------------------
# Elicitation result wrapper
# ---------------------------------------------------------------------------

@dataclass
class ElicitationOutcome:
    """Normalised result of an elicitation attempt.

    Attributes:
        confirmed: ``True`` only when the user explicitly accepted AND set
                   ``confirm=True`` in the form.
        used_elicitation: ``True`` if the MCP elicitation protocol was used,
                          ``False`` if the call fell back to the legacy
                          confirmation-required response.
        fallback_response: When ``used_elicitation`` is ``False``, contains the
                           legacy JSON payload that should be returned to the
                           caller so the old two-tool flow can proceed.
    """

    confirmed: bool
    used_elicitation: bool
    fallback_response: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------

def supports_elicitation(ctx: Context) -> bool:
    """Return ``True`` if the connected MCP client advertised elicitation support."""
    try:
        session = ctx.request_context.session
        if session.client_params and session.client_params.capabilities:
            return session.client_params.capabilities.elicitation is not None
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Elicit-or-fallback helper
# ---------------------------------------------------------------------------

async def elicit_or_fallback(
    ctx: Context,
    message: str,
    schema: type[BaseModel],
    *,
    fallback_payload: dict[str, Any] | None = None,
    auto_confirm_on_fallback: bool = False,
) -> ElicitationOutcome:
    """Request user confirmation via elicitation, falling back gracefully.

    If the client supports elicitation the user is shown a structured form.
    If it does not (older client, no capability, exception), the behaviour
    depends on ``auto_confirm_on_fallback``:

    * ``False`` (default) — return the ``fallback_payload`` so the caller
      can direct the LLM to a legacy two-tool confirmation flow (e.g.
      ``confirm_delete_group``).
    * ``True`` — treat the operation as confirmed and let the caller
      proceed immediately.  This restores the pre-elicitation behaviour
      for tools that never had a separate confirmation step.

    Parameters
    ----------
    ctx:
        The tool's ``Context`` instance.
    message:
        Human-readable prompt shown to the user.
    schema:
        A Pydantic ``BaseModel`` subclass describing the form fields.
    fallback_payload:
        Optional dict to return when elicitation is not available.  If
        ``None``, a generic payload is used.  Ignored when
        ``auto_confirm_on_fallback`` is ``True``.
    auto_confirm_on_fallback:
        When ``True`` and elicitation is unavailable, the returned
        outcome has ``confirmed=True`` so the tool can proceed without
        user interaction (pre-elicitation behaviour).

    Returns
    -------
    ElicitationOutcome
    """
    if not supports_elicitation(ctx):
        if auto_confirm_on_fallback:
            logger.info("Client does not support elicitation — auto-confirming (pre-elicitation behaviour)")
            return ElicitationOutcome(confirmed=True, used_elicitation=False)
        logger.info("Client does not support elicitation — using fallback")
        return ElicitationOutcome(
            confirmed=False,
            used_elicitation=False,
            fallback_response=fallback_payload or {
                "confirmation_required": True,
                "message": message,
            },
        )

    try:
        result = await ctx.elicit(message=message, schema=schema)

        if isinstance(result, AcceptedElicitation) and result.data:
            confirmed = getattr(result.data, "confirm", False)
            logger.info(f"Elicitation accepted — confirm={confirmed}")
            return ElicitationOutcome(confirmed=confirmed, used_elicitation=True)
        elif isinstance(result, DeclinedElicitation):
            logger.info("Elicitation declined by user")
            return ElicitationOutcome(confirmed=False, used_elicitation=True)
        elif isinstance(result, CancelledElicitation):
            logger.info("Elicitation cancelled by user")
            return ElicitationOutcome(confirmed=False, used_elicitation=True)
        else:
            logger.warning(f"Elicitation returned unexpected result: {result}")
            return ElicitationOutcome(confirmed=False, used_elicitation=True)

    except McpError as exc:
        if exc.error.code == METHOD_NOT_FOUND:
            logger.info("Elicitation not supported by client (METHOD_NOT_FOUND)")
        else:
            logger.warning(f"MCP error during elicitation: {exc}")
        if auto_confirm_on_fallback:
            logger.info("Auto-confirming after MCP error (pre-elicitation behaviour)")
            return ElicitationOutcome(confirmed=True, used_elicitation=False)
        return ElicitationOutcome(
            confirmed=False,
            used_elicitation=False,
            fallback_response=fallback_payload or {
                "confirmation_required": True,
                "message": message,
            },
        )
    except Exception as exc:
        logger.warning(f"Elicitation failed ({type(exc).__name__}: {exc}) — using fallback")
        if auto_confirm_on_fallback:
            logger.info("Auto-confirming after elicitation failure (pre-elicitation behaviour)")
            return ElicitationOutcome(confirmed=True, used_elicitation=False)
        return ElicitationOutcome(
            confirmed=False,
            used_elicitation=False,
            fallback_response=fallback_payload or {
                "confirmation_required": True,
                "message": message,
            },
        )
