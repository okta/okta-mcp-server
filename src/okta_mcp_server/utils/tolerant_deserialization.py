# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Per-item tolerance for Okta SDK **list** responses.

Why this exists
---------------
:mod:`okta_mcp_server.utils.okta_compat` fixes four *known* over-strict models,
but those models live inside a pinned dependency generated from a spec that keeps
drifting; the next attribute Okta adds will break deserialization again.  For
audit and inventory work — "list every app in the tenant" — partial results with
an explicit warning are strictly more useful than a hard failure that returns
nothing at all.

Where it hooks in
-----------------
``okta/api_client.py`` maps a 200 response to a type string such as
``"List[Application]"`` and expands it with::

    return [self.__deserialize(sub_data, sub_kls) for sub_data in data]

There is no per-element guard, so one bad record aborts the whole page.  This
module replaces ``ApiClient``'s name-mangled ``_ApiClient__deserialize`` with a
wrapper that, for ``List[...]`` targets, parses each element in its own
``try``/``except``.  Assigning to the mangled attribute is sufficient: the SDK's
internal ``self.__deserialize(...)`` calls compile to
``self._ApiClient__deserialize(...)`` and therefore resolve to the replacement.

Hooking the SDK's own deserialization seam — rather than bypassing the typed
client and re-issuing raw requests — means we do not have to re-implement the
SDK's snake_case→camelCase query-parameter mapping, and the tolerance
generalizes to policies, policy rules, groups and users rather than only apps.

Scope: **list responses only**
------------------------------
Single-object endpoints (``get_application``, ``get_policy``,
``get_policy_rule``) are deliberately **not** made tolerant.  There is no partial
result to salvage from a single object — dropping it would turn a hard error into
a silent ``None`` — and those paths are already covered by the targeted model
patches in :mod:`okta_mcp_server.utils.okta_compat`.

Warnings and redaction
----------------------
Failures are collected in a :class:`contextvars.ContextVar`, so they are
async-safe and scoped per request rather than shared process-wide.  Each entry
carries the target model name, a compact rendering of the validation error, and
the item's **raw payload dict**.

That raw payload is real tenant data in production.  It is surfaced to the
operator through the tool's JSON result — which is the point — but it is **never**
written to the logs at INFO or above: the log line emitted on a drop names only
the model and the error summary, and the payload appears solely in DEBUG output.

Strict mode
-----------
Set ``OKTA_MCP_STRICT_DESERIALIZATION`` to ``1``/``true``/``yes``
(case-insensitive) to disable tolerance entirely and let ``ValidationError``
propagate exactly as it does without this module.  The flag is read at call time,
not import time.
"""

from __future__ import annotations

import contextvars
import os
import re
from typing import Any, Callable, Dict, List, Optional

from loguru import logger
from pydantic import ValidationError

__all__ = [
    "STRICT_ENV_VAR",
    "get_deserialization_warnings",
    "install_tolerant_deserialization",
    "reset_deserialization_warnings",
    "strict_deserialization_enabled",
]


#: Environment variable that restores the SDK's original hard-fail behavior.
STRICT_ENV_VAR = "OKTA_MCP_STRICT_DESERIALIZATION"

#: Maximum characters of ``str(exc)`` kept in a warning entry.
_ERROR_SUMMARY_LIMIT = 512

#: Matches the SDK's own ``List[...]`` response-type spelling.
_LIST_TYPE_RE = re.compile(r"^List\[(.*)]$")

#: Per-request collection of dropped items.  ``None`` means "nothing collected
#: in this context yet"; the list is created lazily so the ContextVar never
#: shares a mutable default across contexts.
_warnings: contextvars.ContextVar[Optional[List[Dict[str, Any]]]] = contextvars.ContextVar(
    "okta_mcp_deserialization_warnings", default=None
)

#: Set once :func:`install_tolerant_deserialization` has patched ``ApiClient``.
_installed = False


def strict_deserialization_enabled() -> bool:
    """Return True when the operator has opted out of per-item tolerance.

    Truthy values: ``1``, ``true``, ``yes`` (case-insensitive).  Read on every
    call rather than cached at import, so tests and operators can toggle it.
    """
    return os.environ.get(STRICT_ENV_VAR, "").strip().lower() in {"1", "true", "yes"}


def reset_deserialization_warnings() -> None:
    """Start a fresh, empty warning collection for the current context.

    Called by :func:`okta_mcp_server.utils.serialization.json_response` before it
    invokes a tool, so warnings never leak between requests.
    """
    _warnings.set([])


def get_deserialization_warnings() -> List[Dict[str, Any]]:
    """Return a copy of the warnings collected in the current context."""
    collected = _warnings.get()
    return list(collected) if collected else []


def _record_warning(model_name: str, exc: BaseException, payload: Any) -> None:
    """Record one dropped item, and log it **without** the raw payload above DEBUG."""
    summary = str(exc).replace("\n", " ")[:_ERROR_SUMMARY_LIMIT]
    entry: Dict[str, Any] = {
        "type": "deserialization_error",
        "model": model_name,
        "error": summary,
        "message": (
            f"An item of type {model_name!r} returned by Okta did not match the SDK's "
            f"model and was omitted from the results. The raw payload is included "
            f"under 'raw_item'."
        ),
        "raw_item": payload,
    }
    collected = _warnings.get()
    if collected is None:
        collected = []
        _warnings.set(collected)
    collected.append(entry)

    # The raw payload is real tenant data — DEBUG only, never INFO or above.
    logger.warning(f"[tolerant_deserialization] dropped one {model_name}: {summary}")
    logger.debug(f"[tolerant_deserialization] dropped {model_name} raw payload: {payload!r}")


def install_tolerant_deserialization() -> bool:
    """Patch ``okta.api_client.ApiClient`` for per-item list tolerance.

    Idempotent: a second call is a no-op and returns ``False``.  Returns ``True``
    when the patch was installed by this call.

    Called at the top of :mod:`okta_mcp_server.server` alongside
    :func:`okta_mcp_server.utils.okta_compat.apply_okta_model_compat`.
    """
    global _installed
    if _installed:
        return False

    try:
        from okta.api_client import ApiClient
    except ImportError as exc:  # pragma: no cover — SDK is a hard dependency
        logger.warning(f"[tolerant_deserialization] okta.api_client unavailable: {exc}")
        return False

    original: Optional[Callable] = getattr(ApiClient, "_ApiClient__deserialize", None)
    if original is None:  # pragma: no cover — future SDK renamed the method
        logger.warning(
            "[tolerant_deserialization] ApiClient.__deserialize not found; "
            "list responses keep the SDK's all-or-nothing behavior"
        )
        return False

    def tolerant_deserialize(self, data, klass):
        """Deserialize ``data`` as ``klass``, dropping unparseable list elements.

        Signature intentionally mirrors the SDK's own ``__deserialize`` — it is
        installed in its place and must accept the same positional arguments.

        Only ``List[...]`` targets are handled specially; everything else is
        delegated to the SDK implementation untouched, which keeps single-object
        endpoints strict.
        """
        if (
            not strict_deserialization_enabled()
            and isinstance(klass, str)
            and isinstance(data, list)
        ):
            match = _LIST_TYPE_RE.match(klass)
            if match is not None:
                sub_kls = match.group(1)
                parsed: List[Any] = []
                for item in data:
                    try:
                        parsed.append(original(self, item, sub_kls))
                    # ValidationError subclasses ValueError in Pydantic v2, but both
                    # are named: the SDK's own ``from_dict`` raises a bare ValueError
                    # for a payload it cannot route (e.g. an unrecognized subtype
                    # discriminator), and that is equally a per-item problem.
                    except (ValidationError, ValueError) as exc:
                        _record_warning(sub_kls, exc, item)
                return parsed

        return original(self, data, klass)

    ApiClient._ApiClient__deserialize = tolerant_deserialize
    _installed = True
    logger.debug("[tolerant_deserialization] installed per-item tolerance on ApiClient")
    return True
