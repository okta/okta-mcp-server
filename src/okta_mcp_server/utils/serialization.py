# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Canonical JSON-response serialization for the Okta MCP Server.

This module provides the single boundary that converts every tool return value
into a JSON-native tree before FastMCP populates ``content[].text``.  It exists
because the Okta Python SDK returns Pydantic v2 models, ``OktaAPIResponse``
transport objects, and ``Enum`` values, none of which FastMCP can serialize
without falling back to ``repr()`` / ``str()`` (see issue #14).

Public surface
--------------
* :func:`to_jsonable` — recursive normalizer producing only JSON-native types
  (``dict | list | str | int | float | bool | None``).  Output is guaranteed
  to satisfy RFC 8259; datetimes are emitted as RFC 3339 strings via Pydantic's
  ``model_dump(mode="json")`` path.
* :func:`json_response` — innermost decorator for every ``@mcp.tool``.  Wraps
  the tool's return through :func:`to_jsonable` and, on serializer failure,
  returns a structured error envelope built from primitives only.

Design properties
-----------------
* **Single chokepoint.**  One module, one decorator — consistent across all tools.
* **Idempotent.**  Re-serializing an already-JSON tree is a no-op, so the
  decorator is safe to add to tools that already call ``.to_dict()`` /
  ``.model_dump(...)`` during the migration window.
* **Fail-safe.**  If :func:`to_jsonable` raises, the decorator returns the
  envelope defined in :func:`_failure_envelope`, never an opaque SDK object.
"""

import functools
import inspect
import os
import traceback
from enum import Enum
from typing import Any, Callable

from loguru import logger


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

#: Maximum number of characters from str(exc) preserved in the failure envelope.
_ERROR_MESSAGE_LIMIT = 1024

#: Maximum number of characters from the traceback preserved in the envelope.
_TRACEBACK_TAIL_LIMIT = 4096

#: Opt-in environment flag that lets operators re-enable the raw traceback tail
#: in the failure envelope.  Off by default so we never leak server-side stack
#: frames to MCP clients unless the operator explicitly asks for them.
#:
#: NOTE: This flag name is deliberately reused from the deferred "raw success
#: envelope" feature described in ``docs/hld_mcp_serialization.txt:341``.  Both
#: modes share a single "verbose diagnostic mode" semantics — operators who
#: want raw success wrapping will also want raw failure tracebacks and vice
#: versa.  If the deferred success-wrapping feature ever lands, it MUST also
#: read this same variable so both behaviors stay in lock-step.
_INCLUDE_RAW_ENV_VAR = "OKTA_MCP_INCLUDE_RAW"


def _include_raw_traceback() -> bool:
    """Return True when the operator has opted in to raw traceback exposure.

    Truthy values: ``1``, ``true``, ``yes``, ``on`` (case-insensitive).  Any
    other value (including unset) evaluates to False.
    """
    val = os.environ.get(_INCLUDE_RAW_ENV_VAR, "").strip().lower()
    return val in {"1", "true", "yes", "on"}

#: Safety bound on recursion depth.  Okta payloads nest no deeper than ~10 in
#: practice; this guard exists only to short-circuit accidental cycles that
#: slip past the standard ``id`` check below.
_MAX_DEPTH = 64


# ---------------------------------------------------------------------------
# Core serializer
# ---------------------------------------------------------------------------

def to_jsonable(obj: Any) -> Any:
    """Convert ``obj`` into a JSON-native tree.

    The output is restricted to ``dict | list | str | int | float | bool | None``
    so that ``json.dumps`` cannot fail on the result.  Conversion rules, in
    priority order:

    1. JSON-native scalars are returned as-is.
    2. ``Enum`` values are unwrapped to ``.value``.
    3. Pydantic v2 models are flattened via
       ``model_dump(by_alias=True, exclude_none=True, mode="json")`` so that
       camelCase keys, datetime → RFC 3339 strings, and ``UUID`` → string
       conversions are applied at the source.
    4. Okta SDK v2 models exposing ``to_dict()`` are flattened via that method.
    5. ``OktaAPIResponse`` (and any class whose name ends with ``ApiResponse``
       and that carries a ``headers`` attribute) is dropped to ``None``; the
       transport object is never useful to MCP callers.
    6. ``dict`` / ``list`` / ``tuple`` / ``set`` / ``frozenset`` are recursed
       element-wise.
    7. Objects exposing ``__dict__`` are flattened via ``vars(obj)`` and recursed.
    8. Anything else falls through to ``str(obj)`` and is logged at DEBUG so
       unexpected types surface during development.

    Types not explicitly handled (``bytes``, ``bytearray``, ``memoryview``,
    ``decimal.Decimal``, ``pathlib.Path``, ``datetime`` at the top level,
    etc.) fall through rule 8 to ``str(obj)`` — lossy but guaranteed
    JSON-serialisable.  Add an explicit branch here if a tool ever needs one
    of those types round-tripped losslessly.

    Args:
        obj: Any Python value coming back from a tool body.

    Returns:
        A JSON-native tree suitable for ``json.dumps``.
    """
    return _to_jsonable(obj, depth=0, seen=set())


def _to_jsonable(obj: Any, depth: int, seen: set) -> Any:
    """Recursive worker for :func:`to_jsonable`.

    ``seen`` tracks ``id(obj)`` for container objects so self-referential
    structures are short-circuited rather than recursed indefinitely.
    """
    if depth > _MAX_DEPTH:
        logger.debug(f"to_jsonable: max depth {_MAX_DEPTH} exceeded for {type(obj).__name__}")
        return str(obj)

    # 1. Enum -> .value (recurse so IntEnum / StrEnum / (str, Enum) mixins stay
    #    correct).  Must precede the scalar passthrough below because
    #    ``(str, Enum)`` classes (e.g. the Okta SDK's ``ApplicationSignOnMode``)
    #    satisfy ``isinstance(x, str)`` yet still carry the enum ``__str__`` /
    #    ``__repr__`` that leak Python object descriptions to any consumer
    #    that does not use ``json.dumps``' str-subclass fast path.
    if isinstance(obj, Enum):
        return _to_jsonable(obj.value, depth + 1, seen)

    # 2. JSON-native scalars
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # 3. Transport objects — drop before model_dump branches, since
    #    OktaAPIResponse exposes neither model_dump nor to_dict.
    if _is_transport_response(obj):
        return None

    # 4. Pydantic v2 model.  We accept the result only if it is dict/list-shaped;
    #    otherwise the attribute is a coincidence (e.g. an auto-generated Mock)
    #    and we fall through to the next strategy rather than recursing on
    #    another opaque object.
    model_dump = getattr(obj, "model_dump", None)
    if callable(model_dump):
        try:
            dumped = model_dump(by_alias=True, exclude_none=True, mode="json")
        except Exception as exc:  # noqa: BLE001 — boundary safeguard
            logger.warning(f"to_jsonable: model_dump failed on {type(obj).__name__}: {exc}")
            raise
        if isinstance(dumped, (dict, list)):
            return _to_jsonable(dumped, depth + 1, seen)

    # 5. Okta SDK v2 model with to_dict().  Same dict/list-shape guard as above.
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        try:
            dumped = to_dict()
        except Exception as exc:  # noqa: BLE001 — boundary safeguard
            logger.warning(f"to_jsonable: to_dict failed on {type(obj).__name__}: {exc}")
            raise
        if isinstance(dumped, (dict, list)):
            return _to_jsonable(dumped, depth + 1, seen)

    # 6. Defensive short-circuit for unittest.mock objects: every attribute
    #    access lazily mutates their ``__dict__``, which both poisons the
    #    ``vars()`` fallback ("dictionary changed size during iteration") and
    #    makes any attribute look callable.  Tools never legitimately return
    #    Mocks in production; emitting ``str(obj)`` keeps tests deterministic.
    #    We run this check *after* the model_dump / to_dict branches above so a
    #    caller that explicitly configures ``mock.to_dict.return_value`` still
    #    gets the configured dict flattened by the normal path.
    if type(obj).__module__ == "unittest.mock":
        return str(obj)

    # 7. Containers (cycle-guarded)
    obj_id = id(obj)
    if isinstance(obj, dict):
        if obj_id in seen:
            return None
        seen.add(obj_id)
        try:
            return {str(k): _to_jsonable(v, depth + 1, seen) for k, v in obj.items()}
        finally:
            seen.discard(obj_id)

    if isinstance(obj, (list, tuple, set, frozenset)):
        if obj_id in seen:
            return None
        seen.add(obj_id)
        try:
            return [_to_jsonable(v, depth + 1, seen) for v in obj]
        finally:
            seen.discard(obj_id)

    # 8. Plain object with attributes
    if hasattr(obj, "__dict__"):
        if obj_id in seen:
            return None
        seen.add(obj_id)
        try:
            return _to_jsonable(vars(obj), depth + 1, seen)
        finally:
            seen.discard(obj_id)

    # 9. Last resort
    logger.debug(f"to_jsonable: falling back to str() for {type(obj).__name__}")
    return str(obj)


def _is_transport_response(obj: Any) -> bool:
    """Return True if ``obj`` is an Okta SDK transport response.

    Covers Okta Python SDK v2 (``OktaAPIResponse``) and the v3 duck-typed
    ``ApiResponse`` family.  Detection is intentionally narrow: the class name
    must end with ``APIResponse`` / ``ApiResponse`` *and* the object must
    expose a ``headers`` or ``has_next`` attribute, so we never drop a
    domain model that happens to share a suffix.
    """
    cls_name = type(obj).__name__
    if not (cls_name.endswith("APIResponse") or cls_name.endswith("ApiResponse")):
        return False
    return hasattr(obj, "headers") or hasattr(obj, "has_next")


# ---------------------------------------------------------------------------
# Failure envelope
# ---------------------------------------------------------------------------

def _failure_envelope(tool_name: str, exc: BaseException) -> dict:
    """Build the structured error envelope returned when serialization fails.

    Every field is a JSON-native primitive, so ``json.dumps`` on the envelope
    cannot itself raise.  The raw traceback tail is intentionally **not**
    included by default so we do not leak server-side stack frames to MCP
    clients.  Operators can opt back in by setting the ``OKTA_MCP_INCLUDE_RAW``
    environment variable (see :func:`_include_raw_traceback`); in that mode the
    ``raw.traceback_tail`` field carries the last ``_TRACEBACK_TAIL_LIMIT``
    characters of ``traceback.format_exc()``.  The full traceback is always
    written to the server log via ``logger.exception`` regardless of the flag.
    """
    envelope = {
        "ok": False,
        "error": {
            "type": exc.__class__.__name__,
            "message": str(exc)[:_ERROR_MESSAGE_LIMIT],
            "tool": tool_name,
        },
        "status_code": None,
        "raw": {},
    }
    if _include_raw_traceback():
        envelope["raw"]["traceback_tail"] = traceback.format_exc()[-_TRACEBACK_TAIL_LIMIT:]
    return envelope


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def json_response(fn: Callable) -> Callable:
    """Wrap ``fn`` so its return value is serialized through :func:`to_jsonable`.

    Place this decorator innermost — directly above ``async def`` and below
    ``@validate_ids(...)``.  Outer wrappers (``@require_scopes``,
    ``@validate_ids``) then only ever observe JSON-native data.

    Behavior:
      * Success → ``to_jsonable(result)`` is returned.
      * Serializer failure → :func:`_failure_envelope` is returned and the
        full traceback is logged via ``logger.exception``.

    Both async and sync functions are supported; the wrapper preserves
    ``__name__`` / ``__doc__`` via :func:`functools.wraps`.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            try:
                return to_jsonable(await fn(*args, **kwargs))
            except Exception as exc:  # noqa: BLE001 — boundary safeguard
                logger.exception(f"[json_response] {fn.__name__} failed to serialize response")
                return _failure_envelope(fn.__name__, exc)

        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args, **kwargs):
        try:
            return to_jsonable(fn(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001 — boundary safeguard
            logger.exception(f"[json_response] {fn.__name__} failed to serialize response")
            return _failure_envelope(fn.__name__, exc)

    return sync_wrapper
