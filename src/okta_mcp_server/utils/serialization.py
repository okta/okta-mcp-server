# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Serialization utilities for converting Okta SDK objects to JSON-safe dicts.

The Okta SDK returns objects that are not JSON-serializable:
- Enum values render as ``<ApplicationSignOnMode.SAML_2_0: 'SAML_2_0'>``
- ``OktaAPIResponse`` objects render as ``<okta.api_response... at 0x...>``
- Some objects expose ``.as_dict()`` while others only have ``.__dict__``

This module provides a single ``serialize`` function that handles all cases
and returns clean JSON-serializable Python dicts/lists.
"""

from enum import Enum
from typing import Any


def serialize(obj: Any) -> Any:
    """Convert an Okta SDK object to a JSON-serializable value.

    Handles SDK model objects, enums, nested structures, and edge cases.
    Returns plain dicts, lists, strings, numbers, booleans, and None.

    Args:
        obj: Any value returned by the Okta SDK.

    Returns:
        A JSON-serializable Python value.
    """
    if obj is None:
        return None

    # Primitives pass through
    if isinstance(obj, (str, int, float, bool)):
        return obj

    # Enums → their string value
    if isinstance(obj, Enum):
        return obj.value

    # Dicts → recurse on values
    if isinstance(obj, dict):
        return {str(k): serialize(v) for k, v in obj.items()}

    # Lists/tuples → recurse on elements
    if isinstance(obj, (list, tuple)):
        return [serialize(item) for item in obj]

    # SDK objects with .as_dict()
    if hasattr(obj, "as_dict"):
        try:
            return serialize(obj.as_dict())
        except Exception:
            pass

    # Objects with __dict__ (SDK model instances)
    if hasattr(obj, "__dict__"):
        result = {}
        for key, value in obj.__dict__.items():
            # Skip private/internal attributes
            if key.startswith("_"):
                continue
            result[key] = serialize(value)
        if result:
            return result

    # Fallback: string representation
    return str(obj)
