# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for okta_mcp_server.utils.serialization"""

import json
from enum import Enum

import pytest

from okta_mcp_server.utils.serialization import serialize


# ---------------------------------------------------------------------------
# Mock SDK objects (simulating Okta SDK model behavior)
# ---------------------------------------------------------------------------


class MockSignOnMode(Enum):
    SAML_2_0 = "SAML_2_0"
    OPENID_CONNECT = "OPENID_CONNECT"
    BROWSER_PLUGIN = "BROWSER_PLUGIN"


class MockUserStatus(Enum):
    ACTIVE = "ACTIVE"
    LOCKED_OUT = "LOCKED_OUT"
    DEPROVISIONED = "DEPROVISIONED"


class MockProfile:
    """Simulates an Okta user/app profile object."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class MockApplication:
    """Simulates an Okta Application SDK object."""

    def __init__(self):
        self.id = "0oa1abc123"
        self.name = "My SAML App"
        self.label = "My SAML App"
        self.status = MockUserStatus.ACTIVE
        self.sign_on_mode = MockSignOnMode.SAML_2_0
        self._links = {"self": "https://dev.okta.com/api/v1/apps/0oa1abc123"}
        self._private_internal = "should be hidden"


class MockApplicationWithAsDict:
    """Simulates an Okta object that has .as_dict()."""

    def __init__(self):
        self.id = "0oa1abc123"
        self._internal = "hidden"

    def as_dict(self):
        return {
            "id": self.id,
            "name": "App via as_dict",
            "signOnMode": "SAML_2_0",
        }


class MockUser:
    """Simulates an Okta User SDK object."""

    def __init__(self):
        self.id = "00u1xyz789"
        self.status = MockUserStatus.ACTIVE
        self.profile = MockProfile(
            email="user@example.com",
            firstName="John",
            lastName="Doe",
            login="user@example.com",
        )
        self._embedded = {"some": "data"}


class MockOktaAPIResponse:
    """Simulates the raw OktaAPIResponse object that has no useful serialization."""

    def __init__(self):
        self._url = "https://dev.okta.com/api/v1/users"
        self._status = 200
        self._headers = {}


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


class TestSerializePrimitives:
    def test_none(self):
        assert serialize(None) is None

    def test_string(self):
        assert serialize("hello") == "hello"

    def test_int(self):
        assert serialize(42) == 42

    def test_float(self):
        assert serialize(3.14) == 3.14

    def test_bool(self):
        assert serialize(True) is True
        assert serialize(False) is False


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestSerializeEnums:
    def test_enum_value(self):
        assert serialize(MockSignOnMode.SAML_2_0) == "SAML_2_0"

    def test_enum_in_dict(self):
        result = serialize({"mode": MockSignOnMode.OPENID_CONNECT})
        assert result == {"mode": "OPENID_CONNECT"}

    def test_enum_in_list(self):
        result = serialize([MockUserStatus.ACTIVE, MockUserStatus.LOCKED_OUT])
        assert result == ["ACTIVE", "LOCKED_OUT"]


# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------


class TestSerializeCollections:
    def test_dict(self):
        result = serialize({"a": 1, "b": "two"})
        assert result == {"a": 1, "b": "two"}

    def test_nested_dict(self):
        result = serialize({"outer": {"inner": "value"}})
        assert result == {"outer": {"inner": "value"}}

    def test_list(self):
        result = serialize([1, "two", 3.0])
        assert result == [1, "two", 3.0]

    def test_tuple_converted_to_list(self):
        result = serialize(("a", "b", "c"))
        assert result == ["a", "b", "c"]

    def test_empty_dict(self):
        assert serialize({}) == {}

    def test_empty_list(self):
        assert serialize([]) == []


# ---------------------------------------------------------------------------
# SDK objects
# ---------------------------------------------------------------------------


class TestSerializeSDKObjects:
    def test_application_with_enums(self):
        app = MockApplication()
        result = serialize(app)
        assert isinstance(result, dict)
        assert result["id"] == "0oa1abc123"
        assert result["status"] == "ACTIVE"
        assert result["sign_on_mode"] == "SAML_2_0"
        # Private attributes should be excluded
        assert "_links" not in result
        assert "_private_internal" not in result

    def test_user_with_nested_profile(self):
        user = MockUser()
        result = serialize(user)
        assert isinstance(result, dict)
        assert result["id"] == "00u1xyz789"
        assert result["status"] == "ACTIVE"
        assert isinstance(result["profile"], dict)
        assert result["profile"]["email"] == "user@example.com"
        assert result["profile"]["firstName"] == "John"

    def test_as_dict_preferred(self):
        app = MockApplicationWithAsDict()
        result = serialize(app)
        assert isinstance(result, dict)
        assert result["id"] == "0oa1abc123"
        assert result["name"] == "App via as_dict"

    def test_api_response_object_fallback(self):
        resp = MockOktaAPIResponse()
        result = serialize(resp)
        # All attrs are private, so __dict__ produces empty dict,
        # fallback to str
        assert isinstance(result, str)

    def test_list_of_sdk_objects(self):
        users = [MockUser(), MockUser()]
        result = serialize(users)
        assert isinstance(result, list)
        assert len(result) == 2
        assert all(isinstance(u, dict) for u in result)
        assert result[0]["id"] == "00u1xyz789"


# ---------------------------------------------------------------------------
# JSON-safe validation
# ---------------------------------------------------------------------------


class TestJSONSafe:
    def test_application_is_json_serializable(self):
        app = MockApplication()
        result = serialize(app)
        # Should not raise
        json_str = json.dumps(result)
        assert isinstance(json_str, str)

    def test_user_is_json_serializable(self):
        user = MockUser()
        result = serialize(user)
        json_str = json.dumps(result)
        assert isinstance(json_str, str)

    def test_list_of_users_is_json_serializable(self):
        users = [MockUser(), MockUser()]
        result = serialize(users)
        json_str = json.dumps(result)
        parsed = json.loads(json_str)
        assert len(parsed) == 2

    def test_tuple_items_are_json_serializable(self):
        """Tuples (the old list_users format) should become JSON arrays."""
        old_format = (
            MockProfile(email="a@b.com", firstName="A"),
            "00u123",
        )
        result = serialize(old_format)
        json_str = json.dumps(result)
        assert isinstance(json_str, str)

    def test_complex_nested_structure(self):
        data = {
            "user": MockUser(),
            "apps": [MockApplication()],
            "status": MockUserStatus.ACTIVE,
            "metadata": {"count": 1, "mode": MockSignOnMode.SAML_2_0},
        }
        result = serialize(data)
        json_str = json.dumps(result)
        parsed = json.loads(json_str)
        assert parsed["status"] == "ACTIVE"
        assert parsed["metadata"]["mode"] == "SAML_2_0"
