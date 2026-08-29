# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for get_app_saml_metadata."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.applications.applications import get_app_saml_metadata


APP_ID = "0oaSAMLAPP000001"

SAML_METADATA_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="http://www.okta.com/exk1abc">'
    '<md:IDPSSODescriptor WantAuthnRequestsSigned="false" '
    'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:KeyDescriptor use="signing">'
    '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    "<ds:X509Data><ds:X509Certificate>MIICertDATA123==</ds:X509Certificate></ds:X509Data>"
    "</ds:KeyInfo></md:KeyDescriptor>"
    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
    'Location="https://test.okta.com/app/exk1abc/sso/saml"/>'
    "</md:IDPSSODescriptor></md:EntityDescriptor>"
)


def _make_ctx():
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager()
    )
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _client_returning(body, execute_error=None):
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "GET"}, None))
    if execute_error is not None:
        executor.execute = AsyncMock(return_value=(None, None, execute_error))
    else:
        executor.execute = AsyncMock(return_value=(MagicMock(), body, None))
    client = MagicMock()
    client.get_request_executor = MagicMock(return_value=executor)
    return client, executor


class TestGetAppSamlMetadata:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_returns_raw_xml_and_parsed_fields(self, mock_get_client):
        client, executor = _client_returning(SAML_METADATA_XML)
        mock_get_client.return_value = client

        result = await get_app_saml_metadata(ctx=_make_ctx(), app_id=APP_ID)

        assert result["metadata_xml"] == SAML_METADATA_XML
        assert result["entity_id"] == "http://www.okta.com/exk1abc"
        assert result["sso_url"] == "https://test.okta.com/app/exk1abc/sso/saml"
        assert result["x509_certificate"] == "MIICertDATA123=="

        create_kwargs = executor.create_request.call_args.kwargs
        assert create_kwargs["method"] == "GET"
        assert create_kwargs["url"].endswith(f"/api/v1/apps/{APP_ID}/sso/saml/metadata")

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_returned(self, mock_get_client):
        client, _ = _client_returning(None, execute_error="Error: 404 not found")
        mock_get_client.return_value = client

        result = await get_app_saml_metadata(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"error": "Error: 404 not found"}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_unparseable_xml_still_returns_raw(self, mock_get_client):
        client, _ = _client_returning("this is not xml")
        mock_get_client.return_value = client

        result = await get_app_saml_metadata(ctx=_make_ctx(), app_id=APP_ID)

        assert result["metadata_xml"] == "this is not xml"
        assert "parse_error" in result
