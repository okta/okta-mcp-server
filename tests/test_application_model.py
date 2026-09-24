# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for _build_application_model — nested model fields must survive serialization."""

from __future__ import annotations

import okta.models as okta_models

from okta_mcp_server.tools.applications.applications import _build_application_model


def _saml_config_with_attributes():
    return {
        "label": "Attr Test SAML",
        "name": "attrtestsaml",
        "signOnMode": "SAML_2_0",
        "settings": {
            "signOn": {
                "ssoAcsUrl": "https://sp.example.com/acs",
                "audience": "sp-entity-id",
                "recipient": "https://sp.example.com/acs",
                "destination": "https://sp.example.com/acs",
                "subjectNameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "subjectNameIdTemplate": "${user.userName}",
                "allowMultipleAcsEndpoints": False,
                "assertionSigned": True,
                "authnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                "digestAlgorithm": "SHA256",
                "honorForceAuthn": True,
                "idpIssuer": "http://www.okta.com/${org.externalKey}",
                "requestCompressed": False,
                "responseSigned": True,
                "signatureAlgorithm": "RSA_SHA256",
                "attributeStatements": [
                    {
                        "type": "EXPRESSION",
                        "name": "email",
                        "namespace": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
                        "values": ["user.email"],
                    },
                    {
                        "type": "EXPRESSION",
                        "name": "firstName",
                        "namespace": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
                        "values": ["user.firstName"],
                    },
                ],
            }
        },
    }


class TestBuildApplicationModel:
    def test_saml_attribute_statements_survive_serialization(self):
        model = _build_application_model(_saml_config_with_attributes())
        assert isinstance(model, okta_models.SamlApplication)

        statements = model.to_dict()["settings"]["signOn"]["attributeStatements"]
        # Pre-fix (Model(**dict)) left these as [null, null]; the union members
        # must now be bound and round-trip with their full content.
        assert len(statements) == 2
        assert all(s is not None for s in statements)
        assert [s["name"] for s in statements] == ["email", "firstName"]
        assert statements[0]["type"] == "EXPRESSION"
        assert statements[0]["values"] == ["user.email"]

    def test_builds_correct_subclass_per_sign_on_mode(self):
        bookmark = _build_application_model(
            {"label": "B", "name": "bookmark", "signOnMode": "BOOKMARK",
             "settings": {"app": {"url": "https://example.com"}}}
        )
        assert isinstance(bookmark, okta_models.BookmarkApplication)
        assert bookmark.settings.app.url == "https://example.com"
