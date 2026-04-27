# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Custom Email Templates tools for the Okta MCP server.

Custom Email Templates let you localise and brand every transactional email
Okta sends to your users.  Each template (e.g. ``UserActivation``,
``ForgotPassword``) can have up to one customization per IETF BCP 47 language
tag.  Exactly one customization per template must be marked ``isDefault=True``
when any exist.  Customizations that include required template variables
(such as ``${activationLink}``) are validated server-side on write.

This module exposes MCP tools for every operation in the Custom Email
Templates API:

Templates (read-only):
    - list_email_templates                 GET  /api/v1/brands/{brandId}/templates/email
    - get_email_template                   GET  /api/v1/brands/{brandId}/templates/email/{templateName}

Customizations (CRUD):
    - list_email_customizations            GET    /…/templates/email/{templateName}/customizations
    - create_email_customization           POST   /…/templates/email/{templateName}/customizations
    - get_email_customization              GET    /…/templates/email/{templateName}/customizations/{id}
    - replace_email_customization          PUT    /…/templates/email/{templateName}/customizations/{id}
    - delete_email_customization           DELETE /…/templates/email/{templateName}/customizations/{id}
    - delete_all_email_customizations      DELETE /…/templates/email/{templateName}/customizations

Preview:
    - get_email_customization_preview      GET    /…/customizations/{id}/preview

Default content:
    - get_email_default_content            GET    /…/templates/email/{templateName}/default-content
    - get_email_default_content_preview    GET    /…/templates/email/{templateName}/default-content/preview

Settings:
    - get_email_settings                   GET    /…/templates/email/{templateName}/settings
    - replace_email_settings               PUT    /…/templates/email/{templateName}/settings

Test:
    - send_test_email                      POST   /…/templates/email/{templateName}/test

Notes:
    - ``template_name`` must be an exact Okta template name, e.g.
      ``"UserActivation"``, ``"ForgotPassword"``, ``"PasswordResetByAdmin"``.
    - ``language`` must be a valid IETF BCP 47 tag, e.g. ``"en"``, ``"fr"``,
      ``"de"``, ``"es"``.
    - ``expand`` for list/get template accepts ``"settings"`` and/or
      ``"customizationCount"``.
    - ``recipients`` for settings accepts ``"ALL_USERS"``, ``"ADMINS_ONLY"``,
      or ``"NO_USERS"``.
    - The two delete operations (single and all) require explicit confirmation.
    - ``send_test_email`` sends a preview email to the current API user and
      returns no content (success is indicated by the absence of an error).
"""

from typing import Any, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import Context
from okta.models.email_customization import EmailCustomization
from okta.models.email_settings import EmailSettings

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import (
    DELETE_ALL_EMAIL_CUSTOMIZATIONS,
    DELETE_EMAIL_CUSTOMIZATION,
)
from okta_mcp_server.utils.validation import validate_ids


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _serialize(obj) -> Any:
    """Recursively serialise SDK v3 models and lists to plain Python types.

    We explicitly use ``model_dump`` (Pydantic v2) rather than ``to_dict``.
    The SDK-generated ``to_dict`` on preview models (e.g. ``EmailPreview``)
    marks ``body`` and ``subject`` as server-readOnly and omits them from the
    output, so calling it would silently return ``{}`` or just ``_links``.
    ``model_dump`` does not apply that exclusion and is therefore the correct
    serialisation path for response objects.

    ``mode='json'`` is required to ensure that any SDK enum values nested
    inside ``_links`` (e.g. ``HttpMethod.GET``) are serialised to their
    primitive string equivalents (e.g. ``"GET"``) rather than left as Python
    enum instances, which would cause JSON serialisation to fail downstream
    and result in an empty ``{}`` being returned to the caller.
    """
    if obj is None:
        return None
    if isinstance(obj, list):
        return [_serialize(item) for item in obj]
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump(by_alias=True, exclude_none=True, mode="json")
        except Exception:
            logger.debug(f"model_dump failed for {type(obj).__name__}, falling back to __dict__")
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items() if not k.startswith("_") and v is not None}
    return obj


# ---------------------------------------------------------------------------
# Internal helper — no-content response validation
# ---------------------------------------------------------------------------

def _check_no_content_response(result) -> Optional[str]:
    """Validate SDK results for operations that return no body on success (HTTP 204).

    The Okta Python SDK has a bug in ``send_test_email``,
    ``delete_email_customization``, and ``delete_all_customizations``: it checks
    ``if response_body == "" or response.status == 204:`` *before* examining the
    error produced by ``check_response_for_error``.  Any response with an empty
    body — including a 401 Unauthorized when the Bearer token is an SSWS token
    used incorrectly — causes the SDK to discard the error and return
    ``(None, ApiResponse(status=401), None)``.  The last element (``err``) is
    ``None`` even though the call failed, so a plain ``if result[-1]:`` check
    silently treats the failure as success.

    This helper inspects **both** ``result[-1]`` (the SDK error field) and
    ``result[1].status_code`` (the raw HTTP status) to catch empty-body failures.

    Returns:
        ``None`` when the call truly succeeded (2xx, no SDK error).
        An error string describing the failure otherwise.
    """
    err = result[-1]
    if err:
        return str(err)
    if len(result) > 1:
        api_resp = result[1]
        if hasattr(api_resp, "status_code") and not (200 <= api_resp.status_code <= 299):
            return (
                f"Okta returned HTTP {api_resp.status_code}. "
                "The Bearer token may be expired or invalid — please re-authenticate and retry."
            )
    return None


# ---------------------------------------------------------------------------
# Templates — list & get
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def list_email_templates(
    ctx: Context,
    brand_id: str,
    expand: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """List all email templates for a brand.

    Returns every Okta-managed email template available on the brand.  By
    default each entry contains only the template ``name`` and ``_links``.
    Use ``expand`` to embed additional metadata inline.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        expand (List[str], optional): Additional metadata to embed in each
            template object.  Valid values: ``"settings"`` (embed the
            recipients setting) and ``"customizationCount"`` (embed the
            number of active customizations).

    Returns:
        List of template dicts.  Each dict contains at minimum ``name`` and
        ``_links``; when expanded, also ``_embedded`` with the requested data.
        Returns a dict with an ``error`` key on failure.
    """
    logger.info(f"Listing email templates for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        templates, _, err = await client.list_email_templates(brand_id, expand=expand)

        if err:
            logger.error(f"Okta API error listing email templates for brand {brand_id}: {err}")
            return {"error": str(err)}

        result = _serialize(templates) or []
        logger.info(f"Successfully listed {len(result)} email templates for brand: {brand_id}")
        return result

    except Exception as e:
        logger.error(f"Exception listing email templates for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def get_email_template(
    ctx: Context,
    brand_id: str,
    template_name: str,
    expand: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Retrieve a single email template for a brand.

    Returns the named Okta email template with its navigation links.  Pass
    ``expand`` to embed settings or customization count inline.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``, ``"ForgotPassword"``,
            ``"PasswordResetByAdmin"``.
        expand (List[str], optional): Additional metadata to embed.  Valid
            values: ``"settings"`` and ``"customizationCount"``.

    Returns:
        Dict containing ``name``, ``_links``, and optionally ``_embedded``
        with the expanded data, or an ``error`` key on failure.
    """
    logger.info(f"Getting email template '{template_name}' for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        template, _, err = await client.get_email_template(brand_id, template_name, expand=expand)

        if err:
            logger.error(f"Okta API error getting email template '{template_name}' for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved email template '{template_name}' for brand: {brand_id}")
        return _serialize(template) or {}

    except Exception as e:
        logger.error(f"Exception getting email template '{template_name}' for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Customizations — CRUD
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def list_email_customizations(
    ctx: Context,
    brand_id: str,
    template_name: str,
) -> List[Dict[str, Any]]:
    """List all customizations for an email template.

    Returns every language variant that has been created for the specified
    email template.  Each entry includes the full customization body,
    subject, language, ``isDefault`` flag, and timestamps.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``, ``"ForgotPassword"``.

    Returns:
        List of customization dicts (may be empty if no customizations exist),
        or a dict with an ``error`` key on failure.
    """
    logger.info(f"Listing customizations for template '{template_name}' on brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        customizations, _, err = await client.list_email_customizations(brand_id, template_name)

        if err:
            logger.error(f"Okta API error listing customizations for template '{template_name}' on brand {brand_id}: {err}")
            return {"error": str(err)}

        result = _serialize(customizations) or []
        logger.info(f"Successfully listed {len(result)} customizations for template '{template_name}' on brand: {brand_id}")
        return result

    except Exception as e:
        logger.error(f"Exception listing customizations for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def create_email_customization(
    ctx: Context,
    brand_id: str,
    template_name: str,
    language: str,
    subject: str,
    body: str,
    is_default: Optional[bool] = None,
) -> Dict[str, Any]:
    """Create a new language customization for an email template.

    Adds a new localized variant for the specified email template.  Only one
    customization per language is allowed — creating a duplicate language
    returns a 409 Conflict error.  The first customization created for a
    template automatically becomes the default (``isDefault=True``); subsequent
    ones default to ``False``.

    The ``body`` must be valid HTML and **must** include all required Okta
    template variables for the template type.  For example, ``UserActivation``
    requires ``${activationLink}`` or ``${activationToken}``.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``, ``"ForgotPassword"``.
        language (str, required): IETF BCP 47 language tag, e.g. ``"en"``,
            ``"fr"``, ``"de"``, ``"es"``.
        subject (str, required): The email subject line.  Supports Okta
            template variables such as ``${org.name}``.
        body (str, required): Full HTML body of the email.  Must contain all
            required Okta template variables for this template type.
        is_default (bool, optional): Whether this customization is the default
            for the template.  Only one customization may be the default at a
            time; setting this to ``True`` clears the flag on any other
            customization.

    Returns:
        Dict containing the created customization (``id``, ``language``,
        ``subject``, ``body``, ``isDefault``, ``created``, ``lastUpdated``,
        ``_links``), or an ``error`` key on failure.
    """
    logger.info(f"Creating {language} customization for template '{template_name}' on brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        # Check if a customization for this language already exists before creating.
        existing, _, list_err = await client.list_email_customizations(brand_id, template_name)
        if not list_err and existing:
            for ex in existing:
                if getattr(ex, "language", None) == language:
                    ex_id = getattr(ex, "id", "unknown")
                    logger.warning(
                        f"A '{language}' customization already exists for template "
                        f"'{template_name}' on brand {brand_id!r} (id: {ex_id})"
                    )
                    return {
                        "error": (
                            f"A '{language}' customization already exists for template "
                            f"'{template_name}' (id: {ex_id!r}). "
                            "Use replace_email_customization() to update it."
                        )
                    }

        instance = EmailCustomization(
            language=language,
            subject=subject,
            body=body,
            is_default=is_default,
        )
        customization, _, err = await client.create_email_customization(brand_id, template_name, instance)

        if err:
            logger.error(f"Okta API error creating customization for template '{template_name}' on brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully created {language} customization (id: {customization.id}) for template '{template_name}' on brand: {brand_id}")
        return _serialize(customization) or {}

    except Exception as e:
        logger.error(f"Exception creating customization for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id", "customization_id")
async def get_email_customization(
    ctx: Context,
    brand_id: str,
    template_name: str,
    customization_id: str,
) -> Dict[str, Any]:
    """Retrieve a specific email customization by its ID.

    Returns the full customization object including the HTML body, subject,
    language, ``isDefault`` status, and timestamps.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``.
        customization_id (str, required): The unique identifier of the
            customization.

    Returns:
        Dict containing ``id``, ``language``, ``subject``, ``body``,
        ``isDefault``, ``created``, ``lastUpdated``, and ``_links``,
        or an ``error`` key on failure.
    """
    logger.info(f"Getting customization {customization_id} for template '{template_name}' on brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        customization, _, err = await client.get_email_customization(brand_id, template_name, customization_id)

        if err:
            logger.error(f"Okta API error getting customization {customization_id} for template '{template_name}' on brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved customization {customization_id} for template '{template_name}' on brand: {brand_id}")
        return _serialize(customization) or {}

    except Exception as e:
        logger.error(f"Exception getting customization {customization_id} for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id", "customization_id")
async def replace_email_customization(
    ctx: Context,
    brand_id: str,
    template_name: str,
    customization_id: str,
    language: str,
    subject: str,
    body: str,
    is_default: Optional[bool] = None,
) -> Dict[str, Any]:
    """Replace an existing email customization (full update).

    Replaces all fields on the specified customization.  All required fields
    must be supplied; the operation is not a partial patch.  The ``body``
    must include all required Okta template variables for the template type
    or the request will be rejected with a validation error.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``.
        customization_id (str, required): The unique identifier of the
            customization to replace.
        language (str, required): IETF BCP 47 language tag, e.g. ``"en"``.
            Must match an existing language — changing the language is not
            supported; create a new customization instead.
        subject (str, required): The updated email subject line.  Supports
            Okta template variables such as ``${org.name}``.
        body (str, required): Updated full HTML body of the email.  Must
            contain all required template variables.
        is_default (bool, optional): Whether this customization is the
            default.  Setting to ``True`` clears the flag on any other
            customization for the same template.

    Returns:
        Dict containing the updated customization, or an ``error`` key on
        failure.
    """
    logger.info(f"Replacing customization {customization_id} for template '{template_name}' on brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        instance = EmailCustomization(
            language=language,
            subject=subject,
            body=body,
            is_default=is_default,
        )
        customization, _, err = await client.replace_email_customization(
            brand_id, template_name, customization_id, instance
        )

        if err:
            logger.error(f"Okta API error replacing customization {customization_id} for template '{template_name}' on brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced customization {customization_id} for template '{template_name}' on brand: {brand_id}")
        return _serialize(customization) or {}

    except Exception as e:
        logger.error(f"Exception replacing customization {customization_id} for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id", "customization_id")
async def delete_email_customization(
    ctx: Context,
    brand_id: str,
    template_name: str,
    customization_id: str,
    language: str = "unknown",
) -> Dict[str, Any]:
    """Delete a specific email customization.

    Permanently removes the specified language customization from the email
    template.  Requires explicit confirmation before proceeding.  If this
    is the only customization (i.e. the default), you may need to delete all
    customizations instead; deleting the sole default customization may
    return an error — use ``delete_all_email_customizations`` in that case.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``.
        customization_id (str, required): The unique identifier of the
            customization to delete.
        language (str, optional): The language of the customization (e.g.
            ``"en"``).  Used only in the confirmation prompt — does not
            affect which record is deleted.

    Returns:
        Dict with ``success`` (bool) and ``message`` (str), or an ``error``
        key on failure.
    """
    logger.info(f"Deleting customization {customization_id} ({language}) for template '{template_name}' on brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    outcome = await elicit_or_fallback(
        ctx,
        DELETE_EMAIL_CUSTOMIZATION.format(
            language=language,
            customization_id=customization_id,
            template_name=template_name,
        ),
        DeleteConfirmation,
    )
    if not outcome.confirmed:
        logger.info(f"Delete customization {customization_id} cancelled for template '{template_name}' on brand: {brand_id}")
        return {"success": False, "message": "Delete email customization cancelled."}

    try:
        client = await get_okta_client(manager)
        result = await client.delete_email_customization(brand_id, template_name, customization_id)
        err_str = _check_no_content_response(result)

        if err_str:
            logger.error(f"Okta API error deleting customization {customization_id} for template '{template_name}' on brand {brand_id}: {err_str}")
            return {"error": err_str}

        logger.info(f"Successfully deleted customization {customization_id} for template '{template_name}' on brand: {brand_id}")
        return {"success": True, "message": f"Email customization {customization_id} deleted."}

    except Exception as e:
        logger.error(f"Exception deleting customization {customization_id} for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def delete_all_email_customizations(
    ctx: Context,
    brand_id: str,
    template_name: str,
) -> Dict[str, Any]:
    """Delete ALL customizations for an email template.

    Permanently removes every language variant from the specified email
    template, reverting it to Okta's built-in default content.  This is
    irreversible and cannot be undone.  Requires explicit confirmation.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name whose
            customizations will all be deleted, e.g. ``"UserActivation"``.

    Returns:
        Dict with ``success`` (bool) and ``message`` (str), or an ``error``
        key on failure.
    """
    logger.info(f"Deleting ALL customizations for template '{template_name}' on brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    outcome = await elicit_or_fallback(
        ctx,
        DELETE_ALL_EMAIL_CUSTOMIZATIONS.format(
            template_name=template_name,
            brand_id=brand_id,
        ),
        DeleteConfirmation,
    )
    if not outcome.confirmed:
        logger.info(f"Delete all customizations cancelled for template '{template_name}' on brand: {brand_id}")
        return {"success": False, "message": "Delete all email customizations cancelled."}

    try:
        client = await get_okta_client(manager)
        result = await client.delete_all_customizations(brand_id, template_name)
        err_str = _check_no_content_response(result)

        if err_str:
            logger.error(f"Okta API error deleting all customizations for template '{template_name}' on brand {brand_id}: {err_str}")
            return {"error": err_str}

        logger.info(f"Successfully deleted all customizations for template '{template_name}' on brand: {brand_id}")
        return {"success": True, "message": f"All customizations for email template '{template_name}' deleted."}

    except Exception as e:
        logger.error(f"Exception deleting all customizations for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Preview
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id", "customization_id")
async def get_email_customization_preview(
    ctx: Context,
    brand_id: str,
    template_name: str,
    customization_id: str,
) -> Dict[str, Any]:
    """Preview a rendered email customization.

    Returns the customization with all Okta template variables replaced by
    representative sample values.  Useful for verifying how the email will
    appear to recipients before publishing.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``.
        customization_id (str, required): The unique identifier of the
            customization to preview.

    Returns:
        Dict containing ``subject`` and ``body`` with all template variables
        rendered, plus ``_links``, or an ``error`` key on failure.
    """
    logger.info(f"Getting preview for customization {customization_id} of template '{template_name}' on brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        preview, _, err = await client.get_customization_preview(brand_id, template_name, customization_id)

        if err:
            logger.error(f"Okta API error getting preview for customization {customization_id} of template '{template_name}' on brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved preview for customization {customization_id} of template '{template_name}' on brand: {brand_id}")
        return _serialize(preview) or {}

    except Exception as e:
        logger.error(f"Exception getting preview for customization {customization_id} of template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Default content
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_email_default_content(
    ctx: Context,
    brand_id: str,
    template_name: str,
    language: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve the Okta default content for an email template.

    Returns the unmodified Okta-provided subject and body for the specified
    template.  This is the fallback content shown when no customization
    exists for a given language.  Useful for inspecting the baseline before
    creating a customization.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``.
        language (str, optional): IETF BCP 47 language tag to retrieve the
            default content for.  Defaults to the current API user's language
            if omitted.

    Returns:
        Dict containing ``subject``, ``body``, and ``_links``, or an
        ``error`` key on failure.
    """
    logger.info(f"Getting default content for template '{template_name}' on brand: {brand_id} (language: {language})")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        content, _, err = await client.get_email_default_content(brand_id, template_name, language=language)

        if err:
            logger.error(f"Okta API error getting default content for template '{template_name}' on brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved default content for template '{template_name}' on brand: {brand_id}")
        return _serialize(content) or {}

    except Exception as e:
        logger.error(f"Exception getting default content for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def get_email_default_content_preview(
    ctx: Context,
    brand_id: str,
    template_name: str,
    language: Optional[str] = None,
) -> Dict[str, Any]:
    """Preview the rendered Okta default content for an email template.

    Returns the Okta default subject and body with all template variables
    replaced by representative sample values.  Unlike
    ``get_email_default_content``, all ``${variable}`` placeholders are
    substituted with real-looking data so you can see exactly what an end
    user would receive.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``.
        language (str, optional): IETF BCP 47 language tag for the preview.
            Defaults to the current API user's language if omitted.

    Returns:
        Dict containing ``subject`` and ``body`` (fully rendered), plus
        ``_links``, or an ``error`` key on failure.
    """
    logger.info(f"Getting default content preview for template '{template_name}' on brand: {brand_id} (language: {language})")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        preview, _, err = await client.get_email_default_preview(brand_id, template_name, language=language)

        if err:
            err_str = str(err)
            logger.error(f"Okta API error getting default preview for template '{template_name}' on brand {brand_id}: {err_str}")
            # Okta's preview endpoint resolves the API token to a real user to
            # populate sample values (e.g. name, username).  OAuth 2.0 service
            # tokens (Client Credentials / private-key flow) are not tied to a
            # human user, so Okta cannot find the user and returns 404.
            if "E0000007" in err_str or "Not found" in err_str:
                return {
                    "error": (
                        "The email default content preview is not available when using an OAuth 2.0 "
                        "service token (Client Credentials / private-key flow). Okta requires a real "
                        "user identity to render the preview with sample values, but service tokens "
                        "are not associated with a human user.\n\n"
                        "Suggested alternatives:\n"
                        "  1. Use 'get_email_default_content' to retrieve the raw template with "
                        "${variable} placeholders instead of resolved values.\n"
                        "  2. Configure the MCP server with an SSWS API token tied to a real Okta "
                        "user to enable full preview rendering."
                    )
                }
            return {"error": err_str}

        logger.info(f"Successfully retrieved default content preview for template '{template_name}' on brand: {brand_id}")
        return _serialize(preview) or {}

    except Exception as e:
        logger.error(f"Exception getting default preview for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_email_settings(
    ctx: Context,
    brand_id: str,
    template_name: str,
) -> Dict[str, Any]:
    """Retrieve the email settings for a template.

    Returns the recipient configuration for the specified email template,
    controlling which user populations will receive emails of this type.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``.

    Returns:
        Dict containing ``recipients`` (one of ``"ALL_USERS"``,
        ``"ADMINS_ONLY"``, ``"NO_USERS"``) and ``_links``, or an ``error``
        key on failure.
    """
    logger.info(f"Getting email settings for template '{template_name}' on brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        settings, _, err = await client.get_email_settings(brand_id, template_name)

        if err:
            logger.error(f"Okta API error getting email settings for template '{template_name}' on brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved email settings for template '{template_name}' on brand: {brand_id}")
        return _serialize(settings) or {}

    except Exception as e:
        logger.error(f"Exception getting email settings for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def replace_email_settings(
    ctx: Context,
    brand_id: str,
    template_name: str,
    recipients: str,
) -> Dict[str, Any]:
    """Replace the email settings for a template.

    Updates the recipient configuration for the specified email template.
    This controls who receives emails of this type across your Okta org.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``.
        recipients (str, required): Who should receive this email type.
            Valid values:
            - ``"ALL_USERS"`` — all users receive the email (default).
            - ``"ADMINS_ONLY"`` — only administrators receive the email.
            - ``"NO_USERS"`` — the email is disabled for all users.

    Returns:
        Dict containing the updated ``recipients`` value and ``_links``,
        or an ``error`` key on failure.
    """
    logger.info(f"Replacing email settings for template '{template_name}' on brand: {brand_id} (recipients: {recipients})")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        email_settings = EmailSettings(recipients=recipients)
        settings, _, err = await client.replace_email_settings(brand_id, template_name, email_settings)

        if err:
            logger.error(f"Okta API error replacing email settings for template '{template_name}' on brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced email settings for template '{template_name}' on brand: {brand_id}")
        return _serialize(settings) or {}

    except Exception as e:
        logger.error(f"Exception replacing email settings for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Test email
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def send_test_email(
    ctx: Context,
    brand_id: str,
    template_name: str,
    language: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a test email for a template to the current API user.

    Triggers Okta to send a test version of the specified email template to
    the email address of the user associated with the current API token.  If
    a customization exists for the requested language, the customized version
    is sent; otherwise the Okta default content is used.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        template_name (str, required): The Okta template name, e.g.
            ``"UserActivation"``, ``"ForgotPassword"``.
        language (str, optional): IETF BCP 47 language tag to select which
            customization to test (e.g. ``"en"``, ``"fr"``).  Defaults to
            the current API user's language if omitted.

    Returns:
        Dict with ``success`` (bool) and ``message`` (str) on success, or an
        ``error`` key on failure.
    """
    logger.info(f"Sending test email for template '{template_name}' on brand: {brand_id} (language: {language})")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        result = await client.send_test_email(brand_id, template_name, language=language)
        err_str = _check_no_content_response(result)

        if err_str:
            logger.error(f"Okta API error sending test email for template '{template_name}' on brand {brand_id}: {err_str}")
            # Okta's send_test_email endpoint sends to the user associated with the
            # current OAuth token.  Client Credentials / service tokens have no 'uid'
            # claim — there is no real user — so Okta returns 404 E0000007 or an
            # empty-body 403.  Surface a clear, actionable message.
            if "E0000007" in err_str or "Not found" in err_str or "HTTP 403" in err_str:
                return {
                    "error": (
                        "This tool does not support Private Key JWT authentication. "
                        "Please switch to Device Authorization Grant and try again."
                    )
                }
            return {"error": err_str}

        logger.info(f"Successfully sent test email for template '{template_name}' on brand: {brand_id}")
        return {"success": True, "message": f"Test email for '{template_name}' sent successfully."}

    except Exception as e:
        logger.error(f"Exception sending test email for template '{template_name}' on brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}
