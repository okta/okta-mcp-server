# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Custom Pages tools for the Okta MCP server.

Custom Pages allow you to customise the HTML content of Okta-hosted pages,
the sign-in page widget behaviour, and the sign-out destination. This module
exposes MCP tools for every operation available in the Custom Pages API:

Error page:
    - get_error_page_resources             GET    /api/v1/brands/{brandId}/pages/error
    - get_customized_error_page            GET    /api/v1/brands/{brandId}/pages/error/customized
    - replace_customized_error_page        PUT    /api/v1/brands/{brandId}/pages/error/customized
    - delete_customized_error_page         DELETE /api/v1/brands/{brandId}/pages/error/customized
    - get_default_error_page               GET    /api/v1/brands/{brandId}/pages/error/default
    - get_preview_error_page               GET    /api/v1/brands/{brandId}/pages/error/preview
    - replace_preview_error_page           PUT    /api/v1/brands/{brandId}/pages/error/preview
    - delete_preview_error_page            DELETE /api/v1/brands/{brandId}/pages/error/preview

Sign-in page:
    - get_sign_in_page_resources           GET    /api/v1/brands/{brandId}/pages/sign-in
    - get_customized_sign_in_page          GET    /api/v1/brands/{brandId}/pages/sign-in/customized
    - replace_customized_sign_in_page      PUT    /api/v1/brands/{brandId}/pages/sign-in/customized
    - delete_customized_sign_in_page       DELETE /api/v1/brands/{brandId}/pages/sign-in/customized
    - get_default_sign_in_page             GET    /api/v1/brands/{brandId}/pages/sign-in/default
    - get_preview_sign_in_page             GET    /api/v1/brands/{brandId}/pages/sign-in/preview
    - replace_preview_sign_in_page         PUT    /api/v1/brands/{brandId}/pages/sign-in/preview
    - delete_preview_sign_in_page          DELETE /api/v1/brands/{brandId}/pages/sign-in/preview
    - list_sign_in_widget_versions         GET    /api/v1/brands/{brandId}/pages/sign-in/widget-versions

Sign-out page:
    - get_sign_out_page_settings           GET    /api/v1/brands/{brandId}/pages/sign-out/customized
    - replace_sign_out_page_settings       PUT    /api/v1/brands/{brandId}/pages/sign-out/customized

Notes:
    - The *customized* pages are what users see in the live environment. The
      *preview* pages are a sandbox used for testing before publishing.
    - Deleting a customized or preview page reverts it to the Okta default.
      All four delete operations require explicit confirmation (elicitation).
    - The default page cannot be modified — it is always the Okta fallback.
    - ``widget_customizations`` for sign-in page tools accepts a dict with
      snake_case keys matching the SDK field names, e.g.::
          {"sign_in_label": "Log in", "forgot_password_label": "Reset"}
    - ``content_security_policy_setting`` accepts a dict with keys
      ``mode`` ("enforced" | "report_only" | "disabled"), ``report_uri``
      (string), and ``src_list`` (list of strings).
    - Sign-out page type: ``OKTA_DEFAULT`` shows the Okta default page;
      ``EXTERNALLY_HOSTED`` redirects to the URL you provide.
"""

from typing import Any, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import Context
from okta.models.content_security_policy_setting import ContentSecurityPolicySetting
from okta.models.error_page import ErrorPage
from okta.models.hosted_page import HostedPage
from okta.models.hosted_page_type import HostedPageType
from okta.models.sign_in_page import SignInPage
from okta.models.sign_in_page_all_of_widget_customizations import SignInPageAllOfWidgetCustomizations

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import (
    DELETE_CUSTOMIZED_ERROR_PAGE,
    DELETE_CUSTOMIZED_SIGN_IN_PAGE,
    DELETE_PREVIEW_ERROR_PAGE,
    DELETE_PREVIEW_SIGN_IN_PAGE,
)
from okta_mcp_server.utils.validation import validate_ids


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _serialize(obj) -> Any:
    """Recursively serialise Pydantic models and lists to plain Python types."""
    if obj is None:
        return None
    if hasattr(obj, "model_dump"):
        return obj.model_dump(by_alias=True, exclude_none=True)
    if isinstance(obj, list):
        return [_serialize(item) for item in obj]
    return obj


def _build_csp(
    mode: Optional[str],
    report_uri: Optional[str],
    src_list: Optional[List[str]],
) -> Optional[ContentSecurityPolicySetting]:
    """Return a ContentSecurityPolicySetting only when at least one param is set."""
    if mode is None and report_uri is None and src_list is None:
        return None
    return ContentSecurityPolicySetting(
        mode=mode,
        report_uri=report_uri,
        src_list=src_list,
    )


def _build_sign_in_page(
    page_content: Optional[str],
    widget_version: Optional[str],
    widget_customizations: Optional[Dict[str, Any]],
    csp: Optional[ContentSecurityPolicySetting],
) -> SignInPage:
    """Assemble a SignInPage model from the individual tool parameters."""
    wc = SignInPageAllOfWidgetCustomizations(**(widget_customizations or {}))
    return SignInPage(
        page_content=page_content,
        widget_version=widget_version,
        widget_customizations=wc,
        content_security_policy_setting=csp,
    )


# ---------------------------------------------------------------------------
# Error page — sub-resources
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_error_page_resources(
    ctx: Context,
    brand_id: str,
    expand: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Retrieve the error page sub-resource links for a brand.

    Returns navigation links (``_links``) for the customized, default, and
    preview error pages. Pass one or more values in ``expand`` to embed the
    full page content of those sub-resources inline in the response.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        expand (List[str], optional): Sub-resources to embed. Valid values:
            ``default``, ``customized``, ``customizedUrl``, ``preview``,
            ``previewUrl``.

    Returns:
        Dict containing ``_links`` (and optionally ``_embedded``) describing
        the available error page resources, or an ``error`` key on failure.
    """
    logger.info(f"Getting error page resources for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        page_root, _, err = await client.get_error_page(brand_id, expand)

        if err:
            logger.error(f"Okta API error getting error page resources for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved error page resources for brand: {brand_id}")
        return _serialize(page_root) or {}

    except Exception as e:
        logger.error(f"Exception getting error page resources for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Error page — customized
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_customized_error_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Retrieve the customized error page for a brand.

    The customized error page is what end-users see in the live environment
    when an error occurs. Returns 404 if no customization exists (the default
    page is in use).

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict containing ``pageContent`` (HTML string) and optionally
        ``contentSecurityPolicySetting``, or an ``error`` key on failure.
    """
    logger.info(f"Getting customized error page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        page, _, err = await client.get_customized_error_page(brand_id)

        if err:
            logger.error(f"Okta API error getting customized error page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved customized error page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception getting customized error page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def replace_customized_error_page(
    ctx: Context,
    brand_id: str,
    page_content: Optional[str] = None,
    csp_mode: Optional[str] = None,
    csp_report_uri: Optional[str] = None,
    csp_src_list: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Replace (or create) the customized error page for a brand.

    Sets the HTML that appears in the live environment when an error occurs.
    Replaces the entire customized page; any fields omitted revert to their
    defaults.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        page_content (str, optional): Full HTML content of the error page.
            Supports Okta template variables such as ``{{errorSummary}}``,
            ``{{errorDescription}}``, ``{{buttonText}}``, and
            ``{{{ErrorPageResources}}}``.
        csp_mode (str, optional): Content Security Policy enforcement mode.
            Valid values: ``enforced``, ``report_only``, ``disabled``.
        csp_report_uri (str, optional): URI where CSP violation reports are
            sent.
        csp_src_list (List[str], optional): Allowed source origins for the
            Content Security Policy.

    Returns:
        Dict containing the updated error page object, or an ``error`` key on
        failure.
    """
    logger.info(f"Replacing customized error page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        csp = _build_csp(csp_mode, csp_report_uri, csp_src_list)
        error_page = ErrorPage(
            page_content=page_content,
            content_security_policy_setting=csp,
        )
        page, _, err = await client.replace_customized_error_page(brand_id, error_page)

        if err:
            logger.error(f"Okta API error replacing customized error page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced customized error page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception replacing customized error page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def delete_customized_error_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Delete the customized error page for a brand.

    Removes the customized error page so the Okta default error page is shown
    in the live environment. Requires explicit confirmation before proceeding.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict with ``success`` (bool) and ``message`` (str), or an ``error``
        key on failure.
    """
    logger.info(f"Deleting customized error page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    outcome = await elicit_or_fallback(
        ctx,
        DELETE_CUSTOMIZED_ERROR_PAGE.format(brand_id=brand_id),
        DeleteConfirmation,
    )
    if not outcome.confirmed:
        logger.info(f"Delete customized error page cancelled for brand: {brand_id}")
        return {"success": False, "message": "Delete customized error page cancelled."}

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_customized_error_page(brand_id)

        if err:
            logger.error(f"Okta API error deleting customized error page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deleted customized error page for brand: {brand_id}")
        return {"success": True, "message": f"Customized error page for brand {brand_id} deleted. The default error page is now active."}

    except Exception as e:
        logger.error(f"Exception deleting customized error page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Error page — default
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_default_error_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Retrieve the default (Okta-provided) error page for a brand.

    The default error page is shown when no customized error page exists. It
    cannot be modified; use ``replace_customized_error_page`` to override it.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict containing ``pageContent`` (HTML string) and optionally
        ``contentSecurityPolicySetting``, or an ``error`` key on failure.
    """
    logger.info(f"Getting default error page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        page, _, err = await client.get_default_error_page(brand_id)

        if err:
            logger.error(f"Okta API error getting default error page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved default error page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception getting default error page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Error page — preview
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_preview_error_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Retrieve the preview error page for a brand.

    The preview page is a sandbox for testing error page changes before they
    go live. Returns 404 if no preview exists.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict containing ``pageContent`` (HTML string) and optionally
        ``contentSecurityPolicySetting``, or an ``error`` key on failure.
    """
    logger.info(f"Getting preview error page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        page, _, err = await client.get_preview_error_page(brand_id)

        if err:
            logger.error(f"Okta API error getting preview error page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved preview error page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception getting preview error page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def replace_preview_error_page(
    ctx: Context,
    brand_id: str,
    page_content: Optional[str] = None,
    csp_mode: Optional[str] = None,
    csp_report_uri: Optional[str] = None,
    csp_src_list: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Replace (or create) the preview error page for a brand.

    Sets the HTML for the error page preview environment. Use this to test
    changes before publishing to the live customized error page.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        page_content (str, optional): Full HTML content of the preview error
            page. Supports Okta template variables.
        csp_mode (str, optional): Content Security Policy enforcement mode.
            Valid values: ``enforced``, ``report_only``, ``disabled``.
        csp_report_uri (str, optional): URI where CSP violation reports are
            sent.
        csp_src_list (List[str], optional): Allowed source origins for the
            Content Security Policy.

    Returns:
        Dict containing the updated preview error page object, or an ``error``
        key on failure.
    """
    logger.info(f"Replacing preview error page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        csp = _build_csp(csp_mode, csp_report_uri, csp_src_list)
        error_page = ErrorPage(
            page_content=page_content,
            content_security_policy_setting=csp,
        )
        page, _, err = await client.replace_preview_error_page(brand_id, error_page)

        if err:
            logger.error(f"Okta API error replacing preview error page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced preview error page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception replacing preview error page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def delete_preview_error_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Delete the preview error page for a brand.

    Removes the preview error page. The preview environment will fall back to
    the default error page. Requires explicit confirmation before proceeding.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict with ``success`` (bool) and ``message`` (str), or an ``error``
        key on failure.
    """
    logger.info(f"Deleting preview error page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    outcome = await elicit_or_fallback(
        ctx,
        DELETE_PREVIEW_ERROR_PAGE.format(brand_id=brand_id),
        DeleteConfirmation,
    )
    if not outcome.confirmed:
        logger.info(f"Delete preview error page cancelled for brand: {brand_id}")
        return {"success": False, "message": "Delete preview error page cancelled."}

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_preview_error_page(brand_id)

        if err:
            logger.error(f"Okta API error deleting preview error page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deleted preview error page for brand: {brand_id}")
        return {"success": True, "message": f"Preview error page for brand {brand_id} deleted."}

    except Exception as e:
        logger.error(f"Exception deleting preview error page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Sign-in page — sub-resources
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_sign_in_page_resources(
    ctx: Context,
    brand_id: str,
    expand: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Retrieve the sign-in page sub-resource links for a brand.

    Returns navigation links (``_links``) for the customized, default, and
    preview sign-in pages. Pass one or more values in ``expand`` to embed the
    full page content of those sub-resources inline in the response.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        expand (List[str], optional): Sub-resources to embed. Valid values:
            ``default``, ``customized``, ``customizedUrl``, ``preview``,
            ``previewUrl``.

    Returns:
        Dict containing ``_links`` (and optionally ``_embedded``) describing
        the available sign-in page resources, or an ``error`` key on failure.
    """
    logger.info(f"Getting sign-in page resources for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        page_root, _, err = await client.get_sign_in_page(brand_id, expand)

        if err:
            logger.error(f"Okta API error getting sign-in page resources for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved sign-in page resources for brand: {brand_id}")
        return _serialize(page_root) or {}

    except Exception as e:
        logger.error(f"Exception getting sign-in page resources for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Sign-in page — customized
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_customized_sign_in_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Retrieve the customized sign-in page for a brand.

    The customized sign-in page is what end-users see in the live environment.
    Returns 404 if no customization exists (the default page is in use).

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict containing ``pageContent``, ``widgetVersion``,
        ``widgetCustomizations``, and optionally
        ``contentSecurityPolicySetting``, or an ``error`` key on failure.
    """
    logger.info(f"Getting customized sign-in page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        page, _, err = await client.get_customized_sign_in_page(brand_id)

        if err:
            logger.error(f"Okta API error getting customized sign-in page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved customized sign-in page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception getting customized sign-in page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def replace_customized_sign_in_page(
    ctx: Context,
    brand_id: str,
    page_content: Optional[str] = None,
    widget_version: Optional[str] = None,
    widget_customizations: Optional[Dict[str, Any]] = None,
    csp_mode: Optional[str] = None,
    csp_report_uri: Optional[str] = None,
    csp_src_list: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Replace (or create) the customized sign-in page for a brand.

    Sets the HTML, widget version, and widget behaviour that appear in the
    live environment. The ``widgetCustomizations`` parameter lets you control
    labels, links, and toggles shown in the Okta sign-in widget.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        page_content (str, optional): Full HTML content of the sign-in page.
        widget_version (str, optional): Okta Sign-In Widget version.
            Accepts wildcards and ranges, e.g. ``"*"``, ``"^5"``, ``"7"``,
            ``"5.15"``. Use ``list_sign_in_widget_versions`` to see available
            values.
        widget_customizations (Dict[str, Any], optional): Dict of widget
            customisation fields using snake_case keys, for example::

                {
                    "sign_in_label": "Log in",
                    "forgot_password_label": "Reset password",
                    "forgot_password_url": "https://example.com/reset",
                    "show_password_visibility_toggle": True,
                    "show_user_identifier": True,
                    "custom_link1_label": "Help",
                    "custom_link1_url": "https://example.com/help"
                }

            Pass ``{}`` to keep all defaults. If omitted, an empty
            widgetCustomizations object is sent (required by the API).
        csp_mode (str, optional): Content Security Policy enforcement mode.
            Valid values: ``enforced``, ``report_only``, ``disabled``.
        csp_report_uri (str, optional): URI where CSP violation reports are
            sent.
        csp_src_list (List[str], optional): Allowed source origins for the
            Content Security Policy.

    Returns:
        Dict containing the updated sign-in page object, or an ``error`` key
        on failure.
    """
    logger.info(f"Replacing customized sign-in page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        csp = _build_csp(csp_mode, csp_report_uri, csp_src_list)
        sign_in_page = _build_sign_in_page(page_content, widget_version, widget_customizations, csp)
        page, _, err = await client.replace_customized_sign_in_page(brand_id, sign_in_page)

        if err:
            logger.error(f"Okta API error replacing customized sign-in page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced customized sign-in page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception replacing customized sign-in page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def delete_customized_sign_in_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Delete the customized sign-in page for a brand.

    Removes the customized sign-in page so the Okta default sign-in page is
    shown in the live environment. Requires explicit confirmation before
    proceeding.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict with ``success`` (bool) and ``message`` (str), or an ``error``
        key on failure.
    """
    logger.info(f"Deleting customized sign-in page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    outcome = await elicit_or_fallback(
        ctx,
        DELETE_CUSTOMIZED_SIGN_IN_PAGE.format(brand_id=brand_id),
        DeleteConfirmation,
    )
    if not outcome.confirmed:
        logger.info(f"Delete customized sign-in page cancelled for brand: {brand_id}")
        return {"success": False, "message": "Delete customized sign-in page cancelled."}

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_customized_sign_in_page(brand_id)

        if err:
            logger.error(f"Okta API error deleting customized sign-in page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deleted customized sign-in page for brand: {brand_id}")
        return {"success": True, "message": f"Customized sign-in page for brand {brand_id} deleted. The default sign-in page is now active."}

    except Exception as e:
        logger.error(f"Exception deleting customized sign-in page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Sign-in page — default
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_default_sign_in_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Retrieve the default (Okta-provided) sign-in page for a brand.

    The default sign-in page is shown when no customized page exists. It
    cannot be modified; use ``replace_customized_sign_in_page`` to override
    it.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict containing ``pageContent``, ``widgetVersion``,
        ``widgetCustomizations``, and optionally
        ``contentSecurityPolicySetting``, or an ``error`` key on failure.
    """
    logger.info(f"Getting default sign-in page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        page, _, err = await client.get_default_sign_in_page(brand_id)

        if err:
            logger.error(f"Okta API error getting default sign-in page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved default sign-in page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception getting default sign-in page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Sign-in page — preview
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_preview_sign_in_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Retrieve the preview sign-in page for a brand.

    The preview page is a sandbox for testing sign-in page changes before
    they go live. Returns 404 if no preview exists.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict containing ``pageContent``, ``widgetVersion``,
        ``widgetCustomizations``, and optionally
        ``contentSecurityPolicySetting``, or an ``error`` key on failure.
    """
    logger.info(f"Getting preview sign-in page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        page, _, err = await client.get_preview_sign_in_page(brand_id)

        if err:
            logger.error(f"Okta API error getting preview sign-in page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved preview sign-in page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception getting preview sign-in page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def replace_preview_sign_in_page(
    ctx: Context,
    brand_id: str,
    page_content: Optional[str] = None,
    widget_version: Optional[str] = None,
    widget_customizations: Optional[Dict[str, Any]] = None,
    csp_mode: Optional[str] = None,
    csp_report_uri: Optional[str] = None,
    csp_src_list: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Replace (or create) the preview sign-in page for a brand.

    Sets the HTML, widget version, and widget behaviour for the sign-in page
    preview environment. Use this to test changes before publishing to the
    live customized sign-in page.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        page_content (str, optional): Full HTML content of the preview sign-in
            page.
        widget_version (str, optional): Okta Sign-In Widget version.
            Accepts wildcards and ranges, e.g. ``"*"``, ``"^5"``, ``"7"``,
            ``"5.15"``.
        widget_customizations (Dict[str, Any], optional): Dict of widget
            customisation fields using snake_case keys. Pass ``{}`` to keep
            all defaults. If omitted, an empty widgetCustomizations object is
            sent (required by the API).
        csp_mode (str, optional): Content Security Policy enforcement mode.
            Valid values: ``enforced``, ``report_only``, ``disabled``.
        csp_report_uri (str, optional): URI where CSP violation reports are
            sent.
        csp_src_list (List[str], optional): Allowed source origins for the
            Content Security Policy.

    Returns:
        Dict containing the updated preview sign-in page object, or an
        ``error`` key on failure.
    """
    logger.info(f"Replacing preview sign-in page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        csp = _build_csp(csp_mode, csp_report_uri, csp_src_list)
        sign_in_page = _build_sign_in_page(page_content, widget_version, widget_customizations, csp)
        page, _, err = await client.replace_preview_sign_in_page(brand_id, sign_in_page)

        if err:
            logger.error(f"Okta API error replacing preview sign-in page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced preview sign-in page for brand: {brand_id}")
        return _serialize(page) or {}

    except Exception as e:
        logger.error(f"Exception replacing preview sign-in page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def delete_preview_sign_in_page(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Delete the preview sign-in page for a brand.

    Removes the preview sign-in page. The preview environment will fall back
    to the default sign-in page. Requires explicit confirmation before
    proceeding.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict with ``success`` (bool) and ``message`` (str), or an ``error``
        key on failure.
    """
    logger.info(f"Deleting preview sign-in page for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    outcome = await elicit_or_fallback(
        ctx,
        DELETE_PREVIEW_SIGN_IN_PAGE.format(brand_id=brand_id),
        DeleteConfirmation,
    )
    if not outcome.confirmed:
        logger.info(f"Delete preview sign-in page cancelled for brand: {brand_id}")
        return {"success": False, "message": "Delete preview sign-in page cancelled."}

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_preview_sign_in_page(brand_id)

        if err:
            logger.error(f"Okta API error deleting preview sign-in page for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deleted preview sign-in page for brand: {brand_id}")
        return {"success": True, "message": f"Preview sign-in page for brand {brand_id} deleted."}

    except Exception as e:
        logger.error(f"Exception deleting preview sign-in page for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Sign-in page — widget versions
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def list_sign_in_widget_versions(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """List all available Okta Sign-In Widget versions for a brand.

    Returns the version strings that can be used in the ``widget_version``
    parameter of ``replace_customized_sign_in_page`` and
    ``replace_preview_sign_in_page``. Includes both specific versions and
    range expressions.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict containing:
        - versions (List[str]): Available widget version strings,
          e.g. ``["5.15", "^5", "6.0", "7", "*"]``.
        - total_fetched (int): Number of versions returned.
        - error (str): Present only when the operation fails.
    """
    logger.info(f"Listing sign-in widget versions for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        versions, _, err = await client.list_all_sign_in_widget_versions(brand_id)

        if err:
            logger.error(f"Okta API error listing widget versions for brand {brand_id}: {err}")
            return {"error": str(err)}

        versions = versions or []
        logger.info(f"Successfully retrieved {len(versions)} widget version(s) for brand: {brand_id}")
        return {
            "versions": versions,
            "total_fetched": len(versions),
        }

    except Exception as e:
        logger.error(f"Exception listing widget versions for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Sign-out page
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_sign_out_page_settings(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Retrieve the sign-out page settings for a brand.

    Returns the current sign-out page configuration, which controls where
    users are redirected after signing out.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict containing:
        - type (str): ``OKTA_DEFAULT`` (show the Okta default sign-out page)
          or ``EXTERNALLY_HOSTED`` (redirect to a custom URL).
        - url (str): The redirect URL, present only when type is
          ``EXTERNALLY_HOSTED``.
        - error (str): Present only when the operation fails.
    """
    logger.info(f"Getting sign-out page settings for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        settings, _, err = await client.get_sign_out_page_settings(brand_id)

        if err:
            logger.error(f"Okta API error getting sign-out page settings for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved sign-out page settings for brand: {brand_id}")
        return _serialize(settings) or {}

    except Exception as e:
        logger.error(f"Exception getting sign-out page settings for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("brand_id")
async def replace_sign_out_page_settings(
    ctx: Context,
    brand_id: str,
    type: str,
    url: Optional[str] = None,
) -> Dict[str, Any]:
    """Replace the sign-out page settings for a brand.

    Controls where users are redirected after they sign out. Set
    ``type`` to ``OKTA_DEFAULT`` to use the built-in Okta sign-out page, or
    ``EXTERNALLY_HOSTED`` to redirect users to a URL you provide.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        type (str, required): Sign-out page type. Must be one of:
            - ``OKTA_DEFAULT`` — show the Okta default sign-out page.
            - ``EXTERNALLY_HOSTED`` — redirect to ``url`` after sign-out.
        url (str, optional): The redirect URL. Required when ``type`` is
            ``EXTERNALLY_HOSTED``.

    Returns:
        Dict containing the updated sign-out page settings (``type`` and
        optionally ``url``), or an ``error`` key on failure.
    """
    logger.info(f"Replacing sign-out page settings for brand: {brand_id}, type: {type}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    type_upper = type.upper()
    valid_types = {t.value for t in HostedPageType}
    if type_upper not in valid_types:
        return {"error": f"Invalid type '{type}'. Must be one of: {sorted(valid_types)}"}

    if type_upper == HostedPageType.EXTERNALLY_HOSTED.value and not url:
        return {"error": "The 'url' parameter is required when type is 'EXTERNALLY_HOSTED'."}

    try:
        client = await get_okta_client(manager)
        hosted_page = HostedPage(
            type=HostedPageType(type_upper),
            url=url,
        )
        settings, _, err = await client.replace_sign_out_page_settings(brand_id, hosted_page)

        if err:
            logger.error(f"Okta API error replacing sign-out page settings for brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced sign-out page settings for brand: {brand_id}")
        return _serialize(settings) or {}

    except Exception as e:
        logger.error(f"Exception replacing sign-out page settings for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}
