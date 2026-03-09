# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Themes tools for the Okta MCP server.

Themes control the visual appearance of Okta-hosted pages and email templates,
including colours, logo, favicon, and background image. This module exposes MCP
tools for every operation available in the Themes API:

    - list_brand_themes                    GET    /api/v1/brands/{brandId}/themes
    - get_brand_theme                      GET    /api/v1/brands/{brandId}/themes/{themeId}
    - replace_brand_theme                  PUT    /api/v1/brands/{brandId}/themes/{themeId}
    - upload_brand_theme_logo              POST   /api/v1/brands/{brandId}/themes/{themeId}/logo
    - delete_brand_theme_logo              DELETE /api/v1/brands/{brandId}/themes/{themeId}/logo
    - upload_brand_theme_favicon           POST   /api/v1/brands/{brandId}/themes/{themeId}/favicon
    - delete_brand_theme_favicon           DELETE /api/v1/brands/{brandId}/themes/{themeId}/favicon
    - upload_brand_theme_background_image  POST   /api/v1/brands/{brandId}/themes/{themeId}/background-image
    - delete_brand_theme_background_image  DELETE /api/v1/brands/{brandId}/themes/{themeId}/background-image

Notes:
    - Each org currently supports only one theme per brand; list_brand_themes
      therefore always returns a single-element list.
    - Image uploads accept a path to a local file on the server. Supported
      formats: PNG, JPG, GIF. Logo < 100 kB; favicon and background < 2 MB.
    - Image deletes are reversible — the theme reverts to the Okta default
      asset; no confirmation prompt is shown.
    - TouchPoint variant enums:
        signInPageTouchPointVariant       : BACKGROUND_IMAGE | BACKGROUND_SECONDARY_COLOR | OKTA_DEFAULT
        endUserDashboardTouchPointVariant : FULL_THEME | LOGO_ON_FULL_WHITE_BACKGROUND | OKTA_DEFAULT | WHITE_LOGO_BACKGROUND
        errorPageTouchPointVariant        : BACKGROUND_IMAGE | BACKGROUND_SECONDARY_COLOR | OKTA_DEFAULT
        emailTemplateTouchPointVariant    : FULL_THEME | OKTA_DEFAULT
        loadingPageTouchPointVariant      : NONE | OKTA_DEFAULT
"""

import os
from typing import Any, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import Context
from okta.models.email_template_touch_point_variant import EmailTemplateTouchPointVariant
from okta.models.end_user_dashboard_touch_point_variant import EndUserDashboardTouchPointVariant
from okta.models.error_page_touch_point_variant import ErrorPageTouchPointVariant
from okta.models.loading_page_touch_point_variant import LoadingPageTouchPointVariant
from okta.models.sign_in_page_touch_point_variant import SignInPageTouchPointVariant
from okta.models.update_theme_request import UpdateThemeRequest

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import (
    DELETE_THEME_BACKGROUND_IMAGE,
    DELETE_THEME_FAVICON,
    DELETE_THEME_LOGO,
)
from okta_mcp_server.utils.validation import validate_ids


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _serialize_theme(theme) -> Dict[str, Any]:
    """Serialize a ThemeResponse Pydantic model to a plain camelCase dict."""
    if theme is None:
        return {}
    if hasattr(theme, "model_dump"):
        return theme.model_dump(by_alias=True, exclude_none=True)
    return dict(theme)


_SIGN_IN_VARIANTS = {e.value for e in SignInPageTouchPointVariant}
_DASHBOARD_VARIANTS = {e.value for e in EndUserDashboardTouchPointVariant}
_ERROR_PAGE_VARIANTS = {e.value for e in ErrorPageTouchPointVariant}
_EMAIL_VARIANTS = {e.value for e in EmailTemplateTouchPointVariant}
_LOADING_VARIANTS = {e.value for e in LoadingPageTouchPointVariant}


# ---------------------------------------------------------------------------
# list_brand_themes
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def list_brand_themes(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """List all themes for a brand.

    Currently each Okta org supports only one theme per brand, so this always
    returns a single-element list.

    Parameters:
        brand_id (str, required): The unique identifier of the brand
            (e.g. ``bnd114iNkrcN6aR680g4``).

    Returns:
        Dict containing:
        - themes (List[Dict]): List of theme objects (always one element).
        - total_fetched (int): Number of themes returned.
        - error (str): Present only when the operation fails.
    """
    logger.info(f"Listing themes for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        themes, _, err = await client.list_brand_themes(brand_id)

        if err:
            logger.error(f"Okta API error while listing themes for brand {brand_id}: {err}")
            return {"error": str(err)}

        themes = themes or []
        serialized = [_serialize_theme(t) for t in themes]
        logger.info(f"Successfully retrieved {len(serialized)} theme(s) for brand: {brand_id}")
        return {
            "themes": serialized,
            "total_fetched": len(serialized),
        }

    except Exception as e:
        logger.error(f"Exception while listing themes for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# get_brand_theme
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id", "theme_id")
async def get_brand_theme(
    ctx: Context,
    brand_id: str,
    theme_id: str,
) -> Dict[str, Any]:
    """Retrieve a specific theme by brand ID and theme ID.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        theme_id (str, required): The unique identifier of the theme
            (e.g. ``thdul904tTZ6kWVhP0g3``).

    Returns:
        Dict containing the theme object, or an ``error`` key on failure.
        Theme fields include: ``id``, ``logo``, ``favicon``, ``backgroundImage``,
        ``primaryColorHex``, ``primaryColorContrastHex``, ``secondaryColorHex``,
        ``secondaryColorContrastHex``, and all five touchpoint variant values.
    """
    logger.info(f"Retrieving theme {theme_id} for brand: {brand_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        theme, _, err = await client.get_brand_theme(brand_id, theme_id)

        if err:
            logger.error(f"Okta API error while retrieving theme {theme_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved theme: {theme_id}")
        return _serialize_theme(theme)

    except Exception as e:
        logger.error(f"Exception while retrieving theme {theme_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# replace_brand_theme
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id", "theme_id")
async def replace_brand_theme(
    ctx: Context,
    brand_id: str,
    theme_id: str,
    primary_color_hex: str,
    secondary_color_hex: str,
    sign_in_page_touch_point_variant: str,
    end_user_dashboard_touch_point_variant: str,
    error_page_touch_point_variant: str,
    email_template_touch_point_variant: str,
    primary_color_contrast_hex: Optional[str] = None,
    secondary_color_contrast_hex: Optional[str] = None,
    loading_page_touch_point_variant: Optional[str] = None,
) -> Dict[str, Any]:
    """Replace (fully update) a theme's colours and touchpoint variants.

    All five touchpoint variant fields are required. Optional fields default to
    ``null`` if omitted, which lets Okta auto-optimise contrast colours.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        theme_id (str, required): The unique identifier of the theme.
        primary_color_hex (str, required): Primary colour hex code (e.g. ``"#1662dd"``).
        secondary_color_hex (str, required): Secondary colour hex code (e.g. ``"#ebebed"``).
        sign_in_page_touch_point_variant (str, required):
            Variant for the sign-in page.
            Valid values: ``BACKGROUND_IMAGE`` | ``BACKGROUND_SECONDARY_COLOR`` | ``OKTA_DEFAULT``.
        end_user_dashboard_touch_point_variant (str, required):
            Variant for the End-User Dashboard.
            Valid values: ``FULL_THEME`` | ``LOGO_ON_FULL_WHITE_BACKGROUND`` | ``OKTA_DEFAULT`` | ``WHITE_LOGO_BACKGROUND``.
        error_page_touch_point_variant (str, required):
            Variant for the error page.
            Valid values: ``BACKGROUND_IMAGE`` | ``BACKGROUND_SECONDARY_COLOR`` | ``OKTA_DEFAULT``.
        email_template_touch_point_variant (str, required):
            Variant for email templates.
            Valid values: ``FULL_THEME`` | ``OKTA_DEFAULT``.
        primary_color_contrast_hex (str, optional): Primary contrast colour hex code.
            When omitted, Okta auto-optimises for accessibility.
        secondary_color_contrast_hex (str, optional): Secondary contrast colour hex code.
        loading_page_touch_point_variant (str, optional):
            Variant for the Okta loading page.
            Valid values: ``NONE`` | ``OKTA_DEFAULT``. Defaults to ``OKTA_DEFAULT``.

    Returns:
        Dict containing the updated theme object, or an ``error`` key on failure.
    """
    logger.info(f"Replacing theme {theme_id} for brand: {brand_id}")

    # Validate enum values before hitting the API
    sign_in_page_touch_point_variant = sign_in_page_touch_point_variant.upper()
    end_user_dashboard_touch_point_variant = end_user_dashboard_touch_point_variant.upper()
    error_page_touch_point_variant = error_page_touch_point_variant.upper()
    email_template_touch_point_variant = email_template_touch_point_variant.upper()

    if sign_in_page_touch_point_variant not in _SIGN_IN_VARIANTS:
        return {"error": f"Invalid signInPageTouchPointVariant '{sign_in_page_touch_point_variant}'. Valid values: {sorted(_SIGN_IN_VARIANTS)}"}
    if end_user_dashboard_touch_point_variant not in _DASHBOARD_VARIANTS:
        return {"error": f"Invalid endUserDashboardTouchPointVariant '{end_user_dashboard_touch_point_variant}'. Valid values: {sorted(_DASHBOARD_VARIANTS)}"}
    if error_page_touch_point_variant not in _ERROR_PAGE_VARIANTS:
        return {"error": f"Invalid errorPageTouchPointVariant '{error_page_touch_point_variant}'. Valid values: {sorted(_ERROR_PAGE_VARIANTS)}"}
    if email_template_touch_point_variant not in _EMAIL_VARIANTS:
        return {"error": f"Invalid emailTemplateTouchPointVariant '{email_template_touch_point_variant}'. Valid values: {sorted(_EMAIL_VARIANTS)}"}

    if loading_page_touch_point_variant is not None:
        loading_page_touch_point_variant = loading_page_touch_point_variant.upper()
        if loading_page_touch_point_variant not in _LOADING_VARIANTS:
            return {"error": f"Invalid loadingPageTouchPointVariant '{loading_page_touch_point_variant}'. Valid values: {sorted(_LOADING_VARIANTS)}"}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        request_data: Dict[str, Any] = {
            "primary_color_hex": primary_color_hex,
            "secondary_color_hex": secondary_color_hex,
            "sign_in_page_touch_point_variant": SignInPageTouchPointVariant(sign_in_page_touch_point_variant),
            "end_user_dashboard_touch_point_variant": EndUserDashboardTouchPointVariant(end_user_dashboard_touch_point_variant),
            "error_page_touch_point_variant": ErrorPageTouchPointVariant(error_page_touch_point_variant),
            "email_template_touch_point_variant": EmailTemplateTouchPointVariant(email_template_touch_point_variant),
        }
        if primary_color_contrast_hex is not None:
            request_data["primary_color_contrast_hex"] = primary_color_contrast_hex
        if secondary_color_contrast_hex is not None:
            request_data["secondary_color_contrast_hex"] = secondary_color_contrast_hex
        if loading_page_touch_point_variant is not None:
            request_data["loading_page_touch_point_variant"] = LoadingPageTouchPointVariant(loading_page_touch_point_variant)

        theme_request = UpdateThemeRequest(**request_data)
        theme, _, err = await client.replace_brand_theme(brand_id, theme_id, theme_request)

        if err:
            logger.error(f"Okta API error while replacing theme {theme_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced theme: {theme_id}")
        return _serialize_theme(theme)

    except Exception as e:
        logger.error(f"Exception while replacing theme {theme_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# upload_brand_theme_logo
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id", "theme_id")
async def upload_brand_theme_logo(
    ctx: Context,
    brand_id: str,
    theme_id: str,
    file_path: str,
) -> Dict[str, Any]:
    """Upload and replace the logo for a theme.

    The file must be in PNG, JPG, or GIF format and less than 100 kB. For
    best results use landscape orientation, a transparent background, and a
    minimum size of 300 × 50 px to prevent upscaling.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        theme_id (str, required): The unique identifier of the theme.
        file_path (str, required): Absolute path to the image file on the server
            (e.g. ``"/tmp/my-logo.png"``).

    Returns:
        Dict containing:
        - url (str): CDN URL of the uploaded logo.
        - error (str): Present only when the operation fails.
    """
    logger.info(f"Uploading logo for theme {theme_id}, brand {brand_id}: {file_path}")

    if not os.path.isfile(file_path):
        return {"error": f"File not found: {file_path}"}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        with open(file_path, "rb") as fh:
            file_bytes = fh.read()

        client = await get_okta_client(manager)
        result, _, err = await client.upload_brand_theme_logo(brand_id, theme_id, file_bytes)

        if err:
            logger.error(f"Okta API error while uploading logo for theme {theme_id}: {err}")
            return {"error": str(err)}

        url = getattr(result, "url", None) if result else None
        logger.info(f"Successfully uploaded logo for theme {theme_id}: {url}")
        return {"url": url}

    except Exception as e:
        logger.error(f"Exception while uploading logo for theme {theme_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# delete_brand_theme_logo
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id", "theme_id")
async def delete_brand_theme_logo(
    ctx: Context,
    brand_id: str,
    theme_id: str,
) -> Dict[str, Any]:
    """Delete the custom logo for a theme.

    After deletion the theme falls back to the default Okta logo. This
    operation is reversible — you can re-upload a logo at any time.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        theme_id (str, required): The unique identifier of the theme.

    Returns:
        Dict with a ``message`` key on success, or an ``error`` key on failure.
    """
    logger.info(f"Requesting delete confirmation for logo of theme: {theme_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    outcome = await elicit_or_fallback(
        ctx,
        DELETE_THEME_LOGO.format(theme_id=theme_id),
        DeleteConfirmation,
    )

    if not outcome or not outcome.confirmed:
        logger.info(f"Deletion of logo for theme {theme_id!r} cancelled by user")
        return {
            "success": False,
            "message": f"Deletion of logo for theme {theme_id!r} was cancelled.",
        }

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_brand_theme_logo(brand_id, theme_id)

        if err:
            logger.error(f"Okta API error while deleting logo for theme {theme_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deleted logo for theme: {theme_id}")
        return {
            "success": True,
            "message": f"Logo for theme {theme_id!r} deleted successfully. The theme now uses the default Okta logo.",
        }

    except Exception as e:
        logger.error(f"Exception while deleting logo for theme {theme_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# upload_brand_theme_favicon
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id", "theme_id")
async def upload_brand_theme_favicon(
    ctx: Context,
    brand_id: str,
    theme_id: str,
    file_path: str,
) -> Dict[str, Any]:
    """Upload and replace the favicon for a theme.

    The file must be in PNG, JPG, or GIF format and less than 2 MB in size.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        theme_id (str, required): The unique identifier of the theme.
        file_path (str, required): Absolute path to the image file on the server
            (e.g. ``"/tmp/my-favicon.png"``).

    Returns:
        Dict containing:
        - url (str): CDN URL of the uploaded favicon.
        - error (str): Present only when the operation fails.
    """
    logger.info(f"Uploading favicon for theme {theme_id}, brand {brand_id}: {file_path}")

    if not os.path.isfile(file_path):
        return {"error": f"File not found: {file_path}"}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        with open(file_path, "rb") as fh:
            file_bytes = fh.read()

        client = await get_okta_client(manager)
        result, _, err = await client.upload_brand_theme_favicon(brand_id, theme_id, file_bytes)

        if err:
            logger.error(f"Okta API error while uploading favicon for theme {theme_id}: {err}")
            return {"error": str(err)}

        url = getattr(result, "url", None) if result else None
        logger.info(f"Successfully uploaded favicon for theme {theme_id}: {url}")
        return {"url": url}

    except Exception as e:
        logger.error(f"Exception while uploading favicon for theme {theme_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# delete_brand_theme_favicon
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id", "theme_id")
async def delete_brand_theme_favicon(
    ctx: Context,
    brand_id: str,
    theme_id: str,
) -> Dict[str, Any]:
    """Delete the custom favicon for a theme.

    After deletion the theme falls back to the default Okta favicon. This
    operation is reversible — you can re-upload a favicon at any time.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        theme_id (str, required): The unique identifier of the theme.

    Returns:
        Dict with a ``message`` key on success, or an ``error`` key on failure.
    """
    logger.info(f"Requesting delete confirmation for favicon of theme: {theme_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    outcome = await elicit_or_fallback(
        ctx,
        DELETE_THEME_FAVICON.format(theme_id=theme_id),
        DeleteConfirmation,
    )

    if not outcome or not outcome.confirmed:
        logger.info(f"Deletion of favicon for theme {theme_id!r} cancelled by user")
        return {
            "success": False,
            "message": f"Deletion of favicon for theme {theme_id!r} was cancelled.",
        }

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_brand_theme_favicon(brand_id, theme_id)

        if err:
            logger.error(f"Okta API error while deleting favicon for theme {theme_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deleted favicon for theme: {theme_id}")
        return {
            "success": True,
            "message": f"Favicon for theme {theme_id!r} deleted successfully. The theme now uses the default Okta favicon.",
        }

    except Exception as e:
        logger.error(f"Exception while deleting favicon for theme {theme_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# upload_brand_theme_background_image
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id", "theme_id")
async def upload_brand_theme_background_image(
    ctx: Context,
    brand_id: str,
    theme_id: str,
    file_path: str,
) -> Dict[str, Any]:
    """Upload and replace the background image for a theme.

    The file must be in PNG, JPG, or GIF format and less than 2 MB in size.
    The background image is used by touchpoint variants that reference
    ``BACKGROUND_IMAGE``.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        theme_id (str, required): The unique identifier of the theme.
        file_path (str, required): Absolute path to the image file on the server
            (e.g. ``"/tmp/background.png"``).

    Returns:
        Dict containing:
        - url (str): CDN URL of the uploaded background image.
        - error (str): Present only when the operation fails.
    """
    logger.info(f"Uploading background image for theme {theme_id}, brand {brand_id}: {file_path}")

    if not os.path.isfile(file_path):
        return {"error": f"File not found: {file_path}"}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        with open(file_path, "rb") as fh:
            file_bytes = fh.read()

        client = await get_okta_client(manager)
        result, _, err = await client.upload_brand_theme_background_image(brand_id, theme_id, file_bytes)

        if err:
            logger.error(f"Okta API error while uploading background image for theme {theme_id}: {err}")
            return {"error": str(err)}

        url = getattr(result, "url", None) if result else None
        logger.info(f"Successfully uploaded background image for theme {theme_id}: {url}")
        return {"url": url}

    except Exception as e:
        logger.error(f"Exception while uploading background image for theme {theme_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# delete_brand_theme_background_image
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id", "theme_id")
async def delete_brand_theme_background_image(
    ctx: Context,
    brand_id: str,
    theme_id: str,
) -> Dict[str, Any]:
    """Delete the background image for a theme.

    After deletion the theme no longer has a background image. Touchpoint
    variants that referenced ``BACKGROUND_IMAGE`` will fall back to their
    default appearance. This operation is reversible — you can re-upload a
    background image at any time.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.
        theme_id (str, required): The unique identifier of the theme.

    Returns:
        Dict with a ``message`` key on success, or an ``error`` key on failure.
    """
    logger.info(f"Requesting delete confirmation for background image of theme: {theme_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    outcome = await elicit_or_fallback(
        ctx,
        DELETE_THEME_BACKGROUND_IMAGE.format(theme_id=theme_id),
        DeleteConfirmation,
    )

    if not outcome or not outcome.confirmed:
        logger.info(f"Deletion of background image for theme {theme_id!r} cancelled by user")
        return {
            "success": False,
            "message": f"Deletion of background image for theme {theme_id!r} was cancelled.",
        }

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_brand_theme_background_image(brand_id, theme_id)

        if err:
            logger.error(f"Okta API error while deleting background image for theme {theme_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deleted background image for theme: {theme_id}")
        return {
            "success": True,
            "message": f"Background image for theme {theme_id!r} deleted successfully.",
        }

    except Exception as e:
        logger.error(f"Exception while deleting background image for theme {theme_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}
