# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Brands tools for the Okta MCP server.

Brands allow you to customise the Okta-hosted sign-in page, error pages,
email templates, and the End-User Dashboard. This module exposes MCP tools
for every operation available in the Brands API:

    - list_brands         GET  /api/v1/brands
    - get_brand           GET  /api/v1/brands/{brandId}
    - create_brand        POST /api/v1/brands
    - replace_brand       PUT  /api/v1/brands/{brandId}
    - delete_brand        DELETE /api/v1/brands/{brandId}
    - list_brand_domains  GET  /api/v1/brands/{brandId}/domains
"""

from typing import Any, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import Context
from okta.models.brand_request import BrandRequest
from okta.models.create_brand_request import CreateBrandRequest
from okta.models.default_app import DefaultApp

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DELETE_BRAND
from okta_mcp_server.utils.pagination import create_paginated_response, paginate_all_results
from okta_mcp_server.utils.validation import validate_ids


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _serialize_brand(brand) -> Dict[str, Any]:
    """Serialize a brand Pydantic model to a plain dict with camelCase keys.

    Uses ``model_dump(by_alias=True)`` so that read-only server-assigned
    fields (``id``, ``isDefault``) are included alongside writable fields.
    ``None`` values are excluded to keep the payload compact.
    """
    if brand is None:
        return {}
    if hasattr(brand, "model_dump"):
        return brand.model_dump(by_alias=True, exclude_none=True)
    # Fallback for non-Pydantic objects
    return dict(brand)


def _build_default_app(default_app_dict: Dict[str, Any]) -> DefaultApp:
    """Convert a user-supplied dict into a ``DefaultApp`` model.

    Accepts both camelCase keys (``appInstanceId``) and snake_case keys
    (``app_instance_id``) because Pydantic resolves both via its alias
    configuration.
    """
    return DefaultApp(**default_app_dict)


# ---------------------------------------------------------------------------
# list_brands
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_brands(
    ctx: Context,
    expand: Optional[List[str]] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    q: Optional[str] = None,
    fetch_all: bool = False,
) -> dict:
    """List all brands in the Okta organization with pagination support.

    Parameters:
        expand (List[str], optional): Additional metadata to embed in each brand object.
            Valid values: "themes", "domains", "emailDomain".
            Example: ["themes", "emailDomain"]
        after (str, optional): Opaque pagination cursor obtained from the ``next_cursor``
            field of a previous response. Used to fetch the next page.
        limit (int, optional): Maximum number of brands to return per page (1–200).
            Defaults to 20 when omitted.
        q (str, optional): Case-insensitive search string that filters brands by name.
        fetch_all (bool, optional): When True the tool automatically follows pagination
            links and returns all brands in a single response. Default: False.

    Examples:
        - First page, no extras:   list_brands()
        - Include theme data:      list_brands(expand=["themes"])
        - Search by name:          list_brands(q="Default")
        - Next page manually:      list_brands(after="<cursor>")
        - All brands at once:      list_brands(fetch_all=True)

    Returns:
        Dict containing:
        - items (List[Dict]): List of brand objects.
        - total_fetched (int): Number of brands in this response.
        - has_more (bool): True if additional pages are available.
        - next_cursor (str | None): Cursor value for the next page.
        - fetch_all_used (bool): True when fetch_all was used.
        - pagination_info (Dict): Detailed stats when fetch_all=True.
    """
    logger.info("Listing brands from Okta organization")
    logger.debug(f"expand={expand}, after='{after}', limit={limit}, q='{q}', fetch_all={fetch_all}")

    # Clamp limit to the valid range
    if limit is not None:
        if limit < 1:
            logger.warning(f"Limit {limit} is below minimum (1), setting to 1")
            limit = 1
        elif limit > 200:
            logger.warning(f"Limit {limit} exceeds maximum (200), setting to 200")
            limit = 200

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        kwargs: Dict[str, Any] = {}
        if expand:
            kwargs["expand"] = expand
        if after:
            kwargs["after"] = after
        if limit:
            kwargs["limit"] = limit
        if q:
            kwargs["q"] = q

        logger.debug("Calling Okta API to list brands")
        brands, response, err = await client.list_brands(**kwargs)

        if err:
            logger.error(f"Okta API error while listing brands: {err}")
            return {"error": str(err)}

        if not brands:
            logger.info("No brands found")
            return create_paginated_response([], response, fetch_all)

        if fetch_all and response and hasattr(response, "has_next") and response.has_next():
            logger.info(f"fetch_all=True, auto-paginating from initial {len(brands)} brand(s)")
            all_brands, pagination_info = await paginate_all_results(response, brands)
            serialized = [_serialize_brand(b) for b in all_brands]
            logger.info(
                f"Successfully retrieved {len(all_brands)} brand(s) across "
                f"{pagination_info['pages_fetched']} page(s)"
            )
            return create_paginated_response(serialized, response, fetch_all_used=True, pagination_info=pagination_info)

        serialized = [_serialize_brand(b) for b in brands]
        logger.info(f"Successfully retrieved {len(brands)} brand(s)")
        return create_paginated_response(serialized, response, fetch_all_used=fetch_all)

    except Exception as e:
        logger.error(f"Exception while listing brands: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# get_brand
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def get_brand(
    ctx: Context,
    brand_id: str,
    expand: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Retrieve a specific brand by its ID.

    Parameters:
        brand_id (str, required): The unique identifier of the brand (e.g. ``bnd114iNkrcN6aR680g4``).
        expand (List[str], optional): Additional metadata to embed in the response.
            Valid values: "themes", "domains", "emailDomain".

    Returns:
        Dict containing the brand object, or an ``error`` key on failure.
    """
    logger.info(f"Retrieving brand: {brand_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        kwargs: Dict[str, Any] = {}
        if expand:
            kwargs["expand"] = expand

        brand, _, err = await client.get_brand(brand_id, **kwargs)

        if err:
            logger.error(f"Okta API error while retrieving brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved brand: {brand_id}")
        return _serialize_brand(brand)

    except Exception as e:
        logger.error(f"Exception while retrieving brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# create_brand
# ---------------------------------------------------------------------------

@mcp.tool()
async def create_brand(
    ctx: Context,
    name: str,
) -> Dict[str, Any]:
    """Create a new brand in the Okta organization.

    A brand controls the look-and-feel of the sign-in page, error pages,
    email templates, and the End-User Dashboard.  After creation you can
    customise it further with ``replace_brand`` and the Themes API.

    Parameters:
        name (str, required): Display name for the new brand.
            Must be unique within the org.
            The reserved name ``DRAPP_DOMAIN_BRAND`` is not allowed.

    Returns:
        Dict containing the newly created brand object, or an ``error`` key on failure.
    """
    logger.info(f"Creating brand with name: '{name}'")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        # Check for an existing brand with the same name before creating.
        existing_brands, _, list_err = await client.list_brands()
        if not list_err and existing_brands:
            for existing in existing_brands:
                if getattr(existing, "name", None) == name:
                    existing_id = getattr(existing, "id", "unknown")
                    logger.warning(
                        f"Brand with name '{name}' already exists (id: {existing_id})"
                    )
                    return {
                        "error": (
                            f"A brand named '{name}' already exists (id: {existing_id!r}). "
                            "Use list_brands() to find it or choose a different name."
                        )
                    }

        create_request = CreateBrandRequest(name=name)
        brand, _, err = await client.create_brand(create_request)

        if err:
            logger.error(f"Okta API error while creating brand '{name}': {err}")
            return {"error": str(err)}

        logger.info(f"Successfully created brand '{name}' with ID: {getattr(brand, 'id', 'unknown')}")
        return _serialize_brand(brand)

    except Exception as e:
        logger.error(f"Exception while creating brand '{name}': {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# replace_brand
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def replace_brand(
    ctx: Context,
    brand_id: str,
    name: str,
    agree_to_custom_privacy_policy: Optional[bool] = None,
    custom_privacy_policy_url: Optional[str] = None,
    remove_powered_by_okta: Optional[bool] = None,
    locale: Optional[str] = None,
    email_domain_id: Optional[str] = None,
    default_app: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Replace (fully update) a brand by its ID.

    This is a full replacement (HTTP PUT). Every writable field in the brand
    will be overwritten — omitted optional fields revert to their defaults.

    Parameters:
        brand_id (str, required): The unique identifier of the brand to update.
        name (str, required): New display name for the brand.
            The reserved name ``DRAPP_DOMAIN_BRAND`` is not allowed.
        agree_to_custom_privacy_policy (bool, optional): Must be ``True`` when
            providing a ``custom_privacy_policy_url``. Not required when clearing
            the URL.
        custom_privacy_policy_url (str, optional): HTTPS URL of your custom
            privacy policy page.  Requires ``agree_to_custom_privacy_policy=True``.
            Pass ``null`` / omit to reset to the Okta default.
        remove_powered_by_okta (bool, optional): When ``True``, removes the
            "Powered by Okta" footer from the sign-in page and the End-User
            Dashboard.  Defaults to ``False``.
        locale (str, optional): IETF BCP 47 language tag for the brand's locale
            (e.g. ``"en"``, ``"fr"``, ``"de"``).
        email_domain_id (str, optional): ID of an email domain to associate with
            this brand (controls the ``From`` address for brand emails).
        default_app (dict, optional): The application shown by default when a
            user navigates to the brand's Okta-hosted domain.  Accepted keys:
            - ``appInstanceId`` (str | None): ID of the app instance.
            - ``appLinkName`` (str | None): App link name.
            - ``classicApplicationUri`` (str | None): URI for classic (Okta1) apps.

    Returns:
        Dict containing the updated brand object, or an ``error`` key on failure.
    """
    logger.info(f"Replacing brand: {brand_id}")
    logger.debug(
        f"name='{name}', locale='{locale}', removePoweredByOkta={remove_powered_by_okta}, "
        f"customPrivacyPolicyUrl='{custom_privacy_policy_url}'"
    )

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        # Build the BrandRequest model — only include fields the caller supplied
        brand_data: Dict[str, Any] = {"name": name}

        if agree_to_custom_privacy_policy is not None:
            brand_data["agreeToCustomPrivacyPolicy"] = agree_to_custom_privacy_policy
        if custom_privacy_policy_url is not None:
            brand_data["customPrivacyPolicyUrl"] = custom_privacy_policy_url
        if remove_powered_by_okta is not None:
            brand_data["removePoweredByOkta"] = remove_powered_by_okta
        if locale is not None:
            brand_data["locale"] = locale
        if email_domain_id is not None:
            brand_data["emailDomainId"] = email_domain_id
        if default_app is not None:
            brand_data["defaultApp"] = _build_default_app(default_app)

        brand_request = BrandRequest(**brand_data)
        brand, _, err = await client.replace_brand(brand_id, brand_request)

        if err:
            logger.error(f"Okta API error while replacing brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced brand: {brand_id}")
        return _serialize_brand(brand)

    except Exception as e:
        logger.error(f"Exception while replacing brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# delete_brand
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def delete_brand(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """Delete a brand by its ID.

    The user is asked to confirm before the deletion is carried out.
    The default (Okta) brand cannot be deleted — the API will return a 409
    error in that case.

    Parameters:
        brand_id (str, required): The unique identifier of the brand to delete.

    Returns:
        Dict with a ``message`` key on success, or an ``error`` key on failure.
    """
    logger.warning(f"Deletion requested for brand: {brand_id}")

    outcome = await elicit_or_fallback(
        ctx=ctx,
        message=DELETE_BRAND.format(brand_id=brand_id),
        schema=DeleteConfirmation,
        fallback_payload={
            "confirmation_required": True,
            "message": (
                f"Deletion of brand {brand_id} requires explicit confirmation. "
                f"Please confirm that you want to permanently delete this brand."
            ),
        },
    )

    if not outcome.used_elicitation:
        return outcome.fallback_response

    if not outcome.confirmed:
        logger.info(f"Brand deletion cancelled by user for brand: {brand_id}")
        return {"message": f"Deletion of brand {brand_id} was cancelled."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_brand(brand_id)

        if err:
            logger.error(f"Okta API error while deleting brand {brand_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deleted brand: {brand_id}")
        return {"message": f"Brand {brand_id} deleted successfully."}

    except Exception as e:
        logger.error(f"Exception while deleting brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# list_brand_domains
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("brand_id")
async def list_brand_domains(
    ctx: Context,
    brand_id: str,
) -> Dict[str, Any]:
    """List all custom domains associated with a brand.

    Each brand can have one or more domains.  The default Okta subdomain
    (e.g. ``yourorg.okta.com``) is always present; additional custom domains
    appear here once they have been verified and activated.

    Parameters:
        brand_id (str, required): The unique identifier of the brand.

    Returns:
        Dict containing:
        - domains (List[Dict]): List of domain objects associated with the brand.
          Each domain object includes: ``id``, ``domain``, ``certificateSourceType``,
          ``validationStatus``, ``brandId``, and ``_links``.
        - total_fetched (int): Number of domains returned.
        - error (str): Present only when the operation fails.
    """
    logger.info(f"Listing domains for brand: {brand_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        brand_domains, _, err = await client.list_brand_domains(brand_id)

        if err:
            logger.error(f"Okta API error while listing domains for brand {brand_id}: {err}")
            return {"error": str(err)}

        if brand_domains is None:
            logger.info(f"No domains found for brand: {brand_id}")
            return {"domains": [], "total_fetched": 0}

        # brand_domains is a BrandDomains model with a .domains list attribute
        raw_domains = getattr(brand_domains, "domains", None) or []
        serialized: List[Dict[str, Any]] = []
        for domain in raw_domains:
            if hasattr(domain, "model_dump"):
                serialized.append(domain.model_dump(by_alias=True, exclude_none=True))
            else:
                serialized.append(dict(domain))

        logger.info(f"Successfully retrieved {len(serialized)} domain(s) for brand: {brand_id}")
        return {
            "domains": serialized,
            "total_fetched": len(serialized),
        }

    except Exception as e:
        logger.error(f"Exception while listing domains for brand {brand_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}
