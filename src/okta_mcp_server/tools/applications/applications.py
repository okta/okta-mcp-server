# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Any, Dict, Optional

import okta.models as okta_models
from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp

# Mapping of signOnMode -> Okta SDK model class for proper serialization
_SIGN_ON_MODE_MODEL_MAP: Dict[str, Any] = {
    "BOOKMARK": okta_models.BookmarkApplication,
    "AUTO_LOGIN": okta_models.AutoLoginApplication,
    "BASIC_AUTH": okta_models.BasicAuthApplication,
    "BROWSER_PLUGIN": okta_models.BrowserPluginApplication,
    "OPENID_CONNECT": okta_models.OpenIdConnectApplication,
    "SAML_1_1": okta_models.Saml11Application,
    "SAML_2_0": okta_models.SamlApplication,
    "SECURE_PASSWORD_STORE": okta_models.SecurePasswordStoreApplication,
    "WS_FEDERATION": okta_models.WsFederationApplication,
}


def _build_application_model(app_config: Dict[str, Any]) -> Any:
    """Convert a plain dict to the appropriate Okta SDK Application model.

    The SDK v3 requires typed model objects, not plain dicts. Without this,
    subclass-specific fields like `name`, `settings`, and `visibility` are
    silently dropped by the base Application model, causing API validation errors.
    """
    sign_on_mode = app_config.get("signOnMode") or app_config.get("sign_on_mode", "")
    model_cls = _SIGN_ON_MODE_MODEL_MAP.get(str(sign_on_mode).upper(), okta_models.Application)
    logger.debug(f"Using model class '{model_cls.__name__}' for signOnMode '{sign_on_mode}'")
    return model_cls(**app_config)


from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeactivateConfirmation, DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DEACTIVATE_APPLICATION, DELETE_APPLICATION
from okta_mcp_server.utils.pagination import build_query_params, create_paginated_response, extract_after_cursor, paginate_all_results
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
@require_scopes("okta.apps.read", error_return_type="list")
async def list_applications(
    ctx: Context,
    q: Optional[str] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    filter: Optional[str] = None,
    expand: Optional[str] = None,
    include_non_deleted: Optional[bool] = None,
    fetch_all: bool = False,
) -> dict:
    """List all applications from the Okta organization.

    Parameters:
        q (str, optional): Searches for applications by label, property, or link
        after (str, optional): Specifies the pagination cursor for the next page of results
        limit (int, optional): Specifies the number of results per page (min 20, max 100)
        filter (str, optional): Filters applications by status, user.id, group.id, or credentials.signing.kid
        expand (str, optional): Expands the app user object to include the user's profile or expand the app group
        object to include the group's profile
        include_non_deleted (bool, optional): Include non-deleted applications in the results
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.

    Examples:
        For pagination:
        - First call: list_applications()
        - Next page: list_applications(after="cursor_value")
        - All pages: list_applications(fetch_all=True)

    Returns:
        Dict containing:
        - items: List of application objects
        - total_fetched: Number of applications returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Listing applications from Okta organization")
    logger.debug(f"Query parameters: q='{q}', filter='{filter}', limit={limit}, fetch_all={fetch_all}")

    # Validate limit parameter range
    if limit is not None:
        if limit < 20:
            logger.warning(f"Limit {limit} is below minimum (20), setting to 20")
            limit = 20
        elif limit > 100:
            logger.warning(f"Limit {limit} exceeds maximum (100), setting to 100")
            limit = 100

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(
            q=q, after=after, limit=limit, filter=filter, expand=expand,
            include_non_deleted=include_non_deleted,
        )

        logger.debug("Calling Okta API to list applications")
        apps, response, err = await client.list_applications(**query_params)

        if err:
            logger.error(f"Okta API error while listing applications: {err}")
            return {"error": str(err)}

        if not apps:
            logger.info("No applications found")
            return create_paginated_response([], response, fetch_all)

        app_count = len(apps)
        logger.debug(f"Retrieved {app_count} applications in first page")

        _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))
        if fetch_all and response and _has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {app_count} applications")

            async def _next_page(cursor):
                p = dict(query_params)
                p["after"] = cursor
                return await client.list_applications(**p)

            async def _on_page(pages, total):
                await ctx.info(f"Fetching applications... {total} fetched so far ({pages} pages)")

            all_apps, pagination_info = await paginate_all_results(
                response, apps, next_page_fn=_next_page, on_page=_on_page
            )
            logger.info(
                f"Successfully retrieved {len(all_apps)} applications across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(all_apps, response, fetch_all_used=True, pagination_info=pagination_info)
        else:
            logger.info(f"Successfully retrieved {app_count} applications")
            return create_paginated_response(apps, response, fetch_all_used=fetch_all)
    except Exception as e:
        logger.error(f"Exception while listing applications: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.read")
@validate_ids("app_id", error_return_type="dict")
async def get_application(ctx: Context, app_id: str, expand: Optional[str] = None) -> Any:
    """Get an application by ID from the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to retrieve
        expand (str, optional): Expands the app user object to include the user's profile or expand the
        app group object

    Returns:
        Dictionary containing the application details or error information.
    """
    logger.info(f"Getting application with ID: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        query_params = {}
        if expand:
            query_params["expand"] = expand

        app, _, err = await client.get_application(app_id, **query_params)

        if err:
            logger.error(f"Okta API error while getting application {app_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved application: {app_id}")
        return app
    except Exception as e:
        logger.error(f"Exception while getting application {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage")
async def create_application(ctx: Context, app_config: Dict[str, Any], activate: bool = True) -> Any:
    """Create a new application in the Okta organization.

    Parameters:
        app_config (dict, required): The application configuration including name, label, signOnMode, settings, etc.
        activate (bool, optional): Execute activation lifecycle operation after creation. Defaults to True.

    Returns:
        Dictionary containing the created application details or error information.
    """
    logger.info("Creating new application in Okta organization")
    logger.debug(f"Application label: {app_config.get('label', 'N/A')}, name: {app_config.get('name', 'N/A')}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        application_model = _build_application_model(app_config)
        logger.debug("Calling Okta API to create application")
        app, _, err = await client.create_application(application_model, activate)

        if err:
            logger.error(f"Okta API error while creating application: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully created application")
        return app
    except Exception as e:
        logger.error(f"Exception while creating application: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage")
@validate_ids("app_id", error_return_type="dict")
async def update_application(ctx: Context, app_id: str, app_config: Dict[str, Any]) -> Any:
    """Update an application by ID in the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to update
        app_config (dict, required): The updated application configuration

    Returns:
        Dictionary containing the updated application details or error information.
    """
    logger.info(f"Updating application with ID: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        application_model = _build_application_model(app_config)
        logger.debug(f"Calling Okta API to update application {app_id}")
        app, _, err = await client.replace_application(app_id, application_model)

        if err:
            logger.error(f"Okta API error while updating application {app_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully updated application: {app_id}")
        return app
    except Exception as e:
        logger.error(f"Exception while updating application {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage", error_return_type="list")
@validate_ids("app_id")
async def delete_application(ctx: Context, app_id: str) -> list:
    """Delete an application by ID from the Okta organization.

    This tool deletes an application by its ID from the Okta organization.
    The user will be asked for confirmation before the deletion proceeds.

    Parameters:
        app_id (str, required): The ID of the application to delete

    Returns:
        List containing the result of the deletion operation.
    """
    logger.warning(f"Deletion requested for application {app_id}")

    fallback_payload = {
        "confirmation_required": True,
        "message": (
            f"To confirm deletion of application {app_id}, please call the "
            f"'confirm_delete_application' tool with app_id='{app_id}' and "
            f"confirmation='DELETE'."
        ),
        "app_id": app_id,
        "tool_to_use": "confirm_delete_application",
    }

    outcome = await elicit_or_fallback(
        ctx,
        message=DELETE_APPLICATION.format(app_id=app_id),
        schema=DeleteConfirmation,
        fallback_payload=fallback_payload,
    )

    if not outcome.used_elicitation:
        logger.info(f"Elicitation unavailable for application {app_id} — returning fallback confirmation prompt")
        return [outcome.fallback_response]

    if not outcome.confirmed:
        logger.info(f"Application deletion cancelled for {app_id}")
        return [{"message": "Application deletion cancelled by user."}]

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to delete application {app_id}")

        result = await client.delete_application(app_id)
        err = result[-1]

        if err:
            logger.error(f"Okta API error while deleting application {app_id}: {err}")
            return [{"error": f"Error: {err}"}]

        logger.info(f"Successfully deleted application: {app_id}")
        return [{"message": f"Application {app_id} deleted successfully"}]
    except Exception as e:
        logger.error(f"Exception while deleting application {app_id}: {type(e).__name__}: {e}")
        return [{"error": f"Exception: {e}"}]


@mcp.tool()
@require_scopes("okta.apps.manage", error_return_type="list")
@validate_ids("app_id")
async def confirm_delete_application(ctx: Context, app_id: str, confirmation: str) -> list:
    """Confirm and execute application deletion after receiving confirmation.

    .. deprecated::
        This tool exists for backward compatibility with clients that do not
        support MCP elicitation.  New clients should rely on the built-in
        elicitation prompt in ``delete_application`` instead.

    This function MUST ONLY be called after the human user has explicitly typed 'DELETE' as confirmation.
    NEVER call this function automatically after delete_application.

    Parameters:
        app_id (str, required): The ID of the application to delete
        confirmation (str, required): Must be 'DELETE' to confirm deletion

    Returns:
        List containing the result of the deletion operation.
    """
    logger.info(f"Processing deletion confirmation for application {app_id} (deprecated flow)")

    if confirmation != "DELETE":
        logger.warning(f"Application deletion cancelled for {app_id} - incorrect confirmation")
        return ["Error: Deletion cancelled. Confirmation 'DELETE' was not provided correctly."]

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to delete application {app_id}")

        result = await client.delete_application(app_id)
        err = result[-1]

        if err:
            logger.error(f"Okta API error while deleting application {app_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully deleted application: {app_id}")
        return [f"Application {app_id} deleted successfully"]
    except Exception as e:
        logger.error(f"Exception while deleting application {app_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
@require_scopes("okta.apps.manage", error_return_type="list")
@validate_ids("app_id")
async def activate_application(ctx: Context, app_id: str) -> list:
    """Activate an application in the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to activate

    Returns:
        List containing the result of the activation operation.
    """
    logger.info(f"Activating application: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to activate application {app_id}")

        result = await client.activate_application(app_id)
        err = result[-1]

        if err:
            logger.error(f"Okta API error while activating application {app_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully activated application: {app_id}")
        return [f"Application {app_id} activated successfully"]
    except Exception as e:
        logger.error(f"Exception while activating application {app_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
@require_scopes("okta.apps.manage", error_return_type="list")
@validate_ids("app_id")
async def deactivate_application(ctx: Context, app_id: str) -> list:
    """Deactivate an application in the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to deactivate

    Returns:
        List containing the result of the deactivation operation.
    """
    logger.info(f"Deactivation requested for application: {app_id}")

    outcome = await elicit_or_fallback(
        ctx,
        message=DEACTIVATE_APPLICATION.format(app_id=app_id),
        schema=DeactivateConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Application deactivation cancelled for {app_id}")
        return [{"message": "Application deactivation cancelled by user."}]

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to deactivate application {app_id}")

        result = await client.deactivate_application(app_id)
        err = result[-1]

        if err:
            logger.error(f"Okta API error while deactivating application {app_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully deactivated application: {app_id}")
        return [f"Application {app_id} deactivated successfully"]
    except Exception as e:
        logger.error(f"Exception while deactivating application {app_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


# ---------------------------------------------------------------------------
# Provisioning (outbound SCIM / directory sync)
# ---------------------------------------------------------------------------


def _provisioning_unsupported_error(connection: Dict[str, Any], app_id: str) -> Optional[Dict[str, Any]]:
    """Detect Okta's "provisioning not supported" sentinel.

    When an app does not support outbound provisioning, Okta returns HTTP 200
    (no error) with the connection ``status`` and ``profile.authScheme`` both set
    to ``UNKNOWN`` instead of a 4xx. Without this guard the tool returns that body
    as if the connection were configured. Returns an error dict when the sentinel
    is detected, otherwise None.
    """
    status = connection.get("status")
    auth_scheme = (connection.get("profile") or {}).get("authScheme")
    if status == "UNKNOWN" and auth_scheme == "UNKNOWN":
        return {
            "error": (
                f"Provisioning is not enabled or supported on application {app_id} "
                f"(Okta returned status=UNKNOWN). Outbound SCIM provisioning only works "
                f"on a provisioning-capable app; a plain custom SAML/OIDC app cannot be "
                f"pointed at a SCIM endpoint."
            )
        }
    return None


@mcp.tool()
@require_scopes("okta.apps.read")
@validate_ids("app_id", error_return_type="dict")
async def get_app_provisioning_connection(ctx: Context, app_id: str) -> Any:
    """Get the provisioning (SCIM) connection configuration for an application.

    Returns the connection's base URL, auth scheme, and status (the bearer token
    itself is never returned by Okta).

    Parameters:
        app_id (str, required): The ID of the application

    Returns:
        Dict with the provisioning connection details, or error information.
    """
    logger.info(f"Getting provisioning connection for application: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        connection, _, err = await client.get_default_provisioning_connection_for_application(app_id)

        if err:
            logger.error(f"Okta API error while getting provisioning connection for {app_id}: {err}")
            return {"error": str(err)}

        if not connection:
            return {}
        conn_dict = connection.to_dict()
        unsupported = _provisioning_unsupported_error(conn_dict, app_id)
        if unsupported:
            return unsupported

        logger.info(f"Successfully retrieved provisioning connection for application: {app_id}")
        return conn_dict
    except Exception as e:
        logger.error(f"Exception while getting provisioning connection for {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage")
@validate_ids("app_id", error_return_type="dict")
async def set_app_provisioning_connection(
    ctx: Context, app_id: str, base_url: str, token: str, activate: bool = True
) -> Any:
    """Configure the outbound SCIM provisioning connection for an application.

    Points the application at an external SCIM endpoint using bearer-token (HEADER)
    authentication, which is the common directory-sync setup.

    Parameters:
        app_id (str, required): The ID of the application
        base_url (str, required): The SCIM connector base URL of the external endpoint
        token (str, required): The bearer token used to authenticate to the SCIM endpoint
        activate (bool, optional): Activate the provisioning connection. Defaults to True.

    Returns:
        Dict with the updated provisioning connection details, or error information.
    """
    logger.info(f"Setting provisioning connection for application {app_id} (base_url={base_url})")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        # Build the request via from_dict so the oneOf union binds to the
        # token-auth variant; the plain constructor would drop base_url/token.
        request = okta_models.UpdateDefaultProvisioningConnectionForApplicationRequest.from_dict(
            {"baseUrl": base_url, "profile": {"authScheme": "TOKEN", "token": token}}
        )
        logger.debug(f"Calling Okta API to set provisioning connection for {app_id} (activate={activate})")

        connection, _, err = await client.update_default_provisioning_connection_for_application(
            app_id, request, activate
        )

        if err:
            logger.error(f"Okta API error while setting provisioning connection for {app_id}: {err}")
            return {"error": str(err)}

        if not connection:
            return {}
        conn_dict = connection.to_dict()
        unsupported = _provisioning_unsupported_error(conn_dict, app_id)
        if unsupported:
            logger.warning(f"Provisioning is not supported on application {app_id} (status=UNKNOWN)")
            return unsupported

        logger.info(f"Successfully set provisioning connection for application: {app_id}")
        return conn_dict
    except Exception as e:
        logger.error(f"Exception while setting provisioning connection for {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage")
@validate_ids("app_id", error_return_type="dict")
async def activate_app_provisioning_connection(ctx: Context, app_id: str) -> Any:
    """Activate the provisioning (SCIM) connection for an application.

    Parameters:
        app_id (str, required): The ID of the application

    Returns:
        Dict with the connection status or a success message, or error information.
    """
    logger.info(f"Activating provisioning connection for application: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        connection, _, err = await client.activate_default_provisioning_connection_for_application(app_id)

        if err:
            logger.error(f"Okta API error while activating provisioning connection for {app_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully activated provisioning connection for application: {app_id}")
        if connection:
            return connection.to_dict()
        return {"message": f"Provisioning connection activated for application {app_id}"}
    except Exception as e:
        logger.error(f"Exception while activating provisioning connection for {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage")
@validate_ids("app_id", error_return_type="dict")
async def deactivate_app_provisioning_connection(ctx: Context, app_id: str) -> Any:
    """Deactivate the provisioning (SCIM) connection for an application.

    Parameters:
        app_id (str, required): The ID of the application

    Returns:
        Dict with the connection status or a success message, or error information.
    """
    logger.info(f"Deactivating provisioning connection for application: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        connection, _, err = await client.deactivate_default_provisioning_connection_for_application(app_id)

        if err:
            logger.error(f"Okta API error while deactivating provisioning connection for {app_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deactivated provisioning connection for application: {app_id}")
        if connection:
            return connection.to_dict()
        return {"message": f"Provisioning connection deactivated for application {app_id}"}
    except Exception as e:
        logger.error(f"Exception while deactivating provisioning connection for {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.read")
@validate_ids("app_id", error_return_type="dict")
async def list_app_features(ctx: Context, app_id: str) -> Any:
    """List the provisioning features and their capabilities for an application.

    Features include ``USER_PROVISIONING`` (outbound to a SCIM target) and
    ``INBOUND_PROVISIONING``. Each entry reports its status and configured
    capabilities (create / update / deactivate users, group push).

    Parameters:
        app_id (str, required): The ID of the application

    Returns:
        Dict with a ``features`` list, or error information.
    """
    logger.info(f"Listing features for application: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        features, _, err = await client.list_features_for_application(app_id)

        if err:
            logger.error(f"Okta API error while listing features for {app_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully listed features for application: {app_id}")
        return {"features": [f.to_dict() for f in features] if features else []}
    except Exception as e:
        logger.error(f"Exception while listing features for {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage")
@validate_ids("app_id", error_return_type="dict")
async def update_app_feature(ctx: Context, app_id: str, feature_name: str, capabilities: Dict[str, Any]) -> Any:
    """Configure a provisioning feature's capabilities for an application.

    Use this to enable the provisioning actions for outbound SCIM directory sync.

    Parameters:
        app_id (str, required): The ID of the application
        feature_name (str, required): The feature to configure — ``USER_PROVISIONING``
            or ``INBOUND_PROVISIONING``.
        capabilities (dict, required): The capabilities object, e.g.
            ``{"create": {"lifecycleCreate": {"status": "ENABLED"}},
            "update": {"profile": {"status": "ENABLED"},
            "lifecycleDeactivate": {"status": "ENABLED"}}}``.

    Returns:
        Dict with the updated feature, or error information.
    """
    logger.info(f"Updating feature '{feature_name}' for application: {app_id}")

    try:
        feature_type = okta_models.ApplicationFeatureType(feature_name)
    except ValueError:
        valid = ", ".join(e.value for e in okta_models.ApplicationFeatureType)
        return {"error": f"Invalid feature_name '{feature_name}'. Must be one of: {valid}."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        # from_dict binds the oneOf capabilities union; the plain constructor would
        # serialize an empty body and silently no-op the configuration.
        request = okta_models.UpdateFeatureForApplicationRequest.from_dict(capabilities)
        logger.debug(f"Calling Okta API to update feature '{feature_name}' for {app_id}")

        feature, _, err = await client.update_feature_for_application(app_id, feature_type, request)

        if err:
            logger.error(f"Okta API error while updating feature '{feature_name}' for {app_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully updated feature '{feature_name}' for application: {app_id}")
        return feature.to_dict() if feature else {}
    except Exception as e:
        logger.error(f"Exception while updating feature '{feature_name}' for {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}
