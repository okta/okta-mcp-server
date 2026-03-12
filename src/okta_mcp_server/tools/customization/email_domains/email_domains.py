# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Email Domains tools for the Okta MCP server.

Email Domains let you customize the sender address on all transactional emails
that Okta sends to your users.  Instead of appearing to come from an
``@okta.com`` or ``@oktapreview.com`` address, messages can originate from
your own domain (e.g. ``noreply@yourcompany.com``).

After creating a domain you must add the returned DNS records at your DNS
provider and then call ``verify_email_domain``.  Okta validates ownership by
checking those records; the domain transitions through validation statuses
until it reaches ``VERIFIED``.

This module exposes MCP tools for every operation in the Email Domain API:

    - list_email_domains     GET    /api/v1/email-domains
    - create_email_domain    POST   /api/v1/email-domains
    - get_email_domain       GET    /api/v1/email-domains/{emailDomainId}
    - replace_email_domain   PUT    /api/v1/email-domains/{emailDomainId}
    - delete_email_domain    DELETE /api/v1/email-domains/{emailDomainId}
    - verify_email_domain    POST   /api/v1/email-domains/{emailDomainId}/verify

Validation status values: NOT_STARTED | POLLING | VERIFIED | ERROR | DELETED
DNS record fields        : recordType | fqdn | verificationValue
"""

from typing import Any, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import Context
from okta.models.email_domain import EmailDomain
from okta.models.update_email_domain import UpdateEmailDomain

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DELETE_EMAIL_DOMAIN
from okta_mcp_server.utils.validation import validate_ids

# ---------------------------------------------------------------------------
# Patch EmailDomainDNSRecordType to accept case-insensitive values.
# Okta's API returns lowercase record types (e.g. "cname") but the SDK enum
# only defines uppercase members ("CNAME", "TXT").
# ---------------------------------------------------------------------------
from okta.models.email_domain_dns_record_type import EmailDomainDNSRecordType as _DNSRecordType  # noqa: E402

for _member in list(_DNSRecordType):
    _lower = _member.value.lower()
    if _lower not in _DNSRecordType._value2member_map_:
        _DNSRecordType._value2member_map_[_lower] = _member


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _serialize(obj) -> Any:
    """Recursively serialise Pydantic SDK models to plain Python types."""
    if obj is None:
        return None
    if hasattr(obj, "model_dump"):
        return obj.model_dump(by_alias=True, exclude_none=True)
    if isinstance(obj, list):
        return [_serialize(item) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# list_email_domains
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_email_domains(
    ctx: Context,
    expand_brands: bool = False,
) -> Dict[str, Any]:
    """List all email domains in the Okta organization.

    Returns every Email Domain configured in the org.  Each domain shows
    its current validation status and the DNS records that must be published
    to complete verification.

    Parameters:
        expand_brands (bool, optional): When ``True``, embeds associated Brand
            objects in ``_embedded.brands`` for each returned domain.
            Default: ``False``.

    Returns:
        Dict containing:
        - ``email_domains`` (List[Dict]): List of email domain objects.
        - ``total_fetched`` (int): Number of domains returned.
        - ``error`` (str): Present only when the operation fails.

    Each email domain object includes:
    - ``id``                   – Unique email domain ID.
    - ``domain``               – The custom domain (e.g. ``"example.com"``).
    - ``displayName``          – Sender display name (e.g. ``"Acme IT"``).
    - ``userName``             – Local part of sender address (e.g. ``"noreply"``).
    - ``validationSubdomain``  – Mail subdomain prefix (default ``"mail"``).
    - ``validationStatus``     – ``NOT_STARTED`` | ``POLLING`` | ``VERIFIED`` |
                                 ``ERROR`` | ``DELETED``.
    - ``dnsValidationRecords`` – DNS records to publish: ``recordType``,
                                 ``fqdn``, ``verificationValue``.
    - ``_embedded.brands``     – Associated Brand objects (when
                                 ``expand_brands=True``).
    """
    logger.info(f"Listing email domains (expand_brands={expand_brands})")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    expand_param = ["brands"] if expand_brands else None

    try:
        client = await get_okta_client(manager)
        domain_list, _, err = await client.list_email_domains(expand=expand_param)

        if err:
            logger.error(f"Okta API error while listing email domains: {err}")
            return {"error": str(err)}

        domains = domain_list or []
        serialized = [_serialize(d) for d in domains]
        logger.info(f"Successfully retrieved {len(serialized)} email domain(s)")
        return {
            "email_domains": serialized,
            "total_fetched": len(serialized),
        }

    except Exception as e:
        logger.error(f"Exception while listing email domains: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# create_email_domain
# ---------------------------------------------------------------------------

@mcp.tool()
async def create_email_domain(
    ctx: Context,
    brand_id: str,
    domain: str,
    display_name: str,
    user_name: str,
    validation_subdomain: str = "mail",
) -> Dict[str, Any]:
    """Create a new email domain for the Okta organization.

    After creation the response includes DNS records (one TXT record and
    three CNAME records) that you must publish at your DNS provider.  Call
    ``verify_email_domain`` once the records are live to complete setup.

    Parameters:
        brand_id (str, required): ID of the Brand to associate with this
            email domain.  Example: ``"bnd1ab2cde3fGhIJK4l5"``
        domain (str, required): The custom domain to send email from.
            Example: ``"yourcompany.com"``
        display_name (str, required): The sender name shown in email clients.
            Example: ``"Acme IT Support"``
        user_name (str, required): Local part of the sender email address
            (before the ``@``).  Example: ``"noreply"`` → ``noreply@yourcompany.com``
        validation_subdomain (str, optional): Subdomain prefix used for the
            mail CNAME records.  Default: ``"mail"``

    Returns:
        Dict containing the created email domain object (including
        ``dnsValidationRecords`` to configure), or an ``error`` key on
        failure.

    Note:
        Each domain name must be unique in the org — attempting to create a
        domain that already exists returns an ``E0000197`` error.
    """
    logger.info(
        f"Creating email domain: domain={domain!r}, brandId={brand_id!r}, "
        f"displayName={display_name!r}, userName={user_name!r}"
    )
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        # Check for an existing email domain with the same name before creating.
        existing_list, _, list_err = await client.list_email_domains()
        if not list_err and existing_list:
            for existing in existing_list:
                if getattr(existing, "domain", None) == domain:
                    existing_id = getattr(existing, "id", "unknown")
                    logger.warning(
                        f"Email domain '{domain}' already exists (id: {existing_id})"
                    )
                    return {
                        "error": (
                            f"An email domain '{domain}' already exists (id: {existing_id!r}). "
                            "Use list_email_domains() to find it or choose a different domain."
                        )
                    }

        req = EmailDomain(
            brand_id=brand_id,
            domain=domain,
            display_name=display_name,
            user_name=user_name,
            validation_subdomain=validation_subdomain,
        )
        created, _, err = await client.create_email_domain(req)

        if err:
            logger.error(f"Okta API error while creating email domain {domain!r}: {err}")
            return {"error": str(err)}

        result = _serialize(created)
        logger.info(
            f"Successfully created email domain {domain!r} with id: {result.get('id')}"
        )
        return result

    except Exception as e:
        logger.error(f"Exception while creating email domain: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# get_email_domain
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("email_domain_id")
async def get_email_domain(
    ctx: Context,
    email_domain_id: str,
    expand_brands: bool = False,
) -> Dict[str, Any]:
    """Retrieve an email domain by its ID.

    Parameters:
        email_domain_id (str, required): Unique ID of the email domain
            (e.g. ``"OeD114iNkrcN6aR680g4"``).
        expand_brands (bool, optional): When ``True``, embeds associated Brand
            objects in ``_embedded.brands``.  Default: ``False``.

    Returns:
        Dict containing the email domain object, or an ``error`` key on
        failure.  Fields include ``id``, ``domain``, ``displayName``,
        ``userName``, ``validationStatus``, ``validationSubdomain``,
        ``dnsValidationRecords``, and (when expanded) ``_embedded.brands``.
    """
    logger.info(
        f"Retrieving email domain: {email_domain_id!r} (expand_brands={expand_brands})"
    )
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    expand_param = ["brands"] if expand_brands else None

    try:
        client = await get_okta_client(manager)
        domain, _, err = await client.get_email_domain(email_domain_id, expand=expand_param)

        if err:
            logger.error(
                f"Okta API error while retrieving email domain {email_domain_id!r}: {err}"
            )
            return {"error": str(err)}

        if domain is None:
            return {"error": f"Email domain {email_domain_id!r} not found."}

        logger.info(f"Successfully retrieved email domain: {email_domain_id}")
        return _serialize(domain)

    except Exception as e:
        logger.error(
            f"Exception while retrieving email domain {email_domain_id}: "
            f"{type(e).__name__}: {e}"
        )
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# replace_email_domain
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("email_domain_id")
async def replace_email_domain(
    ctx: Context,
    email_domain_id: str,
    display_name: str,
    user_name: str,
) -> Dict[str, Any]:
    """Replace the sender display name and username for an email domain.

    Only ``display_name`` and ``user_name`` can be updated — the domain
    name itself and validation subdomain are immutable after creation.
    The domain's validation status and DNS records are preserved.

    Parameters:
        email_domain_id (str, required): Unique ID of the email domain to
            update.
        display_name (str, required): New sender display name shown in email
            clients.  Example: ``"Acme Security Team"``
        user_name (str, required): New local part of the sender address
            (before the ``@``).  Example: ``"security"``

    Returns:
        Dict containing the updated email domain object, or an ``error`` key
        on failure.
    """
    logger.info(
        f"Replacing email domain {email_domain_id!r}: "
        f"displayName={display_name!r}, userName={user_name!r}"
    )
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        update = UpdateEmailDomain(
            display_name=display_name,
            user_name=user_name,
        )
        updated, _, err = await client.replace_email_domain(email_domain_id, update)

        if err:
            logger.error(
                f"Okta API error while replacing email domain {email_domain_id!r}: {err}"
            )
            return {"error": str(err)}

        result = _serialize(updated)
        logger.info(f"Successfully replaced email domain: {email_domain_id}")
        return result

    except Exception as e:
        logger.error(
            f"Exception while replacing email domain {email_domain_id}: "
            f"{type(e).__name__}: {e}"
        )
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# delete_email_domain
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("email_domain_id")
async def delete_email_domain(
    ctx: Context,
    email_domain_id: str,
) -> Dict[str, Any]:
    """Delete an email domain by its ID.

    Permanently removes the email domain from the organization.  Any brands
    currently associated with this domain will revert to sending email from
    the default Okta sender address.  A confirmation prompt is shown before
    proceeding.

    Parameters:
        email_domain_id (str, required): Unique ID of the email domain to
            delete.

    Returns:
        Dict with ``success: True`` and a confirmation message on success,
        ``success: False`` if cancelled by the user, or an ``error`` key on
        failure.
    """
    logger.info(f"Requesting delete confirmation for email domain: {email_domain_id!r}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    # Fetch domain details first so we can show the domain name in the prompt.
    domain_name = email_domain_id
    try:
        client = await get_okta_client(manager)
        domain_obj, _, fetch_err = await client.get_email_domain(email_domain_id)
        if not fetch_err and domain_obj is not None:
            domain_name = getattr(domain_obj, "domain", email_domain_id) or email_domain_id
    except Exception:
        pass  # Fall back to showing just the ID in the prompt.

    confirmation = await elicit_or_fallback(
        ctx,
        DELETE_EMAIL_DOMAIN.format(
            domain=domain_name,
            email_domain_id=email_domain_id,
        ),
        DeleteConfirmation,
    )

    if not confirmation or not confirmation.confirmed:
        logger.info(f"Deletion of email domain {email_domain_id!r} cancelled by user")
        return {
            "success": False,
            "message": f"Deletion of email domain {email_domain_id!r} was cancelled.",
        }

    try:
        _, _, err = await client.delete_email_domain(email_domain_id)

        if err:
            logger.error(
                f"Okta API error while deleting email domain {email_domain_id!r}: {err}"
            )
            return {"error": str(err)}

        logger.info(f"Successfully deleted email domain: {email_domain_id}")
        return {
            "success": True,
            "message": (
                f"Email domain {domain_name!r} (ID: {email_domain_id!r}) "
                "successfully deleted."
            ),
        }

    except Exception as e:
        logger.error(
            f"Exception while deleting email domain {email_domain_id}: "
            f"{type(e).__name__}: {e}"
        )
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# verify_email_domain
# ---------------------------------------------------------------------------

@mcp.tool()
@validate_ids("email_domain_id")
async def verify_email_domain(
    ctx: Context,
    email_domain_id: str,
) -> Dict[str, Any]:
    """Verify an email domain by checking its DNS records.

    Okta looks up the DNS records that were returned when the domain was
    created and verifies that they are correctly published.  On success the
    domain's ``validationStatus`` transitions to ``VERIFIED`` and Okta begins
    routing email through your custom sender address.

    Prerequisites:
        All four DNS records (one TXT + three CNAMEs) from
        ``dnsValidationRecords`` must be published at your DNS provider before
        calling this tool.  DNS propagation can take up to 48 hours.

    Parameters:
        email_domain_id (str, required): Unique ID of the email domain to
            verify.

    Returns:
        Dict containing the updated email domain object with the new
        ``validationStatus``, or an ``error`` key if verification fails
        (e.g. DNS records not found).

    Common ``validationStatus`` values after this call:
    - ``VERIFIED``    – DNS records were found; domain is active.
    - ``POLLING``     – Okta is still checking; call again shortly.
    - ``ERROR``       – Verification failed; check your DNS configuration.
    """
    logger.info(f"Verifying email domain: {email_domain_id!r}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        # AC1: Check the current validation status before calling verify.
        # If already VERIFIED there is nothing to do — return a clear message
        # instead of re-running the verify flow.
        current, _, fetch_err = await client.get_email_domain(email_domain_id)
        if not fetch_err and current:
            current_status = (getattr(current, "validation_status", None) or "").upper()
            if current_status == "VERIFIED":
                logger.info(
                    f"Email domain {email_domain_id!r} is already verified."
                )
                return {
                    "validationStatus": current_status,
                    "message": "Email domain is already verified. No further action needed.",
                }

        result, _, err = await client.verify_email_domain(email_domain_id)

        if err:
            logger.error(
                f"Okta API error while verifying email domain {email_domain_id!r}: {err}"
            )
            return {"error": str(err)}

        serialized = _serialize(result)
        status = serialized.get("validationStatus", "unknown") if serialized else "unknown"
        logger.info(
            f"Email domain {email_domain_id!r} verify result: validationStatus={status!r}"
        )
        return serialized or {}

    except Exception as e:
        logger.error(
            f"Exception while verifying email domain {email_domain_id}: "
            f"{type(e).__name__}: {e}"
        )
        return {"error": str(e)}
