# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Custom Domains tools for the Okta MCP server.

Custom Domains allow you to replace the default Okta subdomain with your own
domain name on the hosted sign-in page, error pages and email templates.
This module exposes MCP tools for every operation available in the Custom
Domain API:

    - list_custom_domains                GET    /api/v1/domains
    - create_custom_domain               POST   /api/v1/domains
    - get_custom_domain                  GET    /api/v1/domains/{domainId}
    - replace_custom_domain              PUT    /api/v1/domains/{domainId}
    - delete_custom_domain               DELETE /api/v1/domains/{domainId}
    - upsert_custom_domain_certificate   PUT    /api/v1/domains/{domainId}/certificate
    - verify_custom_domain               POST   /api/v1/domains/{domainId}/verify

Validation status values: NOT_STARTED | IN_PROGRESS | VERIFIED | COMPLETED | FAILED_TO_VERIFY
Certificate source types : MANUAL | OKTA_MANAGED
Certificate types        : PEM
"""

import os
from typing import Any, Dict, Optional

from loguru import logger
from mcp.server.fastmcp import Context
from okta.models.domain_certificate import DomainCertificate
from okta.models.domain_certificate_source_type import DomainCertificateSourceType
from okta.models.domain_certificate_type import DomainCertificateType
from okta.models.domain_request import DomainRequest
from okta.models.update_domain import UpdateDomain

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DELETE_CUSTOM_DOMAIN
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response
from okta_mcp_server.utils.validation import InvalidFilePathError, validate_file_path, validate_ids


# ---------------------------------------------------------------------------
# list_custom_domains
# ---------------------------------------------------------------------------

@mcp.tool()
@require_scopes("okta.domains.read")
@json_response
async def list_custom_domains(ctx: Context) -> Dict[str, Any]:
    """List all custom domains in the Okta organization.

    Returns all custom domains including the default Okta subdomain (id:
    ``"default"``). The API does not support pagination — all domains are
    returned in a single response.

    Each domain object includes:
    - ``id``                   – Unique domain ID (``"default"`` for the org base domain).
    - ``domain``               – The fully qualified domain name.
    - ``brandId``              – ID of the brand associated with this domain.
    - ``certificateSourceType``– ``"MANUAL"`` or ``"OKTA_MANAGED"``.
    - ``validationStatus``     – ``NOT_STARTED`` | ``IN_PROGRESS`` | ``VERIFIED`` |
                                 ``COMPLETED`` | ``FAILED_TO_VERIFY``.
    - ``dnsRecords``           – DNS records to configure at your DNS provider
                                 (TXT + CNAME, present until domain is verified).
    - ``publicCertificate``    – Certificate metadata (present after verification).

    Returns:
        Dict containing:
        - domains (List[Dict]): List of domain objects.
        - total_fetched (int): Number of domains returned.
        - error (str): Present only when the operation fails.
    """
    logger.info("Listing custom domains from Okta organization")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        domain_list, _, err = await client.list_custom_domains()

        if err:
            logger.error(f"Okta API error while listing custom domains: {err}")
            return {"error": str(err)}

        domains = getattr(domain_list, "domains", None) or []
        logger.info(f"Successfully retrieved {len(domains)} custom domain(s)")
        return {
            "domains": domains,
            "total_fetched": len(domains),
        }

    except Exception as e:
        logger.error(f"Exception while listing custom domains: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# create_custom_domain
# ---------------------------------------------------------------------------

@mcp.tool()
@require_scopes("okta.domains.manage")
@json_response
async def create_custom_domain(
    ctx: Context,
    domain: str,
    certificate_source_type: str,
) -> Dict[str, Any]:
    """Create a new custom domain for the Okta organization.

    After creating a domain, the response includes DNS records (TXT + CNAME)
    that you must configure at your DNS provider before calling
    ``verify_custom_domain``. Okta does not automatically verify domains.

    Parameters:
        domain (str, required): Fully qualified custom domain name.
            Example: ``"login.example.com"``
            Note: The reserved ``drapp.{orgSubdomain}.okta.com`` pattern is not allowed.
        certificate_source_type (str, required): Who manages the TLS certificate.
            - ``"MANUAL"``       – You supply the certificate via
              ``upsert_custom_domain_certificate``. DNS verification uses a
              TXT record only.
            - ``"OKTA_MANAGED"`` – Okta automatically provisions and renews
              the certificate. After DNS verification succeeds, Okta installs
              the certificate.

    Returns:
        Dict containing the newly created domain object (including DNS records
        to configure), or an ``error`` key on failure.
    """
    logger.info(f"Creating custom domain: {domain!r}, certificateSourceType={certificate_source_type!r}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    upper_cst = certificate_source_type.upper().strip()
    valid_types = {"MANUAL", "OKTA_MANAGED"}
    if upper_cst not in valid_types:
        return {
            "error": (
                f"certificate_source_type must be one of {sorted(valid_types)}, "
                f"got: {certificate_source_type!r}"
            )
        }

    try:
        client = await get_okta_client(manager)

        # Check for an existing domain with the same FQDN before creating.
        existing_list, _, list_err = await client.list_custom_domains()
        if not list_err and existing_list:
            existing_domains = getattr(existing_list, "domains", None) or []
            for existing in existing_domains:
                if getattr(existing, "domain", None) == domain:
                    existing_id = getattr(existing, "id", "unknown")
                    logger.warning(
                        f"Custom domain '{domain}' already exists (id: {existing_id})"
                    )
                    return {
                        "error": (
                            f"A custom domain '{domain}' already exists (id: {existing_id!r}). "
                            "Use list_custom_domains() to find it or choose a different domain."
                        )
                    }

        req = DomainRequest(
            domain=domain,
            certificate_source_type=DomainCertificateSourceType(upper_cst),
        )
        created, _, err = await client.create_custom_domain(req)

        if err:
            logger.error(f"Okta API error while creating custom domain {domain!r}: {err}")
            return {"error": str(err)}

        # The Okta Python SDK's ``create_custom_domain`` returns
        # ``(None, response, None)`` when the HTTP response body is empty or
        # returns 204 No Content (see okta.api.custom_domain_api).  The
        # resource IS successfully created on Okta in that scenario, so fall
        # back to ``list_custom_domains`` and locate the freshly-created
        # domain by FQDN so the caller still receives the persisted object.
        #
        # ``GET /api/v1/domains`` does not paginate — all custom domains for
        # the org are returned in a single response — so a plain list scan is
        # sufficient here.  FQDN comparison is case-insensitive per RFC 1035
        # to guard against Okta normalizing the stored ``domain`` field.
        if created is None:
            logger.info(
                f"SDK returned no body for create_custom_domain; refetching '{domain}' "
                "via list_custom_domains"
            )
            refetched_list, _, refetch_err = await client.list_custom_domains()
            if refetch_err:
                return {
                    "error": (
                        f"Custom domain '{domain}' was created on Okta but the follow-up "
                        f"list_custom_domains failed: {refetch_err}"
                    )
                }
            target_domain = domain.lower()
            for candidate in getattr(refetched_list, "domains", None) or []:
                candidate_fqdn = getattr(candidate, "domain", None)
                if isinstance(candidate_fqdn, str) and candidate_fqdn.lower() == target_domain:
                    created = candidate
                    break
            if created is None:
                return {
                    "error": (
                        f"Custom domain '{domain}' create request succeeded but the resource "
                        "was not returned by list_custom_domains. It may still exist on Okta; "
                        "verify with list_custom_domains()."
                    )
                }

        logger.info(
            f"Successfully created custom domain '{domain}' with id: {getattr(created, 'id', None)}"
        )
        return created

    except Exception as e:
        logger.error(f"Exception while creating custom domain: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# get_custom_domain
# ---------------------------------------------------------------------------

@mcp.tool()
@require_scopes("okta.domains.read")
@validate_ids("domain_id")
@json_response
async def get_custom_domain(
    ctx: Context,
    domain_id: str,
) -> Dict[str, Any]:
    """Retrieve a custom domain by its ID.

    Parameters:
        domain_id (str, required): Unique ID of the domain
            (e.g. ``"OcDz6iRyjkaCTXkdo0g3"``). Use ``"default"`` to retrieve
            the org's default Okta subdomain.

    Returns:
        Dict containing the domain object, or an ``error`` key on failure.
    """
    logger.info(f"Retrieving custom domain: {domain_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        domain, _, err = await client.get_custom_domain(domain_id)

        if err:
            logger.error(f"Okta API error while retrieving custom domain {domain_id!r}: {err}")
            return {"error": str(err)}

        if domain is None:
            # Guard against (None, response, None) — the previous per-module
            # ``_serialize_domain`` helper silently returned ``{}`` here.
            logger.warning(
                f"get_custom_domain returned no body for {domain_id!r} despite success status."
            )
            return {
                "error": (
                    f"Okta returned an empty response for custom domain {domain_id!r}. "
                    "Verify the ID with list_custom_domains()."
                )
            }

        logger.info(f"Successfully retrieved custom domain: {domain_id}")
        return domain

    except Exception as e:
        logger.error(f"Exception while retrieving custom domain {domain_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# replace_custom_domain
# ---------------------------------------------------------------------------

@mcp.tool()
@require_scopes("okta.domains.manage")
@validate_ids("domain_id", "brand_id")
@json_response
async def replace_custom_domain(
    ctx: Context,
    domain_id: str,
    brand_id: str,
) -> Dict[str, Any]:
    """Replace the brand associated with a custom domain.

    Associates a different brand with the given custom domain. The brand
    controls the look-and-feel of the sign-in page and email templates served
    under that domain.

    Constraints:
    - The default brand (``isDefault: true``) cannot be mapped to a custom
      domain (API returns 409).
    - The PUT is allowed regardless of the domain's ``validationStatus``;
      the brand association can be changed at any point in the domain lifecycle.

    Parameters:
        domain_id (str, required): Unique ID of the domain to update.
        brand_id (str, required): ID of the brand to associate.

    Returns:
        Dict containing the updated domain object, or an ``error`` key on failure.
    """
    logger.info(f"Replacing brand for custom domain {domain_id!r} → brand {brand_id!r}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        req = UpdateDomain(brand_id=brand_id)
        updated, _, err = await client.replace_custom_domain(domain_id, req)

        if err:
            logger.error(f"Okta API error while replacing brand for domain {domain_id!r}: {err}")
            return {"error": str(err)}

        if updated is None:
            logger.warning(
                f"replace_custom_domain returned no body for {domain_id!r} despite success status."
            )
            return {
                "error": (
                    f"Custom domain {domain_id!r} replace succeeded but the response was empty. "
                    "Re-fetch with get_custom_domain() to confirm the new brand association."
                )
            }

        logger.info(f"Successfully updated brand for custom domain: {domain_id}")
        return updated

    except Exception as e:
        logger.error(f"Exception while replacing custom domain brand: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# delete_custom_domain
# ---------------------------------------------------------------------------

@mcp.tool()
@require_scopes("okta.domains.manage")
@validate_ids("domain_id")
@json_response
async def delete_custom_domain(
    ctx: Context,
    domain_id: str,
) -> Dict[str, Any]:
    """Delete a custom domain by its ID.

    Permanently removes the custom domain from the organization. The default
    org domain (``id: "default"``) cannot be deleted. A confirmation prompt
    is shown before proceeding.

    Parameters:
        domain_id (str, required): Unique ID of the domain to delete.

    Returns:
        Dict with ``success: True`` and a confirmation message on success,
        ``success: False`` if cancelled, or an ``error`` key on failure.
    """
    logger.info(f"Requesting delete confirmation for custom domain: {domain_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    if domain_id.lower() == "default":
        return {"error": "The default Okta org domain cannot be deleted."}

    confirmation = await elicit_or_fallback(
        ctx,
        DELETE_CUSTOM_DOMAIN.format(domain_id=domain_id),
        DeleteConfirmation,
    )

    if not confirmation or not confirmation.confirmed:
        logger.info(f"Deletion of custom domain {domain_id!r} cancelled by user")
        return {
            "success": False,
            "message": f"Deletion of custom domain {domain_id!r} was cancelled.",
        }

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_custom_domain(domain_id)

        if err:
            logger.error(f"Okta API error while deleting custom domain {domain_id!r}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully deleted custom domain: {domain_id}")
        return {
            "success": True,
            "message": f"Custom domain {domain_id!r} successfully deleted.",
        }

    except Exception as e:
        logger.error(f"Exception while deleting custom domain {domain_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# upsert_custom_domain_certificate
# ---------------------------------------------------------------------------

@mcp.tool()
@require_scopes("okta.domains.manage")
@validate_ids("domain_id")
@json_response
async def upsert_custom_domain_certificate(
    ctx: Context,
    domain_id: str,
    certificate: str,
    certificate_chain: str,
    private_key_file_path: str,
) -> Dict[str, Any]:
    """Upload or renew the TLS certificate for a MANUAL custom domain.

    Creates or replaces the PEM-encoded certificate for a custom domain whose
    ``certificateSourceType`` is ``MANUAL``. If the domain is currently
    ``OKTA_MANAGED``, calling this switches it to ``MANUAL`` and Okta stops
    auto-renewing the certificate.

    Okta supports TLS certificates and private keys that are PEM-encoded and
    2048, 3072, or 4096 bits.

    Parameters:
        domain_id (str, required): Unique ID of the domain.
        certificate (str, required): PEM-encoded TLS leaf certificate.
            Must start with ``-----BEGIN CERTIFICATE-----``.
        certificate_chain (str, required): PEM-encoded certificate chain.
            May include intermediate CA certificates concatenated after the
            leaf certificate, or may be identical to ``certificate`` for
            self-signed/root-signed certs.
        private_key_file_path (str, required): Path to the PEM-encoded RSA
            private key file.  The file must reside inside a permitted directory
            (default: ``/tmp`` or ``/var/tmp``; extend via the
            ``OKTA_MCP_ALLOWED_KEY_DIRS`` environment variable).
            Example: ``"/tmp/domain.key"``.
            The key is read from disk and never exposed in the conversation.
            The file must contain a key starting with
            ``-----BEGIN PRIVATE KEY-----`` or ``-----BEGIN RSA PRIVATE KEY-----``.

    Returns:
        Dict with ``success: True`` on success (204 No Content from Okta),
        or an ``error`` key on failure.
    """
    logger.info(f"Upserting certificate for custom domain: {domain_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    # Validate the file path before any filesystem access.
    # validate_file_path returns the symlink-resolved absolute path; use
    # that resolved path for all I/O so the opened file is identical to
    # the one that was validated (eliminates the TOCTOU window).
    try:
        safe_path = validate_file_path(private_key_file_path, "private_key_file_path")
    except InvalidFilePathError as e:
        logger.error(f"Rejected unsafe private_key_file_path: {e}")
        return {"error": str(e)}

    # Read the private key from a local file path so the raw PEM key
    # value is never passed through the LLM conversation.
    if not os.path.isfile(safe_path):
        return {"error": f"Private key file not found: {private_key_file_path!r}"}
    try:
        with open(safe_path, "r") as _fh:
            private_key = _fh.read()
    except OSError as _read_err:
        logger.error(f"Failed to read private key file {private_key_file_path!r}: {_read_err}")
        return {"error": f"Could not read private key file: {_read_err}"}

    try:
        client = await get_okta_client(manager)
        cert_obj = DomainCertificate(
            certificate=certificate,
            certificate_chain=certificate_chain,
            private_key=private_key,
            type=DomainCertificateType("PEM"),
        )
        result = await client.upsert_certificate(domain_id, cert_obj)
        err = result[-1]

        if err:
            logger.error(
                f"Okta API error while upserting certificate for domain {domain_id!r}: {err}"
            )
            return {"error": str(err)}

        logger.info(f"Successfully upserted certificate for custom domain: {domain_id}")
        return {
            "success": True,
            "message": f"Certificate for domain {domain_id!r} successfully upserted.",
        }

    except Exception as e:
        logger.error(
            f"Exception while upserting certificate for domain {domain_id}: {type(e).__name__}: {e}"
        )
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# verify_custom_domain
# ---------------------------------------------------------------------------

@mcp.tool()
@require_scopes("okta.domains.manage")
@validate_ids("domain_id")
@json_response
async def verify_custom_domain(
    ctx: Context,
    domain_id: str,
) -> Dict[str, Any]:
    """Verify a custom domain by checking its DNS records.

    Triggers Okta to verify that the TXT and CNAME records you added at your
    DNS provider match the values returned when the domain was created. DNS
    changes can take time to propagate — if verification fails immediately
    after adding records, wait a few minutes and try again.

    After a successful verification:
    - ``validationStatus`` becomes ``VERIFIED`` (or ``COMPLETED`` once the
      certificate is also installed).
    - If ``certificateSourceType`` is ``OKTA_MANAGED``, Okta also provisions
      and installs a TLS certificate automatically.

    Parameters:
        domain_id (str, required): Unique ID of the domain to verify.

    Returns:
        Dict containing the updated domain object with the new
        ``validationStatus``, or an ``error`` key on failure.
        ``validationStatus`` will be ``FAILED_TO_VERIFY`` when DNS records
        are not yet reachable; retry after DNS propagation.
    """
    logger.info(f"Verifying custom domain: {domain_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        # Check the current validation status before calling verify.
        # If the domain is already verified there is nothing to do - return a
        # clear status message instead of re-running the verify flow and
        # confusing the caller with DNS record output.
        current, _, fetch_err = await client.get_custom_domain(domain_id)
        if not fetch_err and current:
            current_status = (getattr(current, "validation_status", None) or "").upper()
            if current_status in ("VERIFIED", "COMPLETED"):
                logger.info(
                    f"Custom domain {domain_id!r} is already verified "
                    f"(validationStatus={current_status!r})"
                )
                return {
                    "validationStatus": current_status,
                    "message": "Domain is already verified. No further action needed.",
                }

        verified, _, err = await client.verify_domain(domain_id)

        if err:
            logger.error(f"Okta API error while verifying domain {domain_id!r}: {err}")
            return {"error": str(err)}

        validation_status = getattr(verified, "validation_status", None) or "unknown"
        logger.info(f"Custom domain {domain_id!r} verification result: {validation_status}")
        return verified

    except Exception as e:
        logger.error(f"Exception while verifying custom domain {domain_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}
