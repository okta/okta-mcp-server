# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0. 
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
# See the License for the specific language governing permissions and limitations under the License.

# This module handles the authentication flow for Okta using the Device Authorization Grant.
# It initiates the device authorization, polls for the access token, and manages the Okta API token lifecycle.

import os
import sys
import time
import webbrowser
from dataclasses import dataclass, field

import jwt
import keyring
import keyring.backend
import requests
from loguru import logger

SERVICE_NAME = "OktaAuthManager"


@dataclass
class OktaAuthManager:
    """Manages Okta configuration, authentication, and token state."""

    org_url: str = field(init=False)
    client_id: str = field(init=False)
    token_timestamp: int = 0
    scopes: str = "openid profile email offline_access"
    private_key: str = field(init=False, default=None)
    key_id: str = field(init=False, default=None)
    use_browserless_auth: bool = field(init=False, default=False)

    # TODO: Implement a way to set scopes dynamically by the user if needed.

    def __init__(self):
        """Initialize and validate Okta configuration from environment variables."""
        logger.debug("Initializing OktaAuthManager")
        self.org_url = os.environ.get("OKTA_ORG_URL")
        self.client_id = os.environ.get("OKTA_CLIENT_ID")
        self.scopes = f"{self.scopes} {os.environ.get('OKTA_SCOPES', '').strip()}"

        # Check for browserless auth configuration
        self.private_key = os.environ.get("OKTA_PRIVATE_KEY")
        self.key_id = os.environ.get("OKTA_KEY_ID")

        if self.private_key and self.key_id:
            self.use_browserless_auth = True
            logger.info("Browserless authentication is available and will be used")
            # Process private key if it contains escaped newlines
            if "\\n" in self.private_key:
                self.private_key = self.private_key.replace("\\n", "\n")
        else:
            if self.private_key and not self.key_id:
                logger.warning("Private key found but OKTA_KEY_ID is missing. Using device flow instead.")
            logger.info("Using device authorization flow for authentication")

        if not self.org_url or not self.client_id:
            logger.error("OKTA_ORG_URL and OKTA_CLIENT_ID must be set in environment variables")
            sys.exit(1)

        if not self.org_url.startswith("https://"):
            self.org_url = "https://" + self.org_url
            logger.debug(f"Added https:// prefix to org_url: {self.org_url}")

        logger.info(f"OktaAuthManager initialized with org_url: {self.org_url}, client_id: {self.client_id}")
        logger.debug(f"Configured scopes: {self.scopes}")

    def _get_client_assertion(self) -> str:
        """Generate a JWT client assertion for browserless authentication."""
        logger.debug("Generating client assertion JWT")

        token_url = f"{self.org_url}/oauth2/v1/token"

        headers = {"alg": "RS256", "kid": self.key_id}

        payload = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": token_url,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,  # 5 minutes expiration
        }

        try:
            # Ensure the key is in bytes format
            private_key = self.private_key
            if isinstance(private_key, str):
                private_key = private_key.encode("utf-8")

            client_assertion = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

            logger.debug("Client assertion JWT generated successfully")
            return client_assertion

        except Exception as e:
            logger.error(f"Failed to generate client assertion: {e}")
            raise

    def _browserless_authenticate(self) -> str | None:
        """Perform browserless authentication using client credentials with JWT assertion."""
        logger.info("Starting browserless authentication")

        self.org_url = self.org_url.rstrip("/")
        env_scopes = os.environ.get("OKTA_SCOPES", "").strip()
        if env_scopes:
            self.scopes = env_scopes
        token_url = f"{self.org_url}/oauth2/v1/token"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            client_assertion = self._get_client_assertion()

            data = {
                "grant_type": "client_credentials",
                "scope": self.scopes,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
            }

            logger.debug(f"Requesting token from: {token_url}")
            logger.debug(f"Scopes: {self.scopes}")

            response = requests.post(token_url, headers=headers, data=data)
            logger.debug(f"Response status code: {response.status_code}")

            if response.status_code == 200:
                resp_json = response.json()
                access_token = resp_json.get("access_token")

                if access_token:
                    logger.info("Successfully obtained access token via browserless authentication")
                    keyring.set_password(SERVICE_NAME, "api_token", access_token)
                    self.token_timestamp = int(time.time())

                    # Note: Client credentials flow doesn't provide refresh tokens
                    logger.debug("Note: Client credentials flow does not provide refresh tokens")

                    return access_token

                logger.error("No access token in response")
                return None

            logger.error(f"Failed to get token: HTTP {response.status_code} - {response.text}")
            return None

        except requests.RequestException as e:
            logger.error(f"Request error during browserless authentication: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during browserless authentication: {e}")
            return None

    def _initiate_device_authorization(self) -> dict:
        """Initiate the OAuth 2.0 Device Grant authorization flow"""
        auth_url = f"{self.org_url}/oauth2/v1/device/authorize"
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        data = {"client_id": self.client_id, "scope": self.scopes}

        logger.info("Initiating device authorization flow")
        logger.debug(f"Request URL: {auth_url}")
        logger.debug(f"Request data: client_id={self.client_id}, scope={self.scopes}")

        try:
            response = requests.post(auth_url, headers=headers, data=data)
            logger.debug(f"Response status code: {response.status_code}")

            response.raise_for_status()
            result = response.json()
            result.update({"start_time": time.time()})

            logger.info("Device authorization initiated successfully")
            logger.debug(f"Expires in: {result.get('expires_in')} seconds")

            return result

        except requests.RequestException as e:
            logger.error(f"Failed to initiate device authorization: {e}")
            sys.exit(1)

    def _poll_for_token(self, device_data):
        """Poll token endpoint until success or timeout."""
        token_url = f"{self.org_url}/oauth2/v1/token"
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "device_code": device_data["device_code"],
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }

        logger.info("Starting token polling")
        logger.debug(f"Token endpoint: {token_url}")
        poll_count = 0

        while time.time() - device_data["start_time"] < device_data["expires_in"]:
            poll_count += 1
            logger.debug(f"Polling attempt #{poll_count}")

            try:
                response = requests.post(token_url, headers=headers, data=data)
                resp_json = response.json()
                logger.debug(f"Poll response status: {response.status_code}")

                if response.status_code == 200 and "access_token" in resp_json:
                    logger.info("Successfully obtained access token")
                    keyring.set_password(SERVICE_NAME, "api_token", resp_json["access_token"])
                    self.token_timestamp = int(time.time())

                    if "refresh_token" in resp_json:
                        logger.debug("Refresh token received and stored")
                        keyring.set_password(SERVICE_NAME, "refresh_token", resp_json["refresh_token"])

                    return resp_json["access_token"]

                elif resp_json.get("error") == "authorization_pending":
                    logger.debug(f"Authorization pending, waiting {device_data['interval']} seconds")
                    sys.stdout.flush()
                    time.sleep(device_data["interval"])

                elif resp_json.get("error") == "access_denied":
                    logger.error("Access denied by user")
                    return None

                else:
                    error_msg = resp_json.get("error_description", "Unknown error")
                    logger.error(f"Token polling error: {error_msg}")
                    return None

            except requests.RequestException as e:
                logger.warning(f"Token polling request failed: {e}")
                time.sleep(device_data["interval"])

        logger.error("Token polling timed out")
        return None

    def refresh_access_token(self) -> bool:
        """Attempt to refresh the access token using the stored refresh token."""
        logger.info("Attempting to refresh access token")

        refresh_token = keyring.get_password(SERVICE_NAME, "refresh_token")
        if not refresh_token:
            logger.warning("No refresh token available")
            return False

        token_url = f"{self.org_url}/oauth2/v1/token"
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        logger.debug(f"Refresh token request URL: {token_url}")

        try:
            response = requests.post(token_url, headers=headers, data=data)
            logger.debug(f"Refresh response status: {response.status_code}")

            if response.status_code == 200:
                resp_json = response.json()
                keyring.set_password(SERVICE_NAME, "api_token", resp_json["access_token"])

                if "refresh_token" in resp_json:
                    logger.debug("New refresh token received and stored")
                    keyring.set_password(SERVICE_NAME, "refresh_token", resp_json["refresh_token"])

                self.token_timestamp = int(time.time())
                logger.info("Token refreshed successfully")
                return True
            else:
                logger.error(f"Failed to refresh token: HTTP {response.status_code} - {response.text}")
                return False

        except requests.RequestException as e:
            logger.error(f"Error during token refresh: {e}")
            return False

    async def authenticate(self):
        """Perform full authentication using the appropriate flow."""
        if self.use_browserless_auth:
            logger.info("Using browserless authentication flow")
            token = self._browserless_authenticate()
            if token:
                logger.info("Browserless authentication completed successfully")
            else:
                # Don't fall back to device flow for security reasons:
                # - Browserless auth is typically used in server environments where user interaction isn't possible
                # - Falling back could expose credentials or allow unintended authentication paths
                # - The choice of auth method should be explicit based on environment configuration
                sys.exit(1)
        else:
            logger.info("Starting device flow authentication process")
            device_data = self._initiate_device_authorization()

            logger.info(f"Authentication URL: {device_data['verification_uri_complete']}")
            if device_data.get("user_code"):
                logger.info(f"User code: {device_data['user_code']}")

            try:
                webbrowser.open(device_data["verification_uri_complete"])
                logger.info("Opened authentication URL in web browser")
            except webbrowser.Error:
                logger.warning("Failed to open web browser, user must open URL manually")

            token = self._poll_for_token(device_data)

            if token:
                logger.info("Authentication completed successfully")
            else:
                logger.error("Authentication failed")

    async def is_valid_token(self, expiry_duration: int = 3600) -> bool:
        """Ensure that a valid token is available. Refresh or re-authenticate if needed."""
        logger.debug(f"Checking token validity (expiry duration: {expiry_duration}s)")

        api_token = keyring.get_password(SERVICE_NAME, "api_token")
        token_age = time.time() - self.token_timestamp

        if api_token and token_age < expiry_duration:
            logger.debug(f"Token is valid (age: {token_age:.0f}s)")
            return True

        logger.info(f"Token is expired or missing (age: {token_age:.0f}s)")
        if self.use_browserless_auth:
            # For browserless auth, we can't refresh, so re-authenticate
            logger.info("Re-authenticating using browserless flow")
            await self.authenticate()
        else:
            # For device flow, try to refresh first
            refreshed = self.refresh_access_token()

            # If refresh token is not available or refresh failed, re-authenticate
            if not refreshed:
                logger.warning("Token refresh failed, initiating re-authentication")
                await self.authenticate()

        return keyring.get_password(SERVICE_NAME, "api_token") is not None

    def clear_tokens(self):
        """Clear all stored tokens from keyring."""
        logger.info("Clearing stored tokens")

        try:
            keyring.delete_password(SERVICE_NAME, "api_token")
            logger.debug("API token deleted from keyring")
        except keyring.backend.errors.KeyringError as e:
            logger.warning(f"Failed to delete api_token from keyring: {e}")

        try:
            keyring.delete_password(SERVICE_NAME, "refresh_token")
            logger.debug("Refresh token deleted from keyring")
        except keyring.backend.errors.KeyringError as e:
            logger.warning(f"Failed to delete refresh_token from keyring: {e}")

        self.token_timestamp = 0
        logger.info("Token cleanup completed")
