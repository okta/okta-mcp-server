<div align="center">

![Okta Open Source MCP Server](https://raw.githubusercontent.com/okta/okta-mcp-server/main/assets/thumbnail.png)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-%3E%3D3.13-brightgreen.svg)](https://python.org/)

</div>

## :tada: __It's Official__ :tada:
The Okta Open-Source MCP Server integrates with LLMs and AI agents, allowing you to perform various Okta management operations using natural language and is Generally Available (GA).

[MCP (Model Context Protocol)](https://modelcontextprotocol.io/introduction) is an open protocol introduced by Anthropic that standardizes how large language models communicate with external tools, resources or remote services.

The Okta Open Source MCP Server integrates with LLMs and AI agents, allowing you to perform various Okta management operations using natural language. For instance, you could simply ask Claude Desktop to perform Okta management operations:

- > Create a new user and add them to the Engineering group
- > Show me all failed login attempts from the last 24 hours
- > List all applications that haven't been used in the past month

**Empower your LLM Agents to Manage your Okta Organization**

This server is an [Model Context Protocol](https://modelcontextprotocol.io/introduction) server that provides seamless integration with Okta's Admin Management APIs. It allows LLM agents to interact with Okta in a programmatic way, enabling automation and enhanced management capabilities.

## Key Features

* **LLM-Driven Okta Management:** Allows your LLM agents to perform administrative tasks within your Okta environment based on natural language instructions.
* **Secure Authentication:** Supports both Device Authorization Grant for interactive use and Private Key JWT for secure, automated server-to-server communication.
* **Interactive Confirmation via Elicitation:** Destructive operations (deletes, deactivations) prompt the user for confirmation through the [MCP Elicitation API](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation) before proceeding, with automatic fallback for clients that do not yet support the feature.
* **Integration with Okta Admin Management APIs:** Leverages the official Okta APIs to ensure secure and reliable interaction with your Okta org.
* **Extensible Architecture:** Designed to be easily extended with new functionalities and support for additional Okta API endpoints.
* **Comprehensive Tool Support:** Full CRUD operations for users, groups, applications, policies, device assurance policies, brands, themes, custom pages, email templates, custom domains, email domains, and more.
* **Scope-Based Tool Loading:** Tools are automatically enabled or disabled at server startup based on the OAuth 2.0 scopes configured in `OKTA_SCOPES`. Only tools for which your application has been granted the required scope are registered and visible to the LLM — tools without a matching scope are silently removed before the first request.

This MCP server utilizes [Okta's Python SDK v3.4.1](https://github.com/okta/okta-sdk-python) to communicate with the Okta APIs, ensuring a robust and well-supported integration.

## 🚀 Getting Started

**Prerequisites:**

- [Python 3.13+](https://python.org/downloads) OR [Docker](https://docs.docker.com/get-docker/)
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager (if not using Docker)
- [Claude Desktop](https://claude.ai/download) or any other [MCP Client](https://modelcontextprotocol.io/clients)
- [Okta](https://okta.com/) account with appropriate permissions

<br/>

### Install the Okta Open Source MCP Server

Install Okta Open Source MCP Server and configure it to work with your preferred MCP Client.

Choose one of the following installation methods:

<details open>
<summary><b>🐳 Option 1: Docker (Recommended)</b></summary>

Docker provides a consistent environment without needing to install Python or uv locally.

1. Clone the repository:
   ```bash
   git clone https://github.com/okta/okta-mcp-server.git
   cd okta-mcp-server
   ```

2. Create a `.env` file from the example:
   ```bash
   cp .env.example .env
   # Edit .env and add your Okta credentials
   ```

3. Build and run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

4. Configure your MCP Client to use the Docker container:

**Claude Desktop with Docker (Private Key JWT - Recommended for Docker):**

This method requires no browser interaction and is ideal for containerized environments.

```json
{
  "mcpServers": {
    "okta-mcp-server": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "OKTA_ORG_URL",
        "-e", "OKTA_CLIENT_ID",
        "-e", "OKTA_SCOPES",
        "-e", "OKTA_PRIVATE_KEY",
        "-e", "OKTA_KEY_ID",
        "okta-mcp-server"
      ],
      "env": {
        "OKTA_ORG_URL": "https://your-org.okta.com",
        "OKTA_CLIENT_ID": "your-client-id",
        "OKTA_SCOPES": "okta.users.read okta.groups.read",
        "OKTA_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nYour private key content here\n-----END RSA PRIVATE KEY-----",
        "OKTA_KEY_ID": "your-key-id"
      }
    }
  }
}
```

**Claude Desktop with Docker (Device Authorization Grant):**

This method requires browser-based authentication. When the server starts, it will display an authentication URL in the logs. Copy and paste this URL into your browser to complete the authentication.

> **Note:** Docker containers cannot open a browser on the host automatically. You must manually copy the URL from `docker logs okta-mcp-server` and paste it into your browser.

```json
{
  "mcpServers": {
    "okta-mcp-server": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "okta-keyring:/home/appuser/.local/share/python_keyring",
        "-e", "OKTA_ORG_URL",
        "-e", "OKTA_CLIENT_ID",
        "-e", "OKTA_SCOPES",
        "-e", "PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring",
        "okta-mcp-server"
      ],
      "env": {
        "OKTA_ORG_URL": "https://your-org.okta.com",
        "OKTA_CLIENT_ID": "your-client-id",
        "OKTA_SCOPES": "okta.users.read okta.groups.read"
      }
    }
  }
}
```

The `-v okta-keyring:/home/appuser/.local/share/python_keyring` volume persists tokens between container restarts.

**VS Code with Docker (Private Key JWT - Recommended for Docker):**

```json
{
  "mcp": {
    "inputs": [
      {
        "type": "promptString",
        "description": "Okta Organization URL (e.g., https://dev-123456.okta.com)",
        "id": "OKTA_ORG_URL"
      },
      {
        "type": "promptString",
        "description": "Okta Client ID",
        "id": "OKTA_CLIENT_ID",
        "password": true
      },
      {
        "type": "promptString",
        "description": "Okta Scopes (separated by whitespace)",
        "id": "OKTA_SCOPES"
      },
      {
        "type": "promptString",
        "description": "Okta Private Key (for browserless auth)",
        "id": "OKTA_PRIVATE_KEY",
        "password": true
      },
      {
        "type": "promptString",
        "description": "Okta Key ID (for browserless auth)",
        "id": "OKTA_KEY_ID",
        "password": true
      }
    ],
    "servers": {
      "okta-mcp-server": {
        "command": "docker",
        "args": [
          "run", "-i", "--rm",
          "-e", "OKTA_ORG_URL=${input:OKTA_ORG_URL}",
          "-e", "OKTA_CLIENT_ID=${input:OKTA_CLIENT_ID}",
          "-e", "OKTA_SCOPES=${input:OKTA_SCOPES}",
          "-e", "OKTA_PRIVATE_KEY=${input:OKTA_PRIVATE_KEY}",
          "-e", "OKTA_KEY_ID=${input:OKTA_KEY_ID}",
          "okta-mcp-server"
        ]
      }
    }
  }
}
```

**VS Code with Docker (Device Authorization Grant):**

> **Note:** Device Authorization requires manual browser interaction. When the server starts, check the MCP output panel for the authentication URL, then copy and paste it into your browser.

```json
{
  "mcp": {
    "inputs": [
      {
        "type": "promptString",
        "description": "Okta Organization URL (e.g., https://dev-123456.okta.com)",
        "id": "OKTA_ORG_URL"
      },
      {
        "type": "promptString",
        "description": "Okta Client ID",
        "id": "OKTA_CLIENT_ID",
        "password": true
      },
      {
        "type": "promptString",
        "description": "Okta Scopes (separated by whitespace)",
        "id": "OKTA_SCOPES"
      }
    ],
    "servers": {
      "okta-mcp-server": {
        "command": "docker",
        "args": [
          "run", "-i", "--rm",
          "-v", "okta-keyring:/home/appuser/.local/share/python_keyring",
          "-e", "OKTA_ORG_URL=${input:OKTA_ORG_URL}",
          "-e", "OKTA_CLIENT_ID=${input:OKTA_CLIENT_ID}",
          "-e", "OKTA_SCOPES=${input:OKTA_SCOPES}",
          "-e", "PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring",
          "okta-mcp-server"
        ]
      }
    }
  }
}
```

**Alternatively, use docker-compose (requires .env file):**
```json
{
  "mcp": {
    "servers": {
      "okta-mcp-server": {
        "command": "docker-compose",
        "args": [
          "-f",
          "/path/to/okta-mcp-server/docker-compose.yml",
          "run",
          "--rm",
          "okta-mcp-server"
        ]
      }
    }
  }
}
```

**Alternatively, build and run directly:**
```bash
# Build the image
docker build -t okta-mcp-server .

# Run the container
docker run -i --rm \
  -e OKTA_ORG_URL="<OKTA_ORG_URL>" \
  -e OKTA_CLIENT_ID="<OKTA_CLIENT_ID>" \
  -e OKTA_SCOPES="<OKTA_SCOPES>" \
  okta-mcp-server
```

</details>

<details>
<summary><b>📦 Option 2: uv (Python Package Manager)</b></summary>

1. Clone and install the server:
   ```bash
   git clone https://github.com/okta/okta-mcp-server.git
   cd okta-mcp-server
   uv sync
   ```

2. Configure Claude Desktop by adding the following to your `claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "okta-mcp-server": {
         "command": "uv",
         "args": [
           "run",
           "--directory",
           "/path/to/okta-mcp-server",
           "okta-mcp-server"
         ],
         "env": {
           "OKTA_ORG_URL": "<OKTA_ORG_URL>",
           "OKTA_CLIENT_ID": "<OKTA_CLIENT_ID>",
           "OKTA_SCOPES": "<OKTA_SCOPES>",
           "OKTA_PRIVATE_KEY": "<PRIVATE_KEY_IF_NEEDED>",
           "OKTA_KEY_ID": "<KEY_ID_IF_NEEDED>"
         }
       }
     }
   }
   ```

</details>

<details>
<summary><b> Option 3: PyPI (uvx / pipx / pip)</b></summary>

The server is published to [PyPI as `okta-mcp-server`](https://pypi.org/project/okta-mcp-server/), so you can run it without cloning the repository. This is the easiest option if you only want to *use* the server (not modify it).

**Prerequisite:** Python 3.13+ and either [`uv`](https://docs.astral.sh/uv/getting-started/installation/) (recommended, provides `uvx`) or [`pipx`](https://pipx.pypa.io/stable/installation/).

**Quick smoke test (optional):**
```bash
# With uv — no install needed, runs in an ephemeral environment
uvx okta-mcp-server --help

# Or install globally with pipx
pipx install okta-mcp-server
okta-mcp-server --help
```

**Claude Desktop with PyPI (Device Authorization Grant):**

Add the following to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "okta-mcp-server": {
      "command": "uvx",
      "args": ["okta-mcp-server"],
      "env": {
        "OKTA_ORG_URL": "<OKTA_ORG_URL>",
        "OKTA_CLIENT_ID": "<OKTA_CLIENT_ID>",
        "OKTA_SCOPES": "<OKTA_SCOPES>"
      }
    }
  }
}
```

**Claude Desktop with PyPI (Private Key JWT — Browserless):**
```json
{
  "mcpServers": {
    "okta-mcp-server": {
      "command": "uvx",
      "args": ["okta-mcp-server"],
      "env": {
        "OKTA_ORG_URL": "<OKTA_ORG_URL>",
        "OKTA_CLIENT_ID": "<OKTA_CLIENT_ID>",
        "OKTA_SCOPES": "<OKTA_SCOPES>",
        "OKTA_PRIVATE_KEY": "<PRIVATE_KEY_IF_NEEDED>",
        "OKTA_KEY_ID": "<KEY_ID_IF_NEEDED>"
      }
    }
  }
}
```

**VS Code with PyPI:**
```json
{
  "mcp": {
    "inputs": [
      {
        "type": "promptString",
        "description": "Okta Organization URL (e.g., https://dev-123456.okta.com)",
        "id": "OKTA_ORG_URL"
      },
      {
        "type": "promptString",
        "description": "Okta Client ID",
        "id": "OKTA_CLIENT_ID",
        "password": true
      },
      {
        "type": "promptString",
        "description": "Okta Scopes (separated by whitespace)",
        "id": "OKTA_SCOPES"
      }
    ],
    "servers": {
      "okta-mcp-server": {
        "command": "uvx",
        "args": ["okta-mcp-server"],
        "env": {
          "OKTA_ORG_URL": "${input:OKTA_ORG_URL}",
          "OKTA_CLIENT_ID": "${input:OKTA_CLIENT_ID}",
          "OKTA_SCOPES": "${input:OKTA_SCOPES}"
        }
      }
    }
  }
}
```

**Pinning a version (recommended for production):**

`uvx okta-mcp-server` always resolves to the latest published release. To pin a specific version, use the `package@version` form:
```json
"args": ["okta-mcp-server@1.1.2"]
```

**Upgrading:**
- `uvx` — no action needed for unpinned installs; use `uv cache clean` to force a refresh, or bump the pinned version.
- `pipx` — run `pipx upgrade okta-mcp-server`.

> [!TIP]
> Prefer Option 1 (Docker) or Option 2 (uv from source) if you need to modify the server code or run in a locked-down container environment. Choose Option 3 when you just want the released server on your workstation with minimal setup.

</details>

### Configure with Different MCP Clients

<details>
<summary><b>VS Code</b></summary>

Add the following to your VS Code `settings.json`:
```json
{
  "mcp": {
    "inputs": [
      {
        "type": "promptString",
        "description": "Okta Organization URL (e.g., https://dev-123456.okta.com)",
        "id": "OKTA_ORG_URL"
      },
      {
        "type": "promptString",
        "description": "Okta Client ID",
        "id": "OKTA_CLIENT_ID",
        "password": true
      },
      {
        "type": "promptString",
        "description": "Okta Scopes (separated by whitespace, e.g., 'okta.users.read okta.groups.manage')",
        "id": "OKTA_SCOPES"
      },
      {
        "type": "promptString",
        "description": "Okta Private Key. Required for 'browserless' auth.",
        "id": "OKTA_PRIVATE_KEY",
        "password": true
      },
      {
        "type": "promptString",
        "description": "Okta Key ID (KID) for the private key. Required for 'browserless' auth.",
        "id": "OKTA_KEY_ID",
        "password": true
      }
    ],
    "servers": {
      "okta-mcp-server": {
        "command": "uv",
        "args": [
          "run",
          "--directory",
          "/path/to/the/okta-mcp-server",
          "okta-mcp-server"
        ],
        "env": {
          "OKTA_ORG_URL": "${input:OKTA_ORG_URL}",
          "OKTA_CLIENT_ID": "${input:OKTA_CLIENT_ID}",
          "OKTA_SCOPES": "${input:OKTA_SCOPES}",
          "OKTA_PRIVATE_KEY": "${input:OKTA_PRIVATE_KEY}",
          "OKTA_KEY_ID": "${input:OKTA_KEY_ID}"
        }
      }
    }
  }
}
```

</details>

<details>
<summary><b>Other MCP Clients</b></summary>

To use Okta Open Source MCP Server with any other MCP Client, you can manually add this configuration to the client and restart for changes to take effect:

```json
{
  "mcpServers": {
    "okta-mcp-server": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/okta-mcp-server",
        "okta-mcp-server"
      ],
      "env": {
        "OKTA_ORG_URL": "<OKTA_ORG_URL>",
        "OKTA_CLIENT_ID": "<OKTA_CLIENT_ID>",
        "OKTA_SCOPES": "<OKTA_SCOPES>",
        "OKTA_PRIVATE_KEY": "<PRIVATE_KEY_IF_NEEDED>",
        "OKTA_KEY_ID": "<KEY_ID_IF_NEEDED>"
      }
    }
  }
}
```

</details>

### Authenticate with Okta

The server supports two authentication methods. Choose the one that best fits your use case.

**Method 1: Device Authorization Grant (Interactive)**

1. In your Okta org, create a **new App Integration**.
2. Select **OIDC - OpenID Connect** and **Native Application**.
3. Under **Grant type**, ensure **Device Authorization** is checked.
4. Go to the Okta API Scopes tab and Grant permissions for the APIs you need (e.g., okta.users.read, okta.groups.manage).
5. Save the application and copy the **Client ID**.
6. **Documentation:** [Okta Device Authorization Grant Guide](https://developer.okta.com/docs/guides/device-authorization-grant/main/)

**Method 2: Private Key JWT (Browserless)**

1. **Create App:** In your Okta org, create a **new App Integration**. Select **API Services**. Save the app and copy the **Client ID**.
2. **Configure Client Authentication:**
   * On the app's **General** tab, find the **Client Credentials** section and click **Edit**.
   * Disable **Require Demonstrating Proof of Possession (DPoP) header in token requests**.
   * Select **Public key / Private key** for the authentication method.
3. **Add a Public Key:** You have two options for adding a key.
   * **Option A: Generate Key in Okta (Recommended)**
     1. In the **Public keys** section, click **Add key**.
     2. In the dialog, choose **Generate new key**.
     3. Okta will instantly generate a key pair. **Download or save the private key** (`private.pem`) and store it securely.
     4. Copy the **Key ID (KID)** displayed for the newly generated key.
   * **Option B: Use Your Own Key**
     1. Generate a key pair locally using the following `openssl` commands:
        ```bash
        # Generate a 2048-bit RSA private key
        openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
        
        # Extract the public key from the private key
        openssl rsa -in private.pem -pubout -out public.pem
        ```
     2. Click **Add key** and paste the contents of your **public key** (`public.pem`) into the dialog.
     3. Copy the **Key ID (KID)** displayed for the key you added.
4. **Grant API Scopes:** Go to the **Okta API Scopes** tab and **Grant** permissions for the APIs you need.
5. **Assign Admin Roles:** Go to the **Admin roles** tab and assign the appropriate admin role to this application.

### Verify your integration

Restart your MCP Client (Claude Desktop, VS Code, etc.) and ask it to help you manage your Okta tenant:

> Show me the users in my Okta organization

## 🛠️ Supported Tools

The Okta Open Source MCP Server provides the following tools for LLMs to interact with your Okta tenant:

### Users

> **Required scope:** `okta.users.read` (read) · `okta.users.manage` (write)

| Tool                            | Description                                              | Usage Examples                                                                                                                                                |
| ------------------------------- | -------------------------------------------------------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `list_users`                    | List all users in your Okta organization                | - `Show me the users in my Okta org` <br> - `Find users with 'john' in their name` <br> - `What users do I have in the Engineering department?`                 |
| `get_user`                      | Get detailed information about a specific user          | - `Show me details for user john.doe@company.com` <br> - `Get information about user ID 00u1234567890` <br> - `What groups is Jane Smith a member of?`        |
| `create_user`                   | Create a new user in your Okta organization. Pass `activate=false` to create the user in `STAGED` status (no activation email sent); omit or pass `activate=true` (default) to create an active `PROVISIONED` user. | - `Create a new user named John Doe with email john.doe@company.com` <br> - `Add a new employee to the Sales department` <br> - `Create a staged user for john.doe@company.com without sending an activation email` |
| `update_user`                   | Update an existing user's profile information           | - `Update John Doe's department to Engineering` <br> - `Change the phone number for user jane.smith@company.com` <br> - `Update the manager for this user`    |
| `deactivate_user`               | Deactivate a user (prompts for confirmation)            | - `Deactivate the user john.doe@company.com` <br> - `Disable access for former employee Jane Smith` <br> - `Suspend the contractor account temporarily`       |
| `delete_deactivated_user`       | Permanently delete a deactivated user (prompts for confirmation) | - `Delete the deactivated user john.doe@company.com` <br> - `Remove former employee Jane Smith permanently` <br> - `Clean up old contractor accounts`         |
| `get_user_profile_attributes`   | Retrieve all supported user profile attributes          | - `What user profile fields are available?` <br> - `Show me all the custom attributes we can set` <br> - `List the standard Okta user attributes`             |

### Groups

> **Required scope:** `okta.groups.read` (read) · `okta.groups.manage` (write)

| Tool                    | Description                                       | Usage Examples                                                                                                                                                |
| ----------------------- | ------------------------------------------------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `list_groups`           | List all groups in your Okta organization        | - `Show me the groups in my Okta org` <br> - `Find groups with 'Engineering' in their name` <br> - `What security groups do we have?`                         |
| `get_group`             | Get detailed information about a specific group  | - `Show me details for the Engineering group` <br> - `How many members are in the Administrators group?` <br> - `What applications are assigned to Sales?`    |
| `create_group`          | Create a new group                                | - `Create a new group called DevOps Team` <br> - `Set up a security group for the Finance department` <br> - `Add a group for temporary contractors`          |
| `update_group`          | Update an existing group's information            | - `Update the description for the Engineering group` <br> - `Change the name of the Sales group to Revenue Team` <br> - `Modify the Finance group settings`   |
| `delete_group`          | Delete a group (prompts for confirmation)         | - `Delete the old Marketing group` <br> - `Remove the temporary project group` <br> - `Clean up unused security groups`                                       |
| `list_group_users`      | List all users who are members of a group        | - `Who are the members of the Engineering group?` <br> - `Show me all administrators` <br> - `List users in the Finance department`                           |
| `list_group_apps`       | List all applications assigned to a group        | - `What applications does the Engineering group have access to?` <br> - `Show apps assigned to Sales team` <br> - `List all applications for Administrators`  |
| `add_user_to_group`     | Add a user to a group                             | - `Add john.doe@company.com to the Engineering group` <br> - `Give Jane Smith access to the Finance applications` <br> - `Add the new hire to the Sales team` |
| `remove_user_from_group`| Remove a user from a group                        | - `Remove john.doe@company.com from the Engineering group` <br> - `Revoke Jane's admin privileges` <br> - `Remove the contractor from the Finance group`      |

### Applications

> **Required scope:** `okta.apps.read` (read) · `okta.apps.manage` (write)

| Tool                          | Description                                       | Usage Examples                                                                                                                                                |
| ----------------------------- | ------------------------------------------------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `list_applications`           | List all applications in your Okta organization  | - `Show me the applications in my Okta org` <br> - `Find applications with 'API' in their name` <br> - `What SSO applications do we have configured?`         |
| `get_application`             | Get detailed information about a specific app    | - `Show me details for the Salesforce application` <br> - `What are the callback URLs for our mobile app?` <br> - `Get the client ID for our web application` |
| `create_application`          | Create a new application                          | - `Create a new SAML application for our HR system` <br> - `Set up a new API service application` <br> - `Add a mobile app integration`                       |
| `update_application`          | Update an existing application                    | - `Update the callback URLs for our web app` <br> - `Change the logo for the Salesforce application` <br> - `Modify the SAML settings for our HR system`      |
| `delete_application`          | Delete an application (prompts for confirmation)  | - `Delete the old legacy application` <br> - `Remove the unused test application` <br> - `Clean up deprecated integrations`                                   |
| `activate_application`        | Activate an application                           | - `Activate the new HR application` <br> - `Enable the Salesforce integration` <br> - `Turn on the mobile app for users`                                      |
| `deactivate_application`      | Deactivate an application (prompts for confirmation) | - `Deactivate the legacy CRM application` <br> - `Temporarily disable the mobile app` <br> - `Turn off access to the test environment`                        |

### Policies

> **Required scope:** `okta.policies.read` (read) · `okta.policies.manage` (write)

| Tool                        | Description                                    | Usage Examples                                                                                                                                                |
| --------------------------- | ---------------------------------------------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `list_policies`             | List all policies in your Okta organization   | - `Show me the security policies` <br> - `What password policies do we have?` <br> - `List all MFA enrollment policies`                                       |
| `get_policy`                | Get detailed information about a policy       | - `Show me the details of our password policy` <br> - `What are the MFA requirements?` <br> - `Display the sign-on policy for contractors`                    |
| `create_policy`             | Create a new policy                            | - `Create a new password policy for contractors` <br> - `Set up MFA requirements for high-risk applications` <br> - `Add a sign-on policy for remote workers` |
| `update_policy`             | Update an existing policy                      | - `Update the password complexity requirements` <br> - `Modify the MFA policy for executives` <br> - `Change the session timeout for contractors`             |
| `delete_policy`             | Delete a policy (prompts for confirmation)     | - `Delete the old password policy` <br> - `Remove the deprecated MFA policy` <br> - `Clean up unused security policies`                                       |
| `activate_policy`           | Activate a policy                              | - `Activate the new password policy` <br> - `Enable the MFA requirements` <br> - `Turn on the contractor sign-on policy`                                      |
| `deactivate_policy`         | Deactivate a policy (prompts for confirmation) | - `Deactivate the old security policy` <br> - `Temporarily disable MFA for testing` <br> - `Turn off the strict password requirements`                        |
| `list_policy_rules`         | List all rules for a specific policy          | - `Show me all rules for the password policy` <br> - `What MFA rules are configured?` <br> - `List the exceptions in our sign-on policy`                      |
| `get_policy_rule`           | Get detailed information about a policy rule  | - `Show me the details of the contractor MFA rule` <br> - `What are the conditions for the VPN access rule?` <br> - `Display the emergency access rule`       |
| `create_policy_rule`        | Create a new rule for a policy                 | - `Add an exception rule for executives` <br> - `Create a rule for contractor access` <br> - `Set up emergency access rules for IT admins`                    |
| `update_policy_rule`        | Update an existing policy rule                 | - `Update the location restrictions for remote workers` <br> - `Modify the device trust requirements` <br> - `Change the risk-based authentication settings`  |
| `delete_policy_rule`        | Delete a rule from a policy (prompts for confirmation) | - `Delete the old contractor exception` <br> - `Remove the deprecated VPN rule` <br> - `Clean up unused policy exceptions`                                    |
| `activate_policy_rule`      | Activate a policy rule                         | - `Activate the new emergency access rule` <br> - `Enable the contractor restrictions` <br> - `Turn on the location-based access rule`                        |
| `deactivate_policy_rule`    | Deactivate a policy rule (prompts for confirmation) | - `Deactivate the old emergency rule` <br> - `Temporarily disable location restrictions` <br> - `Turn off the device trust requirements for testing`          |

### Device Assurance Policies

> **Required scope:** `okta.deviceAssurance.read` (read) · `okta.deviceAssurance.manage` (write)

| Tool                                  | Description                                                    | Usage Examples                                                                                                                                                                                   |
| ------------------------------------- | -------------------------------------------------------------- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `list_device_assurance_policies`      | List all Device Assurance Policies in your Okta organization  | - `Show me all device assurance policies` <br> - `Which platforms have device compliance policies?` <br> - `Find policies that block jailbroken devices`                                          |
| `get_device_assurance_policy`         | Get details of a specific Device Assurance Policy             | - `Show me the iOS device assurance policy` <br> - `What OS version does our MacOS policy require?` <br> - `Is jailbreak detection enabled in our Android policy?`                               |
| `create_device_assurance_policy`      | Create a new Device Assurance Policy                          | - `Create a MacOS policy requiring OS 14.2 and disk encryption` <br> - `Set up an iOS policy that blocks jailbroken devices` <br> - `Add a Windows compliance policy requiring BitLocker`        |
| `replace_device_assurance_policy`     | Fully replace an existing Device Assurance Policy             | - `Update the MacOS policy to require OS 14.5` <br> - `Enable secure hardware requirement for our Windows policy` <br> - `Change the minimum OS version for our iOS policy`                      |
| `delete_device_assurance_policy`      | Delete a Device Assurance Policy (prompts for confirmation)   | - `Delete the old Windows compliance policy` <br> - `Remove the deprecated Android policy` <br> - `Clean up unused device assurance policies`                                                    |

### Logs

> **Required scope:** `okta.logs.read`

| Tool        | Description                              | Usage Examples                                                                                                                                             |
| ----------- | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `get_logs`  | Retrieve system logs from your Okta org | - `Show me recent login attempts` <br> - `Find failed logins from the past 24 hours` <br> - `Get authentication logs for user john.doe@company.com`     |

### Brands

> **Required scope:** `okta.brands.read` (read) · `okta.brands.manage` (write)

| Tool | Description | Usage Examples |
| ---- | ----------- | -------------- |
| `list_brands` | List all brands in your Okta org | - `Show me all brands` <br> - `Find the brand named Acme` |
| `get_brand` | Get details of a specific brand | - `Show me the agrjatest brand` <br> - `What locale is set on this brand?` |
| `list_brand_domains` | List all custom domains for a brand | - `What domains are attached to the agrjatest brand?` |
| `create_brand` | Create a new brand | - `Create a new brand called Acme Corp` |
| `replace_brand` | Fully update an existing brand | - `Update the agrjatest brand to use French locale` |
| `delete_brand` | Delete a brand (prompts for confirmation) | - `Delete the old test brand` |

### Themes

> **Required scope:** `okta.brands.read` (read) · `okta.brands.manage` (write)

| Tool | Description | Usage Examples |
| ---- | ----------- | -------------- |
| `list_brand_themes` | List all themes for a brand | - `Show me themes for the agrjatest brand` |
| `get_brand_theme` | Get a specific theme | - `What colors are set in the agrjatest theme?` |
| `replace_brand_theme` | Update theme colors and variants | - `Change the primary color of the theme to #FF5733` |
| `upload_brand_theme_logo` | Upload a logo for a theme | - `Upload a new logo for the agrjatest brand` |
| `delete_brand_theme_logo` | Revert to the default logo | - `Remove the custom logo from this theme` |
| `upload_brand_theme_favicon` | Upload a favicon for a theme | - `Set a custom favicon for the agrjatest brand` |
| `delete_brand_theme_favicon` | Revert to the default favicon | - `Remove the custom favicon from this theme` |
| `upload_brand_theme_background_image` | Upload a background image | - `Upload a background image for the sign-in page` |
| `delete_brand_theme_background_image` | Remove the background image | - `Clear the background image from the theme` |

### Custom Pages

> **Required scope:** `okta.brands.read` (read) · `okta.brands.manage` (write)

| Tool | Description | Usage Examples |
| ---- | ----------- | -------------- |
| `get_sign_in_page_resources` | Get sign-in page resource links | - `Show me the sign-in page resources for agrjatest` |
| `get_customized_sign_in_page` | Retrieve the live customized sign-in page | - `Show me the current sign-in page HTML` |
| `get_default_sign_in_page` | Retrieve Okta's default sign-in page | - `What does the default sign-in page look like?` |
| `get_preview_sign_in_page` | Retrieve the sign-in page preview | - `Show me the sign-in page preview` |
| `replace_customized_sign_in_page` | Publish a new sign-in page | - `Update the sign-in page with this new HTML` |
| `delete_customized_sign_in_page` | Revert to default sign-in page (prompts for confirmation) | - `Remove the custom sign-in page and use the default` |
| `replace_preview_sign_in_page` | Update the sign-in page preview (sandbox) | - `Test this new sign-in page HTML in preview` |
| `delete_preview_sign_in_page` | Clear the sign-in page preview | - `Reset the sign-in preview to default` |
| `list_sign_in_widget_versions` | List available Sign-In Widget versions | - `What Sign-In Widget versions can I use?` |
| `get_error_page_resources` | Get error page resource links | - `Show me the error page resources` |
| `get_customized_error_page` | Retrieve the live customized error page | - `Show me the current error page HTML` |
| `get_default_error_page` | Retrieve Okta's default error page | - `What does the default error page look like?` |
| `get_preview_error_page` | Retrieve the error page preview | - `Show me the error page preview` |
| `replace_customized_error_page` | Publish a new error page | - `Update the error page with this new HTML` |
| `delete_customized_error_page` | Revert to default error page (prompts for confirmation) | - `Remove the custom error page` |
| `replace_preview_error_page` | Update the error page preview | - `Test this error page HTML in preview` |
| `delete_preview_error_page` | Clear the error page preview | - `Reset the error page preview` |
| `get_sign_out_page_settings` | Get sign-out page settings | - `What is the sign-out redirect URL?` |
| `replace_sign_out_page_settings` | Update sign-out page settings | - `Set the sign-out redirect to https://example.com` |

### Email Templates & Customizations

> **Required scope:** `okta.templates.read` (read) · `okta.templates.manage` (write)

| Tool | Description | Usage Examples |
| ---- | ----------- | -------------- |
| `list_email_templates` | List all email templates for a brand | - `Show me all email templates for agrjatest` |
| `get_email_template` | Get a specific email template | - `Show me the UserActivation template` |
| `list_email_customizations` | List all language customizations for a template | - `List all customizations for UserActivation` |
| `get_email_customization` | Get a specific customization | - `Show me the French UserActivation customization` |
| `create_email_customization` | Create a new language customization | - `Create a German customization for ForgotPassword` |
| `replace_email_customization` | Replace an existing customization | - `Update the English UserActivation email subject` |
| `delete_email_customization` | Delete a customization (prompts for confirmation) | - `Delete the French UserActivation customization` |
| `delete_all_email_customizations` | Delete all customizations for a template (prompts for confirmation) | - `Remove all customizations from UserActivation` |
| `get_email_customization_preview` | Preview a rendered customization | - `Show me how the German ForgotPassword email will look` |
| `get_email_default_content` | Get Okta's default template content | - `What is the default UserActivation email body?` |
| `get_email_default_content_preview` | Preview Okta's default content with sample data | - `Preview the default ForgotPassword email` |
| `get_email_settings` | Get the recipient settings for a template | - `Who receives the UserActivation email?` |
| `replace_email_settings` | Update recipient settings | - `Set UserActivation emails to go to admins only` |
| `send_test_email` | Send a test email to the current user | - `Send me a test UserActivation email` |

### Custom Domains

> **Required scope:** `okta.domains.read` (read) · `okta.domains.manage` (write)

| Tool | Description | Usage Examples |
| ---- | ----------- | -------------- |
| `list_custom_domains` | List all custom domains | - `Show me all custom domains in my org` |
| `get_custom_domain` | Get details of a custom domain | - `Show me the details for login.example.com` |
| `create_custom_domain` | Create a new custom domain | - `Add login.example.com as a custom domain` |
| `replace_custom_domain` | Update a custom domain | - `Update the custom domain name` |
| `delete_custom_domain` | Delete a custom domain (prompts for confirmation) | - `Remove the old custom domain` |
| `upsert_custom_domain_certificate` | Add or replace a TLS certificate | - `Upload a new TLS certificate for login.example.com` |
| `verify_custom_domain` | Trigger domain DNS verification | - `Verify the DNS for login.example.com` |

### Email Domains

> **Required scope:** `okta.emailDomains.read` (read) · `okta.emailDomains.manage` (write)

| Tool | Description | Usage Examples |
| ---- | ----------- | -------------- |
| `list_email_domains` | List all email domains | - `Show me all email sender domains` |
| `get_email_domain` | Get details of an email domain | - `Show me the details for mail.example.com` |
| `create_email_domain` | Create a new email domain | - `Add no-reply@mail.example.com as an email domain` |
| `replace_email_domain` | Update an email domain | - `Update the display name for this email domain` |
| `delete_email_domain` | Delete an email domain (prompts for confirmation) | - `Remove the old email domain` |
| `verify_email_domain` | Trigger email domain DNS verification | - `Verify the DNS records for mail.example.com` |

### Confirmation for Destructive Operations

All destructive operations (deleting groups, applications, policies, policy rules, device assurance policies, and deactivating/deleting users) use the **[MCP Elicitation API](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation)** to prompt the user for explicit confirmation before proceeding.

- **Clients that support elicitation** (e.g., Claude Desktop with MCP SDK ≥ 1.26): The user sees a confirmation dialog directly in the chat UI. They can accept, decline, or cancel.
- **Clients that do not yet support elicitation**: The tool returns a JSON payload describing the pending action so the LLM can relay the confirmation request to the user. The deprecated `confirm_delete_group` / `confirm_delete_application` tools remain available as a fallback for these clients.

## � Scope-Based Tool Loading

The Okta Open Source MCP Server uses a **scope-based tool loading** mechanism to ensure that only the tools your application is authorized to use are exposed to the LLM.

### How it works

1. **At startup**, after authentication completes, the server reads the scopes listed in your `OKTA_SCOPES` environment variable.
2. Every tool in the server is mapped to a **minimum required OAuth 2.0 scope** (e.g. `okta.users.read`, `okta.brands.manage`). This mapping is defined in `scope_registry.py`.
3. The server compares each tool's required scope against your configured scopes. Tools whose required scope is **not** present are **silently removed** from the tool registry — they will never appear in `tools/list` and the LLM will not be aware of them.
4. At runtime, a `@require_scopes` decorator on each tool provides a second layer of enforcement: if a scope is missing at call time (e.g. token was refreshed with fewer scopes), the tool returns a clear error message instead of making an API call.

### Scope → Tool mapping

| Scope | Tools Unlocked |
| ----- | -------------- |
| `okta.users.read` | `list_users`, `get_user`, `get_user_profile_attributes` |
| `okta.users.manage` | `create_user`, `update_user`, `deactivate_user`, `delete_deactivated_user` |
| `okta.groups.read` | `list_groups`, `get_group`, `list_group_users`, `list_group_apps` |
| `okta.groups.manage` | `create_group`, `update_group`, `delete_group`, `add_user_to_group`, `remove_user_from_group` |
| `okta.apps.read` | `list_applications`, `get_application` |
| `okta.apps.manage` | `create_application`, `update_application`, `delete_application`, `activate_application`, `deactivate_application` |
| `okta.policies.read` | `list_policies`, `get_policy`, `list_policy_rules`, `get_policy_rule` |
| `okta.policies.manage` | `create_policy`, `update_policy`, `delete_policy`, `activate_policy`, `deactivate_policy`, `create_policy_rule`, `update_policy_rule`, `delete_policy_rule`, `activate_policy_rule`, `deactivate_policy_rule` |
| `okta.deviceAssurance.read` | `list_device_assurance_policies`, `get_device_assurance_policy` |
| `okta.deviceAssurance.manage` | `create_device_assurance_policy`, `replace_device_assurance_policy`, `delete_device_assurance_policy` |
| `okta.logs.read` | `get_logs` |
| `okta.brands.read` | `list_brands`, `get_brand`, `list_brand_domains`, `list_brand_themes`, `get_brand_theme`, `get_sign_in_page_resources`, `get_customized_sign_in_page`, `get_default_sign_in_page`, `get_preview_sign_in_page`, `list_sign_in_widget_versions`, `get_error_page_resources`, `get_customized_error_page`, `get_default_error_page`, `get_preview_error_page`, `get_sign_out_page_settings` |
| `okta.brands.manage` | `create_brand`, `replace_brand`, `delete_brand`, `replace_brand_theme`, `upload_brand_theme_logo`, `delete_brand_theme_logo`, `upload_brand_theme_favicon`, `delete_brand_theme_favicon`, `upload_brand_theme_background_image`, `delete_brand_theme_background_image`, `replace_customized_sign_in_page`, `delete_customized_sign_in_page`, `replace_preview_sign_in_page`, `delete_preview_sign_in_page`, `replace_customized_error_page`, `delete_customized_error_page`, `replace_preview_error_page`, `delete_preview_error_page`, `replace_sign_out_page_settings` |
| `okta.templates.read` | `list_email_templates`, `get_email_template`, `list_email_customizations`, `get_email_customization`, `get_email_customization_preview`, `get_email_default_content`, `get_email_default_content_preview`, `get_email_settings` |
| `okta.templates.manage` | `create_email_customization`, `replace_email_customization`, `delete_email_customization`, `delete_all_email_customizations`, `replace_email_settings`, `send_test_email` |
| `okta.domains.read` | `list_custom_domains`, `get_custom_domain` |
| `okta.domains.manage` | `create_custom_domain`, `replace_custom_domain`, `delete_custom_domain`, `upsert_custom_domain_certificate`, `verify_custom_domain` |
| `okta.emailDomains.read` | `list_email_domains`, `get_email_domain` |
| `okta.emailDomains.manage` | `create_email_domain`, `replace_email_domain`, `delete_email_domain`, `verify_email_domain` |

### What you need to do

To enable a group of tools, you must do **two things**:

**1. Grant the scope to your Okta application**

In your Okta Admin Console, open the App Integration you created for the MCP server:
- Go to the **Okta API Scopes** tab.
- Click **Grant** next to each scope you want to enable.

**2. Add the scope to `OKTA_SCOPES` in your MCP client configuration**

Update the `OKTA_SCOPES` value in your `mcp.json` / `settings.json` to include the required scopes as a **space-separated string**:

```json
"OKTA_SCOPES": "okta.users.read okta.groups.read okta.brands.read okta.templates.read"
```

Then restart your MCP client so the server picks up the new scope list.

> [!TIP]
> Start with the minimum set of scopes your use-case requires. For example, if you only need to read users and brands, use `okta.users.read okta.brands.read`. Adding `okta.*.manage` scopes enables write operations — only grant those if needed.

> [!NOTE]
> Scopes follow the pattern `okta.<resource>.read` for read-only access and `okta.<resource>.manage` for full read+write access. You do **not** need both — `okta.users.manage` implicitly enables all read operations on users.

## �🔐 Authentication

The Okta Open Source MCP Server uses the Okta Management API and requires authentication to access your Okta tenant.

### Authentication Flow

The server uses OAuth 2.0 device authorization flow for secure authentication with Okta, or Private Key JWT for browserless authentication. Your credentials are managed securely and are never exposed in plain text.

### Initial Setup

The MCP Server will automatically initiate the appropriate authentication flow based on your configuration:

- **Device Authorization Grant**: Interactive browser-based authentication
- **Private Key JWT**: Browserless authentication using client credentials

> [!NOTE]
> Device authorization flow is not supported for **private cloud** tenants. Private Cloud users should use Private Key JWT authentication with client credentials.

> [!IMPORTANT]
> Using the MCP Server will consume Management API rate limits according to your subscription plan. Refer to the [Rate Limit Policy](https://developer.okta.com/docs/reference/rate-limits/) for more information.

## 🩺 Troubleshooting

When encountering issues with the Okta Open Source MCP Server, several troubleshooting options are available to help diagnose and resolve problems.

### 🐞 Debug Mode

Enable debug mode for more detailed logging:

```bash
export OKTA_LOG_LEVEL=DEBUG
```

> [!TIP]
> Debug mode is particularly useful when troubleshooting connection or authentication issues.

### 🚨 Common Issues

1. **Authentication Failures**
   - Ensure you have the correct permissions in your Okta tenant
   - Verify your `OKTA_ORG_URL`, `OKTA_CLIENT_ID`, and `OKTA_SCOPES` are correct
   - Check that your application has the necessary API scopes granted

2. **MCP Client Can't Connect to the Server**
   - Restart your MCP client after installation
   - Verify the server path is correct in your configuration
   - Check that `uv` is installed and accessible in your PATH

3. **API Errors or Permission Issues**
   - Enable debug mode with `export OKTA_LOG_LEVEL=DEBUG`
   - Verify your Okta application has the required scopes
   - Ensure your application has appropriate admin roles assigned
   - Check the Okta System Log for detailed error information

4. **Docker: "No recommended backend was available" (Keyring Error)**
   - Docker containers don't have a system keyring. Set the environment variable:
     ```bash
     -e PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring
     ```
   - Use a volume to persist tokens: `-v okta-keyring:/home/appuser/.local/share/python_keyring`
   - Alternatively, use Private Key JWT authentication which doesn't require keyring storage

5. **Docker: "Invalid code" when using Device Authorization**
   - The MCP client may restart the server, generating a new device code
   - Copy the URL immediately from the logs and complete authentication quickly
   - Consider using Private Key JWT authentication for Docker environments
   - Use a persistent volume to cache tokens and avoid repeated authentication

6. **"Claude's response was interrupted..." Error**
   - This typically happens when Claude hits its context-length limit
   - Try to be more specific and keep queries concise
   - Break large requests into smaller, focused operations

> [!TIP]
> Most connection issues can be resolved by restarting both the server and your MCP client.

## 📋 Debug Logs

Enable debug mode to view detailed logs:

```bash
export OKTA_LOG_LEVEL=DEBUG
```

You can also specify a log file:

```bash
export OKTA_LOG_FILE="/path/to/okta-mcp.log"
```

## 👨‍💻 Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/okta/okta-mcp-server.git
cd okta-mcp-server

# Install dependencies
uv sync

# Run the server directly
uv run okta-mcp-server
```

### Development Scripts

```bash
# Run with debug logs enabled
OKTA_LOG_LEVEL=DEBUG uv run okta-mcp-server

# Run tests
uv run pytest

# Install in development mode
uv pip install -e .
```

> [!NOTE]
> This server requires [Python 3.13 or higher](https://python.org/downloads) and [uv](https://docs.astral.sh/uv/).

## 🔒 Security

The Okta Open Source MCP Server prioritizes security:

- Credentials are managed through secure authentication flows
- No sensitive information is stored in plain text  
- Authentication uses OAuth 2.0 device authorization flow or Private Key JWT
- Supports fine-grained API scope permissions
- Easy credential management through environment variables

> [!IMPORTANT]
> For security best practices, always review the permissions requested during the authentication process to ensure they align with your security requirements.

> [!CAUTION]
> Always use the principle of least privilege when granting API scopes to your Okta application.

## 🧪 Security Scanning

We recommend regularly scanning this server, and any other MCP-compatible servers you deploy, with community tools built to surface protocol-level risks and misconfigurations.

These scanners help identify issues across key vulnerability classes including: server implementation bugs, tool definition and lifecycle risks, interaction and data flow weaknesses, and configuration or environment gaps.

If you discover a vulnerability, please follow our [responsible disclosure process](https://www.okta.com/security/).

## 💬 Feedback and Contributing

We appreciate feedback and contributions to this project! Before you get started, please see:

- [Okta's general contribution guidelines](CONTRIBUTING.md)

### Reporting Issues

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/okta/okta-mcp-server/issues).

### Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. Please follow the [responsible disclosure process](https://www.okta.com/security/).

## 📄 License

This project is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file for more info.

---

## What is Okta?

<p align="center">
  <picture>
    <img alt="Okta Logo" src="https://raw.githubusercontent.com/okta/okta-mcp-server/main/assets/logo.png" width="150">
  </picture>
</p>
<p align="center">
  Okta is the leading independent identity provider. To learn more checkout <a href="https://www.okta.com/why-okta/">Why Okta?</a>
</p>

Copyright © 2025-Present, Okta, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0. Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

