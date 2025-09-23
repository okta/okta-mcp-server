# Okta MCP Server

This is only for use with Okta, Inc products and services. It is distributed under the terms of the [Apache 2.0 license](LICENSE.md).

This server is an [Model Context Protocol](https://modelcontextprotocol.io/introduction) server that provides seamless integration with Okta's Admin Management APIs. It allows LLM agents to interact with Okta in a programmatic way, enabling automation and enhanced management capabilities.

**Empower your LLM Agents to Manage your Okta Organization**

## Key Features

* **LLM-Driven Okta Management:** Allows your LLM agents to perform administrative tasks within your Okta environment based on natural language instructions.
* **Secure Authentication:** Supports both Device Authorization Grant for interactive use and Private Key JWT for secure, automated server-to-server communication.
* **Integration with Okta Admin Management APIs:** Leverages the official Okta APIs to ensure secure and reliable interaction with your Okta org.
* **Extensible Architecture:** Designed to be easily extended with new functionalities and support for additional Okta API endpoints.
* **Potential Use Cases:**
    * Automating user provisioning and de-provisioning.
    * Managing group memberships.
    * Retrieving user information.
    * Generating reports on Okta activity.
    * And much more, driven by the capabilities of your LLM agents.
 
This MCP server utilizes [Okta's OpenSource SDK](https://github.com/okta) to communicate with the OKTA APIs, ensuring a robust and well-supported integration.

## Installation

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. Clone the repository:
   ```bash
   git clone https://github.com/atko-eng/okta-mcp-server.git
   ```
3. Run `cd okta-mcp-server && uv sync`

## Okta Application Setup

This server supports two authentication methods. Choose the one that best fits your use case. 
**Note:** mcp automatically chooses its authentication type by detecting if a private key and key ID are available as environment variables.

### Method 1: Device Authorization Grant (Uses Browser for Authentication)-Recommended

1.  In your Okta org, create a **new App Integration**.
2.  Select **OIDC - OpenID Connect** and **Native Application**.
3.  Under **Grant type**, ensure **Device Authorization** is checked.
4.  Go to the Okta API Scopes tab and Grant permissions for the APIs you need (e.g., okta.users.read, okta.groups.manage).
5.  Save the application and copy the **Client ID**.
6. **Documentation:** [Okta Device Authorization Grant Guide](https://developer.okta.com/docs/guides/device-authorization-grant/main/)

### Method 2: Private Key JWT (Browserless Authentication)

1.  **Create App:** In your Okta org, create a **new App Integration**. Select **API Services**. Save the app and copy the **Client ID**.
2.  **Configure Client Authentication:**
    * On the app's **General** tab, find the **Client Credentials** section and click **Edit**.
    * Disable **Require Demonstrating Proof of Possession (DPoP) header in token requests** as **Client Credentials** is not supported in DPoP.
    * Select **Public key / Private key** for the authentication method.
3.  **Add a Public Key:** You have two options for adding a key.
    * **Option A: Generate Key in Okta (Recommended)**
        1.  In the **Public keys** section, click **Add key**.
        2.  In the dialog, choose **Generate new key**.
        3.  Okta will instantly generate a key pair. **Download or save the private key** (`private.pem`) and store it securely. You will not be able to download it again.
        4.  Copy the **Key ID (KID)** displayed for the newly generated key.
    * **Option B: Use Your Own Key**
        1.  Generate a key pair locally using the following `openssl` commands:
            ```bash
            # Generate a 2048-bit RSA private key
            openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
            
            # Extract the public key from the private key
            openssl rsa -in private.pem -pubout -out public.pem
            ```
        2.  Click **Add key** and paste the contents of your **public key** (`public.pem`) into the dialog.
        3.  Copy the **Key ID (KID)** displayed for the key you added.
4.  **Grant API Scopes:** Go to the **Okta API Scopes** tab and **Grant** permissions for the APIs you need (e.g., `okta.users.read`, `okta.groups.manage`).
5.  **Assign Admin Roles:** To avoid `403 Forbidden` errors, go to the **Admin roles** tab and assign the **Super Administrator** role to this application.


### Usage with VS Code

To use the Okta MCP server with Visual Studio Code, follow these steps:

1. Install the GitHub Copilot Extension: Make sure you have the latest version of the GitHub Copilot extension installed in VS Code. This will provide you with access to the "agent mode" required to run the MCP server.
2. Enable Agent Mode in Copilot:
   - Open the Copilot chat view in VS Code. 
   - Click on the dropdown menu at the top of the chat view. 
   - Select "Agent" to enable agent mode.
3. Configure settings.json:
   - Open your VS Code settings.json file. 
   - Copy and paste the following JSON configuration into your settings.json file:

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

4. Start the MCP Server:
   - After you have configured your settings.json file, you will see an option to start the "okta-mcp-server". 
   - Click on the "Start" button to launch the server. 
   - If you are running the server for the first time, you will be prompted to enter the following information:
      * Okta Organization URL: Your Okta tenant URL. 
      * Okta Client ID: The client ID of the application you created in your Okta organization. 
      * Okta Scopes: The scopes that you want to grant to the application, separated by spaces.

### Usage with Claude Desktop

To use the Okta MCP server with the Claude Desktop app, you'll need to edit its configuration file directly.
1. Find the Configuration File:
   - In the Claude Desktop app, navigate to Settings -> Developer and click Edit Config. 
   - This will open the claude_desktop_config.json file in your default text editor. The file is located at:
     * macOS: ~/Library/Application Support/Claude/claude_desktop_config.json 
     * Windows: %APPDATA%\Claude\claude_desktop_config.json

2. Add the Server Configuration:
   - Add the following mcpServers block to the claude_desktop_config.json file. If the block already exists, simply add the "okta-mcp-server" entry inside it.

    ```json
       {
         "mcpServers": {
           "okta-mcp-server": {
             "command": "uv",
             "args": [
               "run",
               "--directory",
               "/path/to/the/okta-mcp-server",
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
3. Update Placeholders:
   - Replace /path/to/your/okta-mcp-server with the absolute path to where you cloned the repository. 
   - Replace the placeholder values for OKTA_ORG_URL, OKTA_CLIENT_ID, and OKTA_SCOPES with your specific credentials from the Okta application you configured.
4. Restart Claude Desktop:
   - Completely quit the Claude Desktop app from the system tray (Windows) or menu bar (macOS) and restart it. The Okta tools will now be available for use.

### Usage with AWS Bedrock

To use the Okta MCP server with AWS Bedrock, you will need to configure the server to run as a Bedrock agent. Follow these steps:
1. Click the settings icon in the app, navigate to developer settings, and click on open config file. 
2. Paste the following mcpServers block into the configuration file. 
3. Update the /path/to/your/okta-mcp-server and the environment variables with your specific Okta details. 
4. Once done, completely quit and restart the desktop application.

```json
{
  "mcpServers" : {
    "okta-mcp-server" : {
      "command" : "uv",
      "env" : {
        "OKTA_ORG_URL": "<OKTA_ORG_URL>",
        "OKTA_CLIENT_ID": "<OKTA_CLIENT_ID>",
        "OKTA_SCOPES": "<OKTA_SCOPES>",
        "OKTA_PRIVATE_KEY": "<PRIVATE_KEY_IF_NEEDED>",
        "OKTA_KEY_ID": "<KEY_ID_IF_NEEDED>"
      },
      "args" : [
        "run",
        "--directory",
        "/path/to/the/okta-mcp-server",
        "okta-mcp-server"
      ]
    }
  }
}
```

### Available Tools

<details>

<summary>Users</summary>


- **list_users** - List all users in your Okta organization.
- **get_user_profile_attributes** - Retrieve all supported user profile attributes in your Okta org.
- **get_user** - Get detailed information about a specific user by their ID.
- **create_user** - Create a new user in your Okta organization with a custom profile.
- **update_user** - Update an existing user's profile information.
- **deactivate_user** - Deactivate a user, making them inactive and eligible for deletion.
- **delete_deactivated_user** - Permanently delete a user who has already been deactivated.

</details>

<details>

<summary>Groups</summary>

- **list_groups** - List all groups in your Okta organization.
- **get_group** - Get detailed information about a specific group by its ID.
- **create_group** - Create a new group in your Okta organization.
- **delete_group** - Delete a group by its ID (requires confirmation).
- **confirm_delete_group** - Confirm and execute the deletion of a group after explicit confirmation.
- **update_group** - Update the profile information of an existing group.
- **list_group_users** - List all users who are members of a specific group.
- **list_group_apps** - List all applications assigned to a specific group.
- **add_user_to_group** - Add a user to a group by their respective IDs.
- **remove_user_from_group** - Remove a user from a group by their respective IDs.

</details>

<details>

<summary>Applications</summary>

- **list_applications** - List all applications in your Okta organization.
- **get_application** - Get detailed information about a specific application by its ID.
- **create_application** - Create a new application in your Okta organization.
- **update_application** - Update the configuration of an existing application.
- **delete_application** - Delete an application by its ID (requires confirmation).
- **confirm_delete_application** - Confirm and execute the deletion of an application after explicit confirmation.
- **activate_application** - Activate an application, making it available for use.
- **deactivate_application** - Deactivate an application, making it unavailable for use.

</details>

<details>

<summary>Policies</summary>

- **list_policies** - List all policies in your Okta organization.
- **get_policy** - Get detailed information about a specific policy by its ID.
- **create_policy** - Create a new policy in your Okta organization.
- **update_policy** - Update the configuration of an existing policy.
- **delete_policy** - Delete a policy by its ID.
- **activate_policy** - Activate a policy, making it enforceable.
- **deactivate_policy** - Deactivate a policy, making it inactive.
- **list_policy_rules** - List all rules for a specific policy.
- **get_policy_rule** - Get detailed information about a specific policy rule by its ID.
- **create_policy_rule** - Create a new rule for a specific policy.
- **update_policy_rule** - Update the configuration of an existing policy rule.
- **delete_policy_rule** - Delete a rule from a specific policy.
- **activate_policy_rule** - Activate a policy rule, making it enforceable.
- **deactivate_policy_rule** - Deactivate a policy rule, making it inactive.

</details>

<details>

<summary>Logs</summary>

- **get_logs** - Retrieve system logs from your Okta organization.

</details>

### Logging

To enable logging for the Okta MCP server, you can set the `OKTA_LOG_LEVEL` environment variable to one of the following
values: `TRACE`, `DEBUG`, `INFO`, `SUCCESS`, `WARNING`, `ERROR`, or `CRITICAL`. This will control the verbosity of the logs generated by the server.

You can also specify a log file by setting the `OKTA_LOG_FILE` environment variable to the desired file path. If this variable is set, all logs will be written to the specified file.

### Troubleshooting

"Claude's response was interrupted ... "

If you see this message, Claude likely hit its context-length limit and stopped mid-reply. This happens most often on servers that trigger many chained tool calls such as the observability server.

To reduce the chance of running in to this issue:

Try to be specific, keep your queries concise.
If a single request calls multiple tools, try to to break it into several smaller tool calls to keep the responses short.


### Contributing

Interested in contributing, and running this server locally? See CONTRIBUTING.md to get started.

---

Copyright © 2025-Present, Okta, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0. Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.


