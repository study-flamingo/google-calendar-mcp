# Google Calendar MCP Server

This is a Model Context Protocol (MCP) server that provides integration with Google Calendar. It allows LLMs to read, create, and manage calendar events through a standardized interface.

## Features

- List available calendars
- List events from a calendar
- Create new calendar events
- Update existing events
- Delete events

## Prerequisites

1. Node.js 16 or higher
2. A Google Cloud project with the Calendar API enabled
3. OAuth 2.0 credentials (Client ID and Client Secret)

## Google Cloud Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. Enable the [Google Calendar API](https://console.cloud.google.com/apis/library/calendar-json.googleapis.com) for your project. Ensure that the right project is selected from the top bar before enabling the API.
4. Create OAuth 2.0 credentials:
   - Go to Credentials
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "User data" for the type of data that the app will be accessing
   - Add your app name and contact information
   - Add the following scopes (optional):
     - `https://www.googleapis.com/auth/calendar`
     - `https://www.googleapis.com/auth/calendar.events`
   - Select "Desktop app" as the application type
   - Add your email address as a test user under the [OAuth Consent screen](https://console.cloud.google.com/apis/credentials/consent)

## Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create a `.env` file in the root directory with your Google OAuth credentials. See `.env-example` for an example.

3. Build the TypeScript code:
   ```bash
   npm run build
   ```

## Authentication

Before using the server, you need to authenticate with Google Calendar and complete the OAuth flow:

1. Place your Google OAuth credentials in a file named `gcp-oauth.keys.json` in the root directory of the project. This can be found in the Google Cloud Console under "Credentials".

2. Start the authentication server:
   ```bash
   npm run auth
   ```

3. The OAuth flow will open a browser window to complete the OAuth flow.
4. Follow the Google OAuth flow to grant access to your calendars
   - You will be warned that the app is not verified by Google. This is okay, just click "Continue".
   - Grant access to view and edit your calendars
5. Once complete, you can close the browser window.

The authentication tokens will be securely saved in `.gcp-saved-tokens.json` in the project root directory with restricted permissions (600).

## Usage

The server exposes the following tools:
   - `list-calendars`: List all available calendars
   - `list-events`: List events from a calendar
   - `create-event`: Create a new calendar event
   - `update-event`: Update an existing calendar event
   - `delete-event`: Delete a calendar event

## Using with Claude Desktop

1. Add this configuration to your Claude Desktop config file:
   ```json
   {
     "mcpServers": {
       "google-calendar": {
         "command": "node",
         "args": ["path/to/build/calendar-server.js"]
       }
     }
   }
   ```

2. Restart Claude Desktop

## Example Usage

Here are some example prompts you can use with Claude:

1. List your calendars:
   ```
   Can you list my available calendars?
   ```

2. List events:
   ```
   Show me my events for next week in calendar [calendar-id] or [calendar-name]
   ```

3. Create an event:
   ```
   Create an event that will work well for business hours in my local time as well as local time in Sydney. Meeting with [name] on [date].
   ```

4. Update an event:
   ```
   Update the event [event-id] in calendar [calendar-id] to start at 3 PM instead
   ```

5. Delete an event:
   ```
   Delete the event [event-id] from calendar [calendar-id]
   ```

## Security Notes

- The server runs locally and requires OAuth authentication
- OAuth credentials should be stored in `gcp-oauth.keys.json` in the project root
- Authentication tokens are stored in `.gcp-saved-tokens.json` with restricted file permissions
- Tokens are automatically refreshed when expired
- Never commit your OAuth credentials or token files to version control
- For production use, get your OAuth application verified by Google

## License

MIT
