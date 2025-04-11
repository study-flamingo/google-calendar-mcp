#!/usr/bin/env node


// src/index.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema
} from "@modelcontextprotocol/sdk/types.js";
import { fileURLToPath as fileURLToPath2 } from "url";

// src/auth/client.ts
import { OAuth2Client } from "google-auth-library";
import * as fs from "fs/promises";

// src/auth/utils.ts
import * as path from "path";
import { fileURLToPath } from "url";
function getProjectRoot() {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const projectRoot = path.join(__dirname, "..");
  return path.resolve(projectRoot);
}
function getSecureTokenPath() {
  const projectRoot = getProjectRoot();
  const tokenPath = path.join(projectRoot, ".gcp-saved-tokens.json");
  return tokenPath;
}
function getKeysFilePath() {
  const projectRoot = getProjectRoot();
  const keysPath = path.join(projectRoot, "gcp-oauth.keys.json");
  return keysPath;
}

// src/auth/client.ts
async function initializeOAuth2Client() {
  try {
    const keysContent = await fs.readFile(getKeysFilePath(), "utf-8");
    const keys = JSON.parse(keysContent);
    const { client_id, client_secret, redirect_uris } = keys.installed;
    return new OAuth2Client({
      clientId: client_id,
      clientSecret: client_secret,
      redirectUri: redirect_uris[0]
    });
  } catch (error) {
    throw new Error(`Error loading OAuth keys: ${error instanceof Error ? error.message : error}`);
  }
}
async function loadCredentials() {
  try {
    const keysContent = await fs.readFile(getKeysFilePath(), "utf-8");
    const keys = JSON.parse(keysContent);
    const { client_id, client_secret } = keys.installed;
    if (!client_id || !client_secret) {
      throw new Error("Client ID or Client Secret missing in keys file.");
    }
    return { client_id, client_secret };
  } catch (error) {
    throw new Error(`Error loading credentials: ${error instanceof Error ? error.message : error}`);
  }
}

// src/auth/server.ts
import express from "express";
import { OAuth2Client as OAuth2Client2 } from "google-auth-library";

// src/auth/tokenManager.ts
import * as fs2 from "fs/promises";
import * as path2 from "path";
import { GaxiosError } from "gaxios";
var TokenManager = class {
  oauth2Client;
  tokenPath;
  constructor(oauth2Client2) {
    this.oauth2Client = oauth2Client2;
    this.tokenPath = getSecureTokenPath();
    this.setupTokenRefresh();
  }
  // Method to expose the token path
  getTokenPath() {
    return this.tokenPath;
  }
  async ensureTokenDirectoryExists() {
    try {
      const dir = path2.dirname(this.tokenPath);
      await fs2.mkdir(dir, { recursive: true });
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code !== "EEXIST") {
        console.error("Failed to create token directory:", error);
        throw error;
      }
    }
  }
  setupTokenRefresh() {
    this.oauth2Client.on("tokens", async (newTokens) => {
      try {
        await this.ensureTokenDirectoryExists();
        const currentTokens = JSON.parse(await fs2.readFile(this.tokenPath, "utf-8"));
        const updatedTokens = {
          ...currentTokens,
          ...newTokens,
          refresh_token: newTokens.refresh_token || currentTokens.refresh_token
        };
        await fs2.writeFile(this.tokenPath, JSON.stringify(updatedTokens, null, 2), {
          mode: 384
        });
        console.error("Tokens updated and saved");
      } catch (error) {
        if (error instanceof Error && "code" in error && error.code === "ENOENT") {
          try {
            await fs2.writeFile(this.tokenPath, JSON.stringify(newTokens, null, 2), { mode: 384 });
            console.error("New tokens saved");
          } catch (writeError) {
            console.error("Error saving initial tokens:", writeError);
          }
        } else {
          console.error("Error saving updated tokens:", error);
        }
      }
    });
  }
  async loadSavedTokens() {
    try {
      await this.ensureTokenDirectoryExists();
      if (!await fs2.access(this.tokenPath).then(() => true).catch(() => false)) {
        console.error("No token file found at:", this.tokenPath);
        return false;
      }
      const tokens = JSON.parse(await fs2.readFile(this.tokenPath, "utf-8"));
      if (!tokens || typeof tokens !== "object") {
        console.error("Invalid token format in file:", this.tokenPath);
        return false;
      }
      this.oauth2Client.setCredentials(tokens);
      return true;
    } catch (error) {
      console.error("Error loading tokens:", error);
      if (error instanceof Error && "code" in error && error.code !== "ENOENT") {
        try {
          await fs2.unlink(this.tokenPath);
          console.error("Removed potentially corrupted token file");
        } catch (unlinkErr) {
        }
      }
      return false;
    }
  }
  async refreshTokensIfNeeded() {
    const expiryDate = this.oauth2Client.credentials.expiry_date;
    const isExpired = expiryDate ? Date.now() >= expiryDate - 5 * 60 * 1e3 : !this.oauth2Client.credentials.access_token;
    if (isExpired && this.oauth2Client.credentials.refresh_token) {
      console.error("Auth token expired or nearing expiry, refreshing...");
      try {
        const response = await this.oauth2Client.refreshAccessToken();
        const newTokens = response.credentials;
        if (!newTokens.access_token) {
          throw new Error("Received invalid tokens during refresh");
        }
        this.oauth2Client.setCredentials(newTokens);
        console.error("Token refreshed successfully");
        return true;
      } catch (refreshError) {
        if (refreshError instanceof GaxiosError && refreshError.response?.data?.error === "invalid_grant") {
          console.error("Error refreshing auth token: Invalid grant. Token likely expired or revoked. Please re-authenticate.");
          return false;
        } else {
          console.error("Error refreshing auth token:", refreshError);
          return false;
        }
      }
    } else if (!this.oauth2Client.credentials.access_token && !this.oauth2Client.credentials.refresh_token) {
      console.error("No access or refresh token available. Please re-authenticate.");
      return false;
    } else {
      return true;
    }
  }
  async validateTokens() {
    if (!this.oauth2Client.credentials || !this.oauth2Client.credentials.access_token) {
      if (!await this.loadSavedTokens()) {
        return false;
      }
      if (!this.oauth2Client.credentials || !this.oauth2Client.credentials.access_token) {
        return false;
      }
    }
    return this.refreshTokensIfNeeded();
  }
  async saveTokens(tokens) {
    try {
      await this.ensureTokenDirectoryExists();
      await fs2.writeFile(this.tokenPath, JSON.stringify(tokens, null, 2), { mode: 384 });
      this.oauth2Client.setCredentials(tokens);
      console.error("Tokens saved successfully to:", this.tokenPath);
    } catch (error) {
      console.error("Error saving tokens:", error);
      throw error;
    }
  }
  async clearTokens() {
    try {
      this.oauth2Client.setCredentials({});
      await fs2.unlink(this.tokenPath);
      console.error("Tokens cleared successfully");
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") {
        console.error("Token file already deleted");
      } else {
        console.error("Error clearing tokens:", error);
      }
    }
  }
};

// src/auth/server.ts
import open from "open";
var AuthServer = class {
  baseOAuth2Client;
  // Used by TokenManager for validation/refresh
  flowOAuth2Client = null;
  // Used specifically for the auth code flow
  app;
  server = null;
  tokenManager;
  portRange;
  authCompletedSuccessfully = false;
  // Flag for standalone script
  constructor(oauth2Client2) {
    this.baseOAuth2Client = oauth2Client2;
    this.tokenManager = new TokenManager(oauth2Client2);
    this.app = express();
    this.portRange = { start: 3e3, end: 3004 };
    this.setupRoutes();
  }
  setupRoutes() {
    this.app.get("/", (req, res) => {
      const clientForUrl = this.flowOAuth2Client || this.baseOAuth2Client;
      const scopes = ["https://www.googleapis.com/auth/calendar"];
      const authUrl = clientForUrl.generateAuthUrl({
        access_type: "offline",
        scope: scopes,
        prompt: "consent"
      });
      res.send(`<h1>Google Calendar Authentication</h1><a href="${authUrl}">Authenticate with Google</a>`);
    });
    this.app.get("/oauth2callback", async (req, res) => {
      const code = req.query.code;
      if (!code) {
        res.status(400).send("Authorization code missing");
        return;
      }
      if (!this.flowOAuth2Client) {
        res.status(500).send("Authentication flow not properly initiated.");
        return;
      }
      try {
        const { tokens } = await this.flowOAuth2Client.getToken(code);
        await this.tokenManager.saveTokens(tokens);
        this.authCompletedSuccessfully = true;
        const tokenPath = this.tokenManager.getTokenPath();
        res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Authentication Successful</title>
              <style>
                  body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f4f4f4; margin: 0; }
                  .container { text-align: center; padding: 2em; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                  h1 { color: #4CAF50; }
                  p { color: #333; margin-bottom: 0.5em; }
                  code { background-color: #eee; padding: 0.2em 0.4em; border-radius: 3px; font-size: 0.9em; }
              </style>
          </head>
          <body>
              <div class="container">
                  <h1>Authentication Successful!</h1>
                  <p>Your authentication tokens have been saved successfully to:</p>
                  <p><code>${tokenPath}</code></p>
                  <p>You can now close this browser window.</p>
              </div>
          </body>
          </html>
        `);
      } catch (error) {
        this.authCompletedSuccessfully = false;
        const message = error instanceof Error ? error.message : "Unknown error";
        res.status(500).send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Authentication Failed</title>
              <style>
                  body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f4f4f4; margin: 0; }
                  .container { text-align: center; padding: 2em; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                  h1 { color: #F44336; }
                  p { color: #333; }
              </style>
          </head>
          <body>
              <div class="container">
                  <h1>Authentication Failed</h1>
                  <p>An error occurred during authentication:</p>
                  <p><code>${message}</code></p>
                  <p>Please try again or check the server logs.</p>
              </div>
          </body>
          </html>
        `);
      }
    });
  }
  async start(openBrowser = true) {
    if (await this.tokenManager.validateTokens()) {
      this.authCompletedSuccessfully = true;
      return true;
    }
    const port = await this.startServerOnAvailablePort();
    if (port === null) {
      this.authCompletedSuccessfully = false;
      return false;
    }
    try {
      const { client_id, client_secret } = await loadCredentials();
      this.flowOAuth2Client = new OAuth2Client2(
        client_id,
        client_secret,
        `http://localhost:${port}/oauth2callback`
      );
    } catch (error) {
      this.authCompletedSuccessfully = false;
      await this.stop();
      return false;
    }
    if (openBrowser) {
      const authorizeUrl = this.flowOAuth2Client.generateAuthUrl({
        access_type: "offline",
        scope: ["https://www.googleapis.com/auth/calendar"],
        prompt: "consent"
      });
      await open(authorizeUrl);
    }
    return true;
  }
  async startServerOnAvailablePort() {
    for (let port = this.portRange.start; port <= this.portRange.end; port++) {
      try {
        await new Promise((resolve2, reject) => {
          const testServer = this.app.listen(port, () => {
            this.server = testServer;
            resolve2();
          });
          testServer.on("error", (err) => {
            if (err.code === "EADDRINUSE") {
              testServer.close(() => reject(err));
            } else {
              reject(err);
            }
          });
        });
        return port;
      } catch (error) {
        if (!(error instanceof Error && "code" in error && error.code === "EADDRINUSE")) {
          return null;
        }
      }
    }
    return null;
  }
  getRunningPort() {
    if (this.server) {
      const address = this.server.address();
      if (typeof address === "object" && address !== null) {
        return address.port;
      }
    }
    return null;
  }
  async stop() {
    return new Promise((resolve2, reject) => {
      if (this.server) {
        this.server.close((err) => {
          if (err) {
            reject(err);
          } else {
            this.server = null;
            resolve2();
          }
        });
      } else {
        resolve2();
      }
    });
  }
};

// src/handlers/listTools.ts
var remindersInputProperty = {
  type: "object",
  description: "Reminder settings for the event",
  properties: {
    useDefault: {
      type: "boolean",
      description: "Whether to use the default reminders"
    },
    overrides: {
      type: "array",
      description: "Custom reminders (uses popup notifications by default unless email is specified)",
      items: {
        type: "object",
        properties: {
          method: {
            type: "string",
            enum: ["email", "popup"],
            description: "Reminder method (defaults to popup unless email is specified)",
            default: "popup"
          },
          minutes: {
            type: "number",
            description: "Minutes before the event to trigger the reminder"
          }
        },
        required: ["minutes"]
      }
    }
  },
  required: ["useDefault"]
};
function getToolDefinitions() {
  return {
    tools: [
      {
        name: "list-calendars",
        description: "List all available calendars",
        inputSchema: {
          type: "object",
          properties: {},
          // No arguments needed
          required: []
        }
      },
      {
        name: "list-events",
        description: "List events from a calendar",
        inputSchema: {
          type: "object",
          properties: {
            calendarId: {
              type: "string",
              description: "ID of the calendar to list events from (use 'primary' for the main calendar)"
            },
            timeMin: {
              type: "string",
              format: "date-time",
              description: "Start time in ISO format with timezone required (e.g., 2024-01-01T00:00:00Z or 2024-01-01T00:00:00+00:00). Date-time must end with Z (UTC) or +/-HH:MM offset."
            },
            timeMax: {
              type: "string",
              format: "date-time",
              description: "End time in ISO format with timezone required (e.g., 2024-12-31T23:59:59Z or 2024-12-31T23:59:59+00:00). Date-time must end with Z (UTC) or +/-HH:MM offset."
            }
          },
          required: ["calendarId"]
        }
      },
      {
        name: "search-events",
        description: "Search for events in a calendar by text query",
        inputSchema: {
          type: "object",
          properties: {
            calendarId: {
              type: "string",
              description: "ID of the calendar to search events in (use 'primary' for the main calendar)"
            },
            query: {
              type: "string",
              description: "Free text search query (searches summary, description, location, attendees, etc.)"
            },
            timeMin: {
              type: "string",
              format: "date-time",
              description: "Start time boundary in ISO format with timezone required (e.g., 2024-01-01T00:00:00Z or 2024-01-01T00:00:00+00:00). Date-time must end with Z (UTC) or +/-HH:MM offset."
            },
            timeMax: {
              type: "string",
              format: "date-time",
              description: "End time boundary in ISO format with timezone required (e.g., 2024-12-31T23:59:59Z or 2024-12-31T23:59:59+00:00). Date-time must end with Z (UTC) or +/-HH:MM offset."
            }
          },
          required: ["calendarId", "query"]
        }
      },
      {
        name: "list-colors",
        description: "List available color IDs and their meanings for calendar events",
        inputSchema: {
          type: "object",
          properties: {},
          // No arguments needed
          required: []
        }
      },
      {
        name: "create-event",
        description: "Create a new calendar event",
        inputSchema: {
          type: "object",
          properties: {
            calendarId: {
              type: "string",
              description: "ID of the calendar to create the event in (use 'primary' for the main calendar)"
            },
            summary: {
              type: "string",
              description: "Title of the event"
            },
            description: {
              type: "string",
              description: "Description/notes for the event (optional)"
            },
            start: {
              type: "string",
              format: "date-time",
              description: "Start time in ISO format with timezone required (e.g., 2024-08-15T10:00:00Z or 2024-08-15T10:00:00-07:00). Date-time must end with Z (UTC) or +/-HH:MM offset."
            },
            end: {
              type: "string",
              format: "date-time",
              description: "End time in ISO format with timezone required (e.g., 2024-08-15T11:00:00Z or 2024-08-15T11:00:00-07:00). Date-time must end with Z (UTC) or +/-HH:MM offset."
            },
            timeZone: {
              type: "string",
              description: "Timezone of the event start/end times, formatted as an IANA Time Zone Database name (e.g., America/Los_Angeles). Required if start/end times are specified, especially for recurring events."
            },
            location: {
              type: "string",
              description: "Location of the event (optional)"
            },
            attendees: {
              type: "array",
              description: "List of attendee email addresses (optional)",
              items: {
                type: "object",
                properties: {
                  email: {
                    type: "string",
                    format: "email",
                    description: "Email address of the attendee"
                  }
                },
                required: ["email"]
              }
            },
            colorId: {
              type: "string",
              description: "Color ID for the event (optional, use list-colors to see available IDs)"
            },
            reminders: remindersInputProperty,
            recurrence: {
              type: "array",
              description: 'List of recurrence rules (RRULE, EXRULE, RDATE, EXDATE) in RFC5545 format (optional). Example: ["RRULE:FREQ=WEEKLY;COUNT=5"]',
              items: {
                type: "string"
              }
            }
          },
          required: ["calendarId", "summary", "start", "end", "timeZone"]
        }
      },
      {
        name: "update-event",
        description: "Update an existing calendar event",
        inputSchema: {
          type: "object",
          properties: {
            calendarId: {
              type: "string",
              description: "ID of the calendar containing the event"
            },
            eventId: {
              type: "string",
              description: "ID of the event to update"
            },
            summary: {
              type: "string",
              description: "New title for the event (optional)"
            },
            description: {
              type: "string",
              description: "New description for the event (optional)"
            },
            start: {
              type: "string",
              format: "date-time",
              description: "New start time in ISO format with timezone required (e.g., 2024-08-15T10:00:00Z or 2024-08-15T10:00:00-07:00). Date-time must end with Z (UTC) or +/-HH:MM offset."
            },
            end: {
              type: "string",
              format: "date-time",
              description: "New end time in ISO format with timezone required (e.g., 2024-08-15T11:00:00Z or 2024-08-15T11:00:00-07:00). Date-time must end with Z (UTC) or +/-HH:MM offset."
            },
            timeZone: {
              type: "string",
              description: "Timezone for the start/end times (IANA format, e.g., America/Los_Angeles). Required if modifying start/end, or for recurring events."
            },
            location: {
              type: "string",
              description: "New location for the event (optional)"
            },
            colorId: {
              type: "string",
              description: "New color ID for the event (optional)"
            },
            attendees: {
              type: "array",
              description: "New list of attendee email addresses (optional, replaces existing attendees)",
              items: {
                type: "object",
                properties: {
                  email: {
                    type: "string",
                    format: "email",
                    description: "Email address of the attendee"
                  }
                },
                required: ["email"]
              }
            },
            reminders: {
              ...remindersInputProperty,
              description: "New reminder settings for the event (optional)"
            },
            recurrence: {
              type: "array",
              description: 'New list of recurrence rules (RFC5545 format, optional, replaces existing rules). Example: ["RRULE:FREQ=DAILY;COUNT=10"]',
              items: {
                type: "string"
              }
            }
          },
          required: ["calendarId", "eventId", "timeZone"]
          // timeZone is technically required for PATCH
        }
      },
      {
        name: "delete-event",
        description: "Delete a calendar event",
        inputSchema: {
          type: "object",
          properties: {
            calendarId: {
              type: "string",
              description: "ID of the calendar containing the event"
            },
            eventId: {
              type: "string",
              description: "ID of the event to delete"
            }
          },
          required: ["calendarId", "eventId"]
        }
      }
    ]
  };
}

// src/schemas/validators.ts
import { z } from "zod";
var ReminderSchema = z.object({
  method: z.enum(["email", "popup"]).default("popup"),
  minutes: z.number()
});
var RemindersSchema = z.object({
  useDefault: z.boolean(),
  overrides: z.array(ReminderSchema).optional()
});
var isoDateTimeWithTimezone = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$/;
var ListEventsArgumentsSchema = z.object({
  calendarId: z.string(),
  timeMin: z.string().regex(isoDateTimeWithTimezone, "Must be ISO format with timezone (e.g., 2024-01-01T00:00:00Z)").optional(),
  timeMax: z.string().regex(isoDateTimeWithTimezone, "Must be ISO format with timezone (e.g., 2024-12-31T23:59:59Z)").optional()
});
var SearchEventsArgumentsSchema = z.object({
  calendarId: z.string(),
  query: z.string(),
  timeMin: z.string().regex(isoDateTimeWithTimezone, "Must be ISO format with timezone (e.g., 2024-01-01T00:00:00Z)").optional(),
  timeMax: z.string().regex(isoDateTimeWithTimezone, "Must be ISO format with timezone (e.g., 2024-12-31T23:59:59Z)").optional()
});
var CreateEventArgumentsSchema = z.object({
  calendarId: z.string(),
  summary: z.string(),
  description: z.string().optional(),
  start: z.string().regex(isoDateTimeWithTimezone, "Must be ISO format with timezone (e.g., 2024-01-01T00:00:00Z)"),
  end: z.string().regex(isoDateTimeWithTimezone, "Must be ISO format with timezone (e.g., 2024-01-01T00:00:00Z)"),
  timeZone: z.string(),
  attendees: z.array(
    z.object({
      email: z.string()
    })
  ).optional(),
  location: z.string().optional(),
  colorId: z.string().optional(),
  reminders: RemindersSchema.optional(),
  recurrence: z.array(z.string()).optional()
});
var UpdateEventArgumentsSchema = z.object({
  calendarId: z.string(),
  eventId: z.string(),
  summary: z.string().optional(),
  description: z.string().optional(),
  start: z.string().regex(isoDateTimeWithTimezone, "Must be ISO format with timezone (e.g., 2024-01-01T00:00:00Z)").optional(),
  end: z.string().regex(isoDateTimeWithTimezone, "Must be ISO format with timezone (e.g., 2024-01-01T00:00:00Z)").optional(),
  timeZone: z.string(),
  // Required even if start/end don't change, per API docs for patch
  attendees: z.array(
    z.object({
      email: z.string()
    })
  ).optional(),
  location: z.string().optional(),
  colorId: z.string().optional(),
  reminders: RemindersSchema.optional(),
  recurrence: z.array(z.string()).optional()
});
var DeleteEventArgumentsSchema = z.object({
  calendarId: z.string(),
  eventId: z.string()
});

// src/services/googleCalendar.ts
import { google } from "googleapis";
import { GaxiosError as GaxiosError2 } from "gaxios";
function handleGoogleApiError(error) {
  if (error instanceof GaxiosError2 && error.response?.data?.error === "invalid_grant") {
    throw new Error("Google API Error: Authentication token is invalid or expired. Please re-run the authentication process (e.g., `npm run auth`).");
  }
  throw error;
}
async function listCalendars(client) {
  try {
    const calendar = google.calendar({ version: "v3", auth: client });
    const response = await calendar.calendarList.list();
    return response.data.items || [];
  } catch (error) {
    handleGoogleApiError(error);
    throw error;
  }
}
async function listEvents(client, args) {
  try {
    const calendar = google.calendar({ version: "v3", auth: client });
    const response = await calendar.events.list({
      calendarId: args.calendarId,
      timeMin: args.timeMin,
      timeMax: args.timeMax,
      singleEvents: true,
      orderBy: "startTime"
    });
    return response.data.items || [];
  } catch (error) {
    handleGoogleApiError(error);
    throw error;
  }
}
async function searchEvents(client, args) {
  try {
    const calendar = google.calendar({ version: "v3", auth: client });
    const response = await calendar.events.list({
      calendarId: args.calendarId,
      q: args.query,
      timeMin: args.timeMin,
      timeMax: args.timeMax,
      singleEvents: true,
      orderBy: "startTime"
    });
    return response.data.items || [];
  } catch (error) {
    handleGoogleApiError(error);
    throw error;
  }
}
async function listColors(client) {
  try {
    const calendar = google.calendar({ version: "v3", auth: client });
    const response = await calendar.colors.get();
    if (!response.data) throw new Error("Failed to retrieve colors");
    return response.data;
  } catch (error) {
    handleGoogleApiError(error);
    throw error;
  }
}
async function createEvent(client, args) {
  try {
    const calendar = google.calendar({ version: "v3", auth: client });
    const requestBody = {
      summary: args.summary,
      description: args.description,
      start: { dateTime: args.start, timeZone: args.timeZone },
      end: { dateTime: args.end, timeZone: args.timeZone },
      attendees: args.attendees,
      location: args.location,
      colorId: args.colorId,
      reminders: args.reminders,
      recurrence: args.recurrence
    };
    const response = await calendar.events.insert({
      calendarId: args.calendarId,
      requestBody
    });
    if (!response.data) throw new Error("Failed to create event, no data returned");
    return response.data;
  } catch (error) {
    handleGoogleApiError(error);
    throw error;
  }
}
async function updateEvent(client, args) {
  try {
    const calendar = google.calendar({ version: "v3", auth: client });
    const requestBody = {};
    if (args.summary !== void 0) requestBody.summary = args.summary;
    if (args.description !== void 0) requestBody.description = args.description;
    let timeChanged = false;
    if (args.start !== void 0) {
      requestBody.start = { dateTime: args.start, timeZone: args.timeZone };
      timeChanged = true;
    }
    if (args.end !== void 0) {
      requestBody.end = { dateTime: args.end, timeZone: args.timeZone };
      timeChanged = true;
    }
    if (timeChanged || !args.start && !args.end && args.timeZone) {
      if (!requestBody.start) requestBody.start = {};
      if (!requestBody.end) requestBody.end = {};
      if (!requestBody.start.timeZone) requestBody.start.timeZone = args.timeZone;
      if (!requestBody.end.timeZone) requestBody.end.timeZone = args.timeZone;
    }
    if (args.attendees !== void 0) requestBody.attendees = args.attendees;
    if (args.location !== void 0) requestBody.location = args.location;
    if (args.colorId !== void 0) requestBody.colorId = args.colorId;
    if (args.reminders !== void 0) requestBody.reminders = args.reminders;
    if (args.recurrence !== void 0) requestBody.recurrence = args.recurrence;
    const response = await calendar.events.patch({
      calendarId: args.calendarId,
      eventId: args.eventId,
      requestBody
    });
    if (!response.data) throw new Error("Failed to update event, no data returned");
    return response.data;
  } catch (error) {
    handleGoogleApiError(error);
    throw error;
  }
}
async function deleteEvent(client, args) {
  try {
    const calendar = google.calendar({ version: "v3", auth: client });
    await calendar.events.delete({
      calendarId: args.calendarId,
      eventId: args.eventId
    });
  } catch (error) {
    handleGoogleApiError(error);
  }
}

// src/handlers/callTool.ts
function formatCalendarList(calendars) {
  return calendars.map((cal) => `${cal.summary || "Untitled"} (${cal.id || "no-id"})`).join("\n");
}
function formatEventList(events) {
  return events.map((event) => {
    const attendeeList = event.attendees ? `
Attendees: ${event.attendees.map((a) => `${a.email || "no-email"} (${a.responseStatus || "unknown"})`).join(", ")}` : "";
    const locationInfo = event.location ? `
Location: ${event.location}` : "";
    const colorInfo = event.colorId ? `
Color ID: ${event.colorId}` : "";
    const reminderInfo = event.reminders ? `
Reminders: ${event.reminders.useDefault ? "Using default" : (event.reminders.overrides || []).map((r) => `${r.method} ${r.minutes} minutes before`).join(", ") || "None"}` : "";
    return `${event.summary || "Untitled"} (${event.id || "no-id"})${locationInfo}
Start: ${event.start?.dateTime || event.start?.date || "unspecified"}
End: ${event.end?.dateTime || event.end?.date || "unspecified"}${attendeeList}${colorInfo}${reminderInfo}
`;
  }).join("\n");
}
function formatColorList(colors) {
  const eventColors = colors.event || {};
  return Object.entries(eventColors).map(([id, colorInfo]) => `Color ID: ${id} - ${colorInfo.background} (background) / ${colorInfo.foreground} (foreground)`).join("\n");
}
async function handleCallTool(request, oauth2Client2) {
  const { name, arguments: args } = request.params;
  try {
    switch (name) {
      case "list-calendars": {
        const calendars = await listCalendars(oauth2Client2);
        return {
          content: [{
            type: "text",
            text: formatCalendarList(calendars)
          }]
        };
      }
      case "list-events": {
        const validArgs = ListEventsArgumentsSchema.parse(args);
        const events = await listEvents(oauth2Client2, validArgs);
        return {
          content: [{
            type: "text",
            text: formatEventList(events)
          }]
        };
      }
      case "search-events": {
        const validArgs = SearchEventsArgumentsSchema.parse(args);
        const events = await searchEvents(oauth2Client2, validArgs);
        return {
          content: [{
            type: "text",
            text: formatEventList(events)
            // Same formatting as list-events
          }]
        };
      }
      case "list-colors": {
        const colors = await listColors(oauth2Client2);
        return {
          content: [{
            type: "text",
            text: `Available event colors:
${formatColorList(colors)}`
          }]
        };
      }
      case "create-event": {
        const validArgs = CreateEventArgumentsSchema.parse(args);
        const event = await createEvent(oauth2Client2, validArgs);
        return {
          content: [{
            type: "text",
            text: `Event created: ${event.summary} (${event.id})`
          }]
        };
      }
      case "update-event": {
        const validArgs = UpdateEventArgumentsSchema.parse(args);
        const event = await updateEvent(oauth2Client2, validArgs);
        return {
          content: [{
            type: "text",
            text: `Event updated: ${event.summary} (${event.id})`
          }]
        };
      }
      case "delete-event": {
        const validArgs = DeleteEventArgumentsSchema.parse(args);
        await deleteEvent(oauth2Client2, validArgs);
        return {
          content: [{
            type: "text",
            text: `Event deleted successfully`
          }]
        };
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    console.error(`Error executing tool '${name}':`, error);
    throw error;
  }
}

// src/index.ts
var server = new Server(
  {
    name: "google-calendar",
    version: "1.0.0"
  },
  {
    capabilities: {
      tools: {}
    }
  }
);
var oauth2Client;
var tokenManager;
var authServer;
async function main() {
  console.error("=== MCP SERVER STARTUP SEQUENCE STARTED ===");
  try {
    console.error("Step 1: Initializing Authentication...");
    oauth2Client = await initializeOAuth2Client();
    tokenManager = new TokenManager(oauth2Client);
    authServer = new AuthServer(oauth2Client);
    console.error("Step 2: Validating authentication tokens...");
    const tokensValid = await tokenManager.validateTokens();
    console.error(`Token validation result: ${tokensValid ? "VALID" : "INVALID/MISSING"}`);
    if (!tokensValid) {
      console.error("Authentication required or token expired, starting auth server...");
      const success = await authServer.start();
      if (!success) {
        console.error("Critical: Failed to start authentication server. Please check port availability (3000-3004) or existing auth issues.");
        process.exit(1);
      }
      console.error("Please authenticate via the browser link provided by the auth server.");
    }
    console.error("Step 3: Setting up MCP handlers...");
    console.error("Setting up tool definitions handler...");
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      return getToolDefinitions();
    });
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (!await tokenManager.validateTokens()) {
        throw new Error("Authentication required. Please run 'npm run auth' to authenticate.");
      }
      return handleCallTool(request, oauth2Client);
    });
    console.error("Step 4: Connecting server transport...");
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Step 5: Setting up graceful shutdown...");
    process.on("SIGINT", cleanup);
    process.on("SIGTERM", cleanup);
  } catch (error) {
    process.exit(1);
  }
  console.error("=== MCP SERVER STARTUP SEQUENCE COMPLETED SUCCESSFULLY ===");
}
async function cleanup() {
  try {
    if (authServer) {
      await authServer.stop();
    }
    process.exit(0);
  } catch (error) {
    process.exit(1);
  }
}
var isDirectRun = import.meta.url.startsWith("file://") && process.argv[1] === fileURLToPath2(import.meta.url);
if (isDirectRun) {
  main().catch(() => {
    process.exit(1);
  });
}
export {
  main,
  server
};
//# sourceMappingURL=index.js.map
