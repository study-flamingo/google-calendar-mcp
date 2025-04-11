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
  constructor(oauth2Client) {
    this.oauth2Client = oauth2Client;
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
  constructor(oauth2Client) {
    this.baseOAuth2Client = oauth2Client;
    this.tokenManager = new TokenManager(oauth2Client);
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

// src/auth-server.ts
async function runAuthServer() {
  let authServer = null;
  try {
    const oauth2Client = await initializeOAuth2Client();
    authServer = new AuthServer(oauth2Client);
    const success = await authServer.start(true);
    if (!success && !authServer.authCompletedSuccessfully) {
      process.stderr.write("Authentication failed. Could not start server or validate existing tokens. Check port availability (3000-3004) and try again.\n");
      process.exit(1);
    } else if (authServer.authCompletedSuccessfully) {
      process.stderr.write("Authentication successful.\n");
      process.exit(0);
    }
    process.stderr.write("Authentication server started. Please complete the authentication in your browser...\n");
    const pollInterval = setInterval(async () => {
      if (authServer?.authCompletedSuccessfully) {
        clearInterval(pollInterval);
        await authServer.stop();
        process.stderr.write("Authentication successful. Server stopped.\n");
        process.exit(0);
      }
    }, 1e3);
    process.on("SIGINT", async () => {
      clearInterval(pollInterval);
      if (authServer) {
        await authServer.stop();
      }
      process.exit(0);
    });
  } catch (error) {
    process.stderr.write(`Authentication error: ${error instanceof Error ? error.message : "Unknown error"}
`);
    if (authServer) await authServer.stop();
    process.exit(1);
  }
}
if (import.meta.url.endsWith("auth-server.js")) {
  runAuthServer().catch((error) => {
    process.stderr.write(`Unhandled error: ${error instanceof Error ? error.message : "Unknown error"}
`);
    process.exit(1);
  });
}
//# sourceMappingURL=auth-server.js.map
