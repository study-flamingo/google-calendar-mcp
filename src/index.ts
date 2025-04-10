import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { OAuth2Client } from "google-auth-library";
import { fileURLToPath } from "url";

// Import modular components
import { initializeOAuth2Client } from './auth/client.js';
import { AuthServer } from './auth/server.js';
import { TokenManager } from './auth/tokenManager.js';
import { getToolDefinitions } from './handlers/listTools.js';
import { handleCallTool } from './handlers/callTool.js';

// --- Global Variables --- 
// Create server instance (global for export)
const server = new Server(
  {
    name: "google-calendar",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

let oauth2Client: OAuth2Client;
let tokenManager: TokenManager;
let authServer: AuthServer;

// --- Main Application Logic --- 
async function main() {
  // All logging must use console.error, not console.log, to avoid interfering with stdio transport
  console.error("=== MCP SERVER STARTUP SEQUENCE STARTED ===");
  try {
    // 1. Initialize Authentication
    console.error("Step 1: Initializing Authentication...");
    oauth2Client = await initializeOAuth2Client();
    tokenManager = new TokenManager(oauth2Client);
    authServer = new AuthServer(oauth2Client);

    // 2. Ensure Authentication or Start Auth Server
    // validateTokens attempts to load/refresh first.
    console.error("Step 2: Validating authentication tokens...");
    const tokensValid = await tokenManager.validateTokens();
    console.error(`Token validation result: ${tokensValid ? 'VALID' : 'INVALID/MISSING'}`);
    
    if (!tokensValid) {
      console.error("Authentication required or token expired, starting auth server...");
      const success = await authServer.start(); // Tries ports 3000-3004
      if (!success) {
        console.error("Critical: Failed to start authentication server. Please check port availability (3000-3004) or existing auth issues.");
        // Exit because the server cannot function without potential auth
        process.exit(1);
      }
      // If the auth server starts, the user needs to interact with it.
      // The tool handler will reject calls until authentication is complete.
      console.error("Please authenticate via the browser link provided by the auth server.");
    }

    // 3. Set up MCP Handlers
    console.error("Step 3: Setting up MCP handlers...");
    
    // List Tools Handler
    console.error("Setting up tool definitions handler...");
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      // Directly return the definitions from the handler module
      return getToolDefinitions();
    });

    // Call Tool Handler
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      // Check if tokens are valid before handling the request
      if (!(await tokenManager.validateTokens())) {
        throw new Error("Authentication required. Please run 'npm run auth' to authenticate.");
      }
      
      // Delegate the actual tool execution to the specialized handler
      return handleCallTool(request, oauth2Client);
    });

    // 4. Connect Server Transport
    console.error("Step 4: Connecting server transport...");
    const transport = new StdioServerTransport();
    await server.connect(transport);

    // 5. Set up Graceful Shutdown
    console.error("Step 5: Setting up graceful shutdown...");
    process.on("SIGINT", cleanup);
    process.on("SIGTERM", cleanup);

  } catch (error: unknown) {
    process.exit(1);
  }
  console.error("=== MCP SERVER STARTUP SEQUENCE COMPLETED SUCCESSFULLY ===");
  // Note: After this point, stdout is reserved exclusively for MCP protocol messages
}

// --- Cleanup Logic --- 
async function cleanup() {
  try {
    if (authServer) {
      // Attempt to stop the auth server if it exists and might be running
      await authServer.stop();
    }
    process.exit(0);
  } catch (error: unknown) {
    process.exit(1);
  }
}

// --- Exports & Execution Guard --- 
// Export server and main for testing or potential programmatic use
export { main, server };

// Run main() only when this script is executed directly
const isDirectRun = import.meta.url.startsWith('file://') && process.argv[1] === fileURLToPath(import.meta.url);
if (isDirectRun) {
  main().catch(() => {
    process.exit(1);
  });
}
