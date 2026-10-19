
require("dotenv").config();

const http = require("node:http");
const crypto = require("node:crypto");

const ISSUER = "http://localhost:3003";
const CLIENT_ID = "northstar-local-test";
const REDIRECT_URI = "http://127.0.0.1:3004/callback";

const verifier = crypto.randomBytes(32).toString("base64url");

const challenge = crypto
  .createHash("sha256")
  .update(verifier)
  .digest("base64url");

const state = crypto.randomBytes(16).toString("hex");

const authorizationUrl = new URL(`${ISSUER}/auth`);

authorizationUrl.searchParams.set("client_id", CLIENT_ID);
authorizationUrl.searchParams.set("response_type", "code");
authorizationUrl.searchParams.set("scope", "openid northstar:loads:read");
authorizationUrl.searchParams.set("resource", "http://localhost:3002/mcp");
authorizationUrl.searchParams.set("redirect_uri", REDIRECT_URI);
authorizationUrl.searchParams.set("code_challenge", challenge);
authorizationUrl.searchParams.set("code_challenge_method", "S256");
authorizationUrl.searchParams.set("state", state);

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, REDIRECT_URI);

  if (url.pathname !== "/callback") {
    res.writeHead(404);
    return res.end("Not found");
  }

  if (url.searchParams.get("state") !== state) {
    res.writeHead(400);
    return res.end("Invalid OAuth state");
  }

  const code = url.searchParams.get("code");

  if (!code) {
  const oauthError = url.searchParams.get("error");
  const description = url.searchParams.get("error_description");

  console.log("OAuth authorization error:", oauthError);
  console.log("Error description:", description);

  res.writeHead(400);
  return res.end("Authorization was not completed. Check CMD.");
}

  try {
    const response = await fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier
      })
    });

    const tokens = await response.json();

    if (!response.ok) {
      console.error("Token exchange failed:", {
        status: response.status,
        error: tokens.error,
        description: tokens.error_description
      });

      res.writeHead(400, {
        "Content-Type": "text/plain"
      });
      res.end("OAuth token exchange failed. Check CMD.");
      return;
    }

    console.log("\nOAuth token exchange successful!");
    console.log("Access token received:", Boolean(tokens.access_token));
    const introspectionCredentials = Buffer.from(
    `${encodeURIComponent(process.env.OAUTH_CLIENT_ID || "northstar-mcp-backend")}:${encodeURIComponent(process.env.MCP_INTROSPECTION_SECRET)}`
    ).toString("base64");

    const introspectionResponse = await fetch(
    `${ISSUER}/token/introspection`,
    {
        method: "POST",
        headers: {
        Authorization: `Basic ${introspectionCredentials}`,
        "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
        token: tokens.access_token,
        token_type_hint: "access_token"
        })
    }
);

const introspection = await introspectionResponse.json();

console.log("\nReal token introspection:");
console.log("HTTP status:", introspectionResponse.status);
console.log("Token active:", introspection.active);
console.log("User identity:", introspection.sub);
console.log("Scope:", introspection.scope);
console.log("Audience:", introspection.aud);
console.log("Resource:", introspection.resource);
console.log("Client ID:", introspection.client_id);
console.log("Issuer:", introspection.iss);
    console.log(
        "Access token format:",
        typeof tokens.access_token === "string" &&
        tokens.access_token.split(".").length === 3
            ? "JWT-shaped"
            : "Opaque or non-JWT"
        );
    console.log("ID token received:", Boolean(tokens.id_token));
    console.log("Token type:", tokens.token_type);
    console.log("Expires in:", tokens.expires_in);

    const { Client } = require("../mcp-server/node_modules/@modelcontextprotocol/sdk/dist/cjs/client/index.js");
    const { StreamableHTTPClientTransport } = require("../mcp-server/node_modules/@modelcontextprotocol/sdk/dist/cjs/client/streamableHttp.js");
    const runMcpCheck = async (accessToken, loadId) => {
      const client = new Client({ name: "northstar-final-test", version: "1.0.0" });
      try {
        await client.connect(new StreamableHTTPClientTransport(
          new URL("http://localhost:3002/mcp"),
          { requestInit: { headers: { Authorization: `Bearer ${accessToken}` } } }
        ));
        return await client.callTool({ name: "get_load_status", arguments: { load_id: loadId } });
      } finally {
        await client.close();
      }
    };
    const authorized = await runMcpCheck(tokens.access_token, "NS-A-001");
    const crossTenant = await runMcpCheck(tokens.access_token, "NS-B-001");
    console.log("MCP NS-A-001:", authorized.isError ? "FAIL" : "PASS");
    console.log("MCP NS-B-001 denied:", crossTenant.isError === true ? "PASS" : "FAIL");
    const invalidResponse = await fetch("http://localhost:3002/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer invalid-local-test-token", "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
    });
    console.log("MCP invalid token rejected:", invalidResponse.status === 401 ? "PASS" : "FAIL");

    // Restart the local OAuth process and verify the same opaque token remains active.
    const { execFileSync, spawn } = require("node:child_process");
    execFileSync("powershell.exe", ["-NoProfile", "-Command", "netstat -ano | Select-String ':3003 .*LISTENING' | ForEach-Object { $p=$_.ToString().Trim().Split()[-1]; Stop-Process -Id $p -Force }"], { stdio: "ignore" });
    const restarted = spawn(process.execPath, ["server.js"], { cwd: __dirname, detached: true, stdio: "ignore", env: { ...process.env, PORT: "3003", OAUTH_ISSUER: ISSUER } });
    restarted.unref();
    await new Promise(resolve => setTimeout(resolve, 1800));
    const postRestart = await fetch(`${ISSUER}/token/introspection`, {
      method: "POST",
      headers: { Authorization: `Basic ${introspectionCredentials}`, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: tokens.access_token, token_type_hint: "access_token" })
    });
    const postRestartIntrospection = await postRestart.json();
    console.log("OAuth restart persistence:", postRestartIntrospection.active === true && postRestartIntrospection.sub === "user-a2" ? "PASS" : "FAIL");

    // Do not print tokens: they are credentials.
    res.writeHead(200, {
      "Content-Type": "text/plain"
    });

    res.end("Northstar OAuth authorization successful!");

  } catch (error) {
    console.error("OAuth callback error:", error.message);

    res.writeHead(500);
    res.end("OAuth callback failed");
  } finally {
    server.close();
  }
});

server.listen(3004, "127.0.0.1", () => {
  console.log("\nNorthstar OAuth callback server ready.");
  console.log("\nOpen this URL in your browser:\n");
  console.log(authorizationUrl.toString());
});
