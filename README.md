# Northstar TMS MCP

Northstar exposes shipment tracking through an OAuth-protected MCP server. The MCP service authenticates OAuth access tokens by introspection, creates a short-lived internal token, and calls the protected REST API. Database authorization remains in the REST/database layer, so tenant boundaries are enforced server-side.

## Architecture

```text
ChatGPT MCP client -> HTTPS MCP (northstar-mcp) -> private REST (northstar-rest) -> PostgreSQL
          \-> HTTPS OAuth authorization server (northstar-oauth)
```

Only the MCP and OAuth services are public. The REST API is a private Render service and the database is never exposed through a public route.

## Local setup

Install dependencies in each service directory, copy `.env.example` to local environment files, and provide unique secrets through the environment. Never commit `.env` files, database URLs, passwords, tokens, or signing keys.

Run the existing local services on ports 3001 (REST), 3002 (MCP), and 3003 (OAuth). Use `oauth-server/test-oauth-flow.cjs` for the PKCE login and MCP integration checks.

## Render deployment

`render.yaml` defines one private REST service and two public web services. Create the Render services from this blueprint only after rotating every credential that has previously been exposed. Set `OAUTH_ISSUER` to the final HTTPS OAuth URL and `OAUTH_INTROSPECTION_URL` to its HTTPS introspection endpoint. Configure the OAuth client redirect URI to the HTTPS callback used by the test/client flow and set the MCP resource/audience to the final HTTPS MCP URL.

Keep `DATABASE_URL`, `JWT_SECRET`, `MCP_INTROSPECTION_SECRET`, and `OAUTH_CLIENT_SECRET` in Render secret environment variables. Do not put them in GitHub, Render YAML, logs, or browser output.

## Public repository checklist

Before publishing `northstar-tms-mcp`, scan the complete Git history with a secret scanner, confirm no `.env` or key material is tracked, rotate any credential found, and rerun OAuth introspection, audience/resource binding, tenant isolation, invalid-token, and health checks. Do not publish or deploy until those checks pass.
