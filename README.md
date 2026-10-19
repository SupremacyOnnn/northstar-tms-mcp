# Northstar TMS MCP

Northstar exposes shipment tracking through an OAuth-protected MCP server. It authenticates OAuth access tokens by introspection. Status queries retain their existing direct database authorization check; event queries use short-lived internal JWTs to call the REST API, which checks shipment authorization before reading events.

## Architecture

```text
ChatGPT MCP client -> HTTPS MCP (northstar-mcp) -> private REST (northstar-rest) -> PostgreSQL
          \-> HTTPS OAuth authorization server (northstar-oauth)
```

Only MCP and OAuth are intended to be public. The separate REST backend must already be hosted and reachable from MCP; the two-service blueprint does not provision it. Its production endpoint remains to be supplied through `NORTHSTAR_API_URL`. The diagram describes the REST path; status queries also access PostgreSQL directly.

## Local setup

Install dependencies in each service directory, copy `.env.example` to local environment files, and provide unique secrets through the environment. Never commit `.env` files, database URLs, passwords, tokens, or signing keys.

Run the existing local services on ports 3001 (REST), 3002 (MCP), and 3003 (OAuth). After installing dependencies in all three directories, run `node --test integration.test.cjs` from the repository root. These tests exercise the real HTTP, OAuth, MCP and REST handlers with an isolated fixture database and ephemeral test credentials. They do not use active credentials or stop existing services. The older `test-oauth-flow.cjs` forcibly stops a port-3003 listener and should not be run against unidentified services.

## Render deployment

`render.yaml` defines exactly two free public web services: OAuth and MCP. MCP builds from the repository root so its shared public CA is available. Set `OAUTH_ISSUER` to the exact HTTPS OAuth origin, `OAUTH_INTROSPECTION_URL` to its `/token/introspection` endpoint, and identical `MCP_RESOURCE` values to the final HTTPS MCP URL including `/mcp`. Set `NORTHSTAR_API_URL` to the existing reachable REST endpoint. Public REST endpoints require HTTPS; HTTP is accepted only for local loopback development or production `.internal` hosts.

Render supplies `PORT` and `RENDER=true`; the blueprint sets `NODE_ENV=production`. Proxy trust is limited to one immediate Render hop. Production requests require HTTPS and the canonical host, and OAuth cookies remain Secure, HttpOnly and SameSite=Lax. Only non-sensitive health checks accept internal HTTP. Do not enable Render proxy mode on a server directly reachable by untrusted clients.

Set `CHATGPT_CLIENT_ID` to a separate predefined public OAuth client ID and `CHATGPT_REDIRECT_URIS` to the exact HTTPS callback displayed by ChatGPT. Both are required in production; no callback is assumed. This client uses authorization code with PKCE S256 and `token_endpoint_auth_method=none`; it has no client secret and must not reuse `northstar-mcp-backend`. The local test client is disabled in production. Protected-resource metadata is served at both `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`; OAuth publishes `/.well-known/openid-configuration`.

Credential rotation is not authorized and no prepared replacement is activated by these changes. Previously exposed active credentials remain a security issue to resolve separately before public production use. Free Render services are a preview target with cold starts and shared monthly limits. See `DEPLOYMENT-PREPARATION.md` for remaining configuration and publication steps.

Keep `DATABASE_URL`, `JWT_SECRET`, `MCP_INTROSPECTION_SECRET`, and `OAUTH_CLIENT_SECRET` in Render secret environment variables. Do not put them in GitHub, Render YAML, logs, or browser output.

## Public repository checklist

Before publishing `northstar-tms-mcp`, scan the complete Git history with a secret scanner, confirm no `.env` or key material is tracked, rotate any credential found, and rerun OAuth introspection, audience/resource binding, tenant isolation, invalid-token, and health checks. Do not publish or deploy until those checks pass.
