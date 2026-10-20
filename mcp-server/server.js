
require("dotenv").config({ path: process.env.DOTENV_CONFIG_PATH, quiet: true });

const express = require("express");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");
const { z } = require("zod");
const { configureTransport } = require("../oauth-server/transport.cjs");

const { McpServer } = require(
  "@modelcontextprotocol/sdk/server/mcp.js"
);

const { StreamableHTTPServerTransport } = require(
  "@modelcontextprotocol/sdk/server/streamableHttp.js"
);

const app = express();

const PORT = Number(process.env.PORT || 3002);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true, ca: fs.readFileSync(path.join(__dirname, "../oauth-server/certs/supabase-ca.crt"), "utf8") } });

const OAUTH_ISSUER =
  process.env.OAUTH_ISSUER || "http://localhost:3003";

const INTROSPECTION_URL =
  process.env.OAUTH_INTROSPECTION_URL ||
  `${OAUTH_ISSUER}/token/introspection`;

const OAUTH_CLIENT_ID =
  process.env.OAUTH_CLIENT_ID || "northstar-mcp-backend";

const OAUTH_CLIENT_SECRET =
  process.env.OAUTH_CLIENT_SECRET;

const JWT_SECRET = process.env.JWT_SECRET;

const REQUIRED_SCOPE = "northstar:loads:read";
const MCP_RESOURCE = process.env.MCP_RESOURCE;

if (!process.env.DATABASE_URL || !OAUTH_CLIENT_SECRET || !JWT_SECRET || !MCP_RESOURCE) {
  throw new Error(
    "Missing DATABASE_URL, MCP_RESOURCE, OAUTH_CLIENT_SECRET or JWT_SECRET"
  );
}

const { production } = configureTransport(app, MCP_RESOURCE);
const resourceUrl = new URL(MCP_RESOURCE);
if (resourceUrl.pathname !== '/mcp') throw new Error('MCP_RESOURCE must identify /mcp');
const issuerUrl = new URL(OAUTH_ISSUER);
const introspectionUrl = new URL(INTROSPECTION_URL);
if (production && (issuerUrl.protocol !== 'https:' || introspectionUrl.protocol !== 'https:')) {
  throw new Error('Production OAuth endpoints must use HTTPS');
}
const metadataPath = '/.well-known/oauth-protected-resource/mcp';
const metadataUrl = new URL(metadataPath, resourceUrl.origin).href;
const metadata = {resource: MCP_RESOURCE, authorization_servers: [OAUTH_ISSUER], scopes_supported: [REQUIRED_SCOPE], bearer_methods_supported: ['header']};
app.get(['/.well-known/oauth-protected-resource', metadataPath], (req, res) => res.json(metadata));
function unauthorized(res, invalid = false) {
  const error = invalid ? ', error="invalid_token"' : '';
  res.set('WWW-Authenticate', `Bearer resource_metadata="${metadataUrl}", scope="${REQUIRED_SCOPE}"${error}`);
  res.set('Cache-Control', 'no-store');
  return res.status(401).json({error: invalid ? 'Invalid or unauthorized OAuth token' : 'Authentication required'});
}

// Validate OAuth access token with the authorization server.
async function validateOAuthToken(token) {
  const credentials = Buffer.from(
    `${encodeURIComponent(OAUTH_CLIENT_ID)}:${encodeURIComponent(OAUTH_CLIENT_SECRET)}`
  ).toString("base64");

  const response = await fetch(INTROSPECTION_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      token,
      token_type_hint: "access_token"
    }),
    signal: AbortSignal.timeout(5000)
  });

  if (!response.ok) {
    throw new Error("OAuth introspection failed");
  }

  const result = await response.json();

  if (result.active !== true) {
    throw new Error("Invalid or expired OAuth token");
  }

  if (result.iss !== OAUTH_ISSUER) {
    throw new Error("Unexpected OAuth issuer");
  }

  if (typeof result.sub !== "string" || !result.sub) {
    throw new Error("Missing authenticated user");
  }

  const scopes = String(result.scope || "").split(/\s+/);

  if (!scopes.includes(REQUIRED_SCOPE)) {
    throw new Error("Missing shipment read permission");
  }

  // Reject a token if the authorization server explicitly
  // reports an audience or resource other than this MCP.
  // Note: absent audience is NOT proof of resource binding.
  const audiences = result.aud
    ? [].concat(result.aud)
    : result.resource
      ? [].concat(result.resource)
      : [];

  if (
    audiences.length !== 1 ||
    !audiences.includes(MCP_RESOURCE)
  ) {
    throw new Error("Token is not intended for this MCP server");
  }

  return result.sub;
}

// Issue a short-lived internal JWT for the legacy REST API.
function createRestToken(userId) {
  return jwt.sign(
    {},
    JWT_SECRET,
    {
      algorithm: "HS256",
      subject: userId,
      issuer: "northstar-demo",
      audience: "northstar-rest-api",
      expiresIn: "5m"
    }
  );
}

async function getLoadStatus(userId, loadId) {
  const allowed = await pool.query(
    "SELECT public.demo_can_view_load($1, $2) AS allowed",
    [userId, loadId]
  );
  if (allowed.rows[0]?.allowed !== true) throw new Error("Shipment not found");
  const result = await pool.query(
    `SELECT id AS load_id, status, current_location, estimated_delivery, updated_at
       FROM public.loads WHERE id = $1`,
    [loadId]
  );
  return result.rows[0];
}

async function getLoadEvents(userId, loadId) {
  const allowed = await pool.query(
    "SELECT public.demo_can_view_load($1, $2) AS allowed",
    [userId, loadId]
  );
  if (allowed.rows[0]?.allowed !== true) throw new Error("Shipment not found");
  const result = await pool.query(
    `SELECT id, load_id, event_type, location, description, event_time
       FROM public.load_events
      WHERE load_id = $1
      ORDER BY event_time DESC, id DESC`,
    [loadId]
  );
  return {load_id: loadId, events: result.rows};
}

async function listMyLoads(userId, cursor, limit) {
  const result = await pool.query(
    `SELECT l.id, l.origin, l.destination, l.equipment_type, l.status,
            l.current_location, l.scheduled_delivery, l.estimated_delivery,
            l.updated_at
       FROM public.loads l
      WHERE public.demo_can_view_load($1, l.id)
        AND ($2::text IS NULL OR l.id > $2::text)
      ORDER BY l.id
      LIMIT $3`,
    [userId, cursor || null, limit]
  );
  const nextCursor = result.rows.length === limit
    ? result.rows[result.rows.length - 1].id
    : null;
  return {loads: result.rows, next_cursor: nextCursor};
}

async function getBestLaneOffer(origin, destination, equipment, quantity) {
  const result = await pool.query(
    `SELECT price_usd, trucks_available
       FROM public.demo_best_lane_offer($1, $2, $3, $4)`,
    [origin, destination, equipment, quantity]
  );
  const offer = result.rows[0];
  if (!offer) throw new Error("No demonstration lane offer available");
  const priceUsd = Number(offer.price_usd);
  const trucksAvailable = Number(offer.trucks_available);
  return {
    demo_only: true,
    notice: "Synthetic demonstration data; not a live freight quotation.",
    origin,
    destination,
    equipment,
    quantity,
    price_usd_per_truck: priceUsd,
    trucks_available: trucksAvailable,
    total_price_usd: priceUsd * quantity
  };
}

function createMcpServer(userId) {
  const server = new McpServer({
    name: "northstar-tms",
    version: "1.0.0"
  });

  server.registerTool(
    "get_load_status",
    {
      description:
        "Get the current status, location and ETA of an authorized Northstar TMS shipment.",
      inputSchema: {
        load_id: z.string().min(1)
      }
    },
    async ({ load_id }) => {
      try {
        const data = await getLoadStatus(userId, load_id);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(data, null, 2)
            }
          ]
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: error.message
            }
          ]
        };
      }
    }
  );

  server.registerTool(
    "get_load_events",
    {
      description:
        "Get the tracking event history of an authorized Northstar TMS shipment.",
      inputSchema: {
        load_id: z.string().min(1)
      }
    },
    async ({ load_id }) => {
      try {
        const data = await getLoadEvents(userId, load_id);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(data, null, 2)
            }
          ]
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: error.message
            }
          ]
        };
      }
    }
  );

  server.registerTool(
    "list_my_loads",
    {
      description: "List shipments the authenticated Northstar TMS user is authorized to view.",
      inputSchema: {
        cursor: z.string().min(1).optional(),
        limit: z.number().int().min(1).max(100).default(25)
      }
    },
    async ({cursor, limit = 25}) => {
      try {
        const data = await listMyLoads(userId, cursor, limit);
        return {content: [{type: "text", text: JSON.stringify(data, null, 2)}]};
      } catch (error) {
        return {isError: true, content: [{type: "text", text: error.message}]};
      }
    }
  );

  server.registerTool(
    "get_best_lane_offer",
    {
      description: "Get synthetic demonstration lane pricing; not a live freight quotation.",
      inputSchema: {
        origin: z.string().trim().min(1).max(200),
        destination: z.string().trim().min(1).max(200),
        equipment: z.string().trim().min(1).max(100),
        quantity: z.number().int().min(1).max(1000)
      }
    },
    async ({origin, destination, equipment, quantity}) => {
      try {
        const data = await getBestLaneOffer(origin, destination, equipment, quantity);
        return {content: [{type: "text", text: JSON.stringify(data, null, 2)}]};
      } catch (error) {
        return {isError: true, content: [{type: "text", text: error.message}]};
      }
    }
  );

  return server;
}

app.get("/health", (req, res) => {
  res.json({
    application: "Northstar TMS MCP Server",
    status: "running",
    tools: ["get_load_status", "get_load_events", "list_my_loads", "get_best_lane_offer"]
  });
});

app.use('/mcp', async (req, res, next) => {
  const authorization = req.headers.authorization || "";

  if (!/^Bearer \S+$/i.test(authorization)) {
    return unauthorized(res);
  }

  const oauthToken = authorization.slice(7);

  let userId;

  try {
    userId = await validateOAuthToken(oauthToken);
  } catch (error) {
    return unauthorized(res, true);
  }
  req.authenticatedUserId = userId;
  next();
});

app.post('/mcp', express.json({limit: '64kb'}), async (req, res) => {
  const server = createMcpServer(req.authenticatedUserId);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined
  });

  res.on("close", () => {
    transport.close().catch(() => {});
    server.close().catch(() => {});
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request failed");

    if (!res.headersSent) {
      res.status(500).json({
        error: "MCP request failed"
      });
    }
  }
});

if (require.main === module) app.listen(PORT, () => {
  console.log(
    `Northstar MCP Server running at http://localhost:${PORT}/mcp`
  );
});
module.exports = {app, pool, createMcpServer};
