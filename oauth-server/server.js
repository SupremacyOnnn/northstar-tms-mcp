
import { rateLimit } from "express-rate-limit";
import { createRequire } from "node:module";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import "dotenv/config";
import express from "express";
import * as oidc from "oidc-provider";

import { renderLoginPage } from "./login-page.js";
import { renderConsentPage } from "./consent-page.js";
import { createPgAdapter } from "./pg-adapter.js";

const require = createRequire(import.meta.url);
const verifyUser = require("./verify-user.cjs");
const { configureTransport } = require("./transport.cjs");

const Provider = oidc.Provider;
const app = express();

const csrfSecret = randomBytes(32);

const PORT = Number(process.env.PORT || 3003);
const ISSUER = process.env.OAUTH_ISSUER || "http://localhost:3003";

const MCP_RESOURCE = process.env.MCP_RESOURCE || "http://localhost:3002/mcp";
const MCP_SCOPE = "northstar:loads:read";
const { production, renderProxy } = configureTransport(app, ISSUER);
if (production && new URL(MCP_RESOURCE).protocol !== 'https:') throw new Error('Production MCP resource must use HTTPS');
const chatgptClientId = process.env.CHATGPT_CLIENT_ID;
const chatgptRedirects = (process.env.CHATGPT_REDIRECT_URIS || '').split(',').map(value => value.trim()).filter(Boolean);
if (Boolean(chatgptClientId) !== Boolean(chatgptRedirects.length) || (production && !chatgptClientId)) {
  throw new Error('Configure CHATGPT_CLIENT_ID and exact CHATGPT_REDIRECT_URIS together');
}
if (chatgptClientId && ['northstar-local-test', 'northstar-mcp-backend'].includes(chatgptClientId)) {
  throw new Error('ChatGPT requires a separate OAuth client ID');
}
for (const redirect of chatgptRedirects) {
  const url = new URL(redirect);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('ChatGPT callback must be an exact HTTPS URI');
}
const JWKS = JSON.parse(process.env.OAUTH_JWKS_JSON || "{\"keys\":[]}");

if (!process.env.OAUTH_JWKS_JSON || !Array.isArray(JWKS.keys) || JWKS.keys.length === 0) {
  throw new Error("OAUTH_JWKS_JSON must contain stable signing keys");
}
if (!process.env.DATABASE_URL || !process.env.MCP_INTROSPECTION_SECRET) {
  throw new Error('DATABASE_URL and MCP_INTROSPECTION_SECRET are required');
}

// --------------------------------------------------
// CSRF protection
// --------------------------------------------------

function createCsrfToken(uid, cookieHeader) {
  return createHmac("sha256", csrfSecret)
    .update(uid + ":" + (cookieHeader || ""))
    .digest("hex");
}

function validCsrfToken(uid, cookieHeader, submittedToken) {
  if (typeof submittedToken !== "string") {
    return false;
  }

  const expected = createCsrfToken(uid, cookieHeader);

  if (!/^[a-f0-9]{64}$/.test(submittedToken)) {
    return false;
  }

  return timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(submittedToken, "hex")
  );
}

// --------------------------------------------------
// OAuth configuration
// --------------------------------------------------

const configuration = {
  adapter: createPgAdapter(process.env.OAUTH_STORAGE_DATABASE_URL || process.env.DATABASE_URL),
  jwks: JWKS,
  cookies: {
    long: {secure: new URL(ISSUER).protocol === 'https:', httpOnly: true, sameSite: 'lax'},
    short: {secure: new URL(ISSUER).protocol === 'https:', httpOnly: true, sameSite: 'lax'}
  },
  clients: [
    ...(!production ? [{
      client_id: "northstar-local-test",

      redirect_uris: (process.env.OAUTH_REDIRECT_URIS || "http://127.0.0.1:3004/callback").split(",").map(value => value.trim()),

      response_types: ["code"],
      grant_types: ["authorization_code"],

      token_endpoint_auth_method: "none"
    }] : []),
    ...(chatgptClientId ? [{
      client_id: chatgptClientId,
      redirect_uris: chatgptRedirects,
      response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'none'
    }] : []),

    {
      client_id: "northstar-mcp-backend",

      client_secret: process.env.MCP_INTROSPECTION_SECRET,

      redirect_uris: [],
      response_types: [],
      grant_types: [],

      token_endpoint_auth_method: "client_secret_basic",
      introspection_endpoint_auth_method: "client_secret_basic"
    }
  ],

  scopes: [
    "openid",
    "offline_access",
    MCP_SCOPE
  ],

  pkce: {
    required: () => true
  },

  features: {
    devInteractions: {
      enabled: false
    },

    introspection: {
      enabled: true,
      allowedPolicy(ctx, client, token) {
        return client.clientId === 'northstar-mcp-backend' && token.aud === MCP_RESOURCE;
      }
    },

    resourceIndicators: {
      enabled: true,

      getResourceServerInfo(ctx, resourceIndicator) {
        console.log(
          "[OAuth DEBUG] Requested resource:",
          resourceIndicator
        );

        if (resourceIndicator !== MCP_RESOURCE) {
          console.log("[OAuth DEBUG] Resource mismatch");

          throw new Error("Unknown OAuth resource");
        }

        console.log("[OAuth DEBUG] Resource accepted");

        return {
          scope: MCP_SCOPE,
          audience: MCP_RESOURCE,
          accessTokenFormat: "opaque",
          accessTokenTTL: 3600
        };
      }
    }
  },

  interactions: {
    url(ctx, interaction) {
      return `/interaction/${interaction.uid}`;
    }
  },

  findAccount: async (ctx, accountId) => {
    return {
      accountId,

      async claims() {
        return {
          sub: accountId
        };
      }
    };
  }
};

// --------------------------------------------------
// Initialize OAuth provider
// --------------------------------------------------

const provider = new Provider(ISSUER, configuration);
provider.proxy = renderProxy;
provider.maxIpsCount = 1;

// --------------------------------------------------
// Access token debugging
// --------------------------------------------------

provider.on("access_token.issued", (ctx) => {
  console.log("\n[OAuth DEBUG] Access token issued");

  const token = ctx.oidc?.entities?.AccessToken;

  if (!token) {
    console.log("Access token metadata unavailable");
    return;
  }

  console.log("Client:", token.clientId);
  console.log("Account:", token.accountId);
  console.log("Scope:", token.scope);
  console.log("Resource:", token.resource);
  console.log("Audience:", token.aud);
});

// --------------------------------------------------
// Health endpoint
// --------------------------------------------------

app.get("/health", (req, res) => {
  res.json({
    service: "Northstar OAuth Server",
    status: "running"
  });
});

// --------------------------------------------------
// Display login / consent page
// --------------------------------------------------

app.get("/interaction/:uid", async (req, res) => {
  try {
    const details = await provider.interactionDetails(req, res);

    console.log("OAuth interaction:", {
      prompt: details.prompt.name,
      clientId: details.params.client_id
    });

    if (details.uid !== req.params.uid) {
      return res.status(400).send(
        "Invalid OAuth interaction"
      );
    }

    const csrfToken = createCsrfToken(
      details.uid,
      req.headers.cookie
    );

    res.set("Cache-Control", "no-store");

    if (details.prompt.name === "consent") {
      return res.type("html").send(
        renderConsentPage(
          details.uid,
          details.params.client_id,
          csrfToken
        )
      );
    }

    if (details.prompt.name === "login") {
      return res.type("html").send(
        renderLoginPage(
          details.uid,
          "",
          csrfToken
        )
      );
    }

    return res.status(400).send(
      "Unsupported OAuth interaction"
    );

  } catch (error) {
    console.error(
      "OAuth interaction error:",
      error.message
    );

    return res.status(400).send(
      "Unable to display the authorization page"
    );
  }
});

// --------------------------------------------------
// Login rate limiting
// --------------------------------------------------

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: "Too many login attempts. Please try again later."
});

// --------------------------------------------------
// Process login
// --------------------------------------------------

app.post(
  "/interaction/:uid/login",

  loginLimiter,

  express.urlencoded({
    extended: false,
    limit: "2kb"
  }),

  async (req, res) => {
    res.set("Cache-Control", "no-store");

    let details;

    try {
      details = await provider.interactionDetails(req, res);

    } catch (error) {
      console.error(
        "Invalid OAuth interaction:",
        error.message
      );

      return res.status(400).send(
        "Invalid or expired OAuth interaction"
      );
    }

    if (
      details.uid !== req.params.uid ||
      details.prompt.name !== "login"
    ) {
      return res.status(400).send(
        "Invalid login interaction"
      );
    }

    if (
      !validCsrfToken(
        details.uid,
        req.headers.cookie,
        req.body?._csrf
      )
    ) {
      return res.status(403).send(
        "Invalid login form. Please start again."
      );
    }

    try {
      const { user_id, password } = req.body;

      const user = await verifyUser(user_id, password);

      if (!user) {
        const csrfToken = createCsrfToken(
          details.uid,
          req.headers.cookie
        );

        return res.status(401).type("html").send(
          renderLoginPage(
            details.uid,
            "Invalid credentials",
            csrfToken
          )
        );
      }

      await provider.interactionFinished(
        req,
        res,
        {
          login: {
            accountId: user.id
          }
        },
        {
          mergeWithLastSubmission: false
        }
      );

    } catch (error) {
      console.error(
        "Login interaction failed:",
        error.message
      );

      return res.status(500).send(
        "Unable to complete login"
      );
    }
  }
);

// --------------------------------------------------
// Process consent
// --------------------------------------------------

app.post(
  "/interaction/:uid/consent",

  express.urlencoded({
    extended: false,
    limit: "2kb"
  }),

  async (req, res) => {
    res.set("Cache-Control", "no-store");

    let details;

    try {
      details = await provider.interactionDetails(req, res);

    } catch (error) {
      console.error(
        "Consent interaction error:",
        error.message
      );

      return res.status(400).send(
        "Invalid or expired OAuth interaction"
      );
    }

    if (
      details.uid !== req.params.uid ||
      details.prompt.name !== "consent"
    ) {
      return res.status(400).send(
        "Invalid consent interaction"
      );
    }

    if (
      !validCsrfToken(
        details.uid,
        req.headers.cookie,
        req.body?._csrf
      )
    ) {
      return res.status(403).send(
        "Invalid consent form. Please start again."
      );
    }

    const decision = req.body?.decision;

    if (
      decision !== "allow" &&
      decision !== "deny"
    ) {
      return res.status(400).send(
        "Invalid consent decision"
      );
    }

    try {
      // User denied authorization
      if (decision === "deny") {
        return await provider.interactionFinished(
          req,
          res,
          {
            error: "access_denied",
            error_description: "User denied authorization"
          },
          {
            mergeWithLastSubmission: false
          }
        );
      }

      // Grant only the requested permissions
      const grant = new provider.Grant({
        accountId: details.session.accountId,
        clientId: details.params.client_id
      });

      if (details.prompt.details.missingOIDCScope) {
        grant.addOIDCScope(
          details.prompt.details.missingOIDCScope.join(" ")
        );
      }

      if (details.prompt.details.missingOIDCClaims) {
        grant.addOIDCClaims(
          details.prompt.details.missingOIDCClaims
        );
      }

      if (details.prompt.details.missingResourceScopes) {
        for (
          const [resource, scopes] of Object.entries(
            details.prompt.details.missingResourceScopes
          )
        ) {
          grant.addResourceScope(
            resource,
            scopes.join(" ")
          );
        }
      }

      const grantId = await grant.save();

      return await provider.interactionFinished(
        req,
        res,
        {
          consent: {
            grantId
          }
        },
        {
          mergeWithLastSubmission: false
        }
      );

    } catch (error) {
      console.error(
        "Consent processing failed:",
        error.message
      );

      return res.status(500).send(
        "Unable to complete authorization"
      );
    }
  }
);

// --------------------------------------------------
// OAuth endpoints
// --------------------------------------------------

app.use(provider.callback());

// --------------------------------------------------
// Start server
// --------------------------------------------------

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) app.listen(PORT, () => {
  console.log(
    `Northstar OAuth Server running at ${ISSUER}`
  );
});
export { app, provider };
