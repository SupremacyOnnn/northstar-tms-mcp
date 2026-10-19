
require("dotenv").config({ path: process.env.DOTENV_CONFIG_PATH, quiet: true });

const { Pool } = require("pg");
const fs = require("node:fs");
const path = require("node:path");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing from .env");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync(
      path.join(__dirname, "../oauth-server/certs/supabase-ca.crt"),
      "utf8"
    )
  }
});

module.exports = pool;
