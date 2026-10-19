require("dotenv").config({ path: process.env.DOTENV_CONFIG_PATH, quiet: true });

const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true, ca: fs.readFileSync(path.join(__dirname, "certs", "supabase-ca.crt"), "utf8") }
});

module.exports = pool;
