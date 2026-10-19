
require("dotenv").config();

const { Client } = require("pg");

async function main() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: true
    }
  });

  try {
    await client.connect();
    console.log("Database SSL connection successful");
  } catch (error) {
    console.log("Error code:", error.code || "Not available");
    console.log("Error message:", error.message);
    console.log("Error reason:", error.reason || "Not available");
  } finally {
    await client.end().catch(() => {});
  }
}

main();
