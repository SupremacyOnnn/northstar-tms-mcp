
require("dotenv").config();

const { Client } = require(
  "@modelcontextprotocol/sdk/client/index.js"
);

const { StreamableHTTPClientTransport } = require(
  "@modelcontextprotocol/sdk/client/streamableHttp.js"
);

async function main() {
  const token = process.env.DEMO_TOKEN;

  if (!token) {
    throw new Error("DEMO_TOKEN is missing from .env");
  }

  const transport = new StreamableHTTPClientTransport(
    new URL("http://localhost:3002/mcp"),
    {
      requestInit: {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    }
  );

  const client = new Client({
    name: "northstar-test-client",
    version: "1.0.0"
  });

  try {
    await client.connect(transport);

    const tools = await client.listTools();
    console.log("Available tools:");
    console.log(tools.tools.map(t => t.name));

    for (const loadId of [
    "NS-A-001",
    "NS-A-002",
    "NS-A-003",
    "NS-B-001"
    ]) {
      const result = await client.callTool({
        name: "get_load_status",
        arguments: {
          load_id: loadId
        }
      });

      console.log(`\nShipment: ${loadId}`);
      console.log(JSON.stringify(result, null, 2));
    }

    const events = await client.callTool({
      name: "get_load_events",
      arguments: {
        load_id: "NS-A-002"
      }
    });

    console.log("\nTracking events:");
    console.log(JSON.stringify(events, null, 2));
  } finally {
    await client.close();
  }
}

main().catch(error => {
  console.error("MCP test failed:", error.message);
  process.exitCode = 1;
});
