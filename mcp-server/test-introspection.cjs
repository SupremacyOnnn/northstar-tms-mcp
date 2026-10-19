
require("dotenv").config();

async function testIntrospection() {
  const {
    OAUTH_INTROSPECTION_URL,
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET
  } = process.env;

  if (
    !OAUTH_INTROSPECTION_URL ||
    !OAUTH_CLIENT_ID ||
    !OAUTH_CLIENT_SECRET
  ) {
    throw new Error("Missing OAuth configuration");
  }

  const credentials = Buffer.from(
    `${encodeURIComponent(OAUTH_CLIENT_ID)}:${encodeURIComponent(OAUTH_CLIENT_SECRET)}`
  ).toString("base64");

  const response = await fetch(OAUTH_INTROSPECTION_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      token: "intentionally-invalid-test-token",
      token_type_hint: "access_token"
    })
  });

  const result = await response.json();

  console.log("HTTP status:", response.status);
  console.log("Token active:", result.active);

  if (!response.ok) {
    console.log("OAuth error:", result.error || "Unknown error");
  }
}

testIntrospection().catch((error) => {
  console.error("Test failed:", error.message);
  process.exitCode = 1;
});
