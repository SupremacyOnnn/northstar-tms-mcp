const crypto = require("node:crypto");

const verifier = crypto.randomBytes(32).toString("base64url");

const challenge = crypto
  .createHash("sha256")
  .update(verifier)
  .digest("base64url");

const params = new URLSearchParams({
  client_id: "northstar-local-test",
  response_type: "code",
  scope: "openid",
  redirect_uri: "http://127.0.0.1:3004/callback",
  code_challenge: challenge,
  code_challenge_method: "S256",
  state: crypto.randomBytes(16).toString("hex")
});

console.log(
  "\nOpen this URL in your browser:\n"
);

console.log(
  `http://localhost:3003/auth?${params}`
);