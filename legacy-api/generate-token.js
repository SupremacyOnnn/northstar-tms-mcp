
require("dotenv").config();

const jwt = require("jsonwebtoken");

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is missing from .env");
}

const userId = process.argv[2];

if (!userId) {
  console.error("Usage: node generate-token.js USER_ID");
  process.exit(1);
}

const token = jwt.sign(
  {},
  process.env.JWT_SECRET,
  {
    algorithm: "HS256",
    subject: userId,
    issuer: "northstar-demo",
    audience: "northstar-rest-api",
    expiresIn: "15m"
  }
);

console.log(token);
