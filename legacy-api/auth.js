
const jwt = require("jsonwebtoken");

function authenticate(req, res, next) {
  const authorization = req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  const token = authorization.slice(7);

  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET,
      {
        algorithms: ["HS256"],
        issuer: "northstar-demo",
        audience: "northstar-rest-api"
      }
    );

    if (typeof payload.sub !== "string") {
      return res.status(401).json({
        error: "Invalid user identity"
      });
    }

    req.authenticatedUserId = payload.sub;
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

module.exports = authenticate;
