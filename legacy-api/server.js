
const express = require("express");
const pool = require("./db");
const bcrypt = require("bcrypt");

const app = express();
const PORT = Number(process.env.PORT || 3001);

// Allow JSON requests
app.use(express.json());

// Home endpoint
app.get("/", (req, res) => {
  res.json({
    message: "Welcome to Northstar TMS REST API",
    status: "running"
  });
});

// Database connectivity test
app.get("/health", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COUNT(*)::int AS total FROM public.loads"
    );

    res.json({
      service: "Northstar TMS Mock API",
      status: "healthy",
      totalLoads: result.rows[0].total
    });
  } catch (error) {
    console.error("Health check failed:", error.message);

    res.status(503).json({
      service: "Northstar TMS Mock API",
      status: "unavailable"
    });
  }
});


const authenticate = require("./auth");

// Check access before returning shipment information
async function authorizeLoad(req, res, next) {
  try {
    const loadId = req.params.id;

    const accessResult = await pool.query(
      `SELECT public.demo_can_view_load($1, $2) AS allowed`,
      [req.authenticatedUserId, loadId]
    );

    if (accessResult.rows[0]?.allowed !== true) {
      return res.status(404).json({
        error: "Shipment not found"
      });
    }

    next();
  } catch (error) {
    console.error("Authorization failed:", error.message);

    res.status(500).json({
      error: "Unable to verify shipment access"
    });
  }
}

// Get complete shipment information
app.get(
  "/api/v1/loads/:id",
  authenticate,
  authorizeLoad,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, origin, destination,
                equipment_type, status,
                current_location,
                scheduled_delivery,
                estimated_delivery,
                updated_at
         FROM public.loads
         WHERE id = $1`,
        [req.params.id]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error("Shipment lookup failed:", error.message);
      res.status(500).json({
        error: "Unable to retrieve shipment"
      });
    }
  }
);

// Get shipment status
app.get(
  "/api/v1/loads/:id/status",
  authenticate,
  authorizeLoad,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id AS load_id, status,
                current_location,
                estimated_delivery,
                updated_at
         FROM public.loads
         WHERE id = $1`,
        [req.params.id]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error("Status lookup failed:", error.message);
      res.status(500).json({
        error: "Unable to retrieve shipment status"
      });
    }
  }
);

// Get tracking events
app.get(
  "/api/v1/loads/:id/events",
  authenticate,
  authorizeLoad,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, load_id, event_type,
                location, description, event_time
         FROM public.load_events
         WHERE load_id = $1
         ORDER BY event_time DESC, id DESC`,
        [req.params.id]
      );

      res.json({
        load_id: req.params.id,
        events: result.rows
      });
    } catch (error) {
      console.error("Event lookup failed:", error.message);
      res.status(500).json({
        error: "Unable to retrieve tracking events"
      });
    }
  }
);


app.post("/api/v1/auth/login", async (req, res) => {
  try {
    const { user_id, password } = req.body || {};

    if (
      typeof user_id !== "string" ||
      typeof password !== "string" ||
      !user_id ||
      !password
    ) {
      return res.status(400).json({
        error: "User ID and password are required"
      });
    }

    const result = await pool.query(
      `SELECT
         u.id,
         u.display_name,
         u.role,
         u.active,
         t.allowed AS tenant_allowed,
         c.password_hash
       FROM public.users u
       JOIN public.tenants t
         ON t.id = u.tenant_id
       JOIN public.user_credentials c
         ON c.user_id = u.id
       WHERE u.id = $1`,
      [user_id]
    );

    const user = result.rows[0];

    if (
      !user ||
      !user.active ||
      !user.tenant_allowed ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    return res.json({
      authenticated: true,
      user: {
        id: user.id,
        name: user.display_name,
        role: user.role
      }
    });
  } catch (error) {
    console.error("Login failed:", error.message);

    return res.status(500).json({
      error: "Login service unavailable"
    });
  }
});



// Start server
if (require.main === module) app.listen(PORT, () => {
  console.log(
    `Northstar REST API running at http://localhost:${PORT}`
  );
});
module.exports = {app, pool};
