
const bcrypt = require("bcrypt");
const pool = require("./db.cjs");

async function verifyUser(userId, password) {
  if (
    typeof userId !== "string" ||
    typeof password !== "string" ||
    !userId ||
    !password
  ) {
    return null;
  }

  const result = await pool.query(
    `SELECT u.id, u.display_name, u.role,
            u.active, t.allowed,
            c.password_hash
     FROM public.users u
     JOIN public.tenants t
       ON t.id = u.tenant_id
     JOIN public.user_credentials c
       ON c.user_id = u.id
     WHERE u.id = $1`,
    [userId]
  );

  const user = result.rows[0];

  if (!user || !user.active || !user.allowed) {
    return null;
  }

  const validPassword = await bcrypt.compare(
    password,
    user.password_hash
  );

  if (!validPassword) {
    return null;
  }

  return {
    id: user.id,
    name: user.display_name,
    role: user.role
  };
}

module.exports = verifyUser;
