
const pool = require("./db.cjs");
async function main() {
  try {
    const result = await pool.query(`
      SELECT
        u.id,
        u.display_name,
        u.role,
        CASE
          WHEN c.password_hash IS NOT NULL
          THEN 'Configured'
          ELSE 'Not configured'
        END AS password_status
      FROM public.users u
      LEFT JOIN public.user_credentials c
        ON c.user_id = u.id
      ORDER BY u.id
    `);

    console.table(result.rows);
    console.log("OAuth database connection successful");
  } catch (error) {
    console.error("Database connection failed:", error.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

main();
