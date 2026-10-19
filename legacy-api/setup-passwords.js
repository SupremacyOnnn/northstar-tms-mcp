
require("dotenv").config();

const bcrypt = require("bcrypt");
const pool = require("./db");
const readline = require("node:readline/promises");

async function main() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    const users = [
      { id: "user-a1", name: "Asha Rao" },
      { id: "user-a2", name: "Rahul Mehta" },
      { id: "user-a3", name: "Priya Sharma" },
      { id: "user-b1", name: "Vikram Singh" }
    ];

    for (const user of users) {
      console.log(`\nSetting password for ${user.name} (${user.id})`);

      const password = await rl.question(
        "Enter a unique password : "
      );

      if (password.length === 0) {
        console.log("Password cannot be empty. Skipping this user.");
        continue;
        }

      const hash = await bcrypt.hash(password, 12);

      await pool.query(
        `INSERT INTO public.user_credentials
         (user_id, password_hash)
         VALUES ($1, $2)
         ON CONFLICT (user_id)
         DO UPDATE SET
           password_hash = EXCLUDED.password_hash,
           updated_at = NOW()`,
        [user.id, hash]
      );

      console.log(`Password saved for ${user.id}`);
    }
  } finally {
    rl.close();
    await pool.end();
  }
}

main().catch(error => {
  console.error("Setup failed:", error.message);
  process.exitCode = 1;
});
