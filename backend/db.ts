import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false, // keep false for local
});

// 🔥 Prevent crash when DB disconnects
pool.on("error", (err) => {
  console.error("❌ PostgreSQL error:", err);
});

export const db = new Kysely({
  dialect: new PostgresDialect({
    pool,
  }),
});
