import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";

const isProduction = process.env.NODE_ENV === "production";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction
    ? { rejectUnauthorized: false } // ✅ required for Supabase/Render
    : false, // ✅ local
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
