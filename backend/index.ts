import "dotenv/config";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { z } from "zod";
import { db } from "./db";

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

// 🔐 ENV CHECK
if (!process.env.ACCESS_SECRET || !process.env.REFRESH_SECRET) {
  throw new Error("Missing JWT secrets in .env");
}

const ACCESS_SECRET = process.env.ACCESS_SECRET!;
const REFRESH_SECRET = process.env.REFRESH_SECRET!;

// =======================
// 🧾 SCHEMAS
// =======================

const PatientSchema = z.object({
  name: z.string().min(2),
  age: z.number().int().positive(),
});

const UpdateProfileSchema = z.object({
  name: z.string().min(2).optional(),
  phone: z.string().optional(),
  location: z.string().optional(),
  avatar: z.string().url().optional(),
});

// ✅ Separate schemas
const SignupSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(6),
});

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

// =======================
// 🔐 AUTH MIDDLEWARE
// =======================

const authMiddleware = (req: any, res: any, next: any) => {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, ACCESS_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

// =======================
// 🧑‍💻 SIGNUP
// =======================

app.post("/signup", async (req, res) => {
  try {
    const parsed = SignupSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }

    const existing = await db
      .selectFrom("users")
      .select("id")
      .where("email", "=", parsed.data.email)
      .executeTakeFirst();

    if (existing) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const hashed = await bcrypt.hash(parsed.data.password, 10);

    const user = await db
      .insertInto("users")
      .values({
        name: parsed.data.name,
        email: parsed.data.email,
        password: hashed,
        created_at: new Date(),
      })
      .returningAll()
      .executeTakeFirst();

    res.json({
      id: user?.id,
      name: user?.name,
      email: user?.email,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// =======================
// 🔑 LOGIN
// =======================

app.post("/login", async (req, res) => {
  try {
    const parsed = LoginSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }

    const user = await db
      .selectFrom("users")
      .selectAll()
      .where("email", "=", parsed.data.email)
      .executeTakeFirst();

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    const valid = await bcrypt.compare(parsed.data.password, user.password);

    if (!valid) {
      return res.status(401).json({ error: "Wrong password" });
    }

    // ✅ Tokens (with name included)
    const accessToken = jwt.sign(
      { userId: user.id, name: user.name },
      ACCESS_SECRET,
      { expiresIn: "5m" },
    );

    const refreshToken = jwt.sign({ userId: user.id }, REFRESH_SECRET, {
      expiresIn: "7d",
    });

    await db
      .updateTable("users")
      .set({ refresh_token: refreshToken })
      .where("id", "=", user.id)
      .execute();

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

app.put("/me", authMiddleware, async (req: any, res) => {
  try {
    const userId = req.user.userId;
    const parsed = UpdateProfileSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }

    // Update only the provided fields
    const updatedUser = await db
      .updateTable("users")
      .set({
        ...parsed.data,
        updated_at: new Date(), // If you have this column
      })
      .where("id", "=", userId)
      .returning(["id", "name", "email", "phone", "location", "avatar"])
      .executeTakeFirst();

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(updatedUser);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// =======================
// 🔄 REFRESH TOKEN
// =======================

app.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: "No refresh token" });
  }

  try {
    const decoded: any = jwt.verify(refreshToken, REFRESH_SECRET);

    const user = await db
      .selectFrom("users")
      .selectAll()
      .where("id", "=", decoded.userId)
      .executeTakeFirst();

    if (!user || user.refresh_token !== refreshToken) {
      return res.status(403).json({ error: "Invalid refresh token" });
    }

    const newAccessToken = jwt.sign(
      { userId: user.id, name: user.name },
      ACCESS_SECRET,
      { expiresIn: "5m" },
    );

    const newRefreshToken = jwt.sign({ userId: user.id }, REFRESH_SECRET, {
      expiresIn: "7d",
    });

    await db
      .updateTable("users")
      .set({ refresh_token: newRefreshToken })
      .where("id", "=", user.id)
      .execute();

    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch {
    res.status(403).json({ error: "Invalid refresh token" });
  }
});

// =======================
// 👤 GET PROFILE
// =======================

app.get("/me", authMiddleware, async (req: any, res) => {
  try {
    const userId = req.user.userId;

    const user = await db
      .selectFrom("users")
      .select(["id", "name", "email", "created_at"])
      .where("id", "=", userId)
      .executeTakeFirst();

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch user profile" });
  }
});

// =======================
// 🚪 LOGOUT
// =======================

app.post("/logout", authMiddleware, async (req: any, res) => {
  const userId = req.user.userId;

  await db
    .updateTable("users")
    .set({ refresh_token: null })
    .where("id", "=", userId)
    .execute();

  res.json({ success: true });
});

// =======================
// 🏥 PATIENT ROUTES
// =======================

// GET
app.get("/patients", authMiddleware, async (req, res) => {
  const data = await db.selectFrom("patients").selectAll().execute();
  res.json(data);
});

// POST
app.post("/patients", authMiddleware, async (req, res) => {
  try {
    const parsed = PatientSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }

    const result = await db
      .insertInto("patients")
      .values(parsed.data)
      .returningAll()
      .executeTakeFirst();

    res.json(result);
  } catch {
    res.status(500).json({ error: "Failed to create patient" });
  }
});

// PUT
app.put("/patients/:id", authMiddleware, async (req, res) => {
  try {
    const id = Number(req.params.id);

    const parsed = PatientSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }

    const result = await db
      .updateTable("patients")
      .set(parsed.data)
      .where("id", "=", id)
      .returningAll()
      .executeTakeFirst();

    if (!result) {
      return res.status(404).json({ error: "Patient not found" });
    }

    res.json(result);
  } catch {
    res.status(500).json({ error: "Failed to update patient" });
  }
});

// DELETE
app.delete("/patients/:id", authMiddleware, async (req, res) => {
  try {
    const id = Number(req.params.id);

    await db.deleteFrom("patients").where("id", "=", id).execute();

    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Failed to delete patient" });
  }
});

// =======================
// 🚀 START SERVER
// =======================

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
