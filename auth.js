import 'dotenv/config'; // IMPORTANT: încărcăm .env înainte de orice
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import fs from "fs/promises";
import path from "path";

const router = express.Router();

// === Users file ===
const USERS_PATH = path.join(process.cwd(), "data", "users.json");
async function readUsers() {
  try { return JSON.parse(await fs.readFile(USERS_PATH, "utf8")); }
  catch { return []; }
}
async function writeUsers(users) {
  await fs.mkdir(path.dirname(USERS_PATH), { recursive: true });
  await fs.writeFile(USERS_PATH, JSON.stringify(users, null, 2));
}

// === JWT utils ===
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "1d" }
  );
}

// === Register ===
router.post("/register", async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email + password required" });

  const users = await readUsers();
  if (users.find(u => u.email === email)) return res.status(409).json({ error: "Email already registered" });

  const hashed = await bcrypt.hash(password, 10);
  const user = { id: Date.now().toString(), email, password: hashed, name: name || "" };
  users.push(user);
  await writeUsers(users);

  const token = generateToken(user);
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});

// === Login ===
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const users = await readUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: "Invalid credentials" });

  const token = generateToken(user);
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});

// === JWT Middleware ===
export function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });

  const token = auth.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// === Google Auth (pornită doar dacă avem credențiale reale) ===
const useGoogle =
  !!process.env.GOOGLE_CLIENT_ID &&
  !!process.env.GOOGLE_CLIENT_SECRET &&
  !!process.env.GOOGLE_CALLBACK_URL;

if (useGoogle) {
  passport.use(new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      const users = await readUsers();
      const email = profile.emails?.[0]?.value;
      if (!email) return done(new Error("Google profile has no email"));
      let user = users.find(u => u.email === email);
      if (!user) {
        user = {
          id: Date.now().toString(),
          email,
          name: profile.displayName,
          googleId: profile.id
        };
        users.push(user);
        await writeUsers(users);
      }
      return done(null, user);
    }
  ));
}

router.get("/google", (req, res, next) => {
  if (!useGoogle) return res.status(503).json({ error: "Google auth not configured" });
  return passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

router.get(
  "/google/callback",
  (req, res, next) => {
    if (!useGoogle) return res.status(503).json({ error: "Google auth not configured" });
    next();
  },
  passport.authenticate("google", { session: false }),
  (req, res) => {
    const token = generateToken(req.user);
    // redirect spre FE; folosește CORS_ORIGIN dacă e setat
    const fe = process.env.CORS_ORIGIN || "http://localhost:5173";
    res.redirect(`${fe}/login-success?token=${token}`);
  }
);

export default router;
