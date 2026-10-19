const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");

const PORT = process.env.PORT || 4173;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const DB_PATH = path.join(DATA_DIR, "db.json");
const COOKIE_NAME = "ae_session";
const MAX_COVER_CHARS = 2_500_000;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function emptyDb() {
  return {
    secret: crypto.randomBytes(32).toString("hex"),
    users: [],
    portfolios: [],
  };
}

function readDb() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch {
    const db = emptyDb();
    writeDb(db);
    return db;
  }
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(":");
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(password, salt, 64);
  const actual = Buffer.from(hash, "hex");
  if (actual.length !== test.length) return false;
  return crypto.timingSafeEqual(actual, test);
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function signToken(userId, secret) {
  const exp = Date.now() + 1000 * 60 * 60 * 24 * 14;
  const payload = b64url(JSON.stringify({ uid: userId, exp }));
  const sig = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function readToken(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [payload, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data.uid || data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    out[key] = val;
  });
  return out;
}

function setSession(res, token) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${60 * 60 * 24 * 14}`
  );
}

function clearSession(res) {
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
}

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email };
}

function userPortfolios(db, userId) {
  return db.portfolios
    .filter((p) => p.userId === userId)
    .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
}

function requireUser(req, res, next) {
  const db = readDb();
  const token = parseCookies(req)[COOKIE_NAME];
  const payload = readToken(token, db.secret);
  const user = payload && db.users.find((u) => u.id === payload.uid);
  if (!user) {
    res.status(401).json({ error: "로그인이 필요합니다." });
    return;
  }
  req.db = db;
  req.user = user;
  next();
}

const app = express();
app.use(express.json({ limit: "8mb" }));
app.use("/css", express.static(path.join(ROOT, "css")));
app.use("/js", express.static(path.join(ROOT, "js")));
app.get("/", (_req, res) => {
  res.sendFile(path.join(ROOT, "index.html"));
});

app.post("/api/auth/signup", (req, res) => {
  const name = String(req.body?.name || "").trim();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (name.length < 2) return res.status(400).json({ error: "이름을 2자 이상 입력하세요." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "올바른 이메일을 입력하세요." });
  }
  if (password.length < 8) return res.status(400).json({ error: "비밀번호는 8자 이상이어야 합니다." });

  const db = readDb();
  if (db.users.some((u) => u.email === email)) {
    return res.status(409).json({ error: "이미 가입된 이메일입니다." });
  }

  const user = {
    id: crypto.randomUUID(),
    name,
    email,
    passwordHash: hashPassword(password),
    activePortfolioId: null,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  writeDb(db);
  setSession(res, signToken(user.id, db.secret));
  res.status(201).json({ user: publicUser(user), portfolios: [], activeId: null });
});

app.post("/api/auth/login", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const db = readDb();
  const user = db.users.find((u) => u.email === email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: "이메일 또는 비밀번호가 올바르지 않습니다." });
  }
  setSession(res, signToken(user.id, db.secret));
  res.json({
    user: publicUser(user),
    portfolios: userPortfolios(db, user.id),
    activeId: user.activePortfolioId,
  });
});

app.post("/api/auth/logout", (_req, res) => {
  clearSession(res);
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  const db = readDb();
  const token = parseCookies(req)[COOKIE_NAME];
  const payload = readToken(token, db.secret);
  const user = payload && db.users.find((u) => u.id === payload.uid);
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  res.json({
    user: publicUser(user),
    portfolios: userPortfolios(db, user.id),
    activeId: user.activePortfolioId,
  });
});

app.get("/api/portfolios", requireUser, (req, res) => {
  res.json({
    portfolios: userPortfolios(req.db, req.user.id),
    activeId: req.user.activePortfolioId,
  });
});

app.post("/api/portfolios", requireUser, (req, res) => {
  const body = req.body || {};
  if (body.cover && String(body.cover).length > MAX_COVER_CHARS) {
    return res.status(400).json({ error: "이미지가 너무 큽니다. 더 작은 파일을 선택하세요." });
  }
  const item = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    name: String(body.name || "").trim(),
    school: String(body.school || "").trim(),
    year: String(body.year || "3"),
    yearLabel: String(body.yearLabel || ""),
    gpa: String(body.gpa || ""),
    goal: String(body.goal || "").trim(),
    bio: String(body.bio || "").trim(),
    skills: Array.isArray(body.skills) ? body.skills : [],
    interests: Array.isArray(body.interests) ? body.interests : [],
    projectTitle: String(body.projectTitle || "").trim(),
    projectDesc: String(body.projectDesc || "").trim(),
    cover: String(body.cover || ""),
    updatedAt: new Date().toISOString(),
  };
  if (!item.name || !item.school) {
    return res.status(400).json({ error: "이름과 학교를 입력하세요." });
  }
  req.db.portfolios.unshift(item);
  const user = req.db.users.find((u) => u.id === req.user.id);
  user.activePortfolioId = item.id;
  writeDb(req.db);
  res.status(201).json({
    portfolio: item,
    portfolios: userPortfolios(req.db, req.user.id),
    activeId: user.activePortfolioId,
  });
});

app.put("/api/portfolios/:id", requireUser, (req, res) => {
  const item = req.db.portfolios.find((p) => p.id === req.params.id && p.userId === req.user.id);
  if (!item) return res.status(404).json({ error: "포트폴리오를 찾을 수 없습니다." });
  const body = req.body || {};
  if (body.cover && String(body.cover).length > MAX_COVER_CHARS) {
    return res.status(400).json({ error: "이미지가 너무 큽니다. 더 작은 파일을 선택하세요." });
  }
  Object.assign(item, {
    name: String(body.name || item.name).trim(),
    school: String(body.school || item.school).trim(),
    year: String(body.year || item.year),
    yearLabel: String(body.yearLabel || item.yearLabel),
    gpa: String(body.gpa ?? item.gpa),
    goal: String(body.goal ?? item.goal).trim(),
    bio: String(body.bio ?? item.bio).trim(),
    skills: Array.isArray(body.skills) ? body.skills : item.skills,
    interests: Array.isArray(body.interests) ? body.interests : item.interests,
    projectTitle: String(body.projectTitle ?? item.projectTitle).trim(),
    projectDesc: String(body.projectDesc ?? item.projectDesc).trim(),
    cover: body.cover === undefined ? item.cover : String(body.cover || ""),
    updatedAt: new Date().toISOString(),
  });
  writeDb(req.db);
  res.json({
    portfolio: item,
    portfolios: userPortfolios(req.db, req.user.id),
    activeId: req.user.activePortfolioId,
  });
});

app.delete("/api/portfolios/:id", requireUser, (req, res) => {
  const idx = req.db.portfolios.findIndex((p) => p.id === req.params.id && p.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: "포트폴리오를 찾을 수 없습니다." });
  req.db.portfolios.splice(idx, 1);
  const user = req.db.users.find((u) => u.id === req.user.id);
  if (user.activePortfolioId === req.params.id) {
    const rest = userPortfolios(req.db, req.user.id);
    user.activePortfolioId = rest[0]?.id || null;
  }
  writeDb(req.db);
  res.json({
    portfolios: userPortfolios(req.db, req.user.id),
    activeId: user.activePortfolioId,
  });
});

app.post("/api/portfolios/:id/active", requireUser, (req, res) => {
  const item = req.db.portfolios.find((p) => p.id === req.params.id && p.userId === req.user.id);
  if (!item) return res.status(404).json({ error: "포트폴리오를 찾을 수 없습니다." });
  const user = req.db.users.find((u) => u.id === req.user.id);
  user.activePortfolioId = item.id;
  writeDb(req.db);
  res.json({
    portfolios: userPortfolios(req.db, req.user.id),
    activeId: user.activePortfolioId,
  });
});

app.listen(PORT, () => {
  console.log(`건공아틀리에 running at http://localhost:${PORT}`);
});
