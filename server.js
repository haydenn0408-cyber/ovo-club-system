const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "ovo.sqlite");

if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 24) {
  console.error("請設定至少 24 字元的 ADMIN_TOKEN 環境變數。");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(express.json({ limit: "200kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/claim", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));

const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash TEXT NOT NULL UNIQUE,
  key_hint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unused' CHECK(status IN ('unused','used','revoked','expired')),
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  used_at TEXT,
  credential_id INTEGER
);
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account TEXT NOT NULL,
  password TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'available' CHECK(status IN ('available','issued')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  issued_at TEXT,
  issued_key_id INTEGER UNIQUE
);
CREATE TABLE IF NOT EXISTS claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id INTEGER NOT NULL UNIQUE REFERENCES keys(id),
  credential_id INTEGER NOT NULL UNIQUE REFERENCES credentials(id),
  claimed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const hashKey = key => crypto.createHash("sha256").update(key).digest("hex");
const randomKey = () => "OVO-" + crypto.randomBytes(18).toString("base64url").toUpperCase();
function admin(req, res, next) {
  const auth = req.headers.authorization || "";
  const supplied = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const a = Buffer.from(supplied);
  const b = Buffer.from(ADMIN_TOKEN);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: "管理員驗證失敗" });
  next();
}
function cleanKey(v) {
  return typeof v === "string" ? v.trim() : "";
}
app.get("/api/health", (req,res) => res.json({ ok: true }));

// Client-side key verification only reports eligibility; credentials are returned only by claim.
app.post("/api/verify", rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 }), (req,res) => {
  const key = cleanKey(req.body?.key);
  if (!key || key.length > 200) return res.status(400).json({ error: "請輸入有效密鑰" });
  const row = db.prepare("SELECT status, expires_at FROM keys WHERE key_hash=?").get(hashKey(key));
  if (!row || row.status !== "unused") return res.status(403).json({ error: "密鑰無效、已使用或已停用" });
  if (row.expires_at && Date.parse(row.expires_at) <= Date.now()) {
    db.prepare("UPDATE keys SET status='expired' WHERE key_hash=?").run(hashKey(key));
    return res.status(403).json({ error: "密鑰已過期" });
  }
  res.json({ ok: true, message: "密鑰有效，可領取一次" });
});

// Atomic claim: key and inventory are reserved together inside one SQLite transaction.
const claimTransaction = db.transaction((key) => {
  const kh = hashKey(key);
  const k = db.prepare("SELECT * FROM keys WHERE key_hash=?").get(kh);
  if (!k || k.status !== "unused") return { error: "密鑰無效、已使用或已停用" };
  if (k.expires_at && Date.parse(k.expires_at) <= Date.now()) {
    db.prepare("UPDATE keys SET status='expired' WHERE id=?").run(k.id);
    return { error: "密鑰已過期" };
  }
  const c = db.prepare("SELECT * FROM credentials WHERE status='available' ORDER BY id LIMIT 1").get();
  if (!c) return { error: "目前庫存不足，請稍後聯絡管理員" };
  const now = new Date().toISOString();
  const changedKey = db.prepare("UPDATE keys SET status='used', used_at=?, credential_id=? WHERE id=? AND status='unused'").run(now, c.id, k.id);
  if (changedKey.changes !== 1) return { error: "密鑰已被使用，請勿重複領取" };
  const changedCred = db.prepare("UPDATE credentials SET status='issued', issued_at=?, issued_key_id=? WHERE id=? AND status='available'").run(now, k.id, c.id);
  if (changedCred.changes !== 1) throw new Error("庫存競爭，請重試");
  db.prepare("INSERT INTO claims(key_id, credential_id, claimed_at) VALUES(?,?,?)").run(k.id, c.id, now);
  return { account: c.account, password: c.password, claimedAt: now };
});
app.post("/api/claim", (req,res) => {
  const key = cleanKey(req.body?.key);
  if (!key || key.length > 200) return res.status(400).json({ error: "請輸入有效密鑰" });
  try {
    const result = claimTransaction(key);
    if (result.error) return res.status(403).json({ error: result.error });
    res.json({ ok: true, ...result });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "發放暫時失敗，請稍後再試" });
  }
});

app.get("/api/admin/stats", admin, (req,res) => {
  const credentials = db.prepare("SELECT status, COUNT(*) n FROM credentials GROUP BY status").all();
  const keys = db.prepare("SELECT status, COUNT(*) n FROM keys GROUP BY status").all();
  res.json({ credentials, keys });
});
app.get("/api/admin/keys", admin, (req,res) => {
  res.json(db.prepare("SELECT id,key_hint,status,expires_at,created_at,used_at FROM keys ORDER BY id DESC LIMIT 500").all());
});
app.post("/api/admin/keys", admin, (req,res) => {
  const count = Math.max(1, Math.min(500, Number.parseInt(req.body?.count || "1", 10) || 1));
  const expiresAt = req.body?.expiresAt ? new Date(req.body.expiresAt).toISOString() : null;
  const create = db.transaction(() => {
    const out = [];
    const ins = db.prepare("INSERT INTO keys(key_hash,key_hint,expires_at) VALUES(?,?,?)");
    for (let i=0;i<count;i++) {
      const key = randomKey();
      ins.run(hashKey(key), "…" + key.slice(-6), expiresAt);
      out.push(key); // raw key is shown only once at creation
    }
    return out;
  });
  res.json({ keys: create() });
});
app.post("/api/admin/keys/:id/revoke", admin, (req,res) => {
  const r = db.prepare("UPDATE keys SET status='revoked' WHERE id=? AND status='unused'").run(Number(req.params.id));
  if (!r.changes) return res.status(400).json({ error: "密鑰不存在或已被使用" });
  res.json({ ok: true });
});
app.post("/api/admin/credentials/import", admin, (req,res) => {
  const rows = req.body?.rows;
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > 5000) return res.status(400).json({ error: "請提供 1 至 5000 筆帳密資料" });
  const insert = db.prepare("INSERT INTO credentials(account,password) VALUES(?,?)");
  let count = 0;
  const tx = db.transaction(() => {
    for (const row of rows) {
      const account = String(row?.account ?? "").trim();
      const password = String(row?.password ?? "").trim();
      if (!account || !password || account.length > 500 || password.length > 1000) continue;
      insert.run(account,password); count++;
    }
  });
  tx();
  res.json({ imported: count });
});
app.get("/api/admin/credentials", admin, (req,res) => {
  res.json(db.prepare("SELECT id, substr(account,1,3) || '***' AS account_hint,status,created_at,issued_at FROM credentials ORDER BY id DESC LIMIT 500").all());
});
app.get("/api/admin/claims", admin, (req,res) => {
  res.json(db.prepare("SELECT claims.id, keys.key_hint, credentials.account, claims.claimed_at FROM claims JOIN keys ON keys.id=claims.key_id JOIN credentials ON credentials.id=claims.credential_id ORDER BY claims.id DESC LIMIT 500").all());
});
app.listen(PORT, () => console.log(`OVO 發放系統已啟動：http://localhost:${PORT}`));
