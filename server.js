const express = require("express"), helmet = require("helmet"), rateLimit = require("express-rate-limit");
const { Pool } = require("pg"), bcrypt = require("bcryptjs"), jwt = require("jsonwebtoken"), crypto = require("crypto"), path = require("path");
const E = process.env;
if (!E.DATABASE_URL || !E.JWT_SECRET) throw new Error("DATABASE_URL and JWT_SECRET are required");
const pool = new Pool({ connectionString: E.DATABASE_URL, ssl: E.PGSSL === "true" ? { rejectUnauthorized: true } : undefined });
const q = (t, p) => pool.query(t, p);

// Plans from the Signet group-plans flyer. Price depends on group size (6, 10 or 14 members).
const PLANS = {
  Silver: { pkg: "Pine Package", price: { 6: 140, 10: 250, 14: 300 }, items: ["Pine coffin", "Mortuary facilities", "1 local bus", "Hearse", "1 family car", "2 tables, 50 chairs, 1 tent and 1 toilet", "R100 airtime", "Grave site decor and name board", "50 funeral programmes", "Juice and water at the grave site"] },
  Gold: { pkg: "3 Tier Package", price: { 6: 180, 10: 305, 14: 370 }, items: ["3 tier coffin", "Mortuary facilities", "1 local bus", "Hearse", "1 family car", "3 tables, 50 chairs, 1 tent and 1 toilet", "R100 airtime", "Grave site decor (level 2) and name board", "50 funeral programmes", "Juice and water at the grave site"] },
  Platinum: { pkg: "Casket Package", price: { 6: 210, 10: 360, 14: 440 }, items: ["Casket coffin", "Mortuary facilities", "1 local bus", "Hearse", "2 family cars", "4 tables, 50 chairs, 1 tent and 1 mobile toilet", "R150 airtime", "Grave site decor (level 3) and name board", "50 funeral programmes", "Sound system", "Juice and water at the grave site"] }
};
const MINORS = [
  { age: "Stillborn to 11 months", items: "Baby coffin, hearse, mini floral arrangements, grave site decor" },
  { age: "12 months to 13 years", items: "Coffin, hearse, family car, mini floral arrangements, grave site decor" },
  { age: "14 to 21 years", items: "Full service" }];
const OVER65 = "Covers are for main members aged 18 to 64. Members over 65 incur fixed additional charges.";
const hash = s => crypto.createHash("sha256").update(s + E.JWT_SECRET).digest("hex");
async function sendSms(to, text) {
  if (E.SMS_WEBHOOK_URL) {
    const r = await fetch(E.SMS_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + (E.SMS_API_KEY || "") }, body: JSON.stringify({ to, text }) });
    if (!r.ok) throw new Error("SMS provider error " + r.status);
    return;
  }
  if (E.NODE_ENV !== "production") { console.log("DEV SMS to", to, ":", text); return; }
  throw new Error("SMS is not configured");
}
const pfHost = () => (E.PAYFAST_SANDBOX === "false" ? "www.payfast.co.za" : "sandbox.payfast.co.za");
const pfEnc = v => encodeURIComponent(String(v).trim()).replace(/[!'()*]/g, c => "%" + c.charCodeAt(0).toString(16).toUpperCase()).replace(/%20/g, "+");
const pfSig = o => {
  let s = Object.keys(o).filter(k => k !== "signature" && o[k] !== "" && o[k] != null).map(k => k + "=" + pfEnc(o[k])).join("&");
  if (E.PAYFAST_PASSPHRASE) s += "&passphrase=" + pfEnc(E.PAYFAST_PASSPHRASE);
  return crypto.createHash("md5").update(s).digest("hex");
};
const sign = id => jwt.sign({ uid: id }, E.JWT_SECRET, { expiresIn: "7d" });
const auth = (req, res, next) => {
  try { req.uid = jwt.verify((req.headers.authorization || "").slice(7), E.JWT_SECRET).uid; next(); }
  catch (e) { res.status(401).json({ error: "Please sign in again" }); }
};
const wrap = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: "Server error" }); });

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: { useDefaults: true, directives: {
  "script-src": ["'self'", "'unsafe-inline'"],
  "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
  "font-src": ["https://fonts.gstatic.com"],
  "img-src": ["'self'", "data:"],
  "form-action": ["'self'", "https://www.payfast.co.za", "https://sandbox.payfast.co.za"]
} } }));
app.use(express.json({ limit: "50kb" }));
const lim = rateLimit({ windowMs: 15 * 60 * 1000, limit: 100 });

app.post("/api/register", lim, wrap(async (req, res) => {
  const { name, phone, pin } = req.body || {};
  if (!name || name.trim().length < 2 || !/^\d{10}$/.test(phone || "") || !/^\d{4,6}$/.test(pin || ""))
    return res.status(400).json({ error: "Enter your name, a 10-digit phone number and a 4 to 6 digit PIN" });
  const no = "SIG-" + crypto.randomInt(100000, 999999);
  try {
    const { rows: [m] } = await q("insert into members(member_no,name,phone,pin_hash) values($1,$2,$3,$4) returning id,member_no",
      [no, name.trim(), phone, await bcrypt.hash(pin, 12)]);
    res.json({ token: sign(m.id), member_no: m.member_no });
  } catch (e) { if (e.code === "23505") return res.status(409).json({ error: "That phone number is already registered" }); throw e; }
}));

app.post("/api/login", lim, wrap(async (req, res) => {
  const { member_no, pin } = req.body || {};
  const { rows: [m] } = await q("select * from members where member_no=$1", [String(member_no || "").trim().toUpperCase()]);
  if (m && m.locked_until && new Date(m.locked_until) > new Date()) return res.status(429).json({ error: "Too many attempts. Try again in 15 minutes" });
  if (!m || !(await bcrypt.compare(String(pin || ""), m.pin_hash))) {
    if (m) { const f = m.failed + 1; await q("update members set failed=$2,locked_until=$3 where id=$1", [m.id, f >= 5 ? 0 : f, f >= 5 ? new Date(Date.now() + 9e5) : null]); }
    return res.status(401).json({ error: "Incorrect Membership ID or PIN" });
  }
  await q("update members set failed=0,locked_until=null where id=$1", [m.id]);
  res.json({ token: sign(m.id) });
}));

app.get("/api/me", auth, wrap(async (req, res) => {
  const { rows: [m] } = await q("select m.member_no,m.name,m.phone,m.tokens,m.tier,coalesce(s.status,'none') as sub,s.members_count from members m left join subscriptions s on s.member_id=m.id where m.id=$1", [req.uid]);
  if (!m) return res.status(401).json({ error: "Please sign in again" });
  res.json({ ...m, active: m.sub === "active", pkg: PLANS[m.tier] ? PLANS[m.tier].pkg : "", plans: PLANS, minors: MINORS, over65: OVER65 });
}));

app.post("/api/subscription/checkout", auth, wrap(async (req, res) => {
  const plan = PLANS[req.body && req.body.tier], size = String(req.body && req.body.members);
  const price = plan && plan.price[size];
  if (!price) return res.status(400).json({ error: "Choose a plan and group size" });
  if (!E.PAYFAST_MERCHANT_ID || !E.PAYFAST_MERCHANT_KEY || !E.PUBLIC_URL) return res.status(503).json({ error: "Payments are not configured yet" });
  const { rows: [m] } = await q("select name from members where id=$1", [req.uid]);
  const id = "SIG" + Date.now().toString(36).toUpperCase() + crypto.randomInt(100, 999);
  await q("insert into payments(member_id,m_payment_id,amount,tier,members_count) values($1,$2,$3,$4,$5)", [req.uid, id, price, req.body.tier, +size]);
  const f = {
    merchant_id: E.PAYFAST_MERCHANT_ID, merchant_key: E.PAYFAST_MERCHANT_KEY,
    return_url: E.PUBLIC_URL + "/#paid", cancel_url: E.PUBLIC_URL + "/#cancel", notify_url: E.PUBLIC_URL + "/api/payfast/itn",
    name_first: m.name.split(" ")[0], m_payment_id: id, amount: price.toFixed(2), item_name: "Signet " + req.body.tier + " plan, " + size + " members",
    subscription_type: 1, recurring_amount: price.toFixed(2), frequency: 3, cycles: 0
  };
  f.signature = pfSig(f);
  res.json({ action: "https://" + pfHost() + "/eng/process", fields: f });
}));

// PayFast Instant Transaction Notification. Plan activates here, never on the browser return.
app.post("/api/payfast/itn", express.urlencoded({ extended: false }), async (req, res) => {
  res.sendStatus(200);
  try {
    const b = req.body;
    if (b.signature !== pfSig(b)) return;
    const { rows: [p] } = await q("select * from payments where m_payment_id=$1", [b.m_payment_id]);
    if (!p || Math.abs(+b.amount_gross - +p.amount) > 0.01) return;
    const v = await fetch("https://" + pfHost() + "/eng/query/validate", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(b).toString() });
    if ((await v.text()).trim() !== "VALID") return;
    if (b.payment_status === "COMPLETE" && p.status !== "complete") {
      await q("update payments set status='complete' where id=$1", [p.id]);
      await q("insert into subscriptions(member_id,tier,status,members_count) values($1,$2,'active',$3) on conflict (member_id) do update set tier=$2,status='active',members_count=$3,updated_at=now()", [p.member_id, p.tier, p.members_count]);
      await q("update members set tier=$2,tokens=tokens+200 where id=$1", [p.member_id, p.tier]);
    }
  } catch (e) { console.error("ITN error", e); }
});

app.post("/api/pin/request", lim, wrap(async (req, res) => {
  const { member_no, phone } = req.body || {};
  const { rows: [m] } = await q("select id,phone from members where member_no=$1", [String(member_no || "").trim().toUpperCase()]);
  if (m && m.phone === String(phone || "").trim()) {
    const otp = String(crypto.randomInt(100000, 999999));
    await q("update members set reset_hash=$2,reset_expires=$3,reset_tries=0 where id=$1", [m.id, hash(otp), new Date(Date.now() + 6e5)]);
    try { await sendSms(m.phone, "Your Signet PIN reset code is " + otp + ". It expires in 10 minutes."); } catch (e) { console.error("SMS failed:", e.message); }
  }
  res.json({ ok: true }); // same answer whether or not the details matched
}));
app.post("/api/pin/reset", lim, wrap(async (req, res) => {
  const { member_no, otp, pin } = req.body || {};
  if (!/^\d{4,6}$/.test(pin || "")) return res.status(400).json({ error: "PIN must be 4 to 6 digits" });
  const { rows: [m] } = await q("select * from members where member_no=$1", [String(member_no || "").trim().toUpperCase()]);
  const bad = () => res.status(400).json({ error: "That code is incorrect or has expired" });
  if (!m || !m.reset_hash || new Date(m.reset_expires) < new Date() || m.reset_tries >= 5) return bad();
  if (m.reset_hash !== hash(String(otp || ""))) { await q("update members set reset_tries=reset_tries+1 where id=$1", [m.id]); return bad(); }
  await q("update members set pin_hash=$2,reset_hash=null,reset_expires=null,reset_tries=0,failed=0,locked_until=null where id=$1", [m.id, await bcrypt.hash(pin, 12)]);
  res.json({ ok: true });
}));

app.post("/api/claims", auth, wrap(async (req, res) => {
  const { deceased, relationship, phone } = req.body || {};
  if (!deceased || !/^\d{10}$/.test(phone || "")) return res.status(400).json({ error: "Add the name of the deceased and a 10-digit contact number" });
  const ref = "CLM-" + crypto.randomInt(10000, 99999);
  await q("insert into claims(member_id,ref,deceased,relationship,phone) values($1,$2,$3,$4,$5)", [req.uid, ref, deceased.trim(), (relationship || "").trim(), phone]);
  res.json({ ref });
}));
app.get("/api/claims", auth, wrap(async (req, res) => res.json((await q("select ref,deceased,status,created_at from claims where member_id=$1 order by id desc", [req.uid])).rows)));
app.patch("/api/admin/claims/:ref", wrap(async (req, res) => {
  if (!E.ADMIN_KEY || req.headers["x-admin-key"] !== E.ADMIN_KEY) return res.sendStatus(403);
  const s = req.body && req.body.status;
  if (!["received", "verified", "approved", "paid"].includes(s)) return res.sendStatus(400);
  await q("update claims set status=$1 where ref=$2", [s, req.params.ref]);
  res.sendStatus(204);
}));
app.post("/api/enquiries", auth, wrap(async (req, res) => {
  const { kind, message } = req.body || {};
  if (!kind || !message || message.length < 5) return res.status(400).json({ error: "Please add a short message" });
  await q("insert into enquiries(member_id,kind,message) values($1,$2,$3)", [req.uid, kind, message.slice(0, 1000)]);
  res.json({ ok: true });
}));

// DEMO ONLY: fake data. No broker connection, no real money.
app.get("/api/trading/demo", auth, (req, res) => {
  let v = 10000, s = 7; const curve = [];
  for (let i = 0; i < 30; i++) { s = (s * 9301 + 49297) % 233280; v += (s / 233280 - 0.45) * 180; curve.push(Math.round(v * 100) / 100); }
  res.json({ demo: true, balance: curve[curve.length - 1], curve, signals: [
    { pair: "EUR/USD", side: "BUY", entry: "Market", sl: "1.0820", tp: "1.0940" },
    { pair: "GBP/USD", side: "SELL", entry: "Market", sl: "1.2760", tp: "1.2610" },
    { pair: "XAU/USD", side: "BUY", entry: "Market", sl: "2310.0", tp: "2362.0" }] });
});

const wallet = require("./wallet")({ app, q, auth, wrap, lim, E, crypto });
app.use(express.static(path.join(__dirname, "public")));
const SCHEMA = `
create table if not exists members(id serial primary key,member_no text unique not null,name text not null,phone text unique not null,pin_hash text not null,tokens int not null default 0,tier text not null default 'Silver',failed int not null default 0,locked_until timestamptz,created_at timestamptz default now());
create table if not exists subscriptions(member_id int primary key references members(id),tier text not null,status text not null,updated_at timestamptz default now());
create table if not exists payments(id serial primary key,member_id int references members(id),m_payment_id text unique not null,amount numeric(10,2) not null,tier text not null,status text not null default 'pending',created_at timestamptz default now());
create table if not exists claims(id serial primary key,member_id int references members(id),ref text unique not null,deceased text not null,relationship text,phone text,status text not null default 'received',created_at timestamptz default now());
create table if not exists enquiries(id serial primary key,member_id int references members(id),kind text not null,message text not null,created_at timestamptz default now());`;
const ALTERS = `
alter table members add column if not exists reset_hash text;
alter table members add column if not exists reset_expires timestamptz;
alter table members add column if not exists reset_tries int not null default 0;
alter table subscriptions add column if not exists members_count int;
alter table payments add column if not exists members_count int;`;
pool.query(SCHEMA).then(() => pool.query(ALTERS + wallet.schema)).then(() => app.listen(E.PORT || 3000, () => console.log("Signet running"))).catch(e => { console.error(e); process.exit(1); });
