// Wallet: deposits and withdrawals through Ozow, with the MT5 account behind the mt5.js connector.
// Withdrawals always need back-office approval. Nothing here moves real money until Ozow and MT5 are configured.
module.exports = ({ app, q, auth, wrap, lim, E, crypto }) => {
  const mt5 = require("./mt5")(q);
  const MIN = 5000, MAX = 5000000; // cents: R50 to R50 000
  const sha = s => crypto.createHash("sha512").update(s.toLowerCase()).digest("hex");
  const safeEq = (a, b) => { const x = Buffer.from(String(a || "")), y = Buffer.from(String(b || "")); return x.length === y.length && crypto.timingSafeEqual(x, y); };
  const adm = (req, res, next) => (E.ADMIN_KEY && safeEq(req.headers["x-admin-key"], E.ADMIN_KEY)) ? next() : res.sendStatus(403);
  const sim = () => E.WALLET_SIMULATE === "true" && E.NODE_ENV !== "production";
  const kycOk = m => E.WALLET_SIMULATE === "true" || (m && m.kyc === "verified");

  // Bank account numbers are stored encrypted (AES-256-GCM). DATA_KEY must be 64 hex characters.
  const DK = () => { if (!/^[0-9a-f]{64}$/i.test(E.DATA_KEY || "")) throw new Error("DATA_KEY must be 64 hex characters"); return Buffer.from(E.DATA_KEY, "hex"); };
  const enc = s => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv("aes-256-gcm", DK(), iv), d = Buffer.concat([c.update(s, "utf8"), c.final()]); return [iv, c.getAuthTag(), d].map(b => b.toString("hex")).join("."); };
  const dec = s => { const [iv, tag, d] = s.split(".").map(h => Buffer.from(h, "hex")), c = crypto.createDecipheriv("aes-256-gcm", DK(), iv); c.setAuthTag(tag); return Buffer.concat([c.update(d), c.final()]).toString("utf8"); };

  const BANKS_SIM = [["sim-absa", "ABSA", "632005"], ["sim-capitec", "Capitec", "470010"], ["sim-fnb", "FNB", "250655"], ["sim-nedbank", "Nedbank", "198765"], ["sim-std", "Standard Bank", "051001"], ["sim-tyme", "TymeBank", "678910"]]
    .map(([BankGroupId, BankGroupName, UniversalBranchCode]) => ({ BankGroupId, BankGroupName, UniversalBranchCode }));
  async function banks() {
    if (!E.OZOW_PAYOUT_BASE) return BANKS_SIM;
    const r = await fetch(E.OZOW_PAYOUT_BASE + "/getavailablebanks", { headers: { SiteCode: E.OZOW_SITE_CODE, ApiKey: E.OZOW_API_KEY } });
    if (!r.ok) throw new Error("Could not load banks");
    const j = await r.json(); return Array.isArray(j) ? j : (j.Banks || j.banks || []);
  }

  // ---- Ozow pay-in (deposit). Hash order follows Ozow's "post from merchant website" docs.
  function ozowCheckout(tx) {
    const base = E.PUBLIC_URL;
    const f = { SiteCode: E.OZOW_SITE_CODE, CountryCode: "ZA", CurrencyCode: "ZAR", Amount: (tx.amount_cents / 100).toFixed(2), TransactionReference: tx.ref, BankReference: tx.ref,
      CancelUrl: base + "/#cancel", ErrorUrl: base + "/#error", SuccessUrl: base + "/#deposited", NotifyUrl: base + "/api/ozow/notify", IsTest: String(E.OZOW_TEST !== "false") };
    f.HashCheck = sha(Object.values(f).join("") + E.OZOW_PRIVATE_KEY);
    return { action: "https://pay.ozow.com", fields: f };
  }
  async function creditDeposit(ref) {
    const { rows: [t] } = await q("update wallet_tx set status='processing',updated_at=now() where ref=$1 and kind='deposit' and status='pending' returning *", [ref]);
    if (!t) return; // already handled: makes repeat notifications harmless
    try { await mt5.credit(t.member_id, t.amount_cents, t.ref); await q("update wallet_tx set status='credited',updated_at=now() where id=$1", [t.id]); }
    catch (e) { console.error("MT5 credit failed", e); await q("update wallet_tx set status='credit_failed',updated_at=now() where id=$1", [t.id]); }
  }
  // ---- Ozow payout. Hash and account-number encryption follow Ozow's payouts docs.
  async function ozowPayout(t, bank) {
    if (!E.OZOW_PAYOUT_BASE) return "simulated";
    const key = crypto.randomBytes(32), keyHex = key.toString("hex");
    const iv = crypto.createHash("sha512").update(t.ref + t.amount_cents + keyHex).digest().subarray(0, 16);
    const c = crypto.createCipheriv("aes-256-cbc", key, iv);
    const acct = Buffer.concat([c.update(dec(bank.acct_enc), "utf8"), c.final()]).toString("hex");
    await q("update wallet_tx set enc_key=$2 where id=$1", [t.id, enc(keyHex)]);
    const b = { Amount: t.amount_cents / 100, MerchantReference: t.ref, CustomerBankReference: "SIGNET", IsRtc: false, NotifyUrl: E.PUBLIC_URL + "/api/ozow/payout-notify", BankGroupId: bank.bank_group_id, AccountNumber: acct, BranchCode: bank.branch };
    b.HashCheck = sha([E.OZOW_SITE_CODE, t.amount_cents, b.MerchantReference, b.CustomerBankReference, b.IsRtc, b.NotifyUrl, b.BankGroupId, acct, b.BranchCode].join("") + E.OZOW_API_KEY);
    const r = await fetch(E.OZOW_PAYOUT_BASE + "/requestpayout", { method: "POST", headers: { "Content-Type": "application/json", SiteCode: E.OZOW_SITE_CODE, ApiKey: E.OZOW_API_KEY }, body: JSON.stringify(b) });
    if (!r.ok) throw new Error("Ozow payout rejected: " + r.status);
    return "requested";
  }
  async function reverse(t, status) { // return the money to the trading account exactly once
    const { rows: [x] } = await q("update wallet_tx set status=$2,updated_at=now() where id=$1 and status='paying' returning id", [t.id, status]);
    if (x) await mt5.credit(t.member_id, t.amount_cents, t.ref + "-REV");
  }

  // ---- Customer routes
  app.get("/api/wallet", auth, wrap(async (req, res) => {
    const a = await mt5.ensureAccount(req.uid);
    const { rows: [m] } = await q("select kyc from members where id=$1", [req.uid]);
    const { rows: [b] } = await q("select bank_group_id,bank_name,holder,last4 from bank_accounts where member_id=$1", [req.uid]);
    const { rows: tx } = await q("select kind,amount_cents,status,ref,created_at from wallet_tx where member_id=$1 order by id desc limit 20", [req.uid]);
    let bl = []; if (!b) { try { bl = await banks(); } catch (e) { console.error(e.message); } }
    res.json({ login: a.login, balance_cents: a.balance_cents, demo: mt5.demo === true, kyc: kycOk(m) ? "verified" : m.kyc, bank: b || null, banks: bl, tx });
  }));
  app.post("/api/wallet/bank", auth, wrap(async (req, res) => {
    const { bank_group_id, holder, account } = req.body || {};
    const bk = (await banks()).find(x => x.BankGroupId === bank_group_id);
    if (!bk || !holder || holder.trim().length < 3 || !/^\d{6,16}$/.test(account || "")) return res.status(400).json({ error: "Choose your bank and enter the account holder and a valid account number" });
    const r = await q("insert into bank_accounts(member_id,bank_group_id,bank_name,holder,branch,acct_enc,last4) values($1,$2,$3,$4,$5,$6,$7) on conflict (member_id) do nothing", [req.uid, bk.BankGroupId, bk.BankGroupName, holder.trim(), bk.UniversalBranchCode, enc(account), account.slice(-4)]);
    if (!r.rowCount) return res.status(409).json({ error: "A bank account is already saved. Contact Signet to change it" });
    res.json({ ok: true });
  }));
  app.post("/api/wallet/deposit", auth, wrap(async (req, res) => {
    const cents = Math.round(+(req.body && req.body.amount) * 100);
    if (!(cents >= MIN && cents <= MAX)) return res.status(400).json({ error: "Deposits are between R50 and R50 000" });
    const { rows: [m] } = await q("select kyc from members where id=$1", [req.uid]);
    if (!kycOk(m)) return res.status(403).json({ error: "Your identity check must be verified first" });
    const ref = "DEP" + Date.now().toString(36).toUpperCase() + crypto.randomInt(10, 99);
    await q("insert into wallet_tx(member_id,kind,amount_cents,status,ref) values($1,'deposit',$2,'pending',$3)", [req.uid, cents, ref]);
    if (sim()) return res.json({ simulate: true, ref });
    if (!E.OZOW_SITE_CODE || !E.OZOW_PRIVATE_KEY || !E.PUBLIC_URL) return res.status(503).json({ error: "Deposits are not configured yet" });
    res.json(ozowCheckout({ amount_cents: cents, ref }));
  }));
  app.post("/api/wallet/dev/complete", auth, wrap(async (req, res) => { // testing only
    if (!sim()) return res.sendStatus(404);
    const { rows: [t] } = await q("select 1 from wallet_tx where ref=$1 and member_id=$2", [req.body.ref, req.uid]);
    if (!t) return res.sendStatus(404);
    await creditDeposit(req.body.ref); res.json({ ok: true });
  }));
  app.post("/api/wallet/withdraw", auth, wrap(async (req, res) => {
    const cents = Math.round(+(req.body && req.body.amount) * 100);
    if (!(cents >= MIN && cents <= MAX)) return res.status(400).json({ error: "Withdrawals are between R50 and R50 000" });
    const { rows: [m] } = await q("select kyc from members where id=$1", [req.uid]);
    if (!kycOk(m)) return res.status(403).json({ error: "Your identity check must be verified first" });
    const { rows: [b] } = await q("select 1 from bank_accounts where member_id=$1", [req.uid]);
    if (!b) return res.status(400).json({ error: "Save your bank account first" });
    const { rows: [open] } = await q("select 1 from wallet_tx where member_id=$1 and kind='withdrawal' and status in ('requested','approved','paying')", [req.uid]);
    if (open) return res.status(409).json({ error: "You already have a withdrawal in progress" });
    if ((await mt5.balance(req.uid)) < cents) return res.status(400).json({ error: "Insufficient trading balance" });
    await q("insert into wallet_tx(member_id,kind,amount_cents,status,ref) values($1,'withdrawal',$2,'requested',$3)", [req.uid, cents, "WDR" + Date.now().toString(36).toUpperCase() + crypto.randomInt(10, 99)]);
    res.json({ ok: true });
  }));

  // ---- Ozow callbacks
  app.post("/api/ozow/notify", express_urlencoded(), async (req, res) => {
    res.sendStatus(200);
    try {
      const b = req.body, order = ["SiteCode", "TransactionId", "TransactionReference", "Amount", "Status", "Optional1", "Optional2", "Optional3", "Optional4", "Optional5", "CurrencyCode", "IsTest", "StatusMessage"];
      if (!safeEq(sha(order.map(k => b[k] || "").join("") + E.OZOW_PRIVATE_KEY), String(b.Hash || "").toLowerCase())) return;
      if (String(b.IsTest) === "true" && E.OZOW_TEST === "false") return;
      const { rows: [t] } = await q("select * from wallet_tx where ref=$1 and kind='deposit'", [b.TransactionReference]);
      if (!t || Math.round(+b.Amount * 100) !== t.amount_cents) return;
      if (String(b.Status).toLowerCase() === "complete") await creditDeposit(t.ref);
      else if (/cancel|error|abandon/i.test(b.Status)) await q("update wallet_tx set status='failed',updated_at=now() where id=$1 and status='pending'", [t.id]);
    } catch (e) { console.error("Ozow notify", e); }
  });
  // Ozow calls this to verify a payout request. CONFIRM the exact request/response format in Ozow's docs.
  app.post("/api/ozow/payout-verify", express_urlencoded(), wrap(async (req, res) => {
    const b = req.body || {};
    const { rows: [t] } = await q("select amount_cents from wallet_tx where ref=$1 and kind='withdrawal' and status='paying'", [b.MerchantReference]);
    res.sendStatus(t ? 200 : 400);
  }));
  // Payout result notices are only logged. They do not change money state: an admin confirms with "mark".
  app.post("/api/ozow/payout-notify", express_urlencoded(), (req, res) => { console.log("Ozow payout notice", JSON.stringify(req.body)); res.sendStatus(200); });

  // ---- Back office (x-admin-key)
  app.get("/api/admin/overview", adm, wrap(async (req, res) => {
    const w = await q("select t.id,t.ref,t.amount_cents,t.status,t.created_at,m.member_no,m.name,m.kyc,b.holder,b.bank_name,b.last4,a.balance_cents from wallet_tx t join members m on m.id=t.member_id left join bank_accounts b on b.member_id=t.member_id left join mt5_accounts a on a.member_id=t.member_id where t.kind='withdrawal' and t.status in ('requested','paying','payout_failed') order by t.id");
    const k = await q("select member_no,name,phone from members where kyc='pending' order by id limit 50");
    const s = await q("select ref,kind,amount_cents,status from wallet_tx where status='credit_failed' order by id desc limit 20");
    res.json({ withdrawals: w.rows, kyc: k.rows, stuck: s.rows });
  }));
  app.post("/api/admin/kyc", adm, wrap(async (req, res) => {
    const { member_no, status } = req.body || {};
    if (!["verified", "rejected"].includes(status)) return res.sendStatus(400);
    await q("update members set kyc=$2 where member_no=$1", [String(member_no).toUpperCase(), status]); res.sendStatus(204);
  }));
  app.post("/api/admin/withdrawals/:id/approve", adm, wrap(async (req, res) => {
    const { rows: [t] } = await q("update wallet_tx set status='approved',updated_at=now() where id=$1 and kind='withdrawal' and status='requested' returning *", [+req.params.id]);
    if (!t) return res.status(409).json({ error: "Already handled" });
    try { await mt5.debit(t.member_id, t.amount_cents, t.ref); }
    catch (e) { await q("update wallet_tx set status='rejected',note='Insufficient trading balance',updated_at=now() where id=$1", [t.id]); return res.status(400).json({ error: "Insufficient trading balance" }); }
    await q("update wallet_tx set status='paying',updated_at=now() where id=$1", [t.id]);
    try {
      const { rows: [b] } = await q("select * from bank_accounts where member_id=$1", [t.member_id]);
      const r = await ozowPayout(t, b);
      if (r === "simulated") await q("update wallet_tx set status='paid',updated_at=now() where id=$1", [t.id]);
      res.json({ ok: true, result: r });
    } catch (e) { console.error(e); await reverse(t, "payout_failed"); res.status(502).json({ error: "Payout failed and the balance was returned" }); }
  }));
  app.post("/api/admin/withdrawals/:id/reject", adm, wrap(async (req, res) => {
    const r = await q("update wallet_tx set status='rejected',note=$2,updated_at=now() where id=$1 and kind='withdrawal' and status='requested'", [+req.params.id, String((req.body && req.body.note) || "").slice(0, 200)]);
    res.sendStatus(r.rowCount ? 204 : 409);
  }));
  app.post("/api/admin/withdrawals/:id/mark", adm, wrap(async (req, res) => { // after checking Ozow's dashboard
    const { rows: [t] } = await q("select * from wallet_tx where id=$1 and kind='withdrawal' and status='paying'", [+req.params.id]);
    if (!t) return res.status(409).json({ error: "Not awaiting payout" });
    if (req.body && req.body.result === "paid") await q("update wallet_tx set status='paid',updated_at=now() where id=$1", [t.id]);
    else if (req.body && req.body.result === "failed") await reverse(t, "payout_failed");
    else return res.sendStatus(400);
    res.sendStatus(204);
  }));

  const schema = `
alter table members add column if not exists kyc text not null default 'pending';
create table if not exists mt5_accounts(member_id int primary key references members(id),login text not null,balance_cents int not null default 0);
create table if not exists bank_accounts(member_id int primary key references members(id),bank_group_id text not null,bank_name text,holder text not null,branch text not null,acct_enc text not null,last4 text not null);
create table if not exists wallet_tx(id serial primary key,member_id int references members(id),kind text not null,amount_cents int not null,status text not null,ref text unique not null,note text,enc_key text,created_at timestamptz default now(),updated_at timestamptz default now());`;
  return { schema };
};
function express_urlencoded() { return require("express").urlencoded({ extended: false }); }
