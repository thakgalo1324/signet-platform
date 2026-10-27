// MT5 connector. This STUB keeps demo balances in the database so the wallet flow can be tested.
// Replace it with your broker's Manager/Gateway API once you have their documentation.
// Keep the same methods: ensureAccount, balance, credit, debit (amounts in cents).
module.exports = q => ({
  demo: true,
  async ensureAccount(memberId) {
    const { rows: [a] } = await q("select * from mt5_accounts where member_id=$1", [memberId]);
    if (a) return a;
    const { rows: [n] } = await q("insert into mt5_accounts(member_id,login,balance_cents) values($1,$2,0) on conflict (member_id) do update set login=mt5_accounts.login returning *", [memberId, String(900000 + memberId)]);
    return n;
  },
  async balance(memberId) { return (await this.ensureAccount(memberId)).balance_cents; },
  async credit(memberId, cents, ref) {
    await this.ensureAccount(memberId);
    const r = await q("update mt5_accounts set balance_cents=balance_cents+$2 where member_id=$1 returning balance_cents", [memberId, cents]);
    return r.rows[0].balance_cents;
  },
  async debit(memberId, cents, ref) {
    const r = await q("update mt5_accounts set balance_cents=balance_cents-$2 where member_id=$1 and balance_cents>=$2 returning balance_cents", [memberId, cents]);
    if (!r.rows[0]) throw new Error("Insufficient balance");
    return r.rows[0].balance_cents;
  }
});
