# Signet Platform

One Node service that serves the website and the API. The mobile app (Expo) wraps the same site.

## Deploy to Pxxl
1. Push this folder to GitHub.
2. On Pxxl, create a PostgreSQL database and copy its connection string.
3. Create a Node app from the repo. Install: `npm install`. Start: `npm start`.
4. Add the variables from `.env.example` in Pxxl's environment settings (never commit `.env`).
   `PUBLIC_URL` must be your live https address. Tables are created on first start.

## PayFast
- Keep `PAYFAST_SANDBOX=true` until tested. Use sandbox merchant details first.
- Set a passphrase in PayFast and in `PAYFAST_PASSPHRASE`.
- Payment notifications arrive at `PUBLIC_URL/api/payfast/itn`. Plans activate there, not on the browser return.
- Before going live, also check the notification's source IP against PayFast's published list.

## PIN reset
Members enter their Membership ID and registered mobile number, receive a 6-digit code by SMS (valid 10 minutes, 5 tries), then set a new PIN.
Set `SMS_WEBHOOK_URL` (and `SMS_API_KEY`) to your SMS provider's endpoint; the server POSTs `{to, text}` as JSON. Adapt `sendSms` in `server.js` to your provider's exact format.
Without it, codes are only printed to the server log outside production, and PIN reset will not work in production.

## Plans
Silver = Pine Package, Gold = 3 Tier Package, Platinum = Casket Package. Prices are per group size (6, 10 or 14 members) and are edited in `PLANS` in `server.js`.

## Wallet (Ozow deposits and withdrawals)
- Customers deposit by Ozow instant bank payment; the **verified** Ozow notification credits the MT5 account. Withdrawals go to the customer's own saved bank account only, after a back-office approval.
- Back office: open `/admin.html`, enter `ADMIN_KEY`. Verify identity checks, approve or reject withdrawals, and confirm payouts. Protect this page further (IP allow-list or VPN) before going live.
- `mt5.js` is a DEMO stub with fake balances. Replace it with your broker's Manager/Gateway API (keep the same four methods).
- Local testing: `WALLET_SIMULATE=true` (and not production) skips Ozow and identity checks and credits deposits instantly; payouts are simulated.
- Ozow sandbox: set `OZOW_TEST=true`, your site code and private key. For payouts set `OZOW_PAYOUT_BASE` to Ozow's **mock** payouts URL first and `OZOW_API_KEY`.
- **Verify against Ozow's docs before live use** (not confirmable from the pages I could read): the payout request path (`/requestpayout`) and body field names, the amount unit in the payout body, the payout-verify webhook format, and the encryption-key encoding. Payout result notices are only logged; an admin confirms with "Mark paid / failed" after checking Ozow's dashboard.
- Set `DATA_KEY` (64 hex characters, e.g. `openssl rand -hex 32`). Bank account numbers are encrypted with it. Losing it means losing access to saved accounts.
- Whether customer money may flow through your Ozow account and where it must be held is a licensing and trust-account question for your compliance practitioner, not something the code decides.

## Admin
Update a claim: `PATCH /api/admin/claims/CLM-12345` with header `x-admin-key` and body `{"status":"verified"}`
(statuses: received, verified, approved, paid).

## Android app
```
npx create-expo-app signet-mobile
cd signet-mobile && npx expo install react-native-webview
```
Replace its `App.js` with `mobile/App.js`, set `WEB_URL`, then `npx expo start` to test and EAS Build for the Play Store.

## Not built yet (on purpose)
- Live trading, profit shares and withdrawals. The trading tab is demo data only until the account model, licensing and broker approval are settled.
- Admin screen, email notices, POPIA consent and privacy pages.
- A fourth (Diamond) plan: the flyer only has three priced packages (Pine, 3 Tier, Casket), so the app shows Silver, Gold and Platinum.
- Replace the placeholder plan prices and cover amounts in `server.js`.
