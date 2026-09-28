# SHARX Backend Security Hardening

This build is a security-focused backend revision. It intentionally does **not** ship production secrets.

## What was hardened

- Passkey registration now requires an already authenticated account; an email address alone can no longer attach a new passkey.
- Passkey RP ID/origin are fixed server configuration, not derived from request headers.
- Passkey login identifies the account from the WebAuthn credential ID rather than trusting `userHandle`.
- JWTs are pinned to HS256, issuer/audience, and a per-user `tokenVersion`.
- Password reset increments `tokenVersion`, invalidating previously issued access tokens.
- OAuth callbacks use a short-lived, one-time exchange code instead of placing a reusable JWT in the redirect URL.
- OAuth login has a state cookie/parameter check for CSRF protection.
- Password-reset OTPs are stored hashed in Postgres, expire, and have an attempt limit; they are no longer held only in process memory.
- RazorpayX webhooks verify HMAC against the raw request body and are idempotent.
- RazorpayX payout state changes update the Withdrawal state and safely refund rejected/reversed payouts.
- Withdrawal balance reservation is atomic and concurrency-safe; a second concurrent withdrawal cannot spend the same balance.
- RazorpayX payout creation uses a deterministic idempotency key per withdrawal.
- Real payouts are disabled unless `RAZORPAYX_ENABLED=true` is explicitly configured.
- Reward sessions use a database partial unique index so one user cannot have two ACTIVE sessions, including concurrent start requests.
- Reward heartbeat transactions retry serialization failures.
- Reward endpoints and withdrawal endpoints have rate limits.
- Proxy redirects are manually followed and each redirect target is SSRF-checked.
- Proxy responses have size limits and proxy endpoints are rate-limited.
- The shared `lastProxiedGameUrl` state was removed; fallback proxy resolution now uses the request referer instead of cross-user global state.
- Production fatal process errors now terminate the process so Render can restart a known-bad instance.
- Excessively large JSON/form request bodies are rejected.
- The old Express in-memory session middleware was removed because OAuth uses `session:false` and JWT authentication.
- Client-submitted match scores are rate-limited and bounded. They are still not cryptographically authoritative game scores; a trustworthy anti-cheat score system requires game-specific server validation.

## Database migration

After deploying the code, run:

```bash
npx prisma migrate deploy
npx prisma generate
```

The new migration also cleans duplicate ACTIVE reward sessions before creating the one-active-session partial unique index.

## Required production environment

See `.env.example`.

At minimum:

- `DATABASE_URL`
- `DIRECT_URL`
- `JWT_SECRET`
- `CLIENT_URL`
- `PUBLIC_BASE_URL`
- `ALLOWED_ORIGINS`
- `PASSKEY_RP_ID`
- `PASSKEY_ORIGIN`

For SHARX at production, these should normally be:

```text
CLIENT_URL=https://sharx.in
PUBLIC_BASE_URL=https://sharx-backend.onrender.com
ALLOWED_ORIGINS=https://sharx.in
PASSKEY_RP_ID=sharx.in
PASSKEY_ORIGIN=https://sharx.in
```

## RazorpayX

Keep this disabled until RazorpayX API Payout access and the webhook are actually enabled:

```text
RAZORPAYX_ENABLED=false
```

When ready, configure the RazorpayX API credentials, Customer Identifier, and webhook secret as Render environment variables. Never put them in Git or `.env` files that are uploaded/shared.

The withdrawal implementation is currently **UPI-only** through RazorpayX. The payout amount is bounded to ₹10–₹10,000 per request.

RazorpayX API payouts use the `/v1/payouts` API and an `X-Payout-Idempotency` key. Razorpay recommends webhook-based status tracking rather than polling. See the official RazorpayX API documentation before enabling live payouts.

## OAuth frontend contract change

The OAuth callback now redirects as:

```text
/auth/callback?code=<one-time-code>
```

The frontend callback page must POST that code to:

```text
POST https://sharx-backend.onrender.com/auth/exchange
Content-Type: application/json

{"code":"..."}
```

The response contains the normal access token and user object. The code expires quickly and can only be consumed once.

Do **not** re-enable the old `?token=<JWT>` callback pattern.

## Passkey frontend contract change

Passkey registration is now an authenticated account-management action. The frontend must send the user's normal Bearer access token to:

```text
POST /passkey/register/options
POST /passkey/register/verify
```

Passkey login remains public at:

```text
POST /passkey/login/options
POST /passkey/login/verify
```

## Secrets in the supplied archive

The original archive contained a `.env` file with credentials. This hardened archive intentionally excludes `.env` and includes only `.env.example`.

Rotate any credentials that were present in the supplied archive before using the hardened deployment, especially database credentials, JWT secret, OAuth secrets, email API keys, RazorpayX API credentials, and the RazorpayX webhook secret.
