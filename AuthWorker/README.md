# Nesiam sign-in worker

Emails a 6-digit code and checks it. No passwords. The code itself is never stored; the worker keeps only a tiny hashed counter per email address (see "Abuse protection").

## Deploy

1. **Resend** (resend.com): verify the sending domain (`mail.nesiam.com`) and create a Sending-access API key for it.
2. **Cloudflare Turnstile** (dashboard, left menu **Turnstile → Add widget**): hostnames `jaykaluza.github.io` (and `nesiam.com`, `www.nesiam.com`), mode **Managed**. Keep the **Site key** (public, goes in `docs/index.html`) and the **Secret key** (private).
3. In this folder:
   ```
   npm install -g wrangler
   wrangler login
   wrangler secret put AUTH_SECRET        # 32+ random characters
   wrangler secret put RESEND_API_KEY     # the Resend key
   wrangler secret put TURNSTILE_SECRET   # the Turnstile secret key
   wrangler deploy
   ```
4. In `docs/index.html` set `provider: {type: 'worker', url: '<worker address>', turnstileSiteKey: '<site key>'}`.

Deploy the worker and publish the page together: the new worker refuses requests that carry no Turnstile token.

## How it works
- `POST /send {email, turnstile}` checks Turnstile, emails the code and returns a signed challenge (never the code).
- `POST /verify {email, code, challenge}` returns `{ok: true, token}` for a right code, `{ok: false, error}` otherwise.
- `GET /me` with `Authorization: Bearer <token>` tells one of your own servers who the token belongs to.
- Codes work for 10 minutes and once only. Tokens work for 12 hours. Only the websites in `ALLOWED_ORIGINS` can use it from a browser.

## Abuse protection
- **Turnstile** on `/send`: scripts cannot ask for codes in bulk.
- **One Durable Object per email address**, named by a keyed hash so it never holds the address: one active code (a new one cancels the old), 30 seconds between codes, 6 codes an hour, 5 tries per code, a code works once. This is what stops code guessing.
- **Daily cap** (`DAILY_CAP`, default 90) on emails across everyone, to protect Resend's free quota and the domain's reputation.
- **Per-address rate limits** (`SEND_LIMIT`, `VERIFY_LIMIT`) as extra cover. If they ever fail, the worker refuses requests instead of allowing them. The same applies if the Durable Object cannot be reached.
- Errors from Resend are logged for `wrangler tail` and never sent to the browser.

The sign-in only decides what the website shows. Anything that must really be protected has to check the token with `/me` on a server.
