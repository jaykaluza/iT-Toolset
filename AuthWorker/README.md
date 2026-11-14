# Nesiam sign-in worker

Emails a 6-digit code and checks it. No passwords, and the worker stores nothing: no database, no list of emails.

## Deploy (about 10 minutes)

1. **Resend** (resend.com, free tier): create an API key, and add and verify a sending domain (a few DNS records). Until a domain is verified, Resend only lets you email yourself.
2. **Cloudflare** (free account), then in this folder:
   ```
   npm install -g wrangler
   wrangler login
   ```
3. Edit `wrangler.toml`: set `FROM` to an address on your verified domain.
4. Set the two secrets:
   ```
   wrangler secret put AUTH_SECRET     # paste a long random text (32+ characters)
   wrangler secret put RESEND_API_KEY  # paste the Resend key
   ```
5. `wrangler deploy` prints the worker address, like `https://nesiam-auth.<you>.workers.dev`.
6. Put that address in `docs/index.html`: `provider: {type: 'worker', url: '...'}`.

## How it works
- `POST /send {email}` emails the code and returns a signed challenge (never the code).
- `POST /verify {email, code, challenge}` returns `{ok: true, token}` for a right code, `{ok: false, error}` otherwise.
- `GET /me` with `Authorization: Bearer <token>` tells one of your own servers who the token belongs to.
- Codes work for 10 minutes. Tokens work for 12 hours. Only the websites in `ALLOWED_ORIGINS` can use it.
- Because nothing is stored, a code is not cancelled when a newer one is sent (it still ends after 10 minutes); the rate limits (3 codes and 5 tries a minute per email and per address) stop guessing.
