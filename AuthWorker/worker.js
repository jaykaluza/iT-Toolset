/*
 * Nesiam sign-in worker: emails a 6-digit code and checks it. Runs on Cloudflare Workers. Stores NOTHING (no database, no list of emails).
 *
 * How it stays stateless: /send makes a random nonce and an expiry, and the code is HMAC(secret, "code|" + payload) reduced to 6 digits.
 * The code is emailed; the browser gets only the payload and its HMAC signature, which reveal nothing about the code.
 * /verify recomputes the code from the payload, so it needs no stored copy. A good code returns a signed session token (12 hours).
 *
 * Secrets (wrangler secret put): AUTH_SECRET (long random text), RESEND_API_KEY.  Variables (wrangler.toml): FROM, ALLOWED_ORIGINS.
 * Rate limits use the optional Workers Rate Limiting bindings SEND_LIMIT and VERIFY_LIMIT (see wrangler.toml).
 */
const CODE_VALID_S = 10 * 60, SESSION_VALID_S = 12 * 60 * 60;
const EMAIL = /^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)+$/;
const enc = new TextEncoder();

const b64u = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const key = secret => crypto.subtle.importKey('raw', enc.encode(secret), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
async function hmac(secret, text) { return new Uint8Array(await crypto.subtle.sign('HMAC', await key(secret), enc.encode(text))); }
function same(a, b) {   // constant-time comparison
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function codeFor(secret, payload) {
  const h = await hmac(secret, 'code|' + payload);
  return String(((h[0] << 24 | h[1] << 16 | h[2] << 8 | h[3]) >>> 0) % 1000000).padStart(6, '0');
}
const sig = async (secret, payload) => b64u(await hmac(secret, 'sig|' + payload));

function cors(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  return allowed.includes(origin) ? {'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'POST, GET, OPTIONS', 'Vary': 'Origin', 'Access-Control-Max-Age': '600'} : null;
}
const json = (body, status, headers) => new Response(JSON.stringify(body), {status, headers: {'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers}});

async function limited(binding, key) {
  if (!binding) return false;   // the limit is optional so the worker also runs without it, but turn it on for real use
  try { return !(await binding.limit({key})).success; } catch (e) { return false; }
}

async function sendMail(env, to, code) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: {Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json'},
    body: JSON.stringify({from: env.FROM, to: [to], subject: 'Your Nesiam sign-in code: ' + code,
      text: `Your Nesiam sign-in code is ${code}\n\nIt works for 10 minutes. If you did not ask for it, ignore this email: nobody can sign in without the code.`,
      html: `<p>Your Nesiam sign-in code is</p><p style="font-size:28px;font-weight:600;letter-spacing:4px">${code}</p><p>It works for 10 minutes. If you did not ask for it, ignore this email: nobody can sign in without the code.</p>`})
  });
  if (!r.ok) console.log('Resend refused the email:', r.status, (await r.text()).slice(0, 300));   // visible with `wrangler tail`; never sent to the browser
  return r.ok;
}

async function readJson(request) {
  try { const text = await request.text(); if (text.length > 2000) return null; return JSON.parse(text); } catch (e) { return null; }
}

async function send(request, env, h) {
  const body = await readJson(request), email = String(body && body.email || '').trim().toLowerCase();
  if (!EMAIL.test(email) || email.length > 254) return json({error: 'Enter a valid email address.'}, 400, h);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await limited(env.SEND_LIMIT, 'e:' + email) || await limited(env.SEND_LIMIT, 'ip:' + ip)) return json({error: 'Too many codes requested. Wait a minute and try again.'}, 429, h);
  const payload = b64u(enc.encode(JSON.stringify({e: email, x: Math.floor(Date.now() / 1000) + CODE_VALID_S, n: b64u(crypto.getRandomValues(new Uint8Array(12)))})));
  const code = await codeFor(env.AUTH_SECRET, payload);
  if (!await sendMail(env, email, code)) return json({error: 'The code could not be sent. Try again.'}, 502, h);
  return json({challenge: payload + '.' + await sig(env.AUTH_SECRET, payload)}, 200, h);   // no code in the answer
}

async function verify(request, env, h) {
  const body = await readJson(request), email = String(body && body.email || '').trim().toLowerCase(), code = String(body && body.code || ''), challenge = String(body && body.challenge || '');
  const wrong = () => json({ok: false, error: 'Code not matched.'}, 200, h);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await limited(env.VERIFY_LIMIT, 'e:' + email) || await limited(env.VERIFY_LIMIT, 'ip:' + ip)) return json({ok: false, error: 'Too many tries. Wait a minute, then send a new code.'}, 429, h);
  const [payload, s] = challenge.split('.');
  if (!payload || !s || !/^\d{6}$/.test(code) || !same(s, await sig(env.AUTH_SECRET, payload))) return wrong();
  let p; try { p = JSON.parse(new TextDecoder().decode(unb64u(payload))); } catch (e) { return wrong(); }
  if (p.e !== email) return wrong();
  if (p.x < Date.now() / 1000) return json({ok: false, error: 'That code has expired. Send it again.', expired: true}, 200, h);
  if (!same(code, await codeFor(env.AUTH_SECRET, payload))) return wrong();
  const session = b64u(enc.encode(JSON.stringify({e: email, x: Math.floor(Date.now() / 1000) + SESSION_VALID_S})));
  return json({ok: true, token: session + '.' + await sig(env.AUTH_SECRET, 'session|' + session)}, 200, h);
}

async function me(request, env, h) {   // what a server of yours calls to learn who a token belongs to
  const [session, s] = String(request.headers.get('Authorization') || '').replace(/^Bearer /, '').split('.');
  if (!session || !s || !same(s, await sig(env.AUTH_SECRET, 'session|' + session))) return json({error: 'Not signed in.'}, 401, h);
  try { const p = JSON.parse(new TextDecoder().decode(unb64u(session))); if (p.x < Date.now() / 1000) return json({error: 'Session expired.'}, 401, h); return json({email: p.e, expires: p.x}, 200, h); }
  catch (e) { return json({error: 'Not signed in.'}, 401, h); }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url), h = cors(request, env) || (!request.headers.get('Origin') && url.pathname === '/me' ? {} : null);   // /me is for your own servers, so it may come without a site
    if (!h) return json({error: 'Not allowed.'}, 403, {});   // browsers from other sites get nothing
    if (request.method === 'OPTIONS') return new Response(null, {status: 204, headers: h});
    if (!env.AUTH_SECRET || String(env.AUTH_SECRET).length < 32) return json({error: 'The worker is not set up (AUTH_SECRET).'}, 500, h);
    if (request.method === 'POST' && url.pathname === '/send') return send(request, env, h);
    if (request.method === 'POST' && url.pathname === '/verify') return verify(request, env, h);
    if (request.method === 'GET' && url.pathname === '/me') return me(request, env, h);
    return json({error: 'Not found.'}, 404, h);
  }
};
