/*
 * Nesiam sign-in worker: emails a 6-digit code and checks it. Runs on Cloudflare Workers.
 *
 * The code is HMAC(secret, "code|" + payload) reduced to 6 digits, so it is never stored: /send emails it and hands the browser only the
 * payload and its signature. /verify recomputes it. A good code returns a signed session token (12 hours).
 *
 * Abuse protection:
 *  - Cloudflare Turnstile on /send, so scripts cannot ask for codes in bulk.
 *  - A tiny Durable Object per email address (named by a keyed hash, so it never holds the address) that allows one code at a time,
 *    waits between codes, caps codes per hour, gives each code 5 tries, and makes a code work once. That is what stops code guessing.
 *  - A global daily cap on emails, so Resend's free quota and the sending domain's reputation cannot be drained.
 *  - Optional per-address rate limits (RATE bindings). They only add to the above, and they fail CLOSED when broken.
 *
 * Secrets (wrangler secret put): AUTH_SECRET (32+ random characters), RESEND_API_KEY, TURNSTILE_SECRET.
 * Variables (wrangler.toml): FROM, ALLOWED_ORIGINS, DAILY_CAP.
 */
const CODE_VALID_S = 10 * 60, SESSION_VALID_S = 12 * 60 * 60;
const COOLDOWN_S = 30, MAX_CODES_PER_HOUR = 6, MAX_TRIES = 5;
const EMAIL = /^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)+$/;
const enc = new TextEncoder();

const b64u = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
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

// Fails CLOSED: if a rate-limit binding is configured but errors, the request is refused (and logged), never waved through.
async function limited(binding, k) {
  if (!binding) return false;
  try { return !(await binding.limit({key: k})).success; } catch (e) { console.log('Rate limit binding failed:', String(e)); return true; }
}

// ---- one Durable Object per email address (named by a keyed hash of it)
export class Guard {
  constructor(ctx) { this.ctx = ctx; }
  async fetch(request) {
    const path = new URL(request.url).pathname, b = await request.json(), now = Math.floor(Date.now() / 1000);
    const st = (await this.ctx.storage.get('s')) || {n: '', x: 0, tries: 0, hist: []};
    st.hist = (st.hist || []).filter(t => now - t < 3600);
    const reply = (body, status = 200) => Response.json(body, {status});
    if (path === '/issue') {   // a new code replaces the previous one
      const last = st.hist[st.hist.length - 1] || 0;
      if (now - last < COOLDOWN_S) return reply({ok: false, wait: COOLDOWN_S - (now - last)}, 429);
      if (st.hist.length >= MAX_CODES_PER_HOUR) return reply({ok: false, wait: 3600 - (now - st.hist[0]), hour: true}, 429);
      st.hist.push(now); st.n = b.nonce; st.x = b.exp; st.tries = 0;
      await this.ctx.storage.put('s', st);
      return reply({ok: true});
    }
    if (path === '/cancel') {   // the email could not be sent, so give the person their turn back
      st.hist.pop(); st.n = ''; st.x = 0;
      await this.ctx.storage.put('s', st);
      return reply({ok: true});
    }
    if (path === '/attempt') {   // every try counts, right or wrong, and only the newest code can be tried
      if (!st.n || st.x < now) return reply({ok: false, reason: 'expired'});
      st.tries += 1;
      await this.ctx.storage.put('s', st);
      if (st.tries > MAX_TRIES) return reply({ok: false, reason: 'locked'});
      if (b.nonce !== st.n) return reply({ok: false, reason: 'old'});
      return reply({ok: true});
    }
    if (path === '/consume') {   // a code works once
      st.n = ''; st.x = 0; st.tries = 0;
      await this.ctx.storage.put('s', st);
      return reply({ok: true});
    }
    if (path === '/count') {   // the global daily email cap (an object named "daily")
      const day = new Date().toISOString().slice(0, 10), c = (await this.ctx.storage.get('c')) || {day, n: 0};
      if (c.day !== day) { c.day = day; c.n = 0; }
      if (c.n >= b.limit) return reply({ok: false}, 429);
      c.n += 1; await this.ctx.storage.put('c', c);
      return reply({ok: true});
    }
    return reply({ok: false}, 404);
  }
}
async function guard(env, name, path, body) {   // null if the guard could not be reached: callers then refuse
  try {
    const stub = env.GUARD.get(env.GUARD.idFromName(name));
    const r = await stub.fetch('https://guard' + path, {method: 'POST', body: JSON.stringify(body)});
    return {status: r.status, body: await r.json()};
  } catch (e) { console.log('Guard failed:', String(e)); return null; }
}
const guardName = async (env, email) => 'e:' + hex(await hmac(env.AUTH_SECRET, 'guard|' + email));

async function turnstileOk(env, token, ip) {
  if (!env.TURNSTILE_SECRET || !token || String(token).length > 2100) return false;
  try {
    const form = new FormData(); form.append('secret', env.TURNSTILE_SECRET); form.append('response', token); if (ip && ip !== 'unknown') form.append('remoteip', ip);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {method: 'POST', body: form});
    return !!(await r.json()).success;
  } catch (e) { console.log('Turnstile check failed:', String(e)); return false; }
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
  try { const text = await request.text(); if (text.length > 4000) return null; return JSON.parse(text); } catch (e) { return null; }
}

async function send(request, env, h) {
  const body = await readJson(request), email = String(body && body.email || '').trim().toLowerCase();
  if (!EMAIL.test(email) || email.length > 254) return json({error: 'Enter a valid email address.'}, 400, h);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await limited(env.SEND_LIMIT, 'ip:' + ip) || await limited(env.SEND_LIMIT, 'e:' + email)) return json({error: 'Too many codes requested. Wait a minute and try again.'}, 429, h);
  if (!await turnstileOk(env, body.turnstile, ip)) return json({error: 'The robot check did not pass. Reload the page and try again.'}, 403, h);
  const name = await guardName(env, email);
  const exp = Math.floor(Date.now() / 1000) + CODE_VALID_S, nonce = b64u(crypto.getRandomValues(new Uint8Array(12)));
  const payload = b64u(enc.encode(JSON.stringify({e: email, x: exp, n: nonce})));
  const issued = await guard(env, name, '/issue', {nonce, exp});
  if (!issued) return json({error: 'The sign-in service is busy. Try again in a minute.'}, 503, h);
  if (!issued.body.ok) return json({error: issued.body.hour ? 'Too many codes for this address. Try again later.' : `Please wait ${issued.body.wait} seconds before asking for another code.`}, 429, h);
  const cap = await guard(env, 'daily', '/count', {limit: Number(env.DAILY_CAP) || 90});   // counted only once this address has accepted the request, so refused requests cannot use the cap up
  if (!cap || !cap.body.ok) { await guard(env, name, '/cancel', {}); return cap ? json({error: 'Too many sign-in codes were sent today. Try again tomorrow.'}, 429, h) : json({error: 'The sign-in service is busy. Try again in a minute.'}, 503, h); }
  const code = await codeFor(env.AUTH_SECRET, payload);
  if (!await sendMail(env, email, code)) { await guard(env, name, '/cancel', {}); return json({error: 'The code could not be sent. Try again.'}, 502, h); }
  return json({challenge: payload + '.' + await sig(env.AUTH_SECRET, payload)}, 200, h);   // no code in the answer
}

async function verify(request, env, h) {
  const body = await readJson(request), email = String(body && body.email || '').trim().toLowerCase(), code = String(body && body.code || ''), challenge = String(body && body.challenge || '');
  const wrong = () => json({ok: false, error: 'Code not matched.'}, 200, h);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await limited(env.VERIFY_LIMIT, 'ip:' + ip) || await limited(env.VERIFY_LIMIT, 'e:' + email)) return json({ok: false, error: 'Too many tries. Wait a minute, then send a new code.'}, 429, h);
  const [payload, s] = challenge.split('.');
  if (!payload || !s || !/^\d{6}$/.test(code) || !same(s, await sig(env.AUTH_SECRET, payload))) return wrong();
  let p; try { p = JSON.parse(new TextDecoder().decode(unb64u(payload))); } catch (e) { return wrong(); }
  if (p.e !== email) return wrong();
  if (p.x < Date.now() / 1000) return json({ok: false, error: 'That code has expired. Send it again.', expired: true}, 200, h);
  const name = await guardName(env, email);
  const t = await guard(env, name, '/attempt', {nonce: p.n});   // counts this try; only the newest code can be tried
  if (!t) return json({ok: false, error: 'The sign-in service is busy. Try again in a minute.'}, 503, h);
  if (!t.body.ok) return json({ok: false, error: t.body.reason === 'locked' ? 'Too many wrong tries. Send a new code.' : t.body.reason === 'old' ? 'That is an older code. Use the newest one, or send a new code.' : 'That code has expired. Send it again.', expired: true}, 200, h);
  if (!same(code, await codeFor(env.AUTH_SECRET, payload))) return wrong();
  await guard(env, name, '/consume', {});   // a code works once
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
