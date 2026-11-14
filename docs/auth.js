/*
 * Nesiam email-code sign-in. No passwords: the person types an email address, a 6-digit code is emailed, and entering it opens the page.
 *
 *   NesiamAuth.mount(element, {provider, onSignedIn(email)})
 *
 * Providers (how the code is made and checked):
 *   {type: 'mock'}                          Demo only. The code is made in the browser and SHOWN ON SCREEN, so nothing is emailed.
 *   {type: 'worker', url}                   Real email, through the Nesiam sign-in worker (AuthWorker/), which stores nothing.
 *   {type: 'supabase', url, anonKey}        Real email through Supabase Auth.
 *
 * Note for the site owner: this page is static, so the sign-in only controls what the page shows. Anything that must really be
 * protected has to be checked by a server (the signed-in token from the provider is what a server would check).
 */
(function () {
  'use strict';
  const CODE_LENGTH = 6, RESEND_WAIT_S = 30, MAX_TRIES = 5, MOCK_VALID_MS = 10 * 60 * 1000;
  const EMAIL = /^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)+$/;
  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

  // ---- providers: send(email) -> {note?}; verify(email, code) -> {ok, error?}
  function mockProvider() {
    let issued = null;   // {email, code, at, tries}
    const randomCode = () => { const a = new Uint32Array(1); let n; do { crypto.getRandomValues(a); n = a[0]; } while (n >= 4294000000); return String(n % 1000000).padStart(CODE_LENGTH, '0'); };
    return {
      name: 'mock',
      async send(email) { issued = {email, code: randomCode(), at: Date.now(), tries: 0}; return {note: `Demo mode: no email is sent. Your code is <b>${issued.code}</b>.`}; },
      async verify(email, code) {
        if (!issued || issued.email !== email) return {ok: false, error: 'Send a code first.'};
        if (Date.now() - issued.at > MOCK_VALID_MS) return {ok: false, error: 'That code has expired. Send it again.', expired: true};
        if (++issued.tries > MAX_TRIES) return {ok: false, error: 'Too many wrong tries. Send a new code.', expired: true};
        if (code !== issued.code) return {ok: false, error: 'Code not matched.'};
        issued = null;
        return {ok: true};
      }
    };
  }

  // Cloudflare Turnstile: a check that stops scripts from asking for codes in bulk. It is invisible unless it needs the person's help.
  let turnstileScript = null;
  function loadTurnstile() {
    if (window.turnstile) return Promise.resolve(window.turnstile);
    if (!turnstileScript) turnstileScript = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'; s.async = true;
      s.onload = () => resolve(window.turnstile); s.onerror = () => { turnstileScript = null; reject(new Error('The robot check could not load. Check your connection and try again.')); };
      document.head.appendChild(s);
    });
    return turnstileScript;
  }
  async function turnstileToken(siteKey) {
    const ts = await loadTurnstile();
    return new Promise((resolve, reject) => {
      const box = document.createElement('div');
      box.style.cssText = 'position:fixed;left:50%;top:35%;transform:translateX(-50%);z-index:9999';
      document.body.appendChild(box);
      let done = false, id = null, timer = null;
      const finish = (fn, v) => { if (done) return; done = true; clearTimeout(timer); try { ts.remove(id); } catch (e) {} box.remove(); fn(v); };
      timer = setTimeout(() => finish(reject, new Error('The robot check took too long. Try again.')), 45000);
      id = ts.render(box, {sitekey: siteKey, appearance: 'interaction-only', callback: t => finish(resolve, t),
        'error-callback': () => finish(reject, new Error('The robot check did not pass. Reload the page and try again.')),
        'timeout-callback': () => finish(reject, new Error('The robot check expired. Try again.'))});
    });
  }

  function workerProvider(cfg) {
    const base = String(cfg.url || '').replace(/\/+$/, '');
    let challenge = '';
    async function post(path, body) {
      const r = await fetch(base + path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body), cache: 'no-store', referrerPolicy: 'no-referrer'});
      let j = {}; try { j = await r.json(); } catch (e) {}
      return {status: r.status, ok: r.ok, body: j};
    }
    return {
      name: 'worker',
      async send(email) {
        const turnstile = await turnstileToken(cfg.turnstileSiteKey);   // a fresh check for every code, including "send again"
        let r; try { r = await post('/send', {email, turnstile}); } catch (e) { throw new Error('Could not reach the sign-in service. Check your connection and try again.'); }
        if (!r.ok || !r.body.challenge) throw new Error(r.body && r.body.error || 'The code could not be sent. Try again.');
        challenge = r.body.challenge;
        return {};
      },
      async verify(email, code) {
        if (!challenge) return {ok: false, error: 'Send a code first.'};
        let r; try { r = await post('/verify', {email, code, challenge}); } catch (e) { return {ok: false, error: 'Could not reach the sign-in service. Try again.'}; }
        if (r.body && r.body.ok) return {ok: true, token: r.body.token};
        return {ok: false, error: r.body && r.body.error || 'Code not matched.', expired: !!(r.body && r.body.expired)};
      }
    };
  }

  function supabaseProvider(cfg) {
    const base = String(cfg.url || '').replace(/\/+$/, ''), headers = {'Content-Type': 'application/json', apikey: cfg.anonKey};
    async function call(path, body) {
      const r = await fetch(base + path, {method: 'POST', headers, body: JSON.stringify(body), cache: 'no-store', referrerPolicy: 'no-referrer'});
      let j = {}; try { j = await r.json(); } catch (e) {}
      return {status: r.status, ok: r.ok, body: j};
    }
    return {
      name: 'supabase',
      async send(email) {
        const r = await call('/auth/v1/otp', {email, create_user: true});
        if (!r.ok) throw new Error(r.status === 429 ? 'Too many codes requested. Wait a minute and try again.' : 'The code could not be sent. Check the address and try again.');
        return {};
      },
      async verify(email, code) {
        const r = await call('/auth/v1/verify', {type: 'email', email, token: code});
        if (r.ok && r.body && r.body.access_token) return {ok: true, token: r.body.access_token};
        if (r.status === 429) return {ok: false, error: 'Too many tries. Wait a minute, then send a new code.'};
        return {ok: false, error: 'Code not matched.'};   // wrong, expired and used codes look the same to the person
      }
    };
  }

  function makeProvider(cfg) {
    if (cfg && cfg.type === 'worker') { if (!cfg.turnstileSiteKey) throw new Error('NesiamAuth: the worker provider needs turnstileSiteKey.'); if (!/^https:\/\//.test(cfg.url || '') && !/^http:\/\/localhost/.test(cfg.url || '')) throw new Error('NesiamAuth: the worker provider needs an https url.'); return workerProvider(cfg); }
    if (cfg && cfg.type === 'supabase') { if (!cfg.url || !cfg.anonKey) throw new Error('NesiamAuth: the supabase provider needs url and anonKey.'); return supabaseProvider(cfg); }
    return mockProvider();
  }

  // ---- the two-step form
  function mount(root, opts) {
    const provider = makeProvider(opts && opts.provider);
    let email = '', resendTimer = null, busy = false;
    const state = {step: 'email', msg: '', note: '', error: '', wait: 0};

    function draw() {
      if (state.step === 'email') {
        root.innerHTML = `<form data-f="email" novalidate>
          <label for="nsAuthEmail" style="display:block;font-weight:600;font-size:12px;margin:14px 0 4px">Email address</label>
          <input id="nsAuthEmail" type="email" inputmode="email" autocomplete="email" placeholder="you@example.com" value="${esc(email)}" maxlength="254" required>
          <p class="muted" data-r="err" style="color:#8c1515;min-height:1.2em">${esc(state.error)}</p>
          <p><button class="btn" type="submit"${busy ? ' disabled' : ''}>${busy ? 'Sending…' : 'Send me a code'}</button></p>
          <p class="muted">No password. We email a ${CODE_LENGTH}-digit code to open the page.</p></form>`;
        const f = root.querySelector('form'), input = root.querySelector('input');
        input.focus();
        f.onsubmit = async e => {
          e.preventDefault();
          const v = input.value.trim().toLowerCase();
          if (!EMAIL.test(v)) { state.error = 'Enter a valid email address, like name@example.com.'; return draw(); }
          email = v; await sendCode(true);
        };
      } else {
        root.innerHTML = `<form data-f="code" novalidate>
          <p>We sent a ${CODE_LENGTH}-digit code to <b>${esc(email)}</b>. Enter it below.</p>
          ${state.note ? `<p class="muted" style="background:#fff3d6;color:#a05a00;border-radius:8px;padding:6px 10px">${state.note}</p>` : ''}
          <label for="nsAuthCode" style="display:block;font-weight:600;font-size:12px;margin:14px 0 4px">Code</label>
          <input id="nsAuthCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" maxlength="${CODE_LENGTH}" placeholder="${'0'.repeat(CODE_LENGTH)}" style="max-width:160px;letter-spacing:.35em;font-weight:600;text-align:center" ${busy ? 'disabled' : ''}>
          <p data-r="err" role="alert" style="color:#8c1515;font-weight:600;min-height:1.2em">${esc(state.error)}</p>
          <p style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <button class="btn" type="submit"${busy ? ' disabled' : ''}>${busy ? 'Checking…' : 'Open'}</button>
            <button class="btn" type="button" data-a="resend" style="background:transparent;color:var(--red)"${state.wait > 0 || busy ? ' disabled' : ''}>${state.wait > 0 ? `Send code again (${state.wait})` : 'Send code again'}</button>
            <button class="btn" type="button" data-a="change" style="background:transparent;color:var(--red)">Change email address</button></p></form>`;
        const f = root.querySelector('form'), input = root.querySelector('input');
        if (!busy) input.focus();
        input.oninput = () => { input.value = input.value.replace(/\D/g, '').slice(0, CODE_LENGTH); if (input.value.length === CODE_LENGTH) f.requestSubmit(); };
        f.onsubmit = async e => { e.preventDefault(); if (input.value.length === CODE_LENGTH) await check(input.value); else { state.error = `Enter all ${CODE_LENGTH} digits.`; draw(); } };
        root.querySelector('[data-a=resend]').onclick = () => sendCode(false);
        root.querySelector('[data-a=change]').onclick = () => { clearInterval(resendTimer); state.step = 'email'; state.error = ''; state.note = ''; draw(); };
      }
    }

    async function sendCode(first) {
      busy = true; state.error = ''; draw();
      try {
        const r = await provider.send(email);
        state.note = r.note || '';
        state.step = 'code'; state.error = first ? '' : 'A new code was sent. Use the newest one.';
        startWait();
      } catch (e) { state.step = first ? 'email' : 'code'; state.error = e.message || 'The code could not be sent.'; }
      busy = false; draw();
    }

    function startWait() {
      clearInterval(resendTimer); state.wait = RESEND_WAIT_S;
      resendTimer = setInterval(() => {
        state.wait--;
        const b = root.querySelector('[data-a=resend]');
        if (b) { b.disabled = state.wait > 0; b.textContent = state.wait > 0 ? `Send code again (${state.wait})` : 'Send code again'; }
        if (state.wait <= 0) clearInterval(resendTimer);
      }, 1000);
    }

    async function check(code) {
      busy = true; state.error = ''; draw();
      let r;
      try { r = await provider.verify(email, code); } catch (e) { r = {ok: false, error: 'Could not check the code. Try again.'}; }
      busy = false;
      if (r.ok) { clearInterval(resendTimer); opts.onSignedIn(email, r.token || ''); return; }
      state.error = r.error || 'Code not matched.'; draw();   // the person can retype, send again, or change the address
    }

    draw();
    return {reset() { clearInterval(resendTimer); email = ''; state.step = 'email'; state.error = ''; state.note = ''; busy = false; draw(); }};
  }

  window.NesiamAuth = {mount};
})();
