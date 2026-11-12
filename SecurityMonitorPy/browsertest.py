"""Browser security self-test, modelled on BrowserAudit (browseraudit.com).

It checks that the browser you run it in enforces the standard web protections: the same-origin policy, CORS,
cookie flags, Content Security Policy and the security response headers. Everything runs against My Security's own
local server, using its two addresses (localhost and 127.0.0.1) as two different "websites". Nothing leaves the PC.
The pages under /bt/ are fixed test material with no secrets in them, so they need no sign-in key; reading the
recorded results and saving the outcome do.
"""
import datetime as dt
import json
import re
import secrets
import urllib.parse

GIF = bytes.fromhex('47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b')
RUN_RE = re.compile(r'^[0-9a-f]{16}$')
COOKIES = ('mysec_bt_js=1; Path=/; Max-Age=300', 'mysec_bt_http=1; Path=/; Max-Age=300; HttpOnly', 'mysec_bt_strict=1; Path=/; Max-Age=300; SameSite=Strict')

FRAME = b'''<!doctype html><meta charset=utf-8><body>frame<script>try{parent.postMessage({bt:new URLSearchParams(location.search).get('n')||'plain'},'*')}catch(e){}</script>'''
CSP_PAGE = '''<!doctype html><meta charset=utf-8><body>
<script>parent.postMessage({bt:'csp-inline-ran'},'*')</script>
<script nonce="__N__">
var r=new URLSearchParams(location.search).get('r'),out={bt:'csp-done',evalRan:false,img:''};
try{eval('out.evalRan=true')}catch(e){}
var i=new Image();i.onload=function(){out.img='loaded';parent.postMessage(out,'*')};i.onerror=function(){out.img='blocked';parent.postMessage(out,'*')};
i.src='/bt/pixel?n=csp-img&r='+encodeURIComponent(r);
</script>'''
NOSNIFF_PAGE = b'''<!doctype html><meta charset=utf-8><body><script src="/bt/nosniff.js"></script><script>parent.postMessage({bt:'nosniff-done',ran:!!window.__ns},'*')</script>'''
IMG_PAGE = '''<!doctype html><meta charset=utf-8><body><script nonce="__N__">
var q=new URLSearchParams(location.search),i=new Image(),done=function(){parent.postMessage({bt:'__DONE__'},'*')};
i.onload=done;i.onerror=done;i.src='__TARGET__/bt/pixel?n=__NAME__&r='+encodeURIComponent(q.get('r'));
</script>'''

RUNNER = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>my_security browser test</title>
<style>body{font:14px -apple-system,"Segoe UI",system-ui,sans-serif;background:#f5f5f7;color:#1d1d1f;margin:0;padding:24px}main{max-width:860px;margin:auto}
h1{font-size:20px;margin:0 0 4px}p{color:#6e6e73;margin:4px 0 14px}.row{display:flex;gap:10px;align-items:baseline;background:#fff;border:1px solid #d2d2d7;border-radius:10px;padding:7px 13px;margin:4px 0}
.mk{font-weight:800;width:16px;flex:none;text-align:center}.ok .mk{color:#1a9d4b}.bad .mk{color:#c0392b}.bad{border-color:#e0b33a;background:#fdf6e3}.na .mk{color:#6e6e73}
.g{color:#6e6e73;font-size:12px;width:150px;flex:none}.nm{font-weight:600}.d{margin-left:auto;color:#6e6e73;font-size:12px;text-align:right;max-width:330px}#sum{font-weight:700;color:#1d1d1f}</style></head>
<body><main><h1>Browser security self-test</h1><p id="sum">Running the checks in this browser…</p><div id="out"></div>
<p>These checks only talk to My Security on this PC. Checks that need a real HTTPS website (HSTS, Secure cookies, mixed content) are not possible locally; the full BrowserAudit suite at browseraudit.com covers those.</p></main>
<script nonce="__N__">
const TOKEN='__TOKEN__',ME=location.origin,OTHER='http://'+(location.hostname==='localhost'?'127.0.0.1':'localhost')+':'+location.port;
const R=[...crypto.getRandomValues(new Uint8Array(8))].map(b=>b.toString(16).padStart(2,'0')).join('');
const msgs=[];addEventListener('message',e=>{if(e.data&&e.data.bt)msgs.push(e.data)});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function waitMsg(n,ms){const t=Date.now();while(Date.now()-t<(ms||3000)){const m=msgs.find(m=>m.bt===n);if(m)return m;await sleep(50)}return null}
function frame(src,sandbox){const f=document.createElement('iframe');f.style.cssText='width:1px;height:1px;border:0;position:absolute;left:-9px';if(sandbox!==undefined)f.setAttribute('sandbox',sandbox);f.src=src;document.body.appendChild(f);return f}
function img(src){return new Promise(r=>{const i=new Image();i.onload=i.onerror=()=>r();i.src=src})}
async function blocked(p){try{const r=await p;await r.text();return false}catch(e){return true}}
const rows=[],add=(g,n,ok,d)=>rows.push({Group:g,Name:n,Ok:ok,Detail:d||''});
(async()=>{
  const NA='Could not be tested in this browser';
  // --- start everything that needs a frame
  const fx=frame(OTHER+'/bt/frame?n=xdom');
  frame(ME+'/bt/frame?n=ctl');frame(ME+'/bt/xfo?n=xfo');frame(ME+'/bt/fa?n=fa');frame(ME+'/bt/frame?n=sandbox','');
  frame(ME+'/bt/csp?r='+R);frame(ME+'/bt/nosniff-page');frame(ME+'/bt/ref-page?r='+R);
  let cookiesSet=false;try{await fetch('/bt/set-cookies');cookiesSet=true}catch(e){}
  frame(OTHER+'/bt/xsite?r='+R+'&o='+location.hostname);
  await img(ME+'/bt/pixel?n=same&r='+R);await img(OTHER+'/bt/pixel?n=ref-cross&r='+R);
  // --- same-origin policy and CORS
  const xm=await waitMsg('xdom');let readable=false;
  if(xm){try{const d=fx.contentDocument||fx.contentWindow.document;readable=!!(d&&d.body)}catch(e){}}
  add('Same-origin policy','A page cannot read another site\'s page',xm?!readable:null,xm?(readable?'This browser let one site read another site\'s content':''):NA);
  add('Same-origin policy','A page cannot read another site\'s data',await blocked(fetch(OTHER+'/bt/secret?r='+R)),'');
  const corsOk=!(await blocked(fetch(OTHER+'/bt/cors')));
  add('CORS','A site can share data when it chooses to',corsOk?true:null,corsOk?'':'A permitted request was blocked, perhaps by an extension. Other results may be affected');
  const pre=await blocked(fetch(OTHER+'/bt/preflight?r='+R,{method:'POST',headers:{'X-Test':'1'}}));
  const star=await blocked(fetch(OTHER+'/bt/cors-star',{credentials:'include'}));
  add('CORS','Sign-in details are not sent to a site that allows "everyone"',star,star?'':'The browser accepted a wildcard permission together with cookies');
  // --- wait for the frames, then ask the server what it saw
  const ctl=await waitMsg('ctl'),csp=await waitMsg('csp-done'),ns=await waitMsg('nosniff-done'),rf=await waitMsg('ref-done'),xs=await waitMsg('xsite-done');
  const xfo=await waitMsg('xfo',1200),fa=await waitMsg('fa',300),sb=await waitMsg('sandbox',300);
  let hits={};try{hits=await(await fetch('/bt/hits?r='+R,{headers:{'X-MySec-Token':TOKEN}})).json()}catch(e){}
  add('CORS','An unusual request is checked with the other site first',pre?!hits['preflight-real']:false,pre&&!hits['preflight-real']?'':'The request reached the other site without permission');
  // --- cookies
  const same=(hits.same||{}).cookies||[],js=document.cookie;
  const canCookie=cookiesSet&&js.includes('mysec_bt_js')&&same.includes('mysec_bt_http');
  add('Cookies','Scripts cannot read HttpOnly cookies',canCookie?!js.includes('mysec_bt_http'):null,canCookie?(js.includes('mysec_bt_http')?'A script could read a cookie marked HttpOnly':''):NA+' (cookies are off or blocked)');
  const xc=hits.xsite?hits.xsite.cookies:null,canStrict=canCookie&&same.includes('mysec_bt_strict')&&xs&&xc;
  add('Cookies','SameSite=Strict cookies are not sent from another site',canStrict?!xc.includes('mysec_bt_strict'):null,canStrict?(xc.includes('mysec_bt_strict')?'The cookie was sent with a request made by another site':''):NA);
  // --- Content Security Policy
  const inl=msgs.some(m=>m.bt==='csp-inline-ran');
  add('Content Security Policy','Blocks scripts written into the page',csp?!inl:null,csp?(inl?'An unapproved inline script ran':''):NA);
  add('Content Security Policy','Blocks code built from text (eval)',csp?!csp.evalRan:null,csp?(csp.evalRan?'eval() ran although the policy forbids it':''):NA);
  add('Content Security Policy','Blocks images the policy forbids',csp?(csp.img==='blocked'&&!hits['csp-img']):null,csp?(csp.img==='blocked'&&!hits['csp-img']?'':'A forbidden image was requested'):NA);
  // --- framing and response headers
  add('Framing','X-Frame-Options stops a page being put in a frame',ctl?!xfo:null,ctl?(xfo?'The page was shown in a frame anyway (clickjacking risk)':''):NA);
  add('Framing','frame-ancestors stops a page being put in a frame',ctl?!fa:null,ctl?(fa?'The page was shown in a frame anyway (clickjacking risk)':''):NA);
  add('Framing','A sandboxed frame cannot run scripts',ctl?!sb:null,ctl?(sb?'A script ran inside a sandboxed frame':''):NA);
  add('Response headers','nosniff stops text being run as a script',ns?!ns.ran:null,ns?(ns.ran?'A text file was run as a script':''):NA);
  const rn=hits['ref-none'],rc=hits['ref-cross'];
  add('Request headers','Referrer-Policy: no-referrer is obeyed',rf&&rn?rn.referer==='':null,rf&&rn?(rn.referer?'The page address was sent anyway':''):NA);
  const leak=rc&&(rc.referer.includes('k=')||rc.referer.includes('/browser-test'));
  add('Request headers','Other sites are not told the full page address',rc?!leak:null,rc?(leak?'The full address, including its private part, was sent to another site':''):NA);
  try{await fetch('/bt/clear-cookies')}catch(e){}
  // --- show and save
  const out=document.getElementById('out');
  for(const r of rows){const d=document.createElement('div');d.className='row '+(r.Ok===true?'ok':r.Ok===false?'bad':'na');
    for(const [c,t] of [['mk',r.Ok===true?'✓':r.Ok===false?'✗':'–'],['g',r.Group],['nm',r.Name],['d',r.Ok===true?'OK':r.Detail]]){const s=document.createElement('span');s.className=c;s.textContent=t;d.appendChild(s)}
    out.appendChild(d)}
  const ua=navigator.userAgent,br=/Edg\//.test(ua)?'Edge':/OPR\//.test(ua)?'Opera':/Vivaldi/.test(ua)?'Vivaldi':/Firefox\//.test(ua)?'Firefox':/Chrome\//.test(ua)?'Chrome':/Safari\//.test(ua)?'Safari':'This browser';
  const bad=rows.filter(r=>r.Ok===false).length,na=rows.filter(r=>r.Ok===null).length;
  let saved=false;try{const r=await fetch('/bt/result',{method:'POST',headers:{'Content-Type':'application/json','X-MySec-Token':TOKEN},body:JSON.stringify({browser:br,rows})});saved=(await r.json()).ok}catch(e){}
  document.getElementById('sum').textContent=br+': '+(rows.length-bad-na)+' of '+rows.length+' checks passed'+(bad?', '+bad+' failed':'')+(na?', '+na+' could not be tested':'')+'. '+(saved?'The result is saved in My Security\'s Browsers tab. You can close this tab.':'The result could not be saved to My Security (it may have been restarted).');
})();
</script></body></html>'''


def _send(h, status, ctype, body, headers=()):
    h.send_response(status)
    for k, v in (('Content-Type', ctype), ('Content-Length', str(len(body))), ('Cache-Control', 'no-store')) + tuple(headers):
        h.send_header(k, v)
    h.end_headers()
    h.wfile.write(body)


def _record(app, h, run, name):
    if not RUN_RE.match(run or ''):
        return
    name = re.sub(r'[^a-z0-9-]', '', str(name or ''))[:24]
    cookies = sorted({c.split('=')[0].strip() for c in (h.headers.get('Cookie') or '').split(';') if c.strip().startswith('mysec_bt_')})
    with app.lock:
        if run not in app.bt_hits and len(app.bt_hits) >= 20:
            app.bt_hits.pop(next(iter(app.bt_hits)))
        app.bt_hits.setdefault(run, {})[name] = {'cookies': cookies, 'referer': (h.headers.get('Referer') or '')[:300]}


def handle_get(h, app, port, token, launch_key, local_origins):
    """Serves the test runner and its test material. Returns after sending a response."""
    u = urllib.parse.urlsplit(h.path)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    path, run = u.path, q.get('r', '')
    both = ' '.join(local_origins)
    html = 'text/html; charset=utf-8'
    if path == '/browser-test':
        if not secrets.compare_digest(q.get('k', '').encode('utf-8', 'replace'), launch_key.encode()):
            return _send(h, 403, 'text/plain', b'This address has expired. Open the test from My Security.')
        n = secrets.token_urlsafe(18)
        csp = f"default-src 'none'; script-src 'nonce-{n}'; style-src 'unsafe-inline'; connect-src {both}; frame-src {both}; img-src data: {both}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        return _send(h, 200, html, RUNNER.replace('__N__', n).replace('__TOKEN__', token).encode('utf-8'), (('Content-Security-Policy', csp), ('X-Content-Type-Options', 'nosniff')))
    relaxed = ('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'")
    if path == '/bt/frame':
        return _send(h, 200, html, FRAME, (relaxed,))
    if path == '/bt/xfo':
        return _send(h, 200, html, FRAME, (relaxed, ('X-Frame-Options', 'DENY')))
    if path == '/bt/fa':
        return _send(h, 200, html, FRAME, (('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'"),))
    if path == '/bt/csp':
        n = secrets.token_urlsafe(18)
        return _send(h, 200, html, CSP_PAGE.replace('__N__', n).encode(), (('Content-Security-Policy', f"default-src 'none'; script-src 'nonce-{n}'; img-src 'none'"),))
    if path == '/bt/nosniff-page':
        return _send(h, 200, html, NOSNIFF_PAGE, (('Content-Security-Policy', "default-src 'none'; script-src 'self' 'unsafe-inline'"),))
    if path == '/bt/nosniff.js':
        return _send(h, 200, 'text/plain', b'window.__ns=1;', (('X-Content-Type-Options', 'nosniff'),))
    if path in ('/bt/ref-page', '/bt/xsite'):
        n = secrets.token_urlsafe(18)
        if path == '/bt/ref-page':
            page, extra = IMG_PAGE.replace('__TARGET__', '').replace('__NAME__', 'ref-none').replace('__DONE__', 'ref-done'), (('Referrer-Policy', 'no-referrer'),)
        else:   # a page on the "other site" that asks the first site for an image, to see which cookies travel with it
            host = q.get('o') if q.get('o') in ('localhost', '127.0.0.1') else 'localhost'
            page, extra = IMG_PAGE.replace('__TARGET__', f'http://{host}:{port}').replace('__NAME__', 'xsite').replace('__DONE__', 'xsite-done'), ()
        return _send(h, 200, html, page.replace('__N__', n).encode(), (('Content-Security-Policy', f"default-src 'none'; script-src 'nonce-{n}'; img-src {both}"),) + extra)
    if path == '/bt/pixel':
        _record(app, h, run, q.get('n'))
        return _send(h, 200, 'image/gif', GIF)
    if path == '/bt/secret':
        return _send(h, 200, 'application/json', b'{"note":"another site must not be able to read this"}')
    if path == '/bt/cors':
        origin = h.headers.get('Origin')
        return _send(h, 200, 'application/json', b'{"ok":true}', (('Access-Control-Allow-Origin', origin), ('Vary', 'Origin')) if origin in local_origins else ())
    if path == '/bt/cors-star':
        return _send(h, 200, 'application/json', b'{"ok":true}', (('Access-Control-Allow-Origin', '*'),))
    if path == '/bt/set-cookies':
        return _send(h, 200, 'text/plain', b'ok', tuple(('Set-Cookie', c) for c in COOKIES))
    if path == '/bt/clear-cookies':
        return _send(h, 200, 'text/plain', b'ok', tuple(('Set-Cookie', c.split(';')[0] + '; Path=/; Max-Age=0') for c in COOKIES))
    if path == '/bt/hits':
        if not h.token_ok():
            return _send(h, 403, 'application/json', b'{"ok":false}')
        with app.lock:
            data = dict(app.bt_hits.get(run, {})) if RUN_RE.match(run) else {}
        return _send(h, 200, 'application/json', json.dumps(data).encode())
    return _send(h, 404, 'text/plain', b'Not found')


def handle_post(h, app):
    u = urllib.parse.urlsplit(h.path)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    if u.path == '/bt/preflight':   # only reached if the browser skipped the permission check it should have made first
        _record(app, h, q.get('r', ''), 'preflight-real')
        return _send(h, 204, 'text/plain', b'')
    if u.path == '/bt/result':
        if not h.token_ok():
            return _send(h, 403, 'application/json', b'{"ok":false}')
        try:
            b = h.body_json()
            rows = [{'Group': str(r.get('Group', ''))[:40], 'Name': str(r.get('Name', ''))[:90], 'Ok': r.get('Ok') if r.get('Ok') in (True, False) else None, 'Detail': str(r.get('Detail', ''))[:200]}
                    for r in b.get('rows', [])[:40] if isinstance(r, dict)]
        except (ValueError, AttributeError, TypeError):
            return _send(h, 400, 'application/json', b'{"ok":false}')
        with app.lock:
            app.browser_test = {'At': dt.datetime.now().astimezone().isoformat(), 'Browser': re.sub(r'[^A-Za-z ]', '', str(b.get('browser', '')))[:20] or 'Browser', 'Rows': rows}
            app.rev += 1
        failed = [r['Name'] for r in rows if r['Ok'] is False]
        app.log('BROWSER-TEST', f"{app.browser_test['Browser']}: {len(rows) - len(failed)} of {len(rows)} checks not failed" + (f"; failed: {'; '.join(failed)}" if failed else ''))
        return _send(h, 200, 'application/json', b'{"ok":true}')
    return _send(h, 404, 'text/plain', b'Not found')
