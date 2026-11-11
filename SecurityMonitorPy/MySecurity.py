"""
My Security: a local security assessment for Windows. Scans ports, shares, protocols, accounts, services, malware signs,
downloads, patches, published threats and browsers; explains each finding; and fixes what you approve, one click at a time.

Standard library only. Serves a dashboard on http://localhost. Run (Administrator recommended):  py MySecurity.py
"""

import ctypes
import sys

# The app runs as Administrator, often from a Downloads folder, so Windows' own DLLs are loaded from System32 before anything can ask for them by name.
LOAD_FROM_SYSTEM32 = 0x800
for _dll in ('iphlpapi', 'version', 'dnsapi', 'fwpuclnt', 'crypt32', 'bcrypt', 'secur32', 'mswsock', 'wsock32', 'userenv', 'wintrust', 'msasn1', 'winnsi'):
    if sys.platform == 'win32':
        try:
            ctypes.WinDLL(_dll, winmode=LOAD_FROM_SYSTEM32)
        except OSError:
            pass

import argparse
import ctypes.wintypes as wt
import datetime as dt
import http.server
import json
import os
import re
import secrets
import socket
import subprocess
import threading
import time
import traceback
import urllib.parse
import webbrowser
import winreg
from concurrent.futures import ThreadPoolExecutor

if sys.platform != 'win32':
    sys.exit('This version of My Security runs on Windows.')

import fixes_win as X
import scans_win as S
import scans_deep as D   # adds its scans to S.SCANS
import attempts as T
import cleanup   # adds the clean-up check and its two fixes
import hacktools   # adds hacking tools, Sticky Keys and more backdoors to the Hacker tricks check
import exposure   # adds the Exposure scan: Wi-Fi, SNMP, local web services, developer ports, the network itself
import creds   # adds the saved cloud/tool credentials scan

APP_NAME = 'My Security'
EXE_NAME = 'MySecurity.exe'
APP_VERSION = '0.1.10'
HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = getattr(sys, 'frozen', False)
RESOURCES = getattr(sys, '_MEIPASS', HERE)
APP_DIR = S.APP_DIR
WINDIR = S.WINDIR
user32 = S.system_dll('user32')
SEV_RANK = S.SEV_RANK
BROWSERS = S.BROWSERS
MB_YESNO, MB_ICONWARNING, MB_SYSTEMMODAL, IDYES = 0x4, 0x30, 0x1000, 6


class App:
    def __init__(self, args):
        self.args = args
        self.admin = S.is_admin()
        self.lock = threading.RLock()
        self.scans = {key: {'label': label, 'status': 'never', 'findings': [], 'at': '', 'secs': 0} for key, label, _fn in S.SCANS}
        self.ctx = {'admin': self.admin, 'self_pid': os.getpid()}
        self.job = None                  # {'kind', 'queue', 'current', 'done', 'total', 'started'}
        self.autopilot_at = ''
        self.rev = 1
        self.undo = []                   # changes made this session that can be reversed
        self.blocks = {'ports': [], 'programs': [], 'ips': [], 'sites': [], 'quarantine': []}
        # blocked attempts: refused connections from the firewall log that hit one of those blocks
        self.att_reader = T.Reader()
        self.attempts = {'on': None, 'rows': [], 'at': '', 'since': ''}
        self.rec_prev = None             # firewall logging settings from before this app turned recording on
        self.att_wake = threading.Event()
        self.url = ''                    # the dashboard's address, to reopen it after a fix closed the browsers
        self.notice = None               # the result of a fix whose dashboard tab was closed while it ran
        self.restore_point = None         # 'ok' / 'failed' once a System Restore point has been tried this session
        self.activity_log = os.path.join(APP_DIR, 'activity-log.txt')
        os.makedirs(APP_DIR, exist_ok=True)
        self.prune_log()
        # live watch of new processes
        self.events, self.seen_pids = [], {}
        self.event_seq = 0
        self.watch_started = False
        # browser guard
        self.guard_on = True
        self.tabs, self.tab_at = [], ''
        self.tab_findings = {}
        self.cert_cache, self.page_cache = {}, {}
        self.alerted = set()
        self.alerts = []
        self.net_pool = ThreadPoolExecutor(max_workers=6)
        self.last_client = time.time()
        self.tab_closed_at = 0
        self.stop = threading.Event()
        self.stopping = False
        self.action_lock = threading.Lock()

    def bump(self):
        with self.lock:
            self.rev += 1

    def log(self, action, what):
        line = f"{dt.datetime.now():%Y-%m-%d %H:%M:%S}  {action:<9}  {what}\n"
        try:
            with open(self.activity_log, 'a', encoding='utf-8') as f:
                f.write(line)
        except OSError:
            pass

    def prune_log(self, days=30):
        try:
            with open(self.activity_log, encoding='utf-8') as f:
                lines = f.readlines()
        except OSError:
            return
        cutoff = f'{dt.datetime.now() - dt.timedelta(days=days):%Y-%m-%d %H:%M:%S}'
        keep = [x for x in lines if x[:19] >= cutoff]
        if len(keep) != len(lines):
            try:
                with open(self.activity_log, 'w', encoding='utf-8') as f:
                    f.writelines(keep)
            except OSError:
                pass

    # ---- scans

    def start_scans(self, keys, kind):
        with self.lock:
            if self.job:
                return {'ok': False, 'message': 'A scan is already running. Wait for it to finish.'}
            order = [k for k, _l, _f in S.SCANS if k in keys]
            if not order:
                return {'ok': False, 'message': 'Unknown scan.'}
            self.job = {'kind': kind, 'queue': order, 'current': '', 'done': 0, 'total': len(order), 'started': time.time()}
            for k in order:
                self.scans[k]['status'] = 'queued'
            self.rev += 1
        threading.Thread(target=self._run_job, daemon=True).start()
        return {'ok': True, 'message': 'Autopilot started: running every scan.' if kind == 'autopilot' else 'Scan started.'}

    def _run_job(self):
        fns = {k: f for k, _l, f in S.SCANS}
        self.ctx['blocked_ports'] = {p['Key'] for p in self.blocks.get('ports', [])}
        job = self.job
        for key in list(job['queue']):
            with self.lock:
                job['current'] = key
                self.scans[key]['status'] = 'running'
                self.rev += 1
            start = time.time()
            try:
                findings, status = fns[key](self.ctx), 'done'
            except Exception:
                detail = traceback.format_exc()
                self._write_error(detail)
                findings, status = [S.F(key, 'error', 'info', 'This scan stopped with an error', 'The details were saved to error.log in the app\'s folder.', evidence=detail.strip().splitlines()[-1])], 'error'
            with self.lock:
                self.scans[key].update(status=status, findings=findings, at=dt.datetime.now().astimezone().isoformat(), secs=round(time.time() - start, 1))
                job['done'] += 1
                self.rev += 1
        self.refresh_blocks()
        with self.lock:
            if job['kind'] == 'autopilot':
                self.autopilot_at = dt.datetime.now().astimezone().isoformat()
            self.job = None
            self.rev += 1

    @staticmethod
    def _write_error(text):
        try:
            with open(os.path.join(APP_DIR, 'error.log'), 'a', encoding='utf-8') as f:
                f.write(f'{dt.datetime.now().isoformat()}\n{text}\n')
        except OSError:
            pass

    def refresh_blocks(self):
        fw = X.firewall_blocks() if self.admin else {'ports': [], 'programs': [], 'ips': []}
        with self.lock:
            self.blocks = {**fw, 'sites': X.blocked_sites(), 'quarantine': [{k: q.get(k) for k in ('Id', 'Path', 'Name', 'When', 'Size', 'Sha256', 'Why', 'Source', 'Locked')} | {'Perms': bool(q.get('Access'))} for q in X.quarantine_list()]}
            self.rev += 1
        self.att_wake.set()

    # ---- blocked attempts

    def attempts_loop(self):
        while not self.stop.is_set():
            try:
                if self.admin:
                    rows = T.profiles()
                    on = T.is_on(rows)
                    files = sorted({p['File'] for p in rows if p.get('LogBlocked') == 'True' and p.get('File')})
                    self.att_reader.update(files)
                    with self.lock:
                        blocks = dict(self.blocks)
                    matched = self.att_reader.match(blocks)
                    with self.lock:
                        self.attempts = {'on': on, 'rows': matched, 'at': dt.datetime.now().astimezone().isoformat(), 'since': self.att_reader.since or ''}
                        self.rev += 1
            except Exception:
                self._write_error(traceback.format_exc())
            self.att_wake.wait(60)
            self.att_wake.clear()

    def set_recording(self, on):
        if not self.admin:
            return {'ok': False, 'message': 'Recording needs Administrator rights. Start My Security as Administrator.'}
        with self.action_lock:
            if on:
                prev = T.profiles()
                r = T.start(prev)
                if r['ok'] and not T.is_on(prev):
                    self.rec_prev = [{'Name': p['Name'], 'LogBlocked': p['LogBlocked'], 'Size': p['Size']} for p in prev]
            else:
                r = T.stop(self.rec_prev)
                if r['ok']:
                    self.rec_prev = None
        self.log('RECORDING' if r['ok'] else 'FAILED', r['message'])
        self.att_wake.set()
        return r

    # ---- live watch: looks at each new process once, as it appears

    def watch_loop(self):
        first = True
        me = os.getpid()
        while not self.stop.is_set():
            try:
                snap = S.process_snapshot()
                new = []
                for pid, (name, ppid) in snap.items():
                    if pid <= 4 or self.seen_pids.get(pid) == name:
                        continue
                    self.seen_pids[pid] = name
                    path = S.process_path(pid)
                    if ppid == me or S.is_this_app(pid, path):   # this app, its launcher, and its own helpers
                        continue
                    new.append((pid, name, ppid, path, S.process_cmdline(pid)))
                for pid in [p for p in self.seen_pids if p not in snap]:
                    del self.seen_pids[pid]
                if new:
                    signs = S.sign_info([n[3] for n in new if n[3] and not S.in_windows(n[3])])
                    for pid, name, ppid, path, cmd in new:
                        parent = snap.get(ppid, ('', 0))[0]
                        sev, reasons = S.judge_process(name, path, cmd, parent, signs.get(path))
                        if sev:
                            self._add_event(pid, name, ppid, parent, path, cmd, sev, reasons, signs.get(path, {}), first)
                with self.lock:
                    changed = False
                    for e in self.events:
                        alive = e['PID'] in snap and snap[e['PID']][0] == e['Name']
                        if e['Running'] != alive:
                            e['Running'] = alive
                            changed = True
                    if changed:
                        self.rev += 1
                self.watch_started = True
                first = False
            except Exception:
                self._write_error(traceback.format_exc())
            self.stop.wait(1.5)

    # ---- escalation guard: notices a new administrator or a suspicious new service within a minute

    def privilege_loop(self):
        known = None
        while not self.stop.is_set():
            try:
                now = D.privilege_state()
                if now and known:
                    for sid, name in now['admins'].items():
                        if sid not in known['admins']:
                            self._live_finding(D.new_admin_finding(sid, name))
                            self.log('DETECTED', f'New administrator: {name}')
                            if sid != now['me']:
                                threading.Thread(target=self._ask_remove_admin, args=(name,), daemon=True).start()
                    for svc, image in now['services'].items():
                        if svc not in known['services']:
                            found = D.new_service_finding(svc, image)
                            if found:
                                self._live_finding(found)
                                self.log('DETECTED', f'Suspicious new service: {svc} {image}')
                                threading.Thread(target=self._warn, args=(f'A suspicious new service just appeared.\n\n{svc}\n{image}\n\nOpen My Security\'s Lateral tab to disable it.',), daemon=True).start()
                if now:
                    known = now
            except Exception:
                self._write_error(traceback.format_exc())
            self.stop.wait(60)

    def _live_finding(self, finding):
        with self.lock:
            s = self.scans['lateral']
            s['findings'] = [f for f in s['findings'] if f['Id'] != finding['Id']] + [finding]
            if s['status'] == 'never':
                s.update(status='done', at=dt.datetime.now().astimezone().isoformat())
            self.rev += 1

    def _ask_remove_admin(self, name):
        if not self.admin:
            self._warn(f'{name} just became an administrator on this PC.\n\nIf you or something you installed did not do this, start My Security as Administrator and remove it in the Lateral tab.')
            return
        answer = user32.MessageBoxW(None, f'{name} just became an administrator on this PC.\n\nIntruders give themselves admin rights right after getting in.\n\nRemove its administrator rights now?', APP_NAME, MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL)
        if answer == IDYES:
            r = X.remove_admin(name)
            self.log('REMOVED' if r['ok'] else 'FAILED', f'{name}: {r["message"]}')

    def _add_event(self, pid, name, ppid, parent, path, cmd, sev, reasons, sign, initial):
        with self.lock:
            self.event_seq += 1
            self.events.insert(0, {'Id': self.event_seq, 'PID': pid, 'Name': name, 'Parent': parent, 'PPID': ppid, 'Path': path, 'Cmd': cmd[:4000], 'Decoded': S.decode_encoded(cmd)[:4000], 'Sev': sev,
                                   'Reasons': [{'Title': t, 'Why': w} for t, w in reasons], 'When': dt.datetime.now().astimezone().isoformat(), 'Running': True, 'Publisher': sign.get('Publisher', ''), 'Existing': initial})
            del self.events[300:]
            self.rev += 1
        self.log('DETECTED', f'[{sev}] {name} (PID {pid}): {reasons[0][0]}')
        if sev == 'critical' and not initial:
            threading.Thread(target=self._warn, args=(f'A running program is doing something dangerous.\n\n{name} (PID {pid})\n{reasons[0][0]}\n\n{reasons[0][1]}\n\nOpen My Security\'s Processes tab to end or block it.',), daemon=True).start()

    def _event(self, eid):
        with self.lock:
            return next((e for e in self.events if e['Id'] == eid), None)

    def kill_event(self, eid):
        e = self._event(eid)
        if not e:
            return {'ok': False, 'message': 'That entry is no longer in the list.'}
        name, pid = e['Name'], e['PID']
        if name.lower() in X.NO_TOUCH_PROCS:
            return {'ok': False, 'message': f'{name} is a core part of Windows or your security software, so My Security won\'t end it.'}
        if S.process_snapshot().get(pid, ('',))[0] != name or S.process_path(pid).lower() != e['Path'].lower():
            return {'ok': True, 'message': f'{name} had already closed.'}
        result = S.terminate(pid)
        if result == 'denied':
            return {'ok': False, 'message': f'Windows refused to end {name}. Start My Security as Administrator and try again.'}
        self.log('ENDED', f'{name} (PID {pid}) {e["Path"]}')
        return {'ok': True, 'message': f'Ended {name} (PID {pid}).'}

    def block_event(self, eid):
        e = self._event(eid)
        if not e:
            return {'ok': False, 'message': 'That entry is no longer in the list.'}
        if not self.admin:
            return {'ok': False, 'message': 'Blocking needs Administrator rights. Start My Security as Administrator.'}
        r = X.block_process(e['PID'], e['Name'], e['Path'])
        self.log('BLOCKED' if r['ok'] else 'FAILED', f"{e['Name']} {e['Path']}: {r['message']}")
        self.refresh_blocks()
        return r

    # ---- browser guard

    def guard_loop(self):
        while not self.stop.is_set():
            if self.guard_on:
                try:
                    self.check_tabs()
                except Exception:
                    self._write_error(traceback.format_exc())
            self.stop.wait(12)

    def _cert(self, host):
        c = self.cert_cache.get(host)
        if c is None or time.time() - c[1] > 3600:
            result = S.check_certificate(host)
            self.cert_cache[host] = c = (result, time.time())
        return c[0]

    def _page(self, url):
        key = url.split('?')[0].split('#')[0]
        c = self.page_cache.get(key)
        if c is None or time.time() - c[1] > 3600:
            result = S.check_page(url)
            self.page_cache[key] = c = (result, time.time())
        return c[0]

    def _check_tab(self, tab):
        url, title = tab['Url'], tab['Title']
        parts = urllib.parse.urlsplit(url) if url else None
        host = (parts.hostname or '').lower() if parts else ''
        site = S.base_site(host) if host and S.SITE_RE.match(host) else ''
        cert, page = None, []
        if host and site and not S._on(host, S.TRUSTED_SITES) and not host.endswith(('.local', '.lan', '.internal')) and host != 'localhost':
            if parts.scheme == 'https':
                cert = self._cert(host)
            page = self._page(url)
        hits = S.check_url(url, title, cert, page) if url else []
        sev = hits[0][0] if hits else ''
        return {**tab, 'Host': host, 'Site': site, 'Sev': sev, 'Hits': [{'Sev': s, 'Title': t, 'Why': w} for s, t, w in hits]}

    def check_tabs(self):
        tabs = S.open_tabs()
        unique = {(t['Url'], t['Title']): t for t in tabs}
        results = list(self.net_pool.map(self._check_tab, unique.values()))
        findings = {}
        blocked = set(X.blocked_sites())
        for r in results:
            if r['Sev'] in ('critical', 'high', 'medium') and r['Site']:
                top = r['Hits'][0]
                action = None if any(r['Site'] == p or r['Site'].endswith('.' + p) for p in S.PROTECTED_SITES) or r['Site'] in blocked else S.A('block_site', 'Block site', f"Block {r['Site']}?\n\nNo browser on this PC will be able to open it.", site=r['Site'])
                f = S.F('tabs', r['Site'], r['Sev'], f"{top['Title']}: {r['Site']}", top['Why'], f"Open in {r['Browser']}: {r['Title']}", r['Url'], 'Close this tab. Block the site so that it can\'t be opened again.', action, Active=r['Sev'] == 'critical')
                findings[f['Id']] = f
                r['FindingId'] = f['Id']
            if r['Site'] in blocked:
                r['Blocked'] = True
        with self.lock:
            self.tabs = results
            self.tab_at = dt.datetime.now().astimezone().isoformat()
            self.tab_findings = findings
            self.rev += 1
        for r in results:
            key = (r['Site'], r['Hits'][0]['Title']) if r['Hits'] else None
            if r['Sev'] == 'critical' and key not in self.alerted:
                self.alerted.add(key)
                self.alerts.insert(0, {'Site': r['Site'], 'Title': r['Hits'][0]['Title'], 'When': dt.datetime.now().astimezone().isoformat()})
                self.log('WARNED', f"{r['Site']}: {r['Hits'][0]['Title']} ({r['Url']})")
                threading.Thread(target=self._warn_site, args=(r,), daemon=True).start()

    def _warn(self, text):
        user32.MessageBoxW(None, text, APP_NAME, MB_ICONWARNING | MB_SYSTEMMODAL)

    def _warn_site(self, r):
        top = r['Hits'][0]
        answer = user32.MessageBoxW(None, f"This open tab looks dangerous.\n\n{r['Browser']}: {r['Title'][:120]}\nSite: {r['Site']}\n\n{top['Title']}\n{top['Why']}\n\nBlock this site on this PC now?", APP_NAME, MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL)
        if answer == IDYES and self.admin:
            result = X.block_site(r['Site'])
            self.log('BLOCKED' if result['ok'] else 'FAILED', f"{r['Site']}: {result['message']}")
            self.refresh_blocks()

    # ---- actions: the page sends only a finding's id; what the button does is held here

    def find_finding(self, fid):
        with self.lock:
            if fid in self.tab_findings:
                return self.tab_findings[fid]
            for s in self.scans.values():
                for f in s['findings']:
                    if f['Id'] == fid:
                        return f
        return None

    def do_action(self, fid):
        f = self.find_finding(fid)
        if not f or not f.get('Action'):
            return {'ok': False, 'message': 'That item is no longer in the list. Run the scan again.'}
        act = f['Action']
        if not self.admin and act['fn'] not in X.NO_ADMIN_NEEDED and act['args'].get('hive') != 'HKCU':
            return {'ok': False, 'message': 'This fix needs Administrator rights. Start My Security as Administrator.'}
        rp_note = ''
        with self.action_lock:
            if self.admin and act['fn'] in X.RESTORE_BEFORE and self.restore_point is None:
                rp = X.create_restore_point()
                self.restore_point = 'ok' if rp.get('ok') else 'failed'
                self.log('RESTORE' if rp.get('ok') else 'RESTORE-FAIL', rp.get('message', ''))
                rp_note = (' A Windows System Restore point was created first, so you can roll this change back.' if rp.get('ok')
                           else f" (No System Restore point could be made — {rp.get('message', '')} — so the change was applied without one.)")
            try:
                extra = {'why': f['Title'], 'source': f.get('Cat', '')} if act['fn'] == 'quarantine' else {}
                r = X.FIXES[act['fn']](**act['args'], **extra)
            except Exception as e:
                self._write_error(traceback.format_exc())
                r = {'ok': False, 'message': f'That did not work: {e}'}
        r['message'] = r.get('message', '') + rp_note
        self.log('FIXED' if r.get('ok') else 'FAILED', f"{f['Title']}: {r.get('message')}")
        if r.get('closed') and self.url:   # the browsers it closed took this dashboard with them
            with self.lock:
                self.notice = {'At': time.time(), 'ok': bool(r.get('ok')), 'message': r.get('message', '')}
            self.tab_closed_at = 0
            open_dashboard(self.url)
            self.last_client = time.time()
        if r.get('ok') and act['fn'] != 'open_settings':
            with self.lock:
                f['Done'] = r.get('message')
                if r.get('undo'):
                    self.undo.insert(0, {'Id': secrets.token_hex(6), 'Label': r['undo'][2], 'What': f['Title'], 'fn': r['undo'][0], 'args': r['undo'][1]})
                self.rev += 1
            if act['fn'] in ('block_port', 'block_ip', 'block_process', 'block_site', 'quarantine'):
                self.refresh_blocks()
            if act['fn'] == 'block_port':
                self._rescan_port_views()
        return {'ok': bool(r.get('ok')), 'message': r.get('message', '')}

    def _rescan_port_views(self):
        # a port block/unblock changes what the Ports and Pentest tabs should show; refresh both so they stay in step
        if not self.job:
            self.start_scans({'ports', 'pentest'}, 'ports')

    def do_undo(self, uid):
        with self.lock:
            u = next((x for x in self.undo if x['Id'] == uid), None)
        if not u:
            return {'ok': False, 'message': 'That change can no longer be undone.'}
        with self.action_lock:
            r = X.FIXES_UNDO[u['fn']](**u['args'])
        if r.get('ok'):
            with self.lock:
                self.undo.remove(u)
                self.rev += 1
        self.log('UNDONE' if r.get('ok') else 'FAILED', f"{u['Label']}: {r.get('message')}")
        return {'ok': bool(r.get('ok')), 'message': r.get('message', '')}

    def do_unblock(self, kind, key):
        fn = {'port': X.unblock_port, 'ip': X.unblock_ip, 'program': X.unblock_process, 'site': X.unblock_site, 'restore': X.quarantine_restore, 'delete': X.quarantine_delete}.get(kind)
        if not fn:
            return {'ok': False, 'message': 'Bad request'}
        if not self.admin and kind in ('port', 'ip', 'program', 'site'):
            return {'ok': False, 'message': 'This needs Administrator rights. Start My Security as Administrator.'}
        with self.action_lock:
            r = fn(str(key))
        self.log(kind.upper() if r.get('ok') else 'FAILED', f"{key}: {r.get('message')}")
        self.refresh_blocks()
        if kind == 'port' and r.get('ok'):
            self._rescan_port_views()
        return {'ok': bool(r.get('ok')), 'message': r.get('message', '')}

    def block_port_manual(self, port, proto):
        if not self.admin:
            return {'ok': False, 'message': 'Blocking ports needs Administrator rights. Start My Security as Administrator.'}
        r = X.block_port(int(port), str(proto))
        self.log('BLOCKED' if r.get('ok') else 'FAILED', f'Port {proto} {port}: {r.get("message")}')
        self.refresh_blocks()
        if r.get('ok'):
            self._rescan_port_views()
        return {'ok': bool(r.get('ok')), 'message': r.get('message', '')}

    def open_log(self):
        try:
            if not os.path.exists(self.activity_log):
                open(self.activity_log, 'a', encoding='utf-8').close()
            subprocess.Popen([os.path.join(WINDIR, 'explorer.exe'), self.activity_log], creationflags=S.CREATE_NO_WINDOW)
        except OSError as e:
            return {'ok': False, 'message': f"Couldn't open the activity log: {e}"}
        return {'ok': True, 'message': f'Opened the activity log: {self.activity_log}'}

    # ---- what the dashboard reads

    @staticmethod
    def _public(f):
        out = {k: v for k, v in f.items() if k != 'Action'}
        a = f.get('Action')
        out['Action'] = {'label': a['label'], 'confirm': a['confirm']} if a else None
        return out

    def plan(self):
        """Every problem, in the order to fix it: 'now' (critical, or high and already happening), 'week' (high), 'later' (medium)."""
        items = []
        for key, s in self.scans.items():
            for f in s['findings']:
                if SEV_RANK[f['Sev']] >= 2 and not f.get('Done'):
                    items.append({**self._public(f), 'From': s['label'], 'Scan': key})
        for f in self.tab_findings.values():
            if SEV_RANK[f['Sev']] >= 2 and not f.get('Done'):
                items.append({**self._public(f), 'From': 'Open browser tabs', 'Scan': '_tabs'})
        for e in self.events:
            if e['Running'] and SEV_RANK[e['Sev']] >= 2 and not e['Existing'] or e['Running'] and SEV_RANK[e['Sev']] >= 3:
                items.append({'Id': f"event:{e['Id']}", 'EventId': e['Id'], 'Cat': 'processes', 'Sev': e['Sev'], 'Title': f"{e['Name']}: {e['Reasons'][0]['Title']}", 'What': e['Reasons'][0]['Why'], 'Risk': '', 'Evidence': e['Cmd'] or e['Path'], 'Fix': 'End it if you did not start it.', 'Action': None, 'From': 'Running programs', 'Scan': '_running', 'Active': e['Sev'] == 'critical'})
        for it in items:
            it['Bucket'] = 'now' if it['Sev'] == 'critical' or (it['Sev'] == 'high' and it.get('Active')) else 'week' if it['Sev'] == 'high' else 'later'
        items.sort(key=lambda x: (-SEV_RANK[x['Sev']], not x.get('Active'), x['Title']))
        return items

    def payload(self):
        with self.lock:
            plan = self.plan()
            counts = {s: sum(1 for x in plan if x['Sev'] == s) for s in ('critical', 'high', 'medium')}
            low = sum(1 for s in self.scans.values() for f in s['findings'] if f['Sev'] == 'low' and not f.get('Done'))
            ran = sum(1 for s in self.scans.values() if s['status'] in ('done', 'error'))
            # critical and high items count in full; a long tail of small items can't sink the score by itself
            score = max(0, round(100 - counts['critical'] * 18 - counts['high'] * 6 - min(20, counts['medium'] * 1.5) - min(5, low * 0.25))) if ran else None
            return {'generated': dt.datetime.now().astimezone().isoformat(), 'rev': self.rev, 'host': socket.gethostname(), 'admin': self.admin, 'version': APP_VERSION,
                    'scans': {k: {**{x: s[x] for x in ('label', 'status', 'at', 'secs')}, 'findings': [self._public(f) for f in s['findings']]} for k, s in self.scans.items()},
                    'job': {k: self.job[k] for k in ('kind', 'current', 'done', 'total', 'started')} if self.job else None,
                    'autopilotAt': self.autopilot_at, 'plan': plan, 'counts': {**counts, 'low': low}, 'score': score, 'ran': ran,
                    'events': self.events, 'watching': self.watch_started, 'guard': self.guard_on, 'tabs': self.tabs, 'tabAt': self.tab_at, 'alerts': self.alerts[:20],
                    'tabFindings': {k: self._public(v) for k, v in self.tab_findings.items()}, 'blocks': self.blocks, 'quarantineDir': X.QUARANTINE, 'notice': self.notice if self.notice and time.time() - self.notice['At'] < 300 else None, 'attempts': self.attempts,
                    'undo': [{k: u[k] for k in ('Id', 'Label', 'What')} for u in self.undo]}


# ---------------------------------------------------------------- local dashboard server (same rules as My Connections)

CSP = "default-src 'none'; script-src 'nonce-{}'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
EXPIRED_PAGE = b'<!doctype html><meta charset=utf-8><title>my_security</title><body style="font:16px sans-serif;padding:40px">This dashboard address has expired or is incomplete. Start My Security again to open it.'
SITE_ORIGINS = ('https://nesiam.com', 'https://www.nesiam.com', 'https://jaykaluza.github.io')


def make_handler(app, page_bytes, token, port, launch_key, nonce):
    csp = CSP.format(nonce)
    page_path = f'/?k={launch_key}'.encode()
    local_origins = (f'http://localhost:{port}', f'http://127.0.0.1:{port}')

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'MySecurity'
        sys_version = ''

        def log_message(self, *args):
            pass

        def send(self, status, ctype, body, extra=None):
            self.send_response(status)
            for k, v in {'Content-Type': ctype, 'Content-Length': str(len(body)), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': csp, 'Referrer-Policy': 'no-referrer', **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status, obj, extra=None):
            self.send(status, 'application/json; charset=utf-8', json.dumps(obj).encode('utf-8'), extra)

        def body_json(self):
            try:
                n = int(self.headers.get('Content-Length', 0))
            except ValueError:
                n = 0
            return json.loads(self.rfile.read(max(0, min(n, 10000))) or b'{}')

        def host_ok(self):
            return self.headers.get('Host') in (f'localhost:{port}', f'127.0.0.1:{port}')

        def token_ok(self):
            origin = self.headers.get('Origin')
            return secrets.compare_digest(self.headers.get('X-MySec-Token', '').encode('utf-8', 'replace'), token.encode()) and (not origin or origin in local_origins)

        def site_origin(self):
            origin = self.headers.get('Origin')
            return origin if origin in SITE_ORIGINS else None

        def do_OPTIONS(self):
            origin = self.site_origin()
            if not self.host_ok() or not origin or self.path not in ('/status', '/site-stop'):
                return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
            self.send(204, 'text/plain', b'', {'Access-Control-Allow-Origin': origin, 'Vary': 'Origin', 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Private-Network': 'true', 'Access-Control-Max-Age': '600'})

        def do_GET(self):
            if not self.host_ok():
                return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
            if self.path == '/' or self.path.startswith('/?'):
                if secrets.compare_digest(self.path.encode('utf-8', 'replace'), page_path):
                    return self.send(200, 'text/html; charset=utf-8', page_bytes)
                return self.send(403, 'text/html; charset=utf-8', EXPIRED_PAGE)
            if self.path == '/status':
                origin = self.site_origin()
                if not origin:
                    return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
                return self.send_json(200, {'app': 'MySecurity', 'version': APP_VERSION, 'stopping': app.stopping}, {'Access-Control-Allow-Origin': origin, 'Vary': 'Origin'})
            if not self.token_ok():
                return self.send_json(403, {'ok': False, 'message': 'Not allowed. Reload the dashboard.'})
            if self.path.startswith('/data'):
                app.last_client = time.time()
                if app.stopping:
                    return self.send_json(200, {'stopping': True})
                m = re.search(r'[?&]rev=(\d+)', self.path)
                if m and int(m.group(1)) == app.rev:
                    return self.send_json(200, {'same': True, 'generated': dt.datetime.now().astimezone().isoformat()})
                return self.send_json(200, app.payload())
            self.send_json(404, {'ok': False, 'message': 'Not found'})

        def do_POST(self):
            if self.path == '/tab-closed':
                n = int(self.headers.get('Content-Length', 0) or 0)
                origin = self.headers.get('Origin')
                if self.host_ok() and secrets.compare_digest(self.rfile.read(min(n, 200)), token.encode()) and (not origin or origin in local_origins):
                    app.tab_closed_at = time.time()
                    return self.send(204, 'text/plain', b'')
                return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
            if self.path == '/site-stop':
                origin = self.site_origin()
                if not self.host_ok() or not origin:
                    return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
                app.stopping = True
                threading.Timer(5, app.stop.set).start()
                return self.send_json(200, {'ok': True, 'message': 'The app is stopping.'}, {'Access-Control-Allow-Origin': origin, 'Vary': 'Origin'})
            if not self.host_ok() or not self.token_ok():
                return self.send_json(403, {'ok': False, 'message': 'Not allowed. Reload the dashboard.'})
            try:
                b = self.body_json()
                if self.path == '/autopilot':
                    r = app.start_scans({k for k, _l, _f in S.SCANS}, 'autopilot')
                elif self.path == '/scan':
                    r = app.start_scans(set(str(x) for x in b['keys']), 'scan')
                elif self.path == '/action':
                    r = app.do_action(str(b['id']))
                elif self.path == '/undo':
                    r = app.do_undo(str(b['id']))
                elif self.path == '/kill':
                    r = app.kill_event(int(b['id']))
                elif self.path == '/block-process':
                    r = app.block_event(int(b['id']))
                elif self.path == '/block-port':
                    r = app.block_port_manual(int(b['port']), str(b['proto']))
                elif self.path == '/unblock':
                    r = app.do_unblock(str(b['kind']), str(b['key']))
                elif self.path == '/recording':
                    r = app.set_recording(bool(b['on']))
                elif self.path == '/guard':
                    app.guard_on = bool(b['on'])
                    app.bump()
                    r = {'ok': True, 'message': 'Browser guard is on.' if app.guard_on else 'Browser guard is off.'}
                elif self.path == '/openlog':
                    r = app.open_log()
                elif self.path == '/quit':
                    self.send_json(200, {'ok': True, 'message': 'The app has stopped.'})
                    app.stop.set()
                    return None
                else:
                    return self.send_json(404, {'ok': False, 'message': 'Not found'})
            except (ValueError, KeyError, TypeError):
                return self.send_json(400, {'ok': False, 'message': 'Bad request'})
            return self.send_json(200, r)

    return Handler


class LocalServer(http.server.ThreadingHTTPServer):
    """Refuses a port another program holds. Python's default on Windows would share it, and requests would reach the wrong app."""
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def start_server(app, port):
    with open(os.path.join(RESOURCES, 'dashboard.html'), encoding='utf-8') as f:
        page = f.read()
    token, launch_key, nonce = secrets.token_hex(32), secrets.token_urlsafe(24), secrets.token_urlsafe(18)
    page_bytes = page.replace('__MYSEC_TOKEN__', token).replace('<script>', f'<script nonce="{nonce}">').encode('utf-8')
    for p in range(port, port + 3):
        try:
            server = LocalServer(('127.0.0.1', p), make_handler(app, page_bytes, token, p, launch_key, nonce))
        except OSError:
            continue
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, p, launch_key
    sys.exit(f"Couldn't open a local port for the dashboard (tried {port} to {port + 2}).")


# ---------------------------------------------------------------- start-up

S.kernel32.CreateMutexW.restype = wt.HANDLE
S.kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.LPCWSTR]
ERROR_ALREADY_EXISTS = 183
_mutex = None
LINK_SCHEME = 'mysecurity'
LINK_PATTERN = re.compile(r'^mysecurity:(//)?(run|unregister)?/?$', re.I)
OPEN_PAGE = os.path.join(APP_DIR, 'open-dashboard.html')
DASHBOARD_URL = re.compile(r'^http://localhost:\d{1,5}/\?k=[\w-]{20,}$')


def another_copy_running():
    global _mutex
    _mutex = S.kernel32.CreateMutexW(None, False, 'Local\\MySecurity')
    return ctypes.get_last_error() == ERROR_ALREADY_EXISTS


def is_redirected(path):
    try:
        return os.lstat(path).st_reparse_tag in (0xA0000003, 0xA000000C)
    except OSError:
        return False


def link_target():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf'Software\Classes\{LINK_SCHEME}\shell\open\command') as k:
            m = re.match(r'^"([^"]+)"', winreg.QueryValueEx(k, '')[0])
            return m.group(1) if m else ''
    except OSError:
        return ''


def register_link(exe):
    base = rf'Software\Classes\{LINK_SCHEME}'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'URL:{APP_NAME}')
        winreg.SetValueEx(k, 'URL Protocol', 0, winreg.REG_SZ, '')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r'\DefaultIcon') as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'"{exe}",0')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r'\shell\open\command') as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'"{exe}" "%1"')


def unregister_link():
    base = rf'Software\Classes\{LINK_SCHEME}'
    for sub in (r'\shell\open\command', r'\shell\open', r'\shell', r'\DefaultIcon', ''):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + sub)
        except OSError:
            pass


def open_dashboard(url):
    if not DASHBOARD_URL.match(url):
        return False
    if not S.is_admin():
        return webbrowser.open(url)
    try:   # through Explorer, so the browser runs as the signed-in user and not as Administrator
        with open(OPEN_PAGE, 'w', encoding='utf-8') as f:
            f.write(f'<!doctype html><meta charset=utf-8><meta http-equiv=refresh content="0;url={url}"><a href="{url}">Open the dashboard</a>')
        subprocess.Popen([os.path.join(WINDIR, 'explorer.exe'), OPEN_PAGE], creationflags=S.CREATE_NO_WINDOW)
        return True
    except OSError:
        return False


def show_error(message):
    user32.MessageBoxW(None, message, APP_NAME, 0x10)


def main():
    ap = argparse.ArgumentParser(description='Local security assessment for Windows.')
    ap.add_argument('--port', type=int, default=8775)
    ap.add_argument('--no-browser', action='store_true')
    ap.add_argument('--app', action='store_true', default=FROZEN, help='one copy only; stops when the dashboard is closed')
    ap.add_argument('--idle-exit', type=int, default=5, help='app mode: minutes without an open dashboard before stopping')
    ap.add_argument('--once', metavar='FILE', help='run every scan once, write the results as JSON to FILE and exit')
    ap.add_argument('link', nargs='?', help=argparse.SUPPRESS)
    args = ap.parse_args()
    exe = sys.executable if FROZEN else os.path.abspath(__file__)
    if args.link and not LINK_PATTERN.match(args.link):
        sys.exit('The app was started from an unsupported link.')
    if args.link and (LINK_PATTERN.match(args.link).group(2) or '').lower() == 'unregister':
        unregister_link()
        if FROZEN:
            user32.MessageBoxW(None, f'The RUN button link was removed. Running {EXE_NAME} again sets it up again.', APP_NAME, 0x40)
        return
    if FROZEN and args.app and (not link_target() or not os.path.isfile(link_target())):
        try:
            register_link(exe)
        except OSError:
            pass
    os.makedirs(APP_DIR, exist_ok=True)
    if S.is_admin() and is_redirected(APP_DIR):
        sys.exit(f"The app's folder ({APP_DIR}) points somewhere else, so it won't write there with Administrator rights. Delete that folder and start the app again.")
    url_file = os.path.join(APP_DIR, 'running.url')
    if args.app and not args.once and another_copy_running():
        try:
            with open(url_file, encoding='utf-8') as f:
                if not open_dashboard(f.read().strip()):
                    show_error('The saved dashboard address is not valid. Stop the app and start it again.')
        except OSError:
            show_error('The app is already running, but its dashboard address could not be found. Wait a minute and try again.')
        return

    app = App(args)
    if args.once:
        app.start_scans({k for k, _l, _f in S.SCANS}, 'autopilot')
        while app.job:
            time.sleep(0.5)
        with open(args.once, 'w', encoding='utf-8') as f:
            json.dump(app.payload(), f, indent=1)
        print(f'Wrote {args.once}')
        return

    threading.Thread(target=app.watch_loop, daemon=True).start()
    threading.Thread(target=app.privilege_loop, daemon=True).start()
    threading.Thread(target=D.memory_sampler, args=(app.stop,), daemon=True).start()
    threading.Thread(target=app.guard_loop, daemon=True).start()
    threading.Thread(target=app.refresh_blocks, daemon=True).start()
    threading.Thread(target=app.attempts_loop, daemon=True).start()
    server, port, launch_key = start_server(app, args.port)
    url = f'http://localhost:{port}/?k={launch_key}'
    app.url = url
    if args.app:
        with open(url_file, 'w', encoding='utf-8') as f:
            f.write(url)
    print(f'{APP_NAME} is running. Dashboard: {url}')
    if not args.no_browser:
        open_dashboard(url)
        app.last_client = time.time()
    try:
        while not app.stop.is_set():
            closed = app.tab_closed_at
            if args.app and closed > app.last_client and time.time() - closed > 6 and not app.action_lock.locked():   # a fix that closes the browsers closes this tab too
                break
            if args.app and time.time() - app.last_client > args.idle_exit * 60 and not app.job:
                break
            app.stop.wait(1)
    except KeyboardInterrupt:
        pass
    finally:
        app.stop.set()
        server.shutdown()
        if args.app:
            for leftover in (url_file, OPEN_PAGE):
                try:
                    os.remove(leftover)
                except OSError:
                    pass
    if args.app:
        os._exit(0)


if __name__ == '__main__':
    try:
        main()
    except SystemExit as e:
        if FROZEN and isinstance(e.code, str):
            show_error(e.code)
        raise
    except Exception:
        if not FROZEN:
            raise
        os.makedirs(APP_DIR, exist_ok=True)
        with open(os.path.join(APP_DIR, 'error.log'), 'a', encoding='utf-8') as f:
            f.write(f'{dt.datetime.now().isoformat()}\n{traceback.format_exc()}\n')
        show_error(f"The app stopped because of an unexpected error. Details were saved to {os.path.join(APP_DIR, 'error.log')}")
