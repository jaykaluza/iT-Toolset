"""
My Connections (viewing-only first version)

Live macOS connection dashboard: maps every network connection to the app that owns it,
flags internet peers and risky items, lists listening ports, and serves it all on
http://localhost. It only reads: it never blocks, closes or changes anything.

Uses only the Python standard library and tools built into macOS (lsof, ps, netstat, codesign).

Run:  sudo python3 MyConnections.py
      (without sudo it works, but macOS only shows your own apps)
Try the page with made-up data on any computer:  python3 MyConnections.py --demo
"""

import argparse
import concurrent.futures
import csv
import datetime as dt
import http.server
import ipaddress
import json
import os
import plistlib
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import webbrowser

APP_NAME = "My Connections"
APP_VERSION = '0.1'
HERE = os.path.dirname(os.path.abspath(__file__))

# full paths, so a program named "ps" earlier in PATH can't run with this app's rights
LSOF, PS, NETSTAT, CODESIGN = '/usr/sbin/lsof', '/bin/ps', '/usr/sbin/netstat', '/usr/bin/codesign'

TCP_STATES = {'ESTABLISHED': 'Established', 'LISTEN': 'Listen', 'CLOSE_WAIT': 'CloseWait', 'SYN_SENT': 'SynSent',
              'SYN_RCVD': 'SynReceived', 'SYN_RECEIVED': 'SynReceived', 'FIN_WAIT_1': 'FinWait1', 'FIN_WAIT_2': 'FinWait2',
              'LAST_ACK': 'LastAck', 'CLOSING': 'Closing', 'TIME_WAIT': 'TimeWait', 'CLOSED': 'Closed', 'BOUND': 'Bound'}
SKIP_STATES = {'Listen', 'Bound', 'TimeWait', 'Closed'}

SCRIPT_HOSTS = {'osascript', 'curl', 'wget', 'nc', 'ncat', 'socat', 'bash', 'sh', 'zsh', 'perl', 'ruby', 'php', 'python', 'python3'}
LOOKALIKE_NAMES = {'launchd', 'kernel_task', 'mdnsresponder', 'syslogd', 'cfprefsd', 'trustd', 'securityd', 'configd',
                   'distnoted', 'coreaudiod', 'windowserver', 'sshd', 'apsd', 'nsurlsessiond', 'rapportd', 'sharingd'}
BAD_PORTS = {4444: 'the default port of the Metasploit hacking tool', 1337: 'a classic backdoor port',
             31337: 'a classic backdoor port', 12345: 'the NetBus trojan port', 6666: 'IRC, used by botnets',
             6667: 'IRC, used by botnets', 6697: 'IRC, used by botnets', 9001: 'the Tor network',
             9030: 'the Tor network', 9050: 'the Tor network'}
SHARING = 'System Settings > General > Sharing'
EXPOSED_PORT_RISK = {
    3389: ('high', "A Remote Desktop server is listening. Fix: if you didn't install remote-control software on purpose, remove it from the Applications folder."),
    5900: ('high', f"Screen Sharing or a VNC remote-control server is listening, so others on your network can try to view and control this Mac. Fix (if you don't use it): {SHARING} > turn off Screen Sharing and Remote Management."),
    23: ('high', "A Telnet server is listening (unencrypted remote login). Fix: remove the app that opened it."),
    21: ('medium', "An FTP server is listening (passwords travel unencrypted). Fix: stop or remove the FTP app if you don't need it."),
    22: ('medium', f"Remote Login (SSH) is on, so others on your network can try to log in. Fix (if you didn't set this up): {SHARING} > turn off Remote Login."),
    445: ('medium', f"File Sharing is on, so others on your network can try to reach your shared folders. Fix (if you don't use it): {SHARING} > turn off File Sharing."),
}
UNUSUAL_FOLDER = re.compile(r'^(/tmp/|/private/tmp/|/var/tmp/|/private/var/tmp/|/Users/Shared/)|/Downloads/|/\.Trash/', re.I)
SYSTEM_FOLDER = re.compile(r'^/(System|usr|bin|sbin|Library/Apple)/')
APP_BUNDLE = re.compile(r'^(.*?\.app)/Contents/')


# ---------------------------------------------------------------- reading what macOS reports

def run_tool(args, timeout=20):
    """A tool's output as text ('' if it can't run). lsof exits with 1 when it merely found nothing, so the exit code is ignored."""
    try:
        return subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=timeout, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def read_lsof():
    return run_tool([LSOF, '-nP', '-i', '-FpPtnT'])


def read_ps():
    return run_tool([PS, '-axww', '-o', 'pid=,comm='])


def read_netstat():
    return run_tool([NETSTAT, '-ib'])


def parse_endpoint(text, family='IPv4'):
    """'10.0.0.2:5000', '[::1]:631' or '*:5353' as (address, port); port 0 means any."""
    addr, _, port = text.rpartition(':')
    if addr.startswith('['):
        addr = addr[1:].rstrip(']')
    addr = addr.split('%')[0]
    if addr == '*':
        addr = '::' if family == 'IPv6' else '0.0.0.0'
    return addr, int(port) if port.isdigit() else 0


def parse_lsof(text):
    """lsof field output as (tcp rows, unconnected udp rows, connected udp rows).
    tcp: (state, local address, local port, remote address, remote port, pid); udp: (local address, local port, pid);
    connected udp: (local address, local port, remote address, remote port, pid)."""
    tcp, udp, udp_conn = set(), set(), set()
    pid, cur = None, {}

    def flush():
        name, proto = cur.get('n'), cur.get('P')
        if pid is None or not name or proto not in ('TCP', 'UDP'):
            return
        family = cur.get('t', 'IPv4')
        name = name.split(' (')[0]
        local, arrow, remote = name.partition('->')
        la, lp = parse_endpoint(local, family)
        if arrow:
            ra, rp = parse_endpoint(remote, family)
        if proto == 'UDP':
            if arrow:
                udp_conn.add((la, lp, ra, rp, pid))
            else:
                udp.add((la, lp, pid))
            return
        state = TCP_STATES.get(cur.get('state', ''), '')
        if not state:
            state = 'Established' if arrow else 'Bound'
        tcp.add((state, la, lp, ra if arrow else '0.0.0.0', rp if arrow else 0, pid))

    for line in text.splitlines():
        if not line:
            continue
        field, value = line[0], line[1:]
        if field in 'pf':
            flush()
            cur = {}
            if field == 'p':
                pid = int(value) if value.isdigit() else None
        elif field == 'T':
            if value.startswith('ST='):
                cur['state'] = value[3:]
        elif field in 'Ptn':
            cur[field] = value
    flush()
    return sorted(tcp), sorted(udp), sorted(udp_conn)


def parse_ps(text):
    """ps output as {pid: (name, path)}; path is '' for parts of the system with no program file."""
    out = {}
    for line in text.splitlines():
        m = re.match(r'\s*(\d+)\s+(.+)$', line)
        if not m:
            continue
        comm = m.group(2).strip()
        path = comm if comm.startswith('/') else ''
        name = (os.path.basename(comm) if path else comm.strip('()')) or comm
        out[int(m.group(1))] = (name, path)
    return out


def parse_netstat(text):
    """netstat -ib as {network adapter: (bytes in, bytes out)}. Only real adapters (en0...), so VPN traffic isn't counted twice."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 9 and re.fullmatch(r'en\d+\*?', parts[0]) and parts[2].startswith('<Link#'):
            try:
                out[parts[0]] = (int(parts[-5]), int(parts[-2]))
            except ValueError:
                pass
    return out


def is_external(ip):
    try:
        addr = ipaddress.ip_address(ip.split('%')[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def app_bundle_name(path):
    """The app a program file belongs to ('Google Chrome' for its helpers), from the outermost .app folder."""
    m = APP_BUNDLE.match(path or '')
    if not m:
        return ''
    try:
        with open(os.path.join(m.group(1), 'Contents', 'Info.plist'), 'rb') as f:
            plist = plistlib.load(f)
        name = plist.get('CFBundleDisplayName') or plist.get('CFBundleName')
        if isinstance(name, str) and name.strip():
            return name.strip()
    except (OSError, ValueError, plistlib.InvalidFileException):
        pass
    return os.path.basename(m.group(1))[:-4]


def parse_codesign(details, verify_failed):
    """codesign's report as {'Status', 'Publisher', 'Kind'}. Kind: apple, appstore, developer or ''."""
    if 'not signed at all' in details:
        return {'Status': 'NotSigned', 'Publisher': '', 'Kind': ''}
    if 'Signature=adhoc' in details:
        return {'Status': 'AdHoc', 'Publisher': '', 'Kind': ''}
    m = re.search(r'^Authority=(.+)$', details, re.M)
    if not m:
        return {'Status': 'Unknown', 'Publisher': '', 'Kind': ''}
    authority = m.group(1).strip()
    if authority == 'Software Signing':
        result = {'Publisher': 'Apple', 'Kind': 'apple'}
    elif authority.startswith('Apple Mac OS Application Signing'):
        result = {'Publisher': 'Mac App Store', 'Kind': 'appstore'}
    else:
        publisher = re.sub(r'^(Developer ID Application|Apple Development|Apple Distribution):\s*', '', authority)
        result = {'Publisher': re.sub(r'\s*\([A-Z0-9]{10}\)$', '', publisher), 'Kind': 'developer'}
    result['Status'] = 'Invalid' if verify_failed else 'Valid'
    if verify_failed:
        result['Publisher'] = ''
    return result


def file_info(path):
    """Who signed a program file. Slow, so it runs in the background."""
    try:
        details = subprocess.run([CODESIGN, '-dv', '--verbose=2', path], capture_output=True, text=True, errors='replace', timeout=30, check=False).stderr
        verify = subprocess.run([CODESIGN, '--verify', path], capture_output=True, text=True, errors='replace', timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return {'Status': 'Unknown', 'Publisher': '', 'Kind': ''}
    return parse_codesign(details, verify.returncode != 0)


# ---------------------------------------------------------------- risk

def issue(level, text):
    return {'Level': level, 'Text': text}


def app_issues(info):
    issues = []
    p, name, sig = info['Path'], info['Name'], info['Signature']
    if p:
        if UNUSUAL_FOLDER.search(p):
            issues.append(issue('high', f"Runs from an unusual folder ({p}). Installed apps normally live in Applications. Fix: if you don't recognise '{name}', quit it in Activity Monitor and delete the file."))
        if name.lower() in LOOKALIKE_NAMES and not SYSTEM_FOLDER.match(p):
            issues.append(issue('high', f"Uses the name of a macOS system program ({name}) but runs from outside the system folders ({p}). This is a common malware disguise. Fix: quit it in Activity Monitor and scan the Mac with your security software."))
        if sig == 'Invalid':
            issues.append(issue('medium', f"The file's signature doesn't check out. This can happen just after an app updates itself, but it can also mean it was tampered with. Fix: restart '{name}'; if this stays, reinstall it from its official website."))
        elif sig in ('NotSigned', 'AdHoc'):
            issues.append(issue('medium', f"Not signed by a known developer. Not always bad (small developer tools and Homebrew programs often aren't), but it means the publisher can't be verified. Fix: if you don't recognise '{name}', look it up and remove it."))
    if name.lower() in SCRIPT_HOSTS:
        issues.append(issue('medium', f"A scripting or command-line tool ({name}) is using the network. That's fine if you or a trusted tool just ran it; attackers also abuse these. Fix: in Activity Monitor, double-click it and open Sample or Open Files and Ports to see what it's doing. Quit it if you didn't start it."))
    return issues


def risk_level(issues):
    if any(i['Level'] == 'high' for i in issues):
        return 'high'
    return 'medium' if issues else ''


def origin_of(info, fi):
    """macos / appstore / thirdparty / unsigned / unknown, from the file's signature."""
    if not info['Path']:
        return 'macos' if info['Name'] == 'kernel_task' else 'unknown'
    kind = fi.get('Kind')
    if fi.get('Status') in ('NotSigned', 'AdHoc', 'Invalid'):
        return 'unsigned'
    return {'apple': 'macos', 'appstore': 'appstore', 'developer': 'thirdparty'}.get(kind, 'unknown')


# ---------------------------------------------------------------- logs

def csv_safe(value):
    """Prefix text a spreadsheet would run as a formula; remote hostnames come from reverse DNS, which the remote server's owner controls."""
    if isinstance(value, str) and value[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value


def real_user():
    """(home folder, uid, gid) of the person who started the app, even under sudo. uid is None when there's nothing to hand back."""
    uid = os.environ.get('SUDO_UID')
    if uid and uid.isdigit():
        import pwd
        entry = pwd.getpwuid(int(uid))
        return entry.pw_dir, entry.pw_uid, entry.pw_gid
    return os.path.expanduser('~'), None, None


def hand_back(path, uid, gid):
    """Files made under sudo would otherwise belong to root, in the person's own home folder."""
    if uid is not None:
        try:
            os.chown(path, uid, gid)
        except OSError:
            pass


def append_csv(path, fields, rows, owner=(None, None)):
    new = not os.path.exists(path)
    try:
        with open(path, 'a', newline='', encoding='utf-8-sig' if new else 'utf-8') as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            if new:
                w.writeheader()
            for r in rows:
                w.writerow({k: csv_safe(r.get(k, '')) for k in fields})
    except OSError:
        return
    if new:
        hand_back(path, *owner)


# ---------------------------------------------------------------- monitor

class Monitor:
    def __init__(self, args, sources=None):
        self.args = args
        self.sources = sources or {'lsof': read_lsof, 'ps': read_ps, 'netstat': read_netstat, 'file_info': file_info, 'bundle': app_bundle_name}
        self.static_dns = getattr(args, 'static_dns', None)
        self.admin = bool(getattr(args, 'force_admin', False)) or (hasattr(os, 'geteuid') and os.geteuid() == 0)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.conns, self.proc_cache, self.file_cache, self.dns_names, self.rdns = {}, {}, {}, {}, {}
        self.sig_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        self.sig_pending = {}
        self.rdns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.prev_counters, self.prev_time = None, 0.0
        self.latest_json = '{}'
        self.owner = (None, None)
        self.csv_dir = ''
        if args.outdir:
            self.csv_dir = args.outdir
        elif not getattr(args, 'demo', False):
            home, uid, gid = real_user()
            self.owner = (uid, gid)
            self.csv_dir = os.path.join(home, 'Library', 'Application Support', 'MyConnections')
        if self.csv_dir:
            os.makedirs(self.csv_dir, exist_ok=True)
            hand_back(self.csv_dir, *self.owner)

    def host_for(self, ip, external):
        if self.static_dns is not None:
            return self.static_dns.get(ip, '')
        if ip in self.dns_names:
            return self.dns_names[ip]
        fut = self.rdns.get(ip)
        if fut is None:
            if external:
                self.rdns[ip] = self.rdns_pool.submit(socket.gethostbyaddr, ip)
            return ''
        if fut.done():
            try:
                self.dns_names[ip] = fut.result()[0]
            except OSError:
                self.dns_names[ip] = ''
            return self.dns_names[ip]
        return ''

    def ensure_proc_infos(self, pids, procs):
        for pid in pids:
            name, path = procs.get(pid, (f'PID {pid}', ''))
            cached = self.proc_cache.get(pid)
            if cached and cached['Name'] == name and cached['Path'] == path:   # PIDs get reused
                continue
            self.proc_cache[pid] = {'Name': name, 'Path': path, 'Description': self.sources['bundle'](path), 'Signature': '', 'Publisher': '', 'Origin': ''}
            if self.proc_cache[pid]['Description'] == name:
                self.proc_cache[pid]['Description'] = ''
        for path, fut in list(self.sig_pending.items()):
            if fut.done():
                try:
                    self.file_cache[path] = fut.result()
                except Exception:   # a check that fails must never stop the monitor
                    self.file_cache[path] = {'Status': 'Unknown', 'Publisher': '', 'Kind': ''}
                del self.sig_pending[path]
        for info in self.proc_cache.values():
            path = info['Path']
            if path and path not in self.file_cache and path not in self.sig_pending:
                self.sig_pending[path] = self.sig_pool.submit(self.sources['file_info'], path)
            fi = self.file_cache.get(path)
            if fi:
                info.update(Signature=fi['Status'], Publisher=fi['Publisher'], Origin=origin_of(info, fi))
            else:
                info['Origin'] = 'checking' if path else origin_of(info, {})

    def poll(self):
        with self.lock:
            self._poll()

    def _poll(self):
        now = dt.datetime.now().astimezone()
        stamp = now.isoformat()
        procs = parse_ps(self.sources['ps']())
        tcp, udp, udp_conn = parse_lsof(self.sources['lsof']())
        self.proc_cache = {p: i for p, i in self.proc_cache.items() if p in procs}
        self.ensure_proc_infos({r[5] for r in tcp} | {r[2] for r in udp} | {r[4] for r in udp_conn}, procs)
        listen_ports = {r[2] for r in tcp if r[0] == 'Listen'}

        rows = [('TCP', st, la, lp, ra, rp, pid) for (st, la, lp, ra, rp, pid) in tcp]
        rows += [('UDP', 'Active', la, lp, ra, rp, pid) for (la, lp, ra, rp, pid) in udp_conn]   # such as QUIC web traffic
        seen, new_rows = set(), []
        for proto, state, laddr, lport, raddr, rport, pid in rows:
            if state in SKIP_STATES or raddr in ('0.0.0.0', '::'):
                continue
            key = f'{proto}|{laddr}|{lport}|{raddr}|{rport}|{pid}'
            seen.add(key)
            external = is_external(raddr)
            host = self.host_for(raddr, external)
            r = self.conns.get(key)
            if r:
                r.update(State=state, LastSeen=stamp, Closed=None)
                if host:
                    r['RemoteHost'] = host
                continue
            info = self.proc_cache[pid]
            direction = 'Inbound' if proto == 'TCP' and lport in listen_ports else 'Outbound'
            issues = []   # issues about this connection itself; the app's own issues are added below
            if external and direction == 'Inbound':
                issues.append(issue('high', f"A computer on the internet ({raddr}) is connected INTO '{info['Name']}'. Unexpected unless you run a server or game host. Fix: quit the app in Activity Monitor, then check System Settings > General > Sharing, and your router's port-forwarding settings."))
            if external and rport in BAD_PORTS:
                issues.append(issue('high', f"Talking to the internet on port {rport}, which is {BAD_PORTS[rport]}. Fix: unless you recognise this, quit '{info['Name']}' in Activity Monitor and scan the Mac with your security software."))
            if external and rport in (21, 23):
                issues.append(issue('medium', f'Uses an unencrypted login protocol (port {rport}), so passwords can be read in transit. Fix: use an SFTP or SSH client instead.'))
            r = {'Risk': '', 'Issues': [], 'Publisher': '', 'Direction': direction, 'External': external, 'App': info['Name'],
                 'Description': '', 'Services': '', 'Path': '', 'PID': pid, 'Protocol': proto, 'LocalAddress': laddr, 'LocalPort': lport,
                 'RemoteAddress': raddr, 'RemotePort': rport, 'RemoteHost': host, 'State': state, 'FirstSeen': stamp, 'LastSeen': stamp,
                 'Closed': None, '_conn_issues': issues}
            self.conns[key] = r
            new_rows.append(r)

        # keep each open connection's app details and risk current (signature checks finish in the background)
        for r in self.conns.values():
            info = self.proc_cache.get(r['PID'])
            if info and not r['Closed'] and info['Name'] == r['App']:
                r['Issues'] = app_issues(info) + r['_conn_issues']
                r.update(Risk=risk_level(r['Issues']), Publisher=info['Publisher'], Description=info['Description'], Path=info['Path'])

        for key, r in list(self.conns.items()):   # mark vanished connections closed, prune old ones
            if key in seen:
                continue
            if not r['Closed']:
                r['Closed'] = stamp
            elif (now - dt.datetime.fromisoformat(r['Closed'])).total_seconds() >= self.args.closed_retention * 60:
                del self.conns[key]

        if new_rows and self.csv_dir:
            path = os.path.join(self.csv_dir, f'connections-{now:%Y%m%d}.csv')
            append_csv(path, ['Time', 'Risk', 'Direction', 'External', 'App', 'PID', 'Path', 'Protocol', 'LocalAddress', 'LocalPort',
                              'RemoteAddress', 'RemotePort', 'RemoteHost', 'Issues'],
                       [dict(r, Time=r['FirstSeen'], Issues=' | '.join(i['Text'] for i in r['Issues'])) for r in new_rows], self.owner)

        listeners = []
        sockets = [('TCP', r[1], r[2], r[5]) for r in tcp if r[0] == 'Listen'] + [('UDP', la, lp, pid) for (la, lp, pid) in udp]
        for proto, addr, port, pid in sockets:
            info = self.proc_cache[pid]
            loopback = addr.startswith('127.') or addr == '::1'
            issues = []
            if not loopback:
                issues += app_issues(info)
                if proto == 'TCP' and port in EXPOSED_PORT_RISK:
                    issues.append(issue(*EXPOSED_PORT_RISK[port]))
            listeners.append({'Risk': risk_level(issues), 'Issues': issues, 'Publisher': info['Publisher'], 'App': info['Name'],
                              'Description': info['Description'], 'Services': '', 'Path': info['Path'], 'PID': pid, 'Protocol': proto,
                              'LocalAddress': addr, 'LocalPort': port, 'Exposed': not loopback})

        rx_rate = tx_rate = None
        counters, t = parse_netstat(self.sources['netstat']()), time.time()
        if counters and self.prev_counters and t > self.prev_time:
            secs = t - self.prev_time
            common = [m for m in counters if m in self.prev_counters]
            rx_rate = sum(max(0, counters[m][0] - self.prev_counters[m][0]) for m in common) / secs
            tx_rate = sum(max(0, counters[m][1] - self.prev_counters[m][1]) for m in common) / secs
        self.prev_counters, self.prev_time = counters, t

        apps = {}
        for info in self.proc_cache.values():
            if info['Name'] in apps and apps[info['Name']]['Path']:
                continue
            apps[info['Name']] = {k: info[k] for k in ('Origin', 'Path', 'Publisher', 'Signature', 'Description')}

        payload = {'generated': stamp, 'host': socket.gethostname(), 'admin': self.admin, 'interval': self.args.interval,
                   'rxRate': rx_rate, 'txRate': tx_rate, 'listeners': listeners, 'apps': apps,
                   'connections': [{k: v for k, v in r.items() if not k.startswith('_')} for r in self.conns.values()]}
        self.latest_json = json.dumps(payload, separators=(',', ':'))


# ---------------------------------------------------------------- local web server

CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"


def make_handler(monitor, page_bytes, token, port):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'MyConnections'
        sys_version = ''

        def log_message(self, *args):
            pass

        def send(self, status, ctype, body):
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', CSP)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status, obj):
            self.send(status, 'application/json; charset=utf-8', json.dumps(obj).encode('utf-8'))

        def host_ok(self):
            # only answer requests addressed to this dashboard (blocks DNS-rebinding tricks)
            return self.headers.get('Host') in (f'localhost:{port}', f'127.0.0.1:{port}')

        def token_ok(self):
            origin = self.headers.get('Origin')
            return (secrets.compare_digest(self.headers.get('X-NetMon-Token', ''), token)
                    and (not origin or origin in (f'http://localhost:{port}', f'http://127.0.0.1:{port}')))

        def do_GET(self):
            if not self.host_ok():
                return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
            if self.path == '/':
                return self.send(200, 'text/html; charset=utf-8', page_bytes)
            if not self.token_ok():
                return self.send_json(403, {'ok': False, 'message': 'Not allowed. Reload the dashboard.'})
            if self.path == '/data':
                return self.send(200, 'application/json; charset=utf-8', monitor.latest_json.encode('utf-8'))
            return self.send_json(404, {'ok': False, 'message': 'Not found'})

        def do_POST(self):
            if not self.host_ok() or not self.token_ok():
                return self.send_json(403, {'ok': False, 'message': 'Not allowed. Reload the dashboard.'})
            if self.path != '/quit':
                return self.send_json(404, {'ok': False, 'message': 'Not found'})
            self.send_json(200, {'ok': True, 'message': 'The app has stopped. You can close this tab.'})
            monitor.stop.set()
            return None

    return Handler


def start_server(monitor, port):
    with open(os.path.join(HERE, 'dashboard.html'), encoding='utf-8') as f:
        page = f.read()
    token = secrets.token_hex(32)
    page_bytes = page.replace('__NETMON_TOKEN__', token).encode('utf-8')
    for p in range(port, port + 21):
        try:
            server = http.server.ThreadingHTTPServer(('127.0.0.1', p), make_handler(monitor, page_bytes, token, p))
        except OSError:
            continue
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, p
    sys.exit(f'No free port between {port} and {port + 20}.')


def open_browser(url):
    """Under sudo, open the page as the person, not as root."""
    user = os.environ.get('SUDO_USER')
    if user and sys.platform == 'darwin':
        try:
            subprocess.run(['/usr/bin/sudo', '-u', user, '/usr/bin/open', url], check=False, timeout=15)
            return
        except (OSError, subprocess.SubprocessError):
            pass
    webbrowser.open(url)


# ---------------------------------------------------------------- made-up data for --demo and the tests

DEMO_PS = """\
    0 kernel_task
    1 /sbin/launchd
  212 /usr/sbin/mDNSResponder
  340 /System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter
  355 /usr/libexec/rapportd
  512 /System/Library/PrivateFrameworks/ApplePushService.framework/apsd
  640 /usr/sbin/sshd
  901 /Applications/Safari.app/Contents/MacOS/Safari
  902 /System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking
 1204 /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/120/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper
 1310 /Applications/Slack.app/Contents/MacOS/Slack
 1466 /Users/demo/Downloads/updater-tool
 1502 /usr/bin/curl
"""

DEMO_LSOF = """\
p212
f12
tIPv4
PUDP
n*:5353
f13
tIPv6
PUDP
n*:5353
p340
f9
tIPv4
PTCP
n*:5000
TST=LISTEN
TQR=0
TQS=0
f10
tIPv6
PTCP
n*:7000
TST=LISTEN
p512
f7
tIPv4
PTCP
n192.168.1.20:50112->17.57.146.68:5223
TST=ESTABLISHED
p640
f4
tIPv4
PTCP
n*:22
TST=LISTEN
p902
f22
tIPv4
PTCP
n192.168.1.20:50230->17.253.144.10:443
TST=ESTABLISHED
f23
tIPv6
PTCP
n[2600:1f18:24e6:b900::10]:50231->[2606:4700::6810:84e5]:443
TST=ESTABLISHED
p1204
f31
tIPv4
PTCP
n192.168.1.20:50301->142.250.72.14:443
TST=ESTABLISHED
f32
tIPv4
PUDP
n192.168.1.20:58911->142.250.72.14:443
f33
tIPv4
PTCP
n192.168.1.20:50302->151.101.1.140:443
TST=CLOSE_WAIT
p1310
f40
tIPv4
PTCP
n192.168.1.20:50410->3.211.45.20:443
TST=ESTABLISHED
f41
tIPv4
PTCP
n127.0.0.1:50411->127.0.0.1:50412
TST=ESTABLISHED
p1466
f5
tIPv4
PTCP
n192.168.1.20:50500->185.220.101.4:9001
TST=ESTABLISHED
p1502
f3
tIPv4
PTCP
n192.168.1.20:50600->140.82.114.4:443
TST=SYN_SENT
"""

DEMO_NETSTAT = """\
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                       2235061     0  901234567  2235061     0  901234567     0
en0        1500  <Link#6>    aa:bb:cc:dd:ee:ff  8123456     0 {rx}  6123456     0 {tx}     0
en0        1500  192.168.1     192.168.1.20      8123456     -  999999999  6123456     -  999999999     -
utun3      1380  <Link#20>                        12345     0    1234567    12345     0    1234567     0
"""

DEMO_DNS = {'17.57.146.68': 'courier.push.apple.com', '17.253.144.10': 'www.apple.com', '142.250.72.14': 'lax17s49-in-f14.1e100.net',
            '151.101.1.140': 'reddit.map.fastly.net', '3.211.45.20': 'ec2-3-211-45-20.compute-1.amazonaws.com'}
DEMO_SIGNERS = {'/Applications/Google Chrome.app': ('Valid', 'Google LLC', 'developer'), '/Applications/Slack.app': ('Valid', 'Slack Technologies', 'developer'),
                '/Users/demo/Downloads/': ('NotSigned', '', '')}


def demo_file_info(path):
    for start, (status, publisher, kind) in DEMO_SIGNERS.items():
        if path.startswith(start):
            return {'Status': status, 'Publisher': publisher, 'Kind': kind}
    return {'Status': 'Valid', 'Publisher': 'Apple', 'Kind': 'apple'}


def demo_sources():
    start = time.time()

    def netstat():
        secs = time.time() - start
        return DEMO_NETSTAT.format(rx=int(5_000_000_000 + secs * 180_000), tx=int(800_000_000 + secs * 24_000))

    def bundle(path):
        return {'Google Chrome Helper': 'Google Chrome', 'ControlCenter': 'Control Center'}.get(os.path.basename(path), '')

    return {'lsof': lambda: DEMO_LSOF, 'ps': lambda: DEMO_PS, 'netstat': netstat, 'file_info': demo_file_info, 'bundle': bundle}


# ---------------------------------------------------------------- start

def main():
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument('--interval', type=int, default=3, help='seconds between refreshes')
    ap.add_argument('--port', type=int, default=8765, help='local port for the dashboard (the next free one is used if taken)')
    ap.add_argument('--closed-retention', type=int, default=10, help='minutes closed connections stay visible')
    ap.add_argument('--outdir', help='where the daily connection logs go')
    ap.add_argument('--no-browser', action='store_true', help="don't open the browser automatically")
    ap.add_argument('--demo', action='store_true', help='show made-up data (works on any computer, reads nothing)')
    args = ap.parse_args()
    if sys.platform != 'darwin' and not args.demo:
        sys.exit('This app only runs on macOS (use --demo to see the page with made-up data).')
    args.interval = max(1, args.interval)
    sources = None
    if args.demo:
        args.static_dns, args.force_admin = DEMO_DNS, True
        sources = demo_sources()
    monitor = Monitor(args, sources)
    monitor.poll()
    server, port = start_server(monitor, args.port)
    url = f'http://localhost:{port}/'
    print(f"{APP_NAME} is running at {url}\nPress Ctrl+C here, or click Stop monitor on the page, to stop it.")
    if not monitor.admin:
        print('Only your own apps are shown. Start it with sudo to see every app.')
    if not args.no_browser:
        open_browser(url)
    try:
        while not monitor.stop.wait(args.interval):
            try:
                monitor.poll()
            except Exception as e:   # one bad reading must not stop the monitor
                print(f'Refresh failed: {e}', file=sys.stderr)
    except KeyboardInterrupt:
        pass
    server.shutdown()
    monitor.sig_pool.shutdown(wait=False)
    monitor.rdns_pool.shutdown(wait=False)
    print('Stopped.')


if __name__ == '__main__':
    main()
