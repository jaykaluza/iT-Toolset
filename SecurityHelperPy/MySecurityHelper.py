"""
My Security Helper: a small read-only helper for the website's Online scan.
It listens on this PC only (127.0.0.1), answers only the Nesiam website, changes nothing, and needs no Administrator rights.
It reads a few Windows facts (Defender, firewall, updates, risky listening ports) so the Online scan can show them next to the browser checks.
"""
import argparse
import ctypes
import http.server
import json
import os
import re
import subprocess
import sys
import threading
import time
import winreg

APP_NAME = 'My Security Helper'
APP_VERSION = '0.1.0'
EXE_NAME = 'MySecurityHelper.exe'
LINK_SCHEME = 'mysecurityhelper'
LINK_PATTERN = re.compile(r'^mysecurityhelper:(//)?(run|unregister)?/?$', re.I)
PORTS = (8781, 8782, 8783)
ALLOWED_ORIGINS = {'https://jaykaluza.github.io'}
FROZEN = getattr(sys, 'frozen', False)
if not FROZEN and os.environ.get('MYSEC_HELPER_ORIGIN'):   # testing only; the built exe ignores it
    ALLOWED_ORIGINS.add(os.environ['MYSEC_HELPER_ORIGIN'])
CREATE_NO_WINDOW = 0x08000000
IDLE_MINUTES = 10
RISKY_PORTS = {21: 'FTP (sends passwords in clear text)', 23: 'Telnet (sends passwords in clear text)', 135: 'Windows RPC', 139: 'NetBIOS file sharing', 445: 'Windows file sharing (SMB)',
               3389: 'Remote Desktop', 5900: 'VNC remote control', 5985: 'Windows remote management', 1433: 'SQL Server', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis'}
user32 = ctypes.windll.user32
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
last_request = time.time()


def run(args, timeout=60):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW, errors='replace')
        return r.stdout
    except (OSError, subprocess.SubprocessError):
        return ''


PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$mp = Get-MpComputerStatus
if ($mp) { $o.defender = [ordered]@{ service = [bool]$mp.AMServiceEnabled; realtime = [bool]$mp.RealTimeProtectionEnabled; signatures = $mp.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd') } }
$fw = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; on = ($_.Enabled -eq 'True' -or $_.Enabled -eq 1) } })
$o.firewall = $fw
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) { $o.lastUpdate = $hf.InstalledOn.ToString('yyyy-MM-dd') }
$g = Get-LocalUser -Name Guest
if ($g) { $o.guestEnabled = [bool]$g.Enabled }
$os = Get-CimInstance Win32_OperatingSystem
if ($os) { $o.os = $os.Caption + ' (build ' + $os.BuildNumber + ')' }
$o | ConvertTo-Json -Depth 4 -Compress
"""


def reg(path, name, root=winreg.HKEY_LOCAL_MACHINE):
    try:
        with winreg.OpenKey(root, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def listening():
    """Programs listening on the network (not only on this PC): [(port, program)]."""
    names = {}
    for line in run(['tasklist', '/fo', 'csv', '/nh'], 30).splitlines():
        m = re.match(r'^"([^"]+)","(\d+)"', line)
        if m:
            names[m.group(2)] = m.group(1)
    seen = {}
    for line in run(['netstat', '-ano', '-p', 'tcp'], 30).splitlines():
        p = line.split()
        if len(p) >= 5 and p[0] == 'TCP' and p[3] == 'LISTENING' and not re.match(r'^(127\.|\[::1\])', p[1]):
            port = int(p[1].rsplit(':', 1)[1])
            seen[port] = names.get(p[4], 'unknown')
    return sorted(seen.items())


def row(status, title, what, value):
    return {'status': status, 'title': title, 'what': what, 'value': value}


def days_ago(day):
    try:
        y, m, d = map(int, day.split('-'))
        return (time.time() - time.mktime((y, m, d, 0, 0, 0, 0, 0, -1))) / 86400
    except (ValueError, AttributeError):
        return None


def checks():
    out = []
    try:
        info = json.loads(run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', PS], 90) or '{}')
    except ValueError:
        info = {}
    d = info.get('defender')
    if d:
        age = days_ago(d.get('signatures'))
        ok = d.get('service') and d.get('realtime') and (age is None or age <= 7)
        out.append(row('ok' if ok else 'bad', 'Antivirus is on and up to date',
                       'Windows Defender (or another antivirus) should scan files as they are used, with threat definitions from the last week.',
                       ('Real-time protection ' + ('on' if d.get('realtime') else 'OFF')) + ', definitions from ' + str(d.get('signatures'))))
    else:
        out.append(row('info', 'Antivirus is on and up to date', 'Windows could not report Defender status. Another antivirus may be managing protection.', 'Not reported'))
    fw = info.get('firewall') or []
    if fw:
        off = [p['name'] for p in fw if not p.get('on')]
        out.append(row('bad' if off else 'ok', 'Windows Firewall is on', 'The firewall blocks unwanted connections from other devices to this PC. It should be on for every network type.',
                       ('Off for: ' + ', '.join(off)) if off else 'On for all network types'))
    up = info.get('lastUpdate')
    if up:
        age = days_ago(up)
        late = age is not None and age > 60
        out.append(row('warn' if late else 'ok', 'Windows updates are recent', 'Security updates fix holes attackers already use. Windows normally installs one at least every month.',
                       'Latest update installed ' + up + (' (over two months ago)' if late else '')))
    if info.get('guestEnabled') is not None:
        out.append(row('bad' if info['guestEnabled'] else 'ok', 'Guest account is off', 'An enabled Guest account lets anyone use the PC without a password.', 'On' if info['guestEnabled'] else 'Off'))
    uac = reg(r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA')
    if uac is not None:
        out.append(row('ok' if uac else 'bad', 'User Account Control is on', 'UAC asks before programs change the system, which stops many silent infections.', 'On' if uac else 'OFF'))
    rdp = reg(r'SYSTEM\CurrentControlSet\Control\Terminal Server', 'fDenyTSConnections')
    if rdp is not None:
        out.append(row('warn' if rdp == 0 else 'ok', 'Remote Desktop is off', 'Remote Desktop lets other computers sign in to this PC. Leave it off unless you use it.', 'On' if rdp == 0 else 'Off'))
    sb = reg(r'SYSTEM\CurrentControlSet\Control\SecureBoot\State', 'UEFISecureBootEnabled')
    if sb is not None:
        out.append(row('ok' if sb else 'warn', 'Secure Boot is on', 'Secure Boot stops tampered start-up software from loading before Windows.', 'On' if sb else 'Off'))
    auto = reg(r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'AutoAdminLogon')
    if auto == '1':
        out.append(row('warn', 'Windows asks for a password at start-up', 'Automatic sign-in means anyone who turns the PC on gets in.', 'Automatic sign-in is on'))
    ports = listening()
    risky = [(p, n) for p, n in ports if p in RISKY_PORTS]
    if risky:
        out.append(row('warn', 'Few services are open to the network', 'These services accept connections from other devices. Close the ones you do not use.',
                       '; '.join(f'{RISKY_PORTS[p]} on port {p} ({n})' for p, n in risky)))
    else:
        out.append(row('ok', 'Few services are open to the network', 'Programs listening for connections from other devices are targets for attackers.',
                       f'{len(ports)} listening, none of the commonly attacked ones'))
    return {'os': info.get('os', ''), 'rows': out}


def ok_origin(h):
    return h.headers.get('Origin') in ALLOWED_ORIGINS


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'MySecurityHelper'
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        global last_request
        last_request = time.time()
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        origin = self.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:   # only the Nesiam site may read answers
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Private-Network', 'true')
            self.send_header('Vary', 'Origin')
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self):
        return (self.headers.get('Host') or '').lower() in {f'localhost:{self.server.server_port}', f'127.0.0.1:{self.server.server_port}'}   # blocks DNS rebinding

    def do_OPTIONS(self):
        if not self._host_ok() or not ok_origin(self):
            return self._send(403, {'error': 'forbidden'})
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', self.headers['Origin'])
        self.send_header('Access-Control-Allow-Methods', 'GET, POST')
        self.send_header('Access-Control-Allow-Private-Network', 'true')
        self.send_header('Vary', 'Origin')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {'error': 'forbidden'})
        if self.path in ('/hello', '/status'):   # /status is what the website's launcher asks, as for every Nesiam tool
            return self._send(200, {'app': APP_NAME, 'name': APP_NAME, 'version': APP_VERSION, 'readOnly': True, 'stopping': False})
        if self.path == '/checks':
            return self._send(200, checks()) if ok_origin(self) else self._send(403, {'error': 'not allowed'})
        self._send(404, {'error': 'not found'})

    def do_POST(self):
        if self.path == '/quit' and self._host_ok() and ok_origin(self):
            self._send(200, {'ok': True})
            threading.Timer(0.3, lambda: os._exit(0)).start()
            return
        self._send(404, {'error': 'not found'})


def another_copy_running():
    global _mutex
    _mutex = kernel32.CreateMutexW(None, False, 'Local\\MySecurityHelper')
    return ctypes.get_last_error() == 183


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


def message(text, flags=0x40):
    user32.MessageBoxW(None, text, APP_NAME, flags)


def main():
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument('--port', type=int, default=0)
    ap.add_argument('--once', action='store_true', help='print the checks as JSON and exit')
    ap.add_argument('link', nargs='?', help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.once:
        print(json.dumps(checks(), indent=1))
        return
    if args.link and not LINK_PATTERN.match(args.link):
        sys.exit('The helper was started from an unsupported link.')
    if args.link and (LINK_PATTERN.match(args.link).group(2) or '').lower() == 'unregister':
        unregister_link()
        message(f'The helper link was removed. Running {EXE_NAME} again sets it up again.')
        return
    exe = sys.executable if FROZEN else os.path.abspath(__file__)
    first_time = FROZEN and not args.link
    if FROZEN:
        try:
            register_link(exe)   # per-user, no Administrator rights
        except OSError:
            pass
    if another_copy_running():
        if first_time:
            message('My Security Helper is already running. Go back to the website and press Run online scan.')
        return
    server = None
    for p in ([args.port] if args.port else PORTS):
        try:
            server = http.server.ThreadingHTTPServer(('127.0.0.1', p), Handler)
            break
        except OSError:
            continue
    if not server:
        message('My Security Helper could not open a local port (8781 to 8783). Another program is using them.', 0x10)
        return
    if first_time:
        message('My Security Helper is ready.\n\nGo back to the website and press Run online scan. It only reads a few Windows settings, changes nothing, and stops by itself after 10 idle minutes.')
    print(f'{APP_NAME} {APP_VERSION} listening on 127.0.0.1:{server.server_port}', flush=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    while time.time() - last_request < IDLE_MINUTES * 60:
        time.sleep(5)


if __name__ == '__main__':
    main()
