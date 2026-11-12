"""Internet and network exposure: what others can reach, and how safe the network around this PC is.

Wi-Fi security and look-alike networks, devices answering SNMP with the factory password, web servers and developer tools
this PC offers to the network, a fake router on the network (ARP spoofing) and redirected traffic routes.
Everything here only looks: one read-only SNMP question to the router and this PC, and one page request to web servers on this PC.
"""
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import time
import urllib.request

import scans_win as S
from knowledge import NEVER_BLOCK_PORTS
from scans_win import F, HKLM, as_list, reg_get, reg_values

STATE = os.path.join(S.APP_DIR, 'network-memory.json')   # the router's hardware address last time, to notice a swap

# which Windows service(s) each running program hosts, so a listening server can be turned off at its source
SVC_MAP_PS = r'''
$o = @(Get-CimInstance Win32_Service -Filter "ProcessId > 0" | ForEach-Object { [pscustomobject]@{ Pid = [int]$_.ProcessId; Name = [string]$_.Name; Display = [string]$_.DisplayName; StartMode = [string]$_.StartMode } })
ConvertTo-Json -InputObject @($o) -Compress
'''


def _port_actions(port, app, service, can_block):
    """(primary, second) buttons for a server listening on a port: turn its service off when it is one dedicated service, and block the port."""
    block = S.A('block_port', 'Block port', f'Block incoming TCP port {port} ({app})?\n\nWindows Firewall will refuse connections to it from other devices. The program keeps running for this PC.\n\nYou can unblock it any time in the Blocked tab.', port=port, proto='TCP') if can_block and ('TCP', port) not in NEVER_BLOCK_PORTS else None
    off = None
    if service and service['Name'].lower() not in S.NO_DISABLE_SERVICES:
        disp = service['Display'] or service['Name']
        off = S.A('disable_service', 'Turn off server', f'Stop and disable the service "{disp}" ({service["Name"]})?\n\nThis turns off the server it runs, and it will not start again with Windows. Anything that relies on it stops working.\n\nYou can undo this from the Blocked tab while My Security is open.', name=service['Name'], display=disp, old_start=service.get('StartMode'), was_running=True)
    return (off, block) if off else (block, None)


def _netsh(*args):
    try:
        r = subprocess.run([os.path.join(S.SYSTEM32, 'netsh.exe'), 'wlan', *args], capture_output=True, timeout=20, creationflags=S.CREATE_NO_WINDOW)
        return r.stdout.decode('utf-8', 'replace') if r.returncode == 0 else ''
    except (OSError, subprocess.SubprocessError):
        return ''


def _field(text, name):
    m = re.search(rf'^\s*{name}\s*:\s*(.+?)\s*$', text, re.M | re.I)
    return m.group(1) if m else ''


WEAK_AUTH = {'open': ('high', 'no password and no encryption'), 'wep': ('high', 'WEP, broken since 2001 and crackable in minutes'),
             'shared': ('high', 'WEP shared key, broken since 2001'), 'wpa-personal': ('medium', 'the first WPA, from 2003'), 'wpa-enterprise': ('low', 'the first WPA')}


def wifi_checks(out):
    add = out.append
    cur = _netsh('show', 'interfaces')
    ssid, auth, cipher = _field(cur, 'SSID'), _field(cur, 'Authentication').lower(), _field(cur, 'Cipher').lower()
    if ssid:
        weak = WEAK_AUTH.get(auth)
        if weak:
            add(F('exposure', 'wifi-now', weak[0], f'Your Wi-Fi "{ssid}" uses {weak[1]}', 'Everything sent over this Wi-Fi can be read by anyone nearby' + (' with free tools.' if weak[0] == 'high' else ' who puts in some effort.'),
                  'Passwords on sites without https, your network traffic and the devices on it are exposed. On a network you don\'t own, also assume someone is watching.', f'Network: {ssid}\nSecurity: {auth} / {cipher}',
                  'At home, set the router to WPA2 or WPA3 with a long password. Elsewhere, use a VPN or your phone\'s hotspot.'))
        elif 'tkip' in cipher:
            add(F('exposure', 'wifi-tkip', 'medium', f'Your Wi-Fi "{ssid}" uses the old TKIP encryption', 'TKIP was a stopgap from 2003 and has known weaknesses.', 'It is slower and weaker than AES.', f'{auth} / {cipher}', 'In the router\'s Wi-Fi settings choose WPA2 (AES) or WPA3.'))
        elif auth:
            add(F('exposure', 'wifi-ok', 'ok', f'Your Wi-Fi "{ssid}" is encrypted with {_field(cur, "Authentication")}', 'Modern Wi-Fi security.', evidence=f'{auth} / {cipher}'))
        # look-alike networks: same name, weaker security, nearby right now ("evil twin")
        nets = _netsh('show', 'networks', 'mode=bssid')
        twins = []
        for block in re.split(r'^\s*SSID \d+\s*:', nets, flags=re.M)[1:]:
            name = block.splitlines()[0].strip()
            a = _field(block, 'Authentication').lower()
            if name == ssid and a and a != auth and a in WEAK_AUTH:
                twins.append(a)
        if twins:
            add(F('exposure', 'eviltwin', 'high', f'A second "{ssid}" network nearby has weaker security', f'Your network uses {auth}, but another network with the same name uses {", ".join(sorted(set(twins)))}.',
                  'A look-alike network ("evil twin") tricks devices into joining it, so its owner sees and changes your traffic. Some routers create an open guest network with the same name, which is also risky.',
                  f'Your network: {ssid} ({auth})\nLook-alike: {", ".join(sorted(set(twins)))}', 'Don\'t join the open one. If it is your own router\'s, turn it off or give it a different name and a password.', Active=True))
    # saved networks that join by themselves without a password
    profiles = re.findall(r'All User Profile\s*:\s*(.+)', _netsh('show', 'profiles'))
    risky = []
    for name in profiles[:40]:
        txt = _netsh('show', 'profile', f'name={name.strip()}')
        if _field(txt, 'Authentication').lower() in ('open', 'wep', 'shared') and 'automatic' in _field(txt, 'Connection mode').lower():
            risky.append(name.strip())
    if risky:
        add(F('exposure', 'wifi-auto-open', 'medium', f'{len(risky)} open Wi-Fi network{"s" if len(risky) > 1 else ""} saved to join automatically',
              'This PC joins these networks by itself whenever it sees their names.', 'Anyone can create a network with the same name (a café\'s, an airport\'s) and this PC will join it without asking.',
              '\n'.join(risky[:15]), 'Forget them in Settings > Network & internet > Wi-Fi > Manage known networks, or untick "Connect automatically".', A_settings()))


def A_settings():
    return S.A('open_settings', 'Open Wi-Fi settings', 'Open Windows\' Wi-Fi settings?', page='ms-settings:network-wifisettings')


# ---- SNMP: devices that answer with the factory password "public"
def _snmp_get(host, community, version):
    oid = bytes.fromhex('2b06010201010100')   # sysDescr.0
    vb = b'\x30' + bytes([len(oid) + 4]) + b'\x06' + bytes([len(oid)]) + oid + b'\x05\x00'
    vbl = b'\x30' + bytes([len(vb)]) + vb
    rid = secrets.token_bytes(4)
    pdu_body = b'\x02\x04' + rid + b'\x02\x01\x00\x02\x01\x00' + vbl
    pdu = b'\xa0' + bytes([len(pdu_body)]) + pdu_body
    c = community.encode()
    body = b'\x02\x01' + bytes([version]) + b'\x04' + bytes([len(c)]) + c + pdu
    msg = b'\x30' + bytes([len(body)]) + body
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1.5)
            s.sendto(msg, (host, 161))
            data, _ = s.recvfrom(4096)
    except OSError:
        return None
    if rid not in data:
        return None
    i = data.rfind(b'\x04')   # the answer's text is the last string in the reply
    while i > 0:
        n = data[i + 1]
        if n < 0x80 and i + 2 + n == len(data):
            return data[i + 2:i + 2 + n].decode('utf-8', 'replace').strip() or '(empty)'
        i = data.rfind(b'\x04', 0, i)
    return '(answered)'


def snmp_checks(out, gw):
    add = out.append
    svc = r'SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
    if reg_get(HKLM, r'SYSTEM\CurrentControlSet\Services\SNMP', 'Start', 4) in (2, 3):
        comms = [n for n, _v in reg_values(HKLM, svc)]
        weak = [c for c in comms if c.lower() in ('public', 'private', 'community', 'snmp', 'admin', 'secret')]
        add(F('exposure', 'snmp-svc', 'high' if weak else 'medium', 'The SNMP service is installed on this PC' + (f' with the password "{weak[0]}"' if weak else ''),
              'SNMP lets other devices read, and sometimes change, this PC\'s details. Versions 1 and 2 send their password in plain text.',
              'Anyone on the network can learn the software, users and network layout of this PC, and with a writable password change settings.', f"Passwords (communities): {', '.join(comms) or 'none'}",
              'Remove it in Settings > System > Optional features > Simple Network Management Protocol, unless monitoring software needs it.'))
    for host, label in ((gw, 'Your router'), ('127.0.0.1', 'This PC')):
        if not host:
            continue
        for community in ('public', 'private'):
            ans = _snmp_get(host, community, 1) or _snmp_get(host, community, 0)
            if ans:
                add(F('exposure', f'snmp:{host}:{community}', 'high', f'{label} answers SNMP with the factory password "{community}"',
                      'SNMP versions 1 and 2 use a "community" as their password, and most devices ship with "public" (read) and "private" (write).',
                      'Anyone on your network can read the device\'s configuration and connected devices; with "private" they can change it. Attackers scan for this first.',
                      f'{host}: {ans[:200]}', 'In the router\'s admin page turn SNMP off, or switch to SNMPv3 with a strong password.', Active=True))
                break


# ---- web servers and developer tools this PC offers to the network
DEV_PORTS = {
    2375: ('critical', 'the Docker engine, without encryption or password', 'Anyone who reaches it can start a container with full access to this PC.'),
    2376: ('medium', 'the Docker engine (TLS)', 'Safe only if certificates are required.'),
    5555: ('high', 'Android debugging (ADB)', 'Anyone who reaches it can control a connected phone or emulator, and often this PC through it.'),
    9222: ('critical', 'a browser\'s remote debugging', 'Gives full control of that browser, including every sign-in cookie.'),
    9229: ('high', 'the Node.js debugger', 'Lets anyone run code inside that program.'),
    6379: ('high', 'Redis (no password by default)', 'Data can be read and changed, and Redis can be used to write files.'),
    27017: ('high', 'MongoDB', 'Often installed without a password.'), 9200: ('high', 'Elasticsearch', 'Often installed without a password.'),
    5432: ('medium', 'PostgreSQL', 'A database open to the network.'), 3306: ('medium', 'MySQL / MariaDB', 'A database open to the network.'),
    1433: ('medium', 'Microsoft SQL Server', 'A database open to the network.'), 11211: ('medium', 'Memcached', 'No password at all.'),
    8888: ('medium', 'Jupyter Notebook', 'Runs any code it is given if no token is set.'), 5900: ('high', 'VNC screen sharing', 'Remote control of the screen.'),
    4444: ('high', 'a port Metasploit uses for backdoors', 'Rarely used by anything legitimate.'), 1337: ('medium', 'a port favoured by hacking tools', 'Rarely used by anything legitimate.'),
}
WEB_BAD = [(re.compile(r'<title>\s*index of /', re.I), 'high', 'shows a list of its files to anyone'),
           (re.compile(r'(traceback \(most recent call last\)|werkzeug debugger|whitelabel error page|stack trace:|at System\.\w+|exception in thread|fatal error</b>)', re.I), 'high', 'shows its program errors and internals'),
           (re.compile(r'(iis windows|apache2 \w+ default page|it works!|welcome to nginx|test page for)', re.I), 'medium', 'shows a default "it works" page, which tells attackers what it is'),
           (re.compile(r'(phpmyadmin|adminer|webmin|jenkins|portainer|grafana|kibana|router login)', re.I), 'medium', 'is an admin page')]
SKIP_PORTS = {135, 139, 445, 2869, 5040, 5357, 7680}   # Windows' own, covered by the Ports tab


def _http_probe(ip, port):
    for scheme in ('http', 'https'):
        try:
            import ssl
            ctx = ssl._create_unverified_context()   # only to read what this PC's own server shows
            req = urllib.request.Request(f'{scheme}://{ip}:{port}/', headers={'User-Agent': 'MySecurity'})
            with urllib.request.urlopen(req, timeout=2, context=ctx) as r:
                return r.status, r.headers.get('Server', ''), r.read(20000).decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.headers.get('Server', ''), e.read(20000).decode('utf-8', 'replace')
            except Exception:
                return e.code, '', ''
        except Exception:
            continue
    return None


def service_checks(out, self_port, lan_ip):
    add = out.append
    names = {p: n[0] for p, n in S.process_snapshot().items()}
    by_pid = {}
    for row in S.run_powershell(SVC_MAP_PS, timeout=60):
        if isinstance(row, dict) and row.get('Name'):
            by_pid.setdefault(int(row.get('Pid') or 0), []).append(row)
    one_service = lambda pid: by_pid[pid][0] if len(by_pid.get(pid, [])) == 1 else None   # a shared host such as svchost runs many, so none is picked
    seen = set()
    for st, addr, port, _ra, _rp, pid in S.tcp_rows():
        if st != 2 or port in seen or port in SKIP_PORTS or port == self_port:
            continue
        open_to_net = addr in ('0.0.0.0', '::') or not (addr.startswith('127.') or addr == '::1')
        app = names.get(pid, f'PID {pid}')
        if port in DEV_PORTS:
            seen.add(port)
            sev, what, why = DEV_PORTS[port]
            if not open_to_net:
                sev = {'critical': 'medium', 'high': 'low'}.get(sev, 'low')
            first, second = _port_actions(port, app, one_service(pid), open_to_net)
            add(F('exposure', f'dev:{port}', sev, f'{app} offers {what} on port {port}' + ('' if open_to_net else ' (this PC only)'),
                  f'Port {port} is {what}.', why + ('' if open_to_net else ' It only listens on this PC, so other devices can\'t reach it, but any program here can.'),
                  f'{app} (PID {pid}) listening on {addr}:{port}', 'Turn it off when you are not using it, or set it to listen on 127.0.0.1 only and require a password.',
                  first, Alt=second, Active=open_to_net))
            continue
        if not open_to_net or port < 80 or not lan_ip:
            continue
        seen.add(port)
        r = _http_probe(lan_ip, port)
        if not r:
            continue
        status, server, body = r
        if server.lower().startswith('microsoft-httpapi') and status in (400, 404, 503):
            continue   # Windows' shared web listener answering for nothing in particular
        hits = [(sev, why) for rx, sev, why in WEB_BAD if rx.search(body)]
        version = bool(re.search(r'/\d', server))
        if status == 200 and not hits and not version:
            hits = [('low', 'answers without asking for a password')]
        if hits or version:
            sev = 'high' if any(h[0] == 'high' for h in hits) else 'medium' if any(h[0] == 'medium' for h in hits) else 'low'
            reasons = [h[1] for h in hits] + (['tells everyone its exact version (' + server + ')'] if version else [])
            first, second = _port_actions(port, app, one_service(pid), True)
            add(F('exposure', f'web:{port}', sev, f'Web server on port {port} ({app}) ' + reasons[0],
                  f'{app} runs a web server that other devices on your network can open.', 'Pages that list files, show errors or admin screens, or name exact versions give attackers what they need for the next step.',
                  f'http(s)://{lan_ip}:{port}/ answered {status}' + (f'\nServer: {server}' if server else '') + '\n' + '\n'.join('- ' + x for x in reasons),
                  'If you don\'t use it, turn the server off or block its port. Otherwise set a password and let it listen on 127.0.0.1 only.', first, Alt=second))


# ---- the network itself: a fake router, redirected routes
NEIGH_PS = r'''
$gw = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | ForEach-Object { [string]$_.NextHop }) | Where-Object { $_ -ne '0.0.0.0' } | Select-Object -First 1
$ip = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike '169.254*' } | ForEach-Object { [string]$_.IPAddress })
$n = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.State -in 'Reachable','Stale','Delay','Probe','Permanent' } | ForEach-Object { [pscustomobject]@{ Ip = [string]$_.IPAddress; Mac = [string]$_.LinkLayerAddress; State = [string]$_.State } })
ConvertTo-Json -InputObject @{ gw = $gw; ips = $ip; n = $n } -Depth 3 -Compress
'''


def network_checks(out, d):
    add = out.append
    gw = str(d.get('gw') or '')
    neigh = [x for x in as_list(d.get('n')) if isinstance(x, dict) and x.get('Mac') and x['Mac'] not in ('00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF') and not x['Mac'].startswith(('01-00-5E', '33-33'))]
    gw_mac = next((x['Mac'] for x in neigh if x['Ip'] == gw), '')
    if gw_mac:
        same = [x['Ip'] for x in neigh if x['Mac'] == gw_mac and x['Ip'] != gw]
        if same:
            add(F('exposure', 'arpspoof', 'high', f'Another device claims to be your router ({", ".join(same[:3])})',
                  f'Your router {gw} and {", ".join(same[:3])} share one hardware address ({gw_mac}).',
                  'This is what "ARP spoofing" looks like: a device on the network pretends to be the router so all your traffic passes through it. Some mesh Wi-Fi and repeaters do this harmlessly.',
                  f'{gw} -> {gw_mac}\n' + '\n'.join(f'{ip} -> {gw_mac}' for ip in same[:5]), 'If you have no mesh system or repeater, unplug unknown devices, restart the router and avoid signing in to anything until it is gone.', Active=True))
        try:
            with open(STATE, encoding='utf-8') as f:
                mem = json.load(f)
        except (OSError, ValueError):
            mem = {}
        before = mem.get('gw', {}).get(gw)
        if before and before != gw_mac:
            add(F('exposure', 'gwchanged', 'medium', f'Your router\'s hardware address changed since the last check',
                  f'Router {gw} was {before}; now it is {gw_mac}.', 'Normal after replacing the router or joining a different network with the same address. Otherwise it can mean a device is impersonating the router.',
                  f'before: {before}\nnow: {gw_mac}', 'If you did not change your router or network, restart the router and run this check again.'))
        mem.setdefault('gw', {})[gw] = gw_mac
        try:
            os.makedirs(S.APP_DIR, exist_ok=True)
            with open(STATE, 'w', encoding='utf-8') as f:
                json.dump(mem, f)
        except OSError:
            pass
    routes = reg_values(HKLM, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes')
    if routes:
        add(F('exposure', 'routes', 'medium', f'{len(routes)} permanent network route{"s" if len(routes) > 1 else ""} added by hand',
              'These send traffic for certain addresses through a chosen gateway.', 'VPN and work setups add them. Malware adds them to send traffic through a machine it controls.',
              '\n'.join(n for n, _v in routes[:10]), 'If you don\'t recognise them, remove them with "route delete" in an administrator command prompt.'))


def scan_exposure(ctx):
    out = []
    d = S.ps_one(NEIGH_PS, timeout=60)
    gw = str(d.get('gw') or '')
    lan = next((ip for ip in as_list(d.get('ips')) if ipaddress.ip_address(ip).is_private and not ip.startswith('127.')), '')
    for step in (lambda: wifi_checks(out), lambda: snmp_checks(out, gw), lambda: service_checks(out, ctx.get('port') or 0, lan), lambda: network_checks(out, d)):
        try:
            step()
        except Exception as e:   # one broken part must not hide the others
            out.append(F('exposure', f'err:{len(out)}', 'info', 'One exposure check could not finish', str(e)[:300]))
    if not [x for x in out if S.SEV_RANK.get(x['Sev'], 0) >= 2]:
        out.append(F('exposure', 'clean', 'ok', 'Nothing risky found in what this PC exposes to the network',
                     'Checked Wi-Fi security and look-alike networks, saved open networks, SNMP on this PC and your router, web servers and developer tools on this PC, signs of a fake router and redirected routes. The Pentest from outside check covers what the internet can reach.'))
    return out


S.SCANS.append(('exposure', 'Internet and network exposure', scan_exposure))
