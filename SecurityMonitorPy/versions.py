"""
Which version of each protocol this PC's open ports speak, and whether that version is safe, weak or should be blocked.
Versions are measured by connecting to this PC's own ports (SMB negotiation, TLS handshake, banners), not guessed from settings.
Only this PC is contacted. Nothing is changed.
"""

import os
import re
import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor

import scans_win as S

SMB_DIALECTS = {0x0202: '2.0.2', 0x0210: '2.1', 0x0300: '3.0', 0x0302: '3.0.2', 0x0311: '3.1.1'}
RANK = {'': 0, 'safe': 1, 'weak': 2, 'block': 3}
TLS_PORTS = {443, 636, 853, 993, 995, 5986, 8443, 9443}
NO_PROBE = {135, 139, 445, 3389}   # handled by their own checks; a stray handshake there only adds log noise

SMB_CFG_PS = r'''
$c = Get-SmbServerConfiguration
ConvertTo-Json -InputObject @{ ok = [bool]$c; smb1 = [bool]$c.EnableSMB1Protocol; smb2 = [bool]$c.EnableSMB2Protocol; enc = [bool]$c.EncryptData; sign = [bool]$c.RequireSecuritySignature; min = [string]$c.Smb2DialectMin } -Compress
'''


def item(name, state, verdict, why):
    return {'Name': name, 'State': state, 'Verdict': verdict, 'Why': why}


def _host(addrs):
    addrs = sorted(addrs)
    if any(a in ('0.0.0.0',) or a.startswith('127.') for a in addrs):
        return '127.0.0.1'
    if '::' in addrs or '::1' in addrs:
        return '::1'
    return addrs[0] if addrs else '127.0.0.1'


def _exchange(host, port, payload, want=74, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(payload)
            data = b''
            while len(data) < want:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data
    except OSError:
        return None


def _nb(payload):
    return struct.pack('>I', len(payload)) + payload


def smb1_accepted(host, port=445):
    """Send an SMB 1.0-only negotiation. A server with SMB 1.0 off hangs up; one with it on answers in SMB 1.0."""
    hdr = b'\xffSMB\x72' + b'\x00' * 4 + b'\x18' + struct.pack('<H', 0x4801) + b'\x00' * 12 + b'\x00\x00\xff\xfe\x00\x00\x00\x00'
    dialects = b'\x02NT LM 0.12\x00'
    try:
        s = socket.create_connection((host, port), timeout=2)
    except OSError:
        return None   # nothing to ask
    data = b''
    try:
        with s:
            s.sendall(_nb(hdr + b'\x00' + struct.pack('<H', len(dialects)) + dialects))
            while len(data) < 40:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except OSError:
        pass   # Windows hangs up on an SMB 1.0 request when SMB 1.0 is off
    return data[4:8] == b'\xffSMB' and data[9:13] == b'\x00\x00\x00\x00'


def smb2_negotiate(host, port=445):
    """Offer every SMB 2 and 3 dialect and see which one this PC picks. Returns (dialect, signing required) or None."""
    dialects = list(SMB_DIALECTS)
    hdr = b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ16s', 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, b'\x00' * 16)
    fixed = struct.pack('<HHHHI16sIHH', 36, len(dialects), 1, 0, 0, os.urandom(16), 112, 1, 0)
    dial = b''.join(struct.pack('<H', d) for d in dialects)
    pre = struct.pack('<HHH', 1, 32, 1) + os.urandom(32)   # SMB 3.1.1 requires a pre-authentication integrity context
    ctx = struct.pack('<HHI', 1, len(pre), 0) + pre
    data = _exchange(host, port, _nb(hdr + fixed + dial + b'\x00\x00' + ctx))
    if not data or len(data) < 74 or data[4:8] != b'\xfeSMB' or struct.unpack('<I', data[12:16])[0] != 0:
        return None
    secmode, dialect = struct.unpack('<HH', data[70:74])
    return SMB_DIALECTS.get(dialect, hex(dialect)), bool(secmode & 2)


def tls_version(host, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=2) as s, ctx.wrap_socket(s, server_hostname='localhost') as t:
            return t.version()
    except (OSError, ssl.SSLError, ValueError):
        return None


def banner(host, port):
    """What a service says first. Many old services (SSH, FTP, SMTP, VNC) announce their name and version this way."""
    try:
        with socket.create_connection((host, port), timeout=1.5) as s:
            s.settimeout(1.0)
            try:
                text = s.recv(256)
            except OSError:
                text = b''
            if not text:
                s.sendall(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
                s.settimeout(1.5)
                text = s.recv(2048)
    except OSError:
        return ''
    text = text.decode('latin-1', 'replace')
    m = re.search(r'^Server:\s*(.+)$', text, re.I | re.M)
    if text.startswith('HTTP/'):
        return 'HTTP' + (f' · {m.group(1).strip()[:60]}' if m else '')
    return re.sub(r'[^\x20-\x7e]', '', text.splitlines()[0] if text else '')[:80]


# ---------------------------------------------------------------- verdicts per protocol

def smb_items(host, exposed, cfg):
    out = []
    v1 = smb1_accepted(host)
    if v1 is None and cfg.get('ok'):
        v1 = cfg.get('smb1')
    if v1:
        out.append(item('SMB 1.0', 'On', 'block', 'Turn it off now. WannaCry and NotPetya spread through SMB 1.0, and nothing made in the last 15 years needs it. Use the Turn off button in the Protocols tab.'))
    elif v1 is False:
        out.append(item('SMB 1.0', 'Off', 'safe', 'Good. The version that WannaCry used is not available.'))
    neg = smb2_negotiate(host)
    if neg:
        dialect, signing = neg
        if dialect == '3.1.1':
            out.append(item(f'SMB {dialect}', 'In use', 'safe', 'The newest version. It detects tampering with the connection setup and can encrypt everything.'))
        elif dialect.startswith('3'):
            out.append(item(f'SMB {dialect}', 'In use', 'safe', 'Supports encryption. Version 3.1.1 adds protection against downgrade attacks.'))
        else:
            out.append(item(f'SMB {dialect}', 'In use', 'weak', 'An old version with no encryption. Update Windows.'))
        mn = str(cfg.get('min') or '')
        if dialect.startswith('3') and not mn.upper().startswith('SMB3'):
            out.append(item('SMB 2.0.2 and 2.1', 'Allowed for old devices', 'weak' if exposed else 'safe', 'Only devices from before 2012 need these, and they can\'t encrypt. Fine on a home network. To refuse them, an administrator can run: Set-SmbServerConfiguration -Smb2DialectMin SMB300'))
        sign_req = signing   # what this PC actually does on the wire, which can differ from what its settings report
        out.append(item('Signing', 'Required' if sign_req else 'Not required', 'safe' if sign_req else 'weak', 'Every message is signed, so it can\'t be altered or relayed.' if sign_req else 'Someone on your network could relay a sign-in to this PC. Require signing in the Shares tab.'))
    if cfg.get('ok'):
        out.append(item('Encryption', 'On' if cfg.get('enc') else 'Off', 'safe' if cfg.get('enc') else ('weak' if exposed else 'safe'), 'Shared files cross the network encrypted.' if cfg.get('enc') else 'Shared files cross the network readable by anyone who can see the traffic. Matters most on shared Wi-Fi.'))
    return out


def rdp_items():
    k = r'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    nla = S.reg_get(S.HKLM, k, 'UserAuthentication', 1)
    layer = S.reg_get(S.HKLM, k, 'SecurityLayer', 2)
    out = [item('Network Level Authentication', 'On' if nla else 'Off', 'safe' if nla else 'block', 'People must prove who they are before Windows shows them anything.' if nla else 'Anyone can reach the login screen with no password. BlueKeep attacked exactly this. Turn NLA on in the Protocols tab.')]
    out.append({0: item('Security layer', 'Old RDP encryption', 'block', 'Its encryption is weak and nothing proves the PC is genuine. Use TLS.'),
                1: item('Security layer', 'Negotiate', 'weak', 'TLS is used when both ends support it, otherwise the old RDP encryption. Setting it to TLS only is safer.'),
                2: item('Security layer', 'TLS', 'safe', 'The connection is encrypted with TLS.')}.get(layer, item('Security layer', str(layer), 'weak', 'Unknown setting.')))
    return out


def tls_item(ver):
    if ver in ('TLSv1.3', 'TLSv1.2'):
        return item(ver.replace('TLSv', 'TLS '), 'In use', 'safe', 'Current encryption.')
    return item(ver.replace('TLSv', 'TLS '), 'In use', 'block', 'Retired encryption that can be broken. Update or reconfigure this program.')


def banner_items(text, exposed):
    t = text.lower()
    if t.startswith('ssh-1.'):
        return [item(text, 'Announced', 'block', 'SSH version 1 is broken. Turn this server off or upgrade it.')]
    if t.startswith('ssh-2.0'):
        return [item(text, 'Announced', 'safe', 'SSH version 2 is current. Keep the server updated.')]
    if t.startswith('rfb 003.003'):
        return [item('VNC (RFB 3.3)', 'Announced', 'block', 'This old VNC version has very weak password protection.')]
    if t.startswith('rfb'):
        return [item(f'VNC ({text})', 'Announced', 'weak', 'VNC passwords are short and often sent weakly. Use it only over a VPN.')]
    if re.match(r'^(220[ -].*ftp|220 )', t):
        return [item(text, 'Announced', 'block' if exposed else 'weak', 'FTP sends passwords as plain text. Use SFTP instead.')]
    if t.startswith('http'):
        return [item(text, 'Answering', 'weak' if exposed else 'safe', 'Plain HTTP: anything sent can be read on the network.' if exposed else 'Plain HTTP, but only this PC can reach it.')]
    return [item(text, 'Announced', '', 'What the program says about itself when something connects.')] if text else []


# ports whose protocol has a fixed version and a clear verdict
KNOWN = {
    ('UDP', 137): ('NetBIOS (1987)', 'block', 'Answers name questions from anyone and can be spoofed to capture password hashes. Modern networks don\'t need it. Turn NetBIOS off in the Protocols tab.'),
    ('UDP', 138): ('NetBIOS (1987)', 'block', 'Old network browsing from the 1990s. Modern networks don\'t need it. Turn NetBIOS off in the Protocols tab.'),
    ('TCP', 139): ('SMB over NetBIOS (1987)', 'block', 'The pre-2000 way of reaching file sharing. Modern devices use port 445. Safe to block.'),
    ('TCP', 135): ('DCE/RPC', 'weak', 'Windows needs it internally. Other devices only use it for remote management, so on a home PC it is safe to block from the network.'),
    ('UDP', 5355): ('LLMNR', 'block', 'Can be spoofed to capture password hashes. Turn LLMNR off in the Protocols tab.'),
    ('UDP', 5353): ('mDNS', 'safe', 'Finds printers, speakers and TVs on your network. Low risk.'),
    ('UDP', 1900): ('SSDP (UPnP 1.0)', 'weak', 'Announces devices and reveals details about them. Block it if you don\'t cast to TVs or speakers.'),
    ('UDP', 3702): ('WS-Discovery', 'safe', 'Finds network printers and scanners. Low risk on a home network.'),
    ('TCP', 5357): ('WSD over HTTP', 'safe', 'Used by Windows to talk to network printers and scanners. Low risk on a home network.'),
    ('TCP', 2869): ('UPnP (HTTP)', 'weak', 'Lets devices control media sharing on this PC. Block it if you don\'t share media.'),
    ('TCP', 5985): ('WinRM over HTTP', 'weak', 'Remote command line. The commands are encrypted by the sign-in, but the transport is not. Turn off unless your workplace uses it.'),
    ('TCP', 23): ('Telnet', 'block', 'Sends everything, passwords included, as plain text. Always block.'),
    ('TCP', 623): ('Intel AMT', 'weak', 'Out-of-band remote management built into the chipset. Keep the Intel ME firmware updated, because older versions had a flaw that skipped the password. If nobody manages this PC remotely, turn AMT off in the BIOS.'),
    ('TCP', 664): ('Intel AMT (TLS)', 'weak', 'Out-of-band remote management built into the chipset. Keep the Intel ME firmware updated. If nobody manages this PC remotely, turn AMT off in the BIOS.'),
    ('TCP', 16992): ('Intel AMT web', 'weak', 'Intel AMT\'s web interface. Keep the Intel ME firmware updated, or turn AMT off in the BIOS.'),
    ('TCP', 16993): ('Intel AMT web (TLS)', 'weak', 'Intel AMT\'s encrypted web interface. Keep the Intel ME firmware updated, or turn AMT off in the BIOS.'),
    ('TCP', 7680): ('Delivery Optimization', 'safe', 'Windows sharing update downloads with other PCs on your network. Low risk. You can limit it in Settings > Windows Update > Advanced options > Delivery Optimization.'),
    ('TCP', 5040): ('Connected Devices Platform', 'safe', 'Windows linking to your phone and other devices. Low risk.'),
}


def measured(i):
    """True for a version actually seen on this PC, as opposed to general advice about a protocol."""
    return i['State'] != 'Protocol'


def summarize(items, fallback='', exposed=True):
    real = [i for i in items if i['Verdict']]
    worst = max((i['Verdict'] for i in real), key=lambda v: RANK[v], default='')
    if worst == 'weak' and not exposed:
        worst = 'safe'
    if not items:
        return {'Version': fallback, 'Verdict': '', 'Versions': []}
    lead = next((i['Name'] for i in items if i['State'] in ('In use', 'Announced', 'Answering')), items[0]['Name'])
    extra = ' · SMB 1.0 ON' if any(i['Name'] == 'SMB 1.0' and i['State'] == 'On' for i in items) else ''
    return {'Version': lead + extra, 'Verdict': worst, 'Versions': items}


def port_versions(rows, self_pid=0):
    """rows: [{'Proto','Port','Addrs','PID','Path','Exposed'}]. Returns {(proto, port): {'Version','Verdict','Versions'}}."""
    paths = [r['Path'] for r in rows if r.get('Path')]
    files = S.sign_info(paths)
    smb = any(r['Port'] in (445, 139) for r in rows)
    cfg = S.ps_one(SMB_CFG_PS, timeout=30) if smb else {}

    def one(r):
        proto, port, exposed = r['Proto'], r['Port'], r['Exposed']
        fv = files.get(r.get('Path'), {}).get('Version', '')
        fallback = f"{os.path.basename(r['Path'])} {fv}".strip() if r.get('Path') and fv else ''
        host = _host(r['Addrs'])
        items = []
        if proto == 'TCP' and port == 445:
            items = smb_items(host, exposed, cfg)
        elif proto == 'TCP' and port == 3389:
            items = rdp_items()
        if (proto, port) in KNOWN:
            name, verdict, why = KNOWN[(proto, port)]
            items.append(item(name, 'Protocol', verdict, why))
        elif proto == 'TCP' and port not in NO_PROBE and r['PID'] != self_pid and (port < 49152 or r['PID'] > 4):
            ver = tls_version(host, port) if port in TLS_PORTS else None
            if ver:
                items.append(tls_item(ver))
            else:
                items.extend(banner_items(banner(host, port), exposed))
        res = summarize(items, fallback, exposed)
        if fallback and res['Versions']:
            res['Program'] = fallback
        return (proto, port), res
    with ThreadPoolExecutor(max_workers=10) as pool:
        return dict(pool.map(one, rows[:80]))
