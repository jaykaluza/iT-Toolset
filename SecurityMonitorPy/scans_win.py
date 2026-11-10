"""
Windows scanners for My Security. Each scan_* returns a list of findings (see F); nothing here changes the PC.
Everything that changes the PC is in fixes_win.py. Values go to PowerShell through environment variables, never into script text.
"""

import base64
import ctypes
import ctypes.wintypes as wt
import datetime as dt
import glob
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import winreg
from concurrent.futures import ThreadPoolExecutor

from knowledge import (BACKDOOR_PORTS, FREE_HOSTING, LOGIN_BRANDS, LOOKALIKE_TARGETS, NEVER_BLOCK_PORTS, REMOTE_CONTROL_PORTS, REMOTE_TOOLS,
                       RISKY_SERVICES, RISKY_TLDS, SPYWARE_NAMES, TRUSTED_SITES, port_info)

LOAD_FROM_SYSTEM32 = 0x800
CREATE_NO_WINDOW = 0x08000000
WINDIR = os.environ.get('WINDIR', r'C:\Windows')
SYSTEM32 = os.path.join(WINDIR, 'System32')
APP_DIR = os.path.join(os.environ.get('LOCALAPPDATA', os.path.dirname(os.path.abspath(__file__))), 'MySecurity')
SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0, 'ok': -1}
USER_WRITABLE = re.compile(r'\\(AppData\\Local\\Temp|Windows\\Temp|Temp|Downloads|Users\\Public|ProgramData\\[^\\]+\.exe|\$Recycle\.Bin)(\\|$)', re.I)
APPDATA_RE = re.compile(r'\\AppData\\(Local|Roaming)\\', re.I)


def system_dll(name, **kw):
    return ctypes.WinDLL(name, winmode=LOAD_FROM_SYSTEM32, **kw)


iphlpapi = system_dll('iphlpapi', use_last_error=True)
kernel32 = system_dll('kernel32', use_last_error=True)
shell32 = system_dll('shell32')
ntdll = system_dll('ntdll')

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID = 5, 1
NO_ERROR, ERROR_INSUFFICIENT_BUFFER, ERROR_ACCESS_DENIED = 0, 122, 5
PROCESS_TERMINATE, PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZE = 0x0001, 0x1000, 0x00100000
WAIT_TIMEOUT, TH32CS_SNAPPROCESS = 0x102, 0x2
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [('dwState', wt.DWORD), ('dwLocalAddr', wt.DWORD), ('dwLocalPort', wt.DWORD),
                ('dwRemoteAddr', wt.DWORD), ('dwRemotePort', wt.DWORD), ('dwOwningPid', wt.DWORD)]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [('ucLocalAddr', ctypes.c_ubyte * 16), ('dwLocalScopeId', wt.DWORD), ('dwLocalPort', wt.DWORD),
                ('ucRemoteAddr', ctypes.c_ubyte * 16), ('dwRemoteScopeId', wt.DWORD), ('dwRemotePort', wt.DWORD),
                ('dwState', wt.DWORD), ('dwOwningPid', wt.DWORD)]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [('dwLocalAddr', wt.DWORD), ('dwLocalPort', wt.DWORD), ('dwOwningPid', wt.DWORD)]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [('ucLocalAddr', ctypes.c_ubyte * 16), ('dwLocalScopeId', wt.DWORD), ('dwLocalPort', wt.DWORD), ('dwOwningPid', wt.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ProcessID', wt.DWORD), ('th32DefaultHeapID', ctypes.c_size_t),
                ('th32ModuleID', wt.DWORD), ('cntThreads', wt.DWORD), ('th32ParentProcessID', wt.DWORD), ('pcPriClassBase', ctypes.c_long),
                ('dwFlags', wt.DWORD), ('szExeFile', ctypes.c_wchar * 260)]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [('Length', wt.USHORT), ('MaximumLength', wt.USHORT), ('Buffer', ctypes.c_void_p)]


iphlpapi.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL, wt.ULONG, ctypes.c_int, wt.ULONG]
iphlpapi.GetExtendedUdpTable.argtypes = iphlpapi.GetExtendedTcpTable.argtypes
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
ntdll.NtQueryInformationProcess.argtypes = [wt.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
ntdll.NtQueryInformationProcess.restype = ctypes.c_long


def is_admin():
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def _read_table(func, family, table_class, row_type):
    size, buf = wt.DWORD(0), None
    for _ in range(5):
        buf = ctypes.create_string_buffer(max(size.value, 4))
        ret = func(buf, ctypes.byref(size), False, family, table_class, 0)
        if ret == NO_ERROR:
            break
        if ret != ERROR_INSUFFICIENT_BUFFER:
            return []
    else:
        return []
    count = wt.DWORD.from_buffer(buf).value
    return list((row_type * count).from_buffer(buf, ctypes.sizeof(wt.DWORD)))


def _port(p):
    return socket.ntohs(p & 0xFFFF)


def _ip4(a):
    return socket.inet_ntoa(struct.pack('<I', a))


def _ip6(b):
    return str(ipaddress.IPv6Address(bytes(b)))


def tcp_rows():
    """(state number, local address, local port, remote address, remote port, pid)"""
    rows = [(r.dwState, _ip4(r.dwLocalAddr), _port(r.dwLocalPort), _ip4(r.dwRemoteAddr), _port(r.dwRemotePort), r.dwOwningPid)
            for r in _read_table(iphlpapi.GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL, MIB_TCPROW_OWNER_PID)]
    rows += [(r.dwState, _ip6(r.ucLocalAddr), _port(r.dwLocalPort), _ip6(r.ucRemoteAddr), _port(r.dwRemotePort), r.dwOwningPid)
             for r in _read_table(iphlpapi.GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL, MIB_TCP6ROW_OWNER_PID)]
    return rows


def udp_rows():
    rows = [(_ip4(r.dwLocalAddr), _port(r.dwLocalPort), r.dwOwningPid)
            for r in _read_table(iphlpapi.GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID)]
    rows += [(_ip6(r.ucLocalAddr), _port(r.dwLocalPort), r.dwOwningPid)
             for r in _read_table(iphlpapi.GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID)]
    return rows


def process_snapshot():
    """{pid: (name without .exe, parent pid)}"""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (None, INVALID_HANDLE_VALUE):
        return {}
    out, entry = {}, PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            exe = entry.szExeFile
            out[entry.th32ProcessID] = (exe[:-4] if exe.lower().endswith('.exe') else exe, entry.th32ParentProcessID)
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return out


def process_path(pid):
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ''
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wt.DWORD(len(buf))
        return buf.value if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)) else ''
    finally:
        kernel32.CloseHandle(h)


def process_cmdline(pid):
    """The full command line of a process ('' if Windows won't say)."""
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ''
    try:
        buf = ctypes.create_string_buffer(70000)
        got = ctypes.c_ulong(0)
        if ntdll.NtQueryInformationProcess(h, 60, buf, len(buf), ctypes.byref(got)) != 0:   # ProcessCommandLineInformation
            return ''
        us = UNICODE_STRING.from_buffer(buf)
        return ctypes.wstring_at(us.Buffer, us.Length // 2) if us.Buffer and us.Length else ''
    finally:
        kernel32.CloseHandle(h)


FROZEN = getattr(sys, 'frozen', False)


def is_this_app(pid, path=''):
    """True only for this running app: its own process, or the small launcher MySecurity.exe starts it from."""
    if pid == os.getpid():
        return True
    return FROZEN and pid == os.getppid() and (path or process_path(pid)).lower() == sys.executable.lower()


def is_running(pid):
    h = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
    if not h:
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED
    try:
        return kernel32.WaitForSingleObject(h, 0) == WAIT_TIMEOUT
    finally:
        kernel32.CloseHandle(h)


def terminate(pid):
    h = kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
    if not h:
        return 'denied' if ctypes.get_last_error() == ERROR_ACCESS_DENIED else 'gone'
    try:
        if kernel32.TerminateProcess(h, 1):
            kernel32.WaitForSingleObject(h, 3000)
            return 'ok'
        return 'gone' if not is_running(pid) else 'denied'
    finally:
        kernel32.CloseHandle(h)


def run_powershell(script, env_extra=None, timeout=90):
    """Run a PowerShell snippet that prints JSON; returns a list."""
    env = {k: v for k, v in os.environ.items() if k.upper() != 'PSMODULEPATH'}
    env.update(env_extra or {})
    full = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = 'SilentlyContinue'\n" + script
    encoded = base64.b64encode(full.encode('utf-16-le')).decode('ascii')
    exe = os.path.join(SYSTEM32, 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    try:
        r = subprocess.run([exe, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                           capture_output=True, timeout=timeout, env=env, creationflags=CREATE_NO_WINDOW)
        text = r.stdout.decode('utf-8', 'replace').strip()
        if not text:
            return []
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


def ps_one(script, env_extra=None, timeout=90):
    row = next(iter(run_powershell(script, env_extra, timeout)), {})
    return row if isinstance(row, dict) else {}


def as_list(v):
    return [] if v is None else v if isinstance(v, list) else [v]


def reg_get(hive, path, name, default=None):
    try:
        with winreg.OpenKey(hive, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default


def reg_values(hive, path):
    out = []
    try:
        with winreg.OpenKey(hive, path) as k:
            for i in range(winreg.QueryInfoKey(k)[1]):
                n, v, _ = winreg.EnumValue(k, i)
                out.append((n, v))
    except OSError:
        pass
    return out


def reg_subkeys(hive, path):
    out = []
    try:
        with winreg.OpenKey(hive, path) as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                out.append(winreg.EnumKey(k, i))
    except OSError:
        pass
    return out


HKLM, HKCU = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER


def F(cat, key, sev, title, what, risk='', evidence='', fix='', action=None, **extra):
    """One thing the scan found. sev is critical/high/medium/low/info/ok; action is what its Fix button does (see A)."""
    return {'Id': f'{cat}:{key}', 'Cat': cat, 'Sev': sev, 'Title': title, 'What': what, 'Risk': risk, 'Evidence': str(evidence or ''), 'Fix': fix, 'Action': action, **extra}


def A(fn, label, confirm, **args):
    """A Fix button: runs the named function in fixes_win.py. The page only ever sends the finding's id, never these arguments."""
    return {'fn': fn, 'label': label, 'confirm': confirm, 'args': args}


def need_admin(cat, what):
    return F(cat, 'needs-admin', 'info', 'Some checks need Administrator rights', f'{what} can only be read with Administrator rights, so those results are missing.',
             fix='Start My Security as Administrator (MySecurity.exe does this by itself) and run the scan again.')


def in_windows(path):
    return str(path).lower().startswith(WINDIR.lower() + '\\')


def exe_from_command(cmd):
    """The program a command line starts."""
    cmd = os.path.expandvars(str(cmd or '')).strip()
    m = re.match(r'^"([^"]+)"', cmd)
    if m:
        return m.group(1)
    m = re.match(r'^(.+?\.(?:exe|bat|cmd|com|scr|ps1|vbs|js|hta|msi|dll))\b', cmd, re.I)
    return m.group(1) if m else cmd.split(' ')[0]


# ---------------------------------------------------------------- file signatures

FILE_INFO_PS = r'''
$paths = $env:MS_PATHS | ConvertFrom-Json
$out = foreach ($p in $paths) {
  $s = $null; try { $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop } catch {}
  $v = $null; try { $v = [Diagnostics.FileVersionInfo]::GetVersionInfo($p) } catch {}
  [pscustomobject]@{ Path = [string]$p; Status = $(if ($s) { [string]$s.Status } else { 'Unknown' })
    Publisher = $(if ($s -and $s.SignerCertificate) { $s.SignerCertificate.Subject -replace '^CN="?([^",]+).*', '$1' } else { '' })
    Company = $(if ($v) { [string]$v.CompanyName } else { '' }); Description = $(if ($v) { [string]$v.FileDescription } else { '' }); Version = $(if ($v) { [string]$v.ProductVersion } else { '' }) }
}
ConvertTo-Json -InputObject @($out) -Compress
'''
_sign_cache = {}


def sign_info(paths):
    """{path: {Status, Publisher, Company, Description}}; results are remembered for this run."""
    todo = sorted({p for p in paths if p and p not in _sign_cache and os.path.isfile(p)})
    batches = [todo[i:i + 12] for i in range(0, len(todo), 12)]
    if batches:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for rows in pool.map(lambda b: run_powershell(FILE_INFO_PS, {'MS_PATHS': json.dumps(b)}), batches):
                for row in rows:
                    if isinstance(row, dict) and isinstance(row.get('Path'), str):
                        _sign_cache[row['Path']] = row
    blank = {'Status': 'Unknown', 'Publisher': '', 'Company': '', 'Description': '', 'Version': ''}
    return {p: _sign_cache.get(p, blank) for p in paths}


def is_unsigned(info):
    return info.get('Status') in ('NotSigned', 'NotTrusted', 'UnknownError', 'HashMismatch')


def pe_imports(path, limit=64 * 1024 * 1024):
    """Names of the Windows functions a program file imports (read from its header; the program is never run)."""
    try:
        if os.path.getsize(path) > limit:
            return set()
        with open(path, 'rb') as f:
            data = f.read()
        if data[:2] != b'MZ':
            return set()
        pe = struct.unpack_from('<I', data, 0x3C)[0]
        if data[pe:pe + 4] != b'PE\0\0':
            return set()
        nsec, optsize = struct.unpack_from('<H', data, pe + 6)[0], struct.unpack_from('<H', data, pe + 20)[0]
        opt = pe + 24
        is64 = struct.unpack_from('<H', data, opt)[0] == 0x20B
        imp_rva = struct.unpack_from('<I', data, opt + (120 if is64 else 104))[0]
        secs = [struct.unpack_from('<IIII', data, opt + optsize + i * 40 + 8) for i in range(nsec)]

        def off(rva):
            for vsize, va, rawsize, raw in secs:
                if va <= rva < va + max(vsize, rawsize):
                    return rva - va + raw
            return None

        names, d = set(), off(imp_rva)
        for _ in range(512):
            if d is None:
                break
            orig, _t, _f, _n, first = struct.unpack_from('<IIIII', data, d)
            if not orig and not first:
                break
            t = off(orig or first)
            for _i in range(4096):
                if t is None:
                    break
                entry = struct.unpack_from('<Q' if is64 else '<I', data, t)[0]
                if not entry:
                    break
                if not entry >> (63 if is64 else 31):
                    n = off(entry & 0x7FFFFFFF)
                    if n is not None:
                        names.add(data[n + 2:data.index(b'\0', n + 2)].decode('ascii', 'replace'))
                t += 8 if is64 else 4
            d += 20
        return names
    except (OSError, struct.error, ValueError):
        return set()


KEY_CAPTURE = {'SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyboardState', 'RegisterRawInputDevices'}
SCREEN_CAPTURE = {'BitBlt', 'GetDC', 'GetDesktopWindow'}
INJECTION = {'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'}

# ---------------------------------------------------------------- 1. Ports

FW_RULES_PS = r'''
$rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow)
function Index($cmd) { $h = @{}; try { & $cmd -All -ErrorAction Stop | ForEach-Object { $h[$_.InstanceID] = $_ } } catch {}; $h }
$pf = Index Get-NetFirewallPortFilter; $ap = Index Get-NetFirewallApplicationFilter
$out = foreach ($r in $rules) { [pscustomobject]@{ F = [string]$r.Profile; P = [string]$pf[$r.Name].Protocol; L = (@($pf[$r.Name].LocalPort) -join ','); A = [string]$ap[$r.Name].Program } }
ConvertTo-Json -InputObject @{
  rules = @($out)
  active = @(Get-NetConnectionProfile | ForEach-Object { [string]$_.NetworkCategory })
  profiles = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; Inbound = [string]$_.DefaultInboundAction } })
} -Depth 4 -Compress
'''


def _port_matches(spec, port):
    spec = str(spec or '')
    if spec in ('', 'Any'):
        return True
    for part in spec.split(','):
        part = part.strip()
        if part.isdigit() and int(part) == port:
            return True
        m = re.match(r'^(\d+)-(\d+)$', part)
        if m and int(m.group(1)) <= port <= int(m.group(2)):
            return True
        if part == 'RPC' and port >= 49152 or part == 'RPCEPMap' and port == 135:
            return True
    return False


def scan_ports(ctx):
    listening = {}
    for st, addr, port, _ra, _rp, pid in tcp_rows():
        if st == 2:
            listening.setdefault(('TCP', port), {'addrs': set(), 'pids': set()})
            listening[('TCP', port)]['addrs'].add(addr)
            listening[('TCP', port)]['pids'].add(pid)
    for addr, port, pid in udp_rows():
        listening.setdefault(('UDP', port), {'addrs': set(), 'pids': set()})
        listening[('UDP', port)]['addrs'].add(addr)
        listening[('UDP', port)]['pids'].add(pid)
    names = {p: n[0] for p, n in process_snapshot().items()}
    paths = {pid: process_path(pid) for v in listening.values() for pid in v['pids'] if pid > 4}
    signs = sign_info([p for p in paths.values() if p and not in_windows(p)])
    fw = ps_one(FW_RULES_PS, timeout=60)
    rules = as_list(fw.get('rules'))
    active = {str(a).replace('DomainAuthenticated', 'Domain') for a in as_list(fw.get('active'))}
    public = 'Public' in active
    disabled = [p['Name'] for p in as_list(fw.get('profiles')) if isinstance(p, dict) and p.get('Enabled') != 'True']
    fw_known = bool(rules)
    out = []
    import versions   # imported here because versions.py itself uses this module
    vers = versions.port_versions([{'Proto': proto, 'Port': port, 'Addrs': v['addrs'], 'PID': next(iter(sorted(v['pids']))), 'Path': paths.get(next(iter(sorted(v['pids']))), ''),
                                    'Exposed': any(not (a.startswith('127.') or a == '::1') for a in v['addrs'])} for (proto, port), v in sorted(listening.items(), key=lambda kv: kv[0][1])], ctx.get('self_pid', 0))
    for (proto, port), v in sorted(listening.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        exposed = any(not (a.startswith('127.') or a == '::1') for a in v['addrs'])
        pid = next(iter(sorted(v['pids'])))
        app, path = names.get(pid, f'PID {pid}'), paths.get(pid, '')
        name, how, risk, breaks = port_info(port, proto)
        allowed = None
        if fw_known and exposed:
            lower = os.path.expandvars(path).lower()
            allowed = bool(disabled and active & set(disabled))
            for r in rules:
                if not isinstance(r, dict) or not (r.get('F') == 'Any' or active & set(re.split(r',\s*', str(r.get('F'))))):
                    continue
                if str(r.get('P')) not in ('Any', proto, {'TCP': '6', 'UDP': '17'}[proto]) or not _port_matches(r.get('L'), port):
                    continue
                prog = os.path.expandvars(str(r.get('A') or 'Any')).lower()
                if prog in ('any', '') or prog == lower or (pid == 4 and prog == 'system'):
                    allowed = True
                    break
        info = signs.get(path, {})
        unsigned = bool(path) and not in_windows(path) and is_unsigned(info)
        tool = next((v2 for k2, v2 in REMOTE_TOOLS.items() if k2 in app.lower()), '')
        sev, why = 'info', ''
        if exposed:
            sev = 'low'
            if port in BACKDOOR_PORTS:
                sev, why = 'critical', 'This port is a known backdoor port, and a program is listening on it.'
            elif tool:
                sev, why = 'high', f'{tool} is remote-control software waiting for connections. Fine if you set it up. Scammers and intruders use it too.'
            elif unsigned and allowed:
                sev, why = 'high', 'An unsigned program is accepting connections from the network and the firewall lets them in.'
            elif unsigned:
                sev, why = 'medium', 'An unsigned program is listening. The firewall has no rule letting it in, so the risk is limited for now.'
            elif port in (23, 21, 69) and allowed is not False:
                sev, why = 'critical' if port == 23 else 'high', 'An unencrypted login service is reachable from the network.'
            elif port in REMOTE_CONTROL_PORTS and allowed:
                sev, why = 'high', 'Remote control of this PC is open to your network.'
            elif port in (135, 139, 445, 5985, 5986) and allowed:
                sev, why = ('high', 'You are on a Public network and this service is open to everyone on it.') if public else ('medium', 'Open to devices on your network. Close it if you do not share files or manage this PC remotely.')
            elif allowed is False:
                sev, why = 'low', 'Something is listening, but Windows Firewall has no rule letting the network reach it.'
        ver = vers.get((proto, port), {})
        bad_ver = [i for i in ver.get('Versions', []) if i['Verdict'] == 'block' and versions.measured(i)]   # general protocol advice is reported by the Protocols tab
        if exposed and bad_ver and SEV_RANK[sev] < SEV_RANK['high'] and allowed is not False:
            sev, why = 'high', f"{bad_ver[0]['Name']}: {bad_ver[0]['Why']}"
        blockable = exposed and (proto, port) not in NEVER_BLOCK_PORTS and pid != ctx.get('self_pid')
        action = A('block_port', 'Block', f'Block incoming {proto} port {port} ({name})?\n\nWindows Firewall will refuse connections to it from other devices.\n\nThis may break: {breaks}\n\nYou can unblock it anytime in the Blocked tab.', port=port, proto=proto) if blockable else None
        out.append(F('ports', f'{proto}:{port}', sev, f'{proto} {port} · {name}', how, risk, why, f'Blocking will break: {breaks}', action,
                     Port=port, Proto=proto, Addr=', '.join(sorted(v['addrs'])), App=app, PID=pid, Path=path, Exposed=exposed, Allowed=allowed,
                     Publisher=info.get('Publisher', ''), Breaks=breaks, Version=ver.get('Version', ''), Verdict=ver.get('Verdict', ''), Versions=ver.get('Versions', []), ProgVersion=ver.get('Program', '')))
    if not rules:
        out.append(F('ports', 'fw-unknown', 'info', 'Firewall rules could not be read', 'My Security could not read Windows Firewall rules, so it can\'t say which ports the firewall lets through.', fix='Run My Security as Administrator.'))
    return out


# ---------------------------------------------------------------- 2. System protection

PROTECTION_PS = r'''
$mp = Get-MpComputerStatus
$pref = Get-MpPreference
$sb = $null; try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch {}
$dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard
ConvertTo-Json -InputObject @{
  av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [pscustomobject]@{ Name = [string]$_.displayName; State = [int]$_.productState } })
  mp = $(if ($mp) { [pscustomobject]@{ Service = [bool]$mp.AMServiceEnabled; RealTime = [bool]$mp.RealTimeProtectionEnabled; SigAge = [int]$mp.AntivirusSignatureAge; Mode = [string]$mp.AMRunningMode; Tamper = [bool]$mp.IsTamperProtected; QuickAge = [long]$mp.QuickScanAge; FullAge = [long]$mp.FullScanAge } })
  exclusions = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ }
  profiles = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; Inbound = [string]$_.DefaultInboundAction } })
  active = @(Get-NetConnectionProfile | ForEach-Object { [string]$_.NetworkCategory })
  secureBoot = $sb
  bitlocker = @(Get-BitLockerVolume | ForEach-Object { [pscustomobject]@{ Mount = [string]$_.MountPoint; Status = [string]$_.ProtectionStatus; Type = [string]$_.VolumeType } })
  vbs = @($dg.SecurityServicesRunning)
  roots = @(Get-ChildItem Cert:\CurrentUser\Root | Where-Object { -not $_.Issuer.Contains('Microsoft') -and (Get-Item -LiteralPath ('Cert:\LocalMachine\Root\' + $_.Thumbprint) -ErrorAction SilentlyContinue) -eq $null } | ForEach-Object { [pscustomobject]@{ Subject = [string]$_.Subject; Thumb = [string]$_.Thumbprint } })
  badroots = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match 'Superfish|eDellRoot|DSDTestProvider|PrivDog|Komodia' } | ForEach-Object { [string]$_.Subject })
} -Depth 4 -Compress
'''
IMPORTANT_HOSTS = re.compile(r'(microsoft|windows|office|live\.com|google|apple|paypal|bank|chase|wellsfargo|amazon|facebook|defender|virustotal|kaspersky|symantec|norton|mcafee|malwarebytes|avast|crowdstrike)', re.I)
HOSTS_FILE = os.path.join(SYSTEM32, 'drivers', 'etc', 'hosts')


def protection_state():
    return ps_one(PROTECTION_PS, timeout=60)


def scan_system(ctx):
    p = protection_state()
    admin, out = ctx['admin'], []
    ctx['protection'] = p
    avs = [a for a in as_list(p.get('av')) if isinstance(a, dict)]
    on = [a for a in avs if f"{int(a.get('State') or 0):06x}"[2:4] in ('10', '11')]
    stale = [a for a in on if f"{int(a.get('State') or 0):06x}"[4:6] != '00']
    if on:
        out.append(F('system', 'av', 'ok', f"Antivirus is on: {', '.join(a['Name'] for a in on)}", 'Windows reports this antivirus as active.'))
    elif avs or p:
        mp_act = A('defender_on', 'Turn on Defender', 'Turn on Microsoft Defender real-time protection?') if admin else None
        out.append(F('system', 'av', 'critical', 'No antivirus is running', 'Windows does not report any active antivirus on this PC.', 'Malware can run with nothing to stop it. This is the most important protection on a PC.', ', '.join(a['Name'] + ' (off)' for a in avs),
                     'Turn on Microsoft Defender, or start your antivirus again.', mp_act, Active=True))
    for a in stale:
        out.append(F('system', 'av-old:' + a['Name'], 'high', f"{a['Name']} is out of date", 'Windows reports that this antivirus has old virus definitions.', 'New malware will not be recognised.', fix='Open the antivirus and update it.'))
    mp = p.get('mp') if isinstance(p.get('mp'), dict) else {}
    if mp.get('Service') and str(mp.get('Mode', '')).lower().startswith('normal'):
        if not mp.get('RealTime'):
            out.append(F('system', 'rtp', 'critical', 'Defender real-time protection is off', 'Defender only checks files when you ask it to.', 'Malware can run the moment it lands on the PC.', fix='Turn it back on.', action=A('defender_on', 'Turn on', 'Turn on Microsoft Defender real-time protection?') if admin else None, Active=True))
        if int(mp.get('SigAge') or 0) > 3:
            out.append(F('system', 'sig', 'high', f"Defender definitions are {mp['SigAge']} days old", 'Defender recognises malware with definitions that are normally updated every day.', 'Recent malware will not be recognised.', fix='Update the definitions.', action=A('defender_update', 'Update now', 'Update Microsoft Defender definitions now?')))
        if not mp.get('Tamper'):
            out.append(F('system', 'tamper', 'medium', 'Defender Tamper Protection is off', 'Tamper Protection stops programs from switching Defender off.', 'Malware commonly disables antivirus first.', fix='Windows Security > Virus & threat protection > Manage settings > Tamper Protection. Windows only allows this to be changed by hand.', action=A('open_settings', 'Open settings', 'Open Windows Security?', page='windowsdefender://threatsettings')))
    for x in as_list(p.get('exclusions')):
        x = str(x)
        if re.match(r'^[a-z]:\\?$', x, re.I) or USER_WRITABLE.search(x) or x.lower().lstrip('.*') in ('exe', 'dll', 'ps1', 'bat', 'js', 'vbs'):
            out.append(F('system', 'excl:' + x, 'high', f'Defender is told to ignore: {x}', 'Exclusions tell antivirus not to look somewhere.', 'Malware adds exclusions like this so that it can hide.', x, 'Remove it unless you added it for a specific reason.', A('defender_remove_exclusion', 'Remove', f'Remove this Defender exclusion?\n\n{x}', value=x), Active=True))
    active = {str(a).replace('DomainAuthenticated', 'Domain') for a in as_list(p.get('active'))}
    profiles = [x for x in as_list(p.get('profiles')) if isinstance(x, dict)]
    off = [x['Name'] for x in profiles if x.get('Enabled') != 'True']
    if profiles and not off:
        out.append(F('system', 'fw', 'ok', 'Windows Firewall is on for every network type', 'Incoming connections are filtered.'))
    elif off:
        now = bool(active & set(off))
        out.append(F('system', 'fw', 'critical' if now else 'high', f"Windows Firewall is off: {', '.join(off)}", 'The firewall decides which connections may reach this PC.', 'Every service on this PC is reachable from the network. Port blocks made in this app also stop working.', fix='Turn the firewall on.',
                     action=A('firewall_on', 'Turn on', 'Turn Windows Firewall on for every network type?', profiles=off) if admin else None, Active=now))
    lua, consent = reg_get(HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA', 1), reg_get(HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'ConsentPromptBehaviorAdmin', 5)
    pol = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if lua == 0:
        out.append(F('system', 'uac', 'critical', 'User Account Control is off', 'UAC is the "Do you want to allow this app?" prompt.', 'Every program runs with full control of the PC, without asking.', fix='Turn UAC back on. A restart is needed.', action=A('set_reg', 'Turn on', 'Turn on User Account Control? A restart is needed.', hive='HKLM', path=pol, name='EnableLUA', value=1, kind='dword', reboot=True), Active=True))
    elif consent == 0:
        out.append(F('system', 'uac', 'high', 'Programs can get admin rights without asking', 'UAC is set to never prompt administrators.', 'Malware running as you silently becomes administrator.', fix='Restore the prompt.', action=A('set_reg', 'Restore prompt', 'Make Windows ask before programs get admin rights?', hive='HKLM', path=pol, name='ConsentPromptBehaviorAdmin', value=5, kind='dword')))
    else:
        out.append(F('system', 'uac', 'ok', 'User Account Control is on', 'Programs must ask before getting admin rights.'))
    if p.get('secureBoot') is False:
        out.append(F('system', 'sb', 'medium', 'Secure Boot is off', 'Secure Boot makes sure only trusted software starts before Windows.', 'Rootkits can load before your antivirus does.', fix='Turn it on in the BIOS/UEFI settings. This can\'t be done from Windows.'))
    elif p.get('secureBoot') is True:
        out.append(F('system', 'sb', 'ok', 'Secure Boot is on', 'Only trusted software starts before Windows.'))
    vols = [v for v in as_list(p.get('bitlocker')) if isinstance(v, dict)]
    sysdrive = os.environ.get('SystemDrive', 'C:')
    for v in vols:
        if v.get('Mount', '').upper() == sysdrive.upper():
            if v.get('Status') == 'Off':
                out.append(F('system', 'bitlocker', 'medium', f'Drive {sysdrive} is not encrypted', 'BitLocker scrambles the drive so it is unreadable without Windows.', 'Anyone who steals this PC can read every file and saved password.', fix='Turn on BitLocker and save the recovery key somewhere safe.', action=A('open_settings', 'Open BitLocker', 'Open BitLocker settings?', page='bitlocker')))
            else:
                out.append(F('system', 'bitlocker', 'ok', f'Drive {sysdrive} is encrypted', 'BitLocker is on.'))
    if not reg_get(HKLM, r'SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL', 0):
        out.append(F('system', 'lsa', 'medium', 'Password memory is not protected (LSA protection off)', 'LSA holds your sign-in secrets in memory. LSA protection stops other programs from reading it.', 'Password-stealing tools read those secrets straight out of memory.', fix='Turn it on. A restart is needed. Very old security drivers might fail to load.', action=A('set_reg', 'Turn on', 'Turn on LSA protection? A restart is needed.', hive='HKLM', path=r'SYSTEM\CurrentControlSet\Control\Lsa', name='RunAsPPL', value=1, kind='dword', reboot=True)))
    if p and 2 not in [int(x) for x in as_list(p.get('vbs')) if str(x).isdigit()]:
        out.append(F('system', 'hvci', 'low', 'Core Isolation (memory integrity) is off', 'Memory integrity uses the processor to stop tampering with Windows itself.', 'Malicious or vulnerable drivers can take over the kernel.', fix='Windows Security > Device security > Core isolation.', action=A('open_settings', 'Open settings', 'Open Core Isolation settings?', page='windowsdefender://coreisolation')))
    if reg_get(HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'NoDriveTypeAutoRun', 0) != 255:
        out.append(F('system', 'autorun', 'low', 'AutoRun is not fully off', 'AutoRun can start programs when a USB drive or disc is connected.', 'An infected USB stick can run by itself.', fix='Turn it off.', action=A('set_reg', 'Turn off', 'Turn off AutoRun for all drives?', hive='HKLM', path=r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', name='NoDriveTypeAutoRun', value=255, kind='dword')))
    try:
        for line in open(HOSTS_FILE, encoding='latin-1'):
            parts = line.split('#', 1)[0].split()
            if len(parts) >= 2 and 'MySecurity' not in line and 'MyConnections' not in line:
                for n in parts[1:]:
                    if IMPORTANT_HOSTS.search(n):
                        out.append(F('system', 'hosts:' + n, 'high', f'The hosts file redirects {n}', 'The hosts file overrides where site names lead.', 'Malware uses it to send you to fake sites or stop antivirus updating.', f'{parts[0]} {n}', f'If you did not add this line, remove it from {HOSTS_FILE}.', A('remove_hosts_line', 'Remove line', f'Remove {n} from the hosts file?', name=n), Active=True))
    except OSError:
        pass
    inet = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if reg_get(HKCU, inet, 'ProxyEnable', 0) and reg_get(HKCU, inet, 'ProxyServer', ''):
        out.append(F('system', 'proxy', 'high', 'Web traffic goes through a proxy', 'A proxy relays your web traffic through another computer.', 'A malicious proxy can read and change what you browse.', reg_get(HKCU, inet, 'ProxyServer', ''), 'Turn it off if you or your workplace did not set it.', A('set_reg', 'Turn off proxy', 'Turn off the Windows proxy setting?', hive='HKCU', path=inet, name='ProxyEnable', value=0, kind='dword')))
    if reg_get(HKCU, inet, 'AutoConfigURL', ''):
        out.append(F('system', 'pac', 'medium', 'A proxy script controls your web traffic', 'A script decides which proxy each site uses.', 'Malware sets this to intercept traffic. Workplaces use it legitimately.', reg_get(HKCU, inet, 'AutoConfigURL', ''), 'Remove it if your workplace did not set it: Settings > Network & internet > Proxy.', A('open_settings', 'Open proxy settings', 'Open proxy settings?', page='ms-settings:network-proxy')))
    for r in as_list(p.get('roots')):
        if isinstance(r, dict):
            out.append(F('system', 'root:' + str(r.get('Thumb')), 'medium', 'A security certificate was added for your account only', 'Root certificates decide which secure sites your PC trusts.', 'Whoever holds this one can impersonate any secure website. Some VPN and developer tools add these on purpose.', r.get('Subject'), 'If you do not recognise it, remove it in certmgr.msc under Trusted Root Certification Authorities.'))
    for s in as_list(p.get('badroots')):
        out.append(F('system', 'badroot:' + str(s), 'critical', 'A known-dangerous root certificate is installed', 'This certificate was shipped by adware or vendors and its private key is public.', 'Anyone can impersonate secure sites to this PC.', s, 'Remove it in certlm.msc under Trusted Root Certification Authorities.', Active=True))
    if not admin:
        out.append(need_admin('system', 'Secure Boot, BitLocker and Defender exclusions'))
    return out


# ---------------------------------------------------------------- 3. Shares and SMB

SHARES_PS = r'''
$cfg = Get-SmbServerConfiguration
ConvertTo-Json -InputObject @{
  shares = @(Get-CimInstance Win32_Share | ForEach-Object { $n = [string]$_.Name; [pscustomobject]@{ Name = $n; Path = [string]$_.Path; Type = [long]$_.Type; Desc = [string]$_.Description
     Access = @(Get-SmbShareAccess -Name $n | ForEach-Object { [pscustomobject]@{ Who = [string]$_.AccountName; Right = [string]$_.AccessRight; Control = [string]$_.AccessControlType } }) } })
  smb1 = $(if ($cfg) { [bool]$cfg.EnableSMB1Protocol } else { $null })
  signing = $(if ($cfg) { [bool]$cfg.RequireSecuritySignature } else { $null })
  encrypt = $(if ($cfg) { [bool]$cfg.EncryptData } else { $null })
} -Depth 5 -Compress
'''
OPEN_TO_ALL = re.compile(r'^(everyone|.*\\everyone|nt authority\\anonymous logon|builtin\\guests|builtin\\users|.*\\authenticated users)$', re.I)


def scan_shares(ctx):
    d, out = ps_one(SHARES_PS, timeout=45), []
    lanman = r'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    smb1 = d.get('smb1')
    if smb1 is None:
        smb1 = reg_get(HKLM, lanman, 'SMB1', None) not in (0, None) or reg_get(HKLM, r'SYSTEM\CurrentControlSet\Services\mrxsmb10', 'Start', 4) != 4
    if smb1:
        out.append(F('shares', 'smb1', 'critical', 'SMBv1 is on', 'SMBv1 is the 1980s version of Windows file sharing.', 'WannaCry and NotPetya spread through it and shut down hospitals and shipping companies worldwide. Nothing modern needs it.', fix='Turn it off. A restart may be needed. Only very old NAS boxes or scanners could be affected.', action=A('disable_smb1', 'Turn off SMBv1', 'Turn off SMBv1?\n\nVery old NAS boxes and scanners may stop connecting. A restart may be needed.') if ctx['admin'] else None, Active=True))
    else:
        out.append(F('shares', 'smb1', 'ok', 'SMBv1 is off', 'The old, dangerous version of file sharing is disabled.'))
    if d.get('signing') is False:
        out.append(F('shares', 'signing', 'medium', 'SMB signing is not required', 'Signing proves that file-sharing traffic has not been changed in transit.', 'An attacker on your network can relay your sign-in to take over a share ("NTLM relay").', fix='Require signing. Some very old devices will stop connecting.', action=A('smb_signing', 'Require signing', 'Require SMB signing?\n\nVery old devices may stop connecting to this PC\'s shares.')))
    if reg_get(HKLM, r'SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation', 'AllowInsecureGuestAuth', 0) == 1:
        out.append(F('shares', 'guestauth', 'high', 'This PC connects to shares with no login', 'Insecure guest logons let this PC open network shares without authenticating.', 'An attacker\'s fake share can feed you malicious files.', fix='Turn it off.', action=A('set_reg', 'Turn off', 'Stop connecting to shares without a login?', hive='HKLM', path=r'SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation', name='AllowInsecureGuestAuth', value=0, kind='dword')))
    if reg_get(HKLM, r'SYSTEM\CurrentControlSet\Control\Lsa', 'RestrictAnonymous', 0) == 0:
        out.append(F('shares', 'anon', 'low', 'Anonymous visitors can list shares', 'Windows answers some questions from connections with no login.', 'Helps attackers map this PC before they attack.', fix='Restrict it. Rarely causes problems.', action=A('set_reg', 'Restrict', 'Stop anonymous visitors from listing shares?', hive='HKLM', path=r'SYSTEM\CurrentControlSet\Control\Lsa', name='RestrictAnonymous', value=1, kind='dword')))
    shares = [s for s in as_list(d.get('shares')) if isinstance(s, dict)]
    default = 0
    for s in shares:
        name, access = s.get('Name', ''), [a for a in as_list(s.get('Access')) if isinstance(a, dict)]
        if name.upper() in ('IPC$', 'ADMIN$', 'PRINT$') or re.match(r'^[A-Za-z]\$$', name):
            default += 1
            continue
        open_all = [a for a in access if a.get('Control') == 'Allow' and OPEN_TO_ALL.match(a.get('Who', ''))]
        writable = [a for a in open_all if a.get('Right') in ('Full', 'Change')]
        evidence = '; '.join(f"{a.get('Who')}: {a.get('Right')}" for a in access) or 'Permissions could not be read'
        hidden = name.endswith('$')
        sev, why = ('critical' if writable and s.get('Path', '').rstrip('\\').count('\\') == 0 else 'high' if writable else 'medium' if open_all or hidden else 'low'), ''
        if writable:
            why = 'Everyone who can reach this PC can change or delete these files, and ransomware encrypts every share it can write to.'
        elif open_all:
            why = 'Everyone who can reach this PC can read these files.'
        elif hidden:
            why = 'A share with a name ending in $ is hidden from network browsing. Attackers create these. Check you know why it exists.'
        else:
            why = 'Only named accounts can reach it. Fine if you still use it.'
        out.append(F('shares', 'share:' + name, sev, f'Shared folder: {name}', f"{s.get('Path') or 'no path'} is shared on the network.", why, evidence, 'Stop sharing it if you no longer need it. The files stay where they are.', A('remove_share', 'Stop sharing', f'Stop sharing "{name}"?\n\n{s.get("Path")}\n\nThe files are not deleted.', name=name)))
    if default:
        out.append(F('shares', 'default', 'info', f'{default} built-in admin shares', 'Windows creates C$, ADMIN$ and IPC$ for administrators. Only administrators can use them.', 'They are normal, but a stolen admin password opens them.'))
    if not ctx['admin']:
        out.append(need_admin('shares', 'Who has access to each share'))
    return out


# ---------------------------------------------------------------- 4. Protocols

PROTOCOLS_PS = r'''
$f = @{}; foreach ($n in 'MicrosoftWindowsPowerShellV2Root','TelnetClient','TFTP','SMB1Protocol') { $x = Get-WindowsOptionalFeature -Online -FeatureName $n; if ($x) { $f[$n] = [string]$x.State } }
ConvertTo-Json -InputObject @{ features = $f
  netbios = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Description; Option = [int]$_.TcpipNetbiosOptions } })
} -Depth 4 -Compress
'''


def _tls_enabled(proto, side):
    return reg_get(HKLM, rf'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{proto}\{side}', 'Enabled', None)


def scan_protocols(ctx):
    d, out, admin = ps_one(PROTOCOLS_PS, timeout=90), [], ctx['admin']
    features = d.get('features') if isinstance(d.get('features'), dict) else {}
    dns_pol = r'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    if reg_get(HKLM, dns_pol, 'EnableMulticast', 1) != 0:
        out.append(F('protocols', 'llmnr', 'medium', 'LLMNR is on', 'When a name can\'t be found in DNS, Windows shouts the question to the whole local network.', 'An attacker on the same Wi-Fi answers "that\'s me" and collects your password hash. Tools for this are free and common.', fix='Turn it off. Normal DNS keeps working.', action=A('set_reg', 'Turn off', 'Turn off LLMNR?', hive='HKLM', path=dns_pol, name='EnableMulticast', value=0, kind='dword')))
    else:
        out.append(F('protocols', 'llmnr', 'ok', 'LLMNR is off', 'Windows does not broadcast name look-ups.'))
    nb = [a for a in as_list(d.get('netbios')) if isinstance(a, dict) and a.get('Option') != 2]
    if nb:
        out.append(F('protocols', 'netbios', 'medium', 'NetBIOS is on', 'A 1980s way of finding PCs by name.', 'Same trick as LLMNR: it can be spoofed to capture password hashes. It also reveals the PC and user name.', ', '.join(a['Name'] for a in nb), 'Turn it off. Only very old devices use it.', A('disable_netbios', 'Turn off', 'Turn off NetBIOS on every network adapter?')))
    lsa = r'SYSTEM\CurrentControlSet\Control\Lsa'
    if reg_get(HKLM, lsa, 'LmCompatibilityLevel', 3) < 3:
        out.append(F('protocols', 'ntlm', 'high', 'Weak password protocols are allowed (LM / NTLMv1)', 'These decide how Windows proves your password over the network.', 'Captured LM and NTLMv1 responses can be cracked in minutes.', evidence=f"LmCompatibilityLevel = {reg_get(HKLM, lsa, 'LmCompatibilityLevel', 3)}", fix='Use NTLMv2 only.', action=A('set_reg', 'Use NTLMv2 only', 'Use NTLMv2 only?\n\nVery old devices may stop connecting.', hive='HKLM', path=lsa, name='LmCompatibilityLevel', value=5, kind='dword')))
    if reg_get(HKLM, lsa, 'NoLMHash', 1) == 0:
        out.append(F('protocols', 'lmhash', 'high', 'Windows stores weak LM password hashes', 'LM is a broken format from the 1980s.', 'A stolen LM hash reveals the password almost instantly.', fix='Stop storing them. Change your password afterwards.', action=A('set_reg', 'Stop storing', 'Stop storing LM password hashes?', hive='HKLM', path=lsa, name='NoLMHash', value=1, kind='dword')))
    wd = r'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    if reg_get(HKLM, wd, 'UseLogonCredential', 0) == 1:
        out.append(F('protocols', 'wdigest', 'critical', 'Passwords are kept in memory as plain text (WDigest)', 'WDigest is a legacy sign-in method that keeps the actual password in memory.', 'Attackers switch this on so they can read passwords out of memory. On a modern PC this setting strongly suggests tampering.', fix='Turn it off.', action=A('set_reg', 'Turn off', 'Turn off WDigest password caching?', hive='HKLM', path=wd, name='UseLogonCredential', value=0, kind='dword'), Active=True))
    for proto, sev, why in (('SSL 2.0', 'high', 'Broken for decades.'), ('SSL 3.0', 'high', 'Broken by the POODLE attack.'), ('TLS 1.0', 'medium', 'Retired by all major browsers.'), ('TLS 1.1', 'medium', 'Retired by all major browsers.')):
        vals = [_tls_enabled(proto, 'Client'), _tls_enabled(proto, 'Server')]
        args = dict(proto=proto)
        if any(v not in (None, 0) for v in vals):
            out.append(F('protocols', proto, sev, f'{proto} is switched on', 'An old version of the encryption that protects network traffic.', why + ' A downgrade attack can force a connection to use it.', fix='Turn it off. A restart is needed.', action=A('disable_tls', 'Turn off', f'Turn off {proto}? A restart is needed. Very old apps may stop connecting.', **args)))
        elif any(v is None for v in vals) and proto.startswith('TLS'):
            out.append(F('protocols', proto, 'low', f'{proto} is not explicitly off', 'Windows decides by itself whether this old encryption is available.', why, fix='Turn it off for certainty. A restart is needed.', action=A('disable_tls', 'Turn off', f'Turn off {proto}? A restart is needed. Very old apps may stop connecting.', **args)))
    ts = r'SYSTEM\CurrentControlSet\Control\Terminal Server'
    if reg_get(HKLM, ts, 'fDenyTSConnections', 1) == 0:
        if reg_get(HKLM, ts + r'\WinStations\RDP-Tcp', 'UserAuthentication', 1) == 0:
            out.append(F('protocols', 'nla', 'critical', 'Remote Desktop accepts connections before login', 'Network Level Authentication makes people prove who they are before the login screen appears.', 'Without it, attackers can reach the Remote Desktop code without a password. BlueKeep exploited this.', fix='Require NLA.', action=A('set_reg', 'Require NLA', 'Require Network Level Authentication for Remote Desktop?', hive='HKLM', path=ts + r'\WinStations\RDP-Tcp', name='UserAuthentication', value=1, kind='dword'), Active=True))
        out.append(F('protocols', 'rdp', 'high', 'Remote Desktop is on', 'Other computers can take full control of this PC if they have a password.', 'The most common way ransomware gets in.', fix='Turn it off if you do not use it.', action=A('set_reg', 'Turn off', 'Turn off Remote Desktop?\n\nIf you are connected remotely right now, you will be disconnected.', hive='HKLM', path=ts, name='fDenyTSConnections', value=1, kind='dword')))
    else:
        out.append(F('protocols', 'rdp', 'ok', 'Remote Desktop is off', 'Nobody can take control of this PC with Remote Desktop.'))
    if features.get('MicrosoftWindowsPowerShellV2Root') == 'Enabled':
        out.append(F('protocols', 'psv2', 'medium', 'PowerShell 2.0 is installed', 'An old version of PowerShell with no script logging or malware scanning.', 'Attackers launch it to hide from antivirus.', fix='Remove it. Almost nothing needs it.', action=A('disable_feature', 'Remove', 'Remove PowerShell 2.0?', feature='MicrosoftWindowsPowerShellV2Root')))
    for f, name in (('TelnetClient', 'Telnet client'), ('TFTP', 'TFTP client')):
        if features.get(f) == 'Enabled':
            out.append(F('protocols', f, 'low', f'{name} is installed', 'An unencrypted network tool from long ago.', 'Attackers use built-in tools like this to move files or reach other devices.', fix='Remove it if you do not use it.', action=A('disable_feature', 'Remove', f'Remove the {name}?', feature=f)))
    if not admin:
        out.append(need_admin('protocols', 'Optional Windows features'))
    return out


# ---------------------------------------------------------------- 5. Accounts and local admin rights

ACCOUNTS_PS = r'''
$grp = Get-LocalGroup -SID 'S-1-5-32-544'
$m = @(); try { $m = @(Get-LocalGroupMember -Group $grp -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Sid = [string]$_.SID; Source = [string]$_.PrincipalSource; Class = [string]$_.ObjectClass } }) } catch {
  $m = @(([ADSI]('WinNT://./' + $grp.Name + ',group')).psbase.Invoke('Members') | ForEach-Object { [pscustomobject]@{ Name = [string]$_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null); Sid=''; Source=''; Class='' } }) }
ConvertTo-Json -InputObject @{ group = [string]$grp.Name; admins = $m; me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; meName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  users = @(Get-LocalUser | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Sid = [string]$_.SID; Enabled = [bool]$_.Enabled; PwRequired = [bool]$_.PasswordRequired; PwExpires = ($_.PasswordExpires -ne $null); PwSet = $(if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd') } else { '' }); Last = $(if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { '' }); Desc = [string]$_.Description } })
} -Depth 4 -Compress
'''


def scan_accounts(ctx):
    d, out = ps_one(ACCOUNTS_PS, timeout=45), []
    users = [u for u in as_list(d.get('users')) if isinstance(u, dict)]
    admins = [a for a in as_list(d.get('admins')) if isinstance(a, dict)]
    me = d.get('me', '')
    by_sid = {u['Sid']: u for u in users}
    for a in admins:
        sid, u = a.get('Sid', ''), by_sid.get(a.get('Sid', ''), {})
        if u and not u.get('Enabled'):
            continue
        builtin = sid.endswith('-500')
        is_me = sid == me
        sev = 'info' if is_me else 'medium'
        title = f"Administrator: {a.get('Name')}" + (' (you)' if is_me else '')
        why = 'You are signed in as an administrator. Malware you run by accident gets admin rights as soon as you click Yes on a prompt.' if is_me else 'This account has full control of the PC.'
        # never offer to remove the signed-in user or the built-in account: that could lock the owner out
        act = None if is_me or builtin or a.get('Class') == 'Group' else A('remove_admin', 'Remove admin rights', f"Remove administrator rights from {a.get('Name')}?\n\nThe account stays, as a standard user.", member=a.get('Name'))
        out.append(F('accounts', 'admin:' + (sid or a.get('Name', '')), sev, title, 'Administrators can install anything, read every file and turn off protection.', why, f"Source: {a.get('Source') or 'unknown'}", 'Remove admin rights from any account that does not need them.', act))
    enabled_admins = len([a for a in admins if by_sid.get(a.get('Sid', ''), {'Enabled': True}).get('Enabled')])
    if enabled_admins > 2:
        out.append(F('accounts', 'many-admins', 'medium', f'{enabled_admins} accounts have administrator rights', 'Each administrator is one more password that can take over the PC.', 'One or two is normal.', fix='Review the accounts above.'))
    hidden = {n for n, v in reg_values(HKLM, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList') if v == 0}
    for u in users:
        n = u.get('Name', '')
        sid = u.get('Sid', '')
        if sid.endswith('-500') and u.get('Enabled'):
            out.append(F('accounts', 'builtin', 'medium', 'The built-in Administrator account is on', 'This account exists on every Windows PC, and its UAC prompts are off.', 'Attackers know the name, so only the password is left to guess.', n, 'Turn it off.', A('disable_account', 'Turn off', f'Turn off the built-in account {n}?\n\nMake sure you have another administrator account first.', name=n, sid=sid)))
        if sid.endswith('-501') and u.get('Enabled'):
            out.append(F('accounts', 'guest', 'high', 'The Guest account is on', 'Guest lets anyone use this PC with no password.', 'Gives attackers a free way in over the network.', n, 'Turn it off.', A('disable_account', 'Turn off', f'Turn off the Guest account ({n})?', name=n, sid=sid), Active=True))
        if not u.get('Enabled'):
            continue
        if n.endswith('$'):
            out.append(F('accounts', 'dollar:' + n, 'critical', f'Disguised account: {n}', 'Account names ending in $ are hidden from normal user lists. Real accounts almost never use this.', 'Intruders create these to keep a way back in.', n, 'Turn it off, then investigate how it got here.', A('disable_account', 'Turn off', f'Turn off the account {n}?', name=n, sid=sid), Active=True))
        if n in hidden:
            out.append(F('accounts', 'hidden:' + n, 'high', f'Hidden account: {n}', 'This account is set to stay off the sign-in screen.', 'Software sometimes does this, but so do intruders keeping a back door.', n, 'Turn it off unless you know what created it.', A('disable_account', 'Turn off', f'Turn off the hidden account {n}?', name=n, sid=sid), Active=True))
        if not u.get('PwRequired') and not sid.endswith(('-501', '-503', '-504')):
            out.append(F('accounts', 'nopw:' + n, 'low', f'{n} is allowed to have no password', 'Windows does not insist on a password for this account. Many PCs show this even when a password is set, because it only reports what is required.', 'If this account really has no password, anyone with access can sign in.', fix='Make sure this account has a strong password, in Settings > Accounts.', action=A('open_settings', 'Open accounts', 'Open account settings?', page='ms-settings:otherusers')))
        if u.get('PwSet') and u['PwSet'] < (dt.date.today() - dt.timedelta(days=730)).isoformat() and not sid.endswith(('-501', '-503', '-504')):
            out.append(F('accounts', 'oldpw:' + n, 'low', f"{n}'s password is over two years old", f"It was last changed on {u['PwSet']}.", 'Old passwords are more likely to have leaked in a data breach.', fix='Change it, and use a different password on every site.'))
    wl = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if str(reg_get(HKLM, wl, 'AutoAdminLogon', '0')) == '1':
        has_pw = bool(reg_get(HKLM, wl, 'DefaultPassword', ''))
        out.append(F('accounts', 'autologon', 'high' if has_pw else 'medium', 'Windows signs in by itself', 'This PC goes straight to the desktop at startup.', 'Anyone who turns it on is signed in as you.' + (' Your password is also stored as plain text in the registry.' if has_pw else ''), reg_get(HKLM, wl, 'DefaultUserName', ''), 'Turn it off.', A('disable_autologon', 'Turn off', 'Turn off automatic sign-in and delete any password stored for it?'), Active=has_pw))
    if not any(a.get('Sid') == me for a in admins) and d:
        out.append(F('accounts', 'std-user', 'ok', 'You use a standard account', 'Good practice: malware you run by accident is limited.'))
    return out


# ---------------------------------------------------------------- 6. Services and backdoors

SERVICES_PS = r'''
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, Description, State, StartMode, PathName, StartName, ProcessId | ConvertTo-Json -Compress
'''
NO_DISABLE_SERVICES = {'windefend', 'mpssvc', 'bfe', 'rpcss', 'dcomlaunch', 'lsm', 'samss', 'eventlog', 'wuauserv', 'cryptsvc', 'dhcp', 'dnscache', 'nsi', 'winmgmt', 'plugplay', 'power', 'sense', 'wscsvc', 'csfalconservice', 'trustedinstaller'}


def scan_services(ctx):
    rows = [s for s in run_powershell(SERVICES_PS, timeout=60) if isinstance(s, dict) and s.get('Name')]
    enabled = [s for s in rows if s.get('StartMode') != 'Disabled']
    paths = {s['Name']: exe_from_command(s.get('PathName')) for s in enabled}
    signs = sign_info([p for p in paths.values() if p and not in_windows(p) and os.path.isfile(p)])
    out, windows_ok = [], 0
    for s in enabled:
        name, disp, cmd = s['Name'], s.get('DisplayName') or s['Name'], s.get('PathName') or ''
        path, info = paths[name], signs.get(paths[name], {})
        running = s.get('State') == 'Running'
        state = f"{s.get('State')}, starts: {s.get('StartMode')}, runs as {s.get('StartName') or 'unknown'}"
        low = (name + ' ' + disp + ' ' + path).lower()
        dis = A('disable_service', 'Stop and disable', f'Stop and disable the service "{disp}" ({name})?\n\nYou can undo this from the Blocked tab while My Security is open.', name=name, display=disp, old_start=s.get('StartMode'), was_running=running)
        if name.lower() in NO_DISABLE_SERVICES:
            dis = None
        risky = RISKY_SERVICES.get(name)
        spy = next((v for k, v in SPYWARE_NAMES.items() if k in low), '')
        tool = next((v for k, v in REMOTE_TOOLS.items() if k in low), '')
        flagged = False
        if spy:
            flagged = True
            out.append(F('services', name, 'critical', f'Spy software service: {disp}', f'This service matches {spy}, a known keylogger or monitoring product.', 'It can record what you type and see, and send it to someone else.', cmd, 'If you did not install it for monitoring your own PC, disable it and uninstall it.', dis, Active=True))
        elif tool and running:
            flagged = True
            out.append(F('services', name, 'high', f'Remote-control service: {disp}', f'{tool} lets someone control this PC remotely, and this service is running in the background.', 'Normal if you or your IT team set it up. Scammers and intruders install the same tools because antivirus trusts them.', cmd, 'If you do not recognise it, disable it and uninstall it.', dis))
        elif risky and (running or s.get('StartMode') == 'Auto') and risky[0] != 'info':
            flagged = True
            out.append(F('services', name, risky[0], f'{risky[1]} is enabled', risky[2], 'Every enabled network service is something an attacker can target.', state, 'Disable it if you do not use it.', dis))
        if path and USER_WRITABLE.search(path):
            flagged = True
            out.append(F('services', name + ':writable', 'critical', f'Service runs from a temporary or public folder: {disp}', 'Windows services run with high privileges and belong in Program Files or Windows.', 'Any program can replace that file and run with full control.', cmd, 'Disable it and scan the file.', dis, Active=True))
        elif path and is_unsigned(info) and not in_windows(path):
            flagged = True
            bad = info.get('Status') == 'HashMismatch'
            out.append(F('services', name + ':unsigned', 'critical' if bad else 'medium', ('Tampered service file: ' if bad else 'Unsigned service: ') + disp, 'The program behind this service has ' + ('a broken signature, so it was changed after it was published.' if bad else 'no digital signature, so its publisher cannot be verified.'), 'Services run with high privileges and start with Windows.', cmd, 'Check you recognise it. Disable it if you do not.', dis, Active=bad))
        if cmd and not cmd.startswith('"') and ' ' in path and '\\' in path and path.lower().endswith('.exe') and not in_windows(path):
            flagged = True
            out.append(F('services', name + ':unquoted', 'medium', f'Unsafe service path: {disp}', 'The path has spaces and no quotes, so Windows tries "C:\\Program.exe" and similar first.', 'A program dropped in the right place runs with the service\'s privileges.', cmd, 'Add quotes around the path.', A('quote_service', 'Fix path', f'Add quotes to the path of "{disp}"?', name=name, path=path)))
        if path and not os.path.isfile(path) and path.lower().endswith('.exe') and s.get('StartMode') == 'Auto':
            flagged = True
            out.append(F('services', name + ':missing', 'low', f'Service points to a missing file: {disp}', 'The program this service starts no longer exists.', 'Leftover from an uninstall. An attacker who can create that file gets its privileges.', cmd, 'Disable it.', dis))
        if not flagged:
            if in_windows(path):
                windows_ok += 1
            elif running:
                out.append(F('services', name, 'info', disp, s.get('Description') or 'A third-party service.', '', f"{info.get('Publisher') or 'Publisher unknown'} · {state}", '', dis, Publisher=info.get('Publisher', '')))
    out.append(F('services', 'windows-ok', 'ok', f'{windows_ok} Windows services look normal', 'They run from the Windows folder and match no risky pattern.'))
    return out


# ---------------------------------------------------------------- 7. Malware, spyware, keyloggers, persistence

MALWARE_PS = r'''
ConvertTo-Json -InputObject @{
  threats = @(Get-MpThreat | ForEach-Object { [pscustomobject]@{ Id = [string]$_.ThreatID; Name = [string]$_.ThreatName; Sev = [int]$_.SeverityID; Active = [bool]$_.IsActive; Resources = @($_.Resources) } })
  detections = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 30 | ForEach-Object { [pscustomobject]@{ Id = [string]$_.ThreatID; When = $_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm'); Status = [int]$_.ThreatStatusID; Action = [int]$_.CleaningActionID; Process = [string]$_.ProcessName; Resources = @($_.Resources) } })
  tasks = @(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { $t = $_; foreach ($a in @($t.Actions)) { if ($a.Execute) { [pscustomobject]@{ Path = [string]$t.TaskPath; Name = [string]$t.TaskName; Exe = [string]$a.Execute; Args = [string]$a.Arguments; Author = [string]$t.Author; Hidden = [bool]$t.Settings.Hidden } } } })
  wmi = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Class = [string]$_.CimClass.CimClassName; Cmd = [string]$_.CommandLineTemplate; Script = [string]$_.ScriptText } })
} -Depth 5 -Compress
'''
# Windows names that belong in System32
SYSTEM_NAMES = {'svchost', 'lsass', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'spoolsv', 'taskhostw', 'dllhost', 'conhost', 'runtimebroker', 'rundll32', 'searchindexer'}
LOLBINS = r'(?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|installutil|forfiles|wmic)'
# what a process's command line reveals: (pattern, severity, title, plain explanation)
COMMAND_RULES = [
    (r'(mimi.?katz|sekurlsa|procdump.*lsass|comsvcs(\.dll)?.*minidump|lsass.*\.dmp)', 'critical', 'Trying to steal passwords from memory', 'This command reads Windows\' password store from memory. Password-stealing tools do this.'),
    (r'(vssadmin.*delete.*shadows|wbadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no)', 'critical', 'Deleting backups (ransomware behaviour)', 'Ransomware deletes restore points and backups just before encrypting files.'),
    (r'(Set-MpPreference.*(DisableRealtime|ExclusionPath)|Add-MpPreference.*Exclusion|netsh.*firewall.*(set.*opmode.*disable|state\s+off)|sc\s+(stop|delete)\s+windefend)', 'critical', 'Trying to turn off security protection', 'Malware commonly disables antivirus or the firewall first.'),
    (r'(net1?\s+user\s+\S+\s+\S+\s+/add|net1?\s+localgroup\s+administrators\s+\S+\s+/add)', 'high', 'Creating an account or admin', 'This creates a new account or gives one administrator rights, which intruders do to keep access.'),
    (r'(login data|\\cookies\b|local state|logins\.json|key4\.db).*(copy|type|sqlite|upload)|(copy|type|sqlite).*(login data|\\cookies\b|logins\.json|key4\.db)', 'critical', 'Reading saved browser passwords or cookies', 'Sign-in cookies and saved passwords let thieves get into your accounts without a password.'),
    (r'--remote-debugging-(port|pipe)|--load-extension=', 'high', 'Browser started in a remotely controllable mode', 'Cookie-stealing malware launches a browser this way to read sign-in tokens. Developers and test tools use it as well.'),
    (r'(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|net\.webclient|start-bitstransfer)\b.*(iex|invoke-expression|\|\s*iex)|(iex|invoke-expression).*(iwr|irm|downloadstring|net\.webclient)', 'critical', 'Downloading a script and running it straight away', 'This is how many infections start, including fake "verify you are human" pages.'),
    (r'certutil.*(-urlcache|-decode)|bitsadmin.*/transfer', 'high', 'Using a Windows tool to download a file', 'Attackers use built-in tools to fetch malware so that it looks normal.'),
    (r'mshta(\.exe)?["\s]+(https?:|javascript:|vbscript:)', 'critical', 'Running a script directly from a web address', 'mshta runs web content as a program, with no browser protections.'),
    (r'(regsvr32.*/i:https?:|rundll32.*(javascript:|https?:))', 'critical', 'Loading code from the internet', 'This uses a trusted Windows tool to run code fetched from the internet.'),
    (r'(schtasks.*/create.*(powershell|cmd|mshta|wscript|http|\\temp\\|\\appdata\\))', 'high', 'Creating a scheduled task to start a script', 'Scheduled tasks are how malware survives a restart.'),
    (r'reg(\.exe)?\s+add.*\\currentversion\\run', 'high', 'Adding itself to Windows startup', 'Malware adds itself here so that it survives a restart.'),
    (r'(-w(indowstyle)?\s+hidden).*(http|-e|iex|download)', 'high', 'Running a hidden PowerShell window', 'A hidden window that also downloads or decodes something is a strong warning sign.'),
    (r'wevtutil\s+cl\b|clear-eventlog', 'critical', 'Erasing the Windows event logs', 'Intruders erase logs to cover their tracks.'),
]
COMMAND_RULES = [(re.compile(p, re.I | re.S), s, t, w) for p, s, t, w in COMMAND_RULES]
ENCODED_RE = re.compile(r'(?:^|\s)-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})', re.I)
BROWSERS = {'chrome', 'msedge', 'firefox', 'opera', 'brave', 'vivaldi', 'iexplore', 'chromium', 'arc'}
OFFICE = {'winword', 'excel', 'powerpnt', 'outlook', 'onenote', 'mspub', 'acrord32', 'acrobat', 'foxitpdfreader'}
CHILD_ALARM = {'powershell', 'pwsh', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'msbuild', 'installutil', 'wmic', 'hh'}


def decode_encoded(cmd):
    m = ENCODED_RE.search(cmd or '')
    if not m:
        return ''
    try:
        raw = m.group(1)
        return base64.b64decode(raw + '=' * (-len(raw) % 4)).decode('utf-16-le', 'replace')
    except ValueError:
        return ''


def judge_process(name, path, cmd, parent, sign=None):
    """(severity, [(title, explanation)]) for one process, from what it is, where it lives and what it was told to do."""
    low, hits = name.lower(), []
    plain = decode_encoded(cmd)
    text = (cmd or '') + ('\n' + plain if plain else '')
    for rx, sev, title, why in COMMAND_RULES:
        if rx.search(text):
            hits.append((sev, title, why))
    if plain and low in ('powershell', 'pwsh') and not hits:
        hits.append(('medium', 'Running a hidden (encoded) PowerShell command', 'The command is scrambled so that people can\'t read it. Some software does this routinely, and attackers do it to hide. The decoded text is shown below.'))
    p = str(parent or '').lower()
    if low in CHILD_ALARM and p in OFFICE:
        hits.append(('critical', f'{parent} started {name}', 'Documents should not start command tools. This is how malicious macros and attachments take over a PC.'))
    elif low in CHILD_ALARM and p in BROWSERS:
        hits.append(('high', f'Your browser ({parent}) started {name}', 'A web page should not be able to start a command tool. This can be a drive-by infection. Some extensions do this legitimately.'))
    if path:
        if low in SYSTEM_NAMES and not in_windows(path):
            hits.append(('critical', 'Windows name, wrong location', f'It is named after a Windows file but runs from {path}. This is a common malware disguise.'))
        if USER_WRITABLE.search(path) and sign is not None and is_unsigned(sign):
            hits.append(('high', 'Unsigned program in a temporary or public folder', 'Installed programs live in Program Files. Malware runs from places anyone can write to.'))
        if sign and sign.get('Status') == 'HashMismatch':
            hits.append(('critical', 'Program file has been tampered with', 'Its digital signature no longer matches its contents.'))
    tool = next((v for k, v in REMOTE_TOOLS.items() if low.startswith(k)), '')
    if tool:
        hits.append(('medium', f'Remote-control tool running: {tool}', 'Normal if you set it up. Scammers and intruders use the same tool.'))
    spy = next((v for k, v in SPYWARE_NAMES.items() if k.replace(' ', '') in low), '')
    if spy:
        hits.append(('critical', f'Known spy software: {spy}', 'This product records what you type or see.'))
    if not hits:
        return '', []
    hits.sort(key=lambda h: -SEV_RANK[h[0]])
    return hits[0][0], [(t, w) for _s, t, w in hits]


def _check_autostart(key, source, cmd, out, signs, action, label):
    path = exe_from_command(cmd)
    info = signs.get(path, {})
    low, base = str(cmd).lower(), os.path.splitext(os.path.basename(path))[0].lower()
    plain = decode_encoded(cmd)
    sev, why = '', ''
    rule = next(((s, t, w) for rx, s, t, w in COMMAND_RULES if rx.search(str(cmd) + '\n' + plain)), None)
    if rule:
        sev, why = rule[0], f'{rule[1]}. {rule[2]}'
    elif re.search(LOLBINS + r'(\.exe)?["\s]', low) and re.search(r'(http|-enc|-e\s|hidden|\\temp\\|\\appdata\\|\\users\\public\\)', low):
        sev, why = 'high', 'A Windows scripting tool starts automatically and runs something from the internet or a user folder.'
    elif USER_WRITABLE.search(path):
        sev, why = 'high' if is_unsigned(info) else 'medium', 'It starts automatically from a temporary or public folder.'
    elif base in SYSTEM_NAMES and not in_windows(path):
        sev, why = 'critical', 'It uses the name of a Windows file but lives elsewhere.'
    elif info.get('Status') == 'HashMismatch':
        sev, why = 'critical', 'Its digital signature is broken, so the file was changed after publishing.'
    elif is_unsigned(info) and APPDATA_RE.search(path):
        sev, why = 'medium', 'An unsigned program starts automatically from your user folder.'
    elif path and not os.path.exists(path) and '\\' in path and not in_windows(path):
        sev, why = 'low', 'It points to a file that no longer exists: a leftover, or a removed infection.'
    if sev:
        out.append(F('malware', key, sev, f'Starts automatically: {label}', f'Found in {source}. Programs listed here run every time Windows starts.', why, str(cmd), 'If you do not recognise it, remove it from startup.', action, Active=sev == 'critical'))
        return True
    return False


def scan_malware(ctx):
    admin, out = ctx['admin'], []
    p = ctx.get('protection') or protection_state()
    d = ps_one(MALWARE_PS, timeout=120)
    mp = p.get('mp') if isinstance(p.get('mp'), dict) else {}
    defender_on = bool(mp.get('Service')) and str(mp.get('Mode', '')).lower().startswith('normal')
    avs = [a for a in as_list(p.get('av')) if isinstance(a, dict) and f"{int(a.get('State') or 0):06x}"[2:4] in ('10', '11')]
    others = [a['Name'] for a in avs if 'defender' not in a['Name'].lower()]
    if defender_on:
        q, f = int(mp.get('QuickAge') or 0), int(mp.get('FullAge') or 0)
        sev = 'high' if q > 30 else 'low' if q > 7 else 'ok'
        out.append(F('malware', 'defender', sev, 'Microsoft Defender scans', f'Last quick scan: {q} days ago. Last full scan: {f if f < 100000 else "never"} days ago.', fix='Run a scan. A quick scan takes minutes; a full scan can take hours and runs in the background.',
                     action=A('defender_scan', 'Quick scan', 'Start a Microsoft Defender quick scan?', kind='quick')))
        out.append(F('malware', 'defender-full', 'info', 'Full system scan', 'A full scan checks every file on the PC.', fix='It can take hours and slows the PC while it runs.', action=A('defender_scan', 'Full scan', 'Start a Microsoft Defender full scan?\n\nThis can take hours.', kind='full')))
    elif others:
        out.append(F('malware', 'other-av', 'info', f"Malware scanning is handled by {', '.join(others)}", 'Windows lets one antivirus lead. Microsoft Defender is not running here, so My Security can\'t start antivirus scans or read detections.', 'The checks below still run, but they look for warning signs and are not a replacement for an antivirus scan.', fix=f"Use {others[0]}'s own console or your IT team to see detections and run scans."))
    active_threats = [t for t in as_list(d.get('threats')) if isinstance(t, dict)]
    for t in active_threats:
        files = [re.sub(r'^\w+:_?', '', str(r)) for r in as_list(t.get('Resources'))][:6]
        live = bool(t.get('Active'))
        out.append(F('malware', 'threat:' + str(t.get('Id')), 'critical' if live or int(t.get('Sev') or 0) >= 4 else 'high', f"Malware detected: {t.get('Name')}", 'Microsoft Defender identified this threat on this PC.', ('It is active right now.' if live else 'Defender has dealt with it or is waiting for you to decide.') + ' Look up the name to see what it does.', '\n'.join(files), 'Clear it with Defender.', A('defender_remove', 'Remove threats', 'Have Microsoft Defender remove all active threats?') if defender_on and admin else None, Active=live, Link='https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=' + urllib.parse.quote(str(t.get('Name')))))
    live_ids = {str(t.get('Id')) for t in active_threats}
    for det in as_list(d.get('detections'))[:15]:   # already dealt with, but worth knowing about
        if isinstance(det, dict) and str(det.get('Id')) not in live_ids and str(det.get('When', '')) >= (dt.date.today() - dt.timedelta(days=30)).isoformat():
            out.append(F('malware', f"detected:{det.get('Id')}:{det.get('When')}", 'low', f"Defender caught something on {det.get('When')}", 'Microsoft Defender detected a threat recently and dealt with it.', 'Worth knowing where it came from.', '\n'.join(str(r) for r in as_list(det.get('Resources'))[:4]), 'Nothing to do unless it keeps coming back.'))
    autostart = 0
    hkeys = [(HKLM, 'HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'), (HKLM, 'HKLM', r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'), (HKLM, 'HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
             (HKCU, 'HKCU', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'), (HKCU, 'HKCU', r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')]
    entries = [(hn, path, n, str(v)) for h, hn, path in hkeys for n, v in reg_values(h, path) if n]
    folders = [os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'), os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), r'Microsoft\Windows\Start Menu\Programs\StartUp')]
    files = [os.path.join(fd, x) for fd in folders for x in (os.listdir(fd) if os.path.isdir(fd) else []) if x.lower() != 'desktop.ini']
    tasks = [t for t in as_list(d.get('tasks')) if isinstance(t, dict)]
    all_paths = [exe_from_command(e[3]) for e in entries] + files + [os.path.expandvars(str(t.get('Exe')).strip('"')) for t in tasks]
    signs = sign_info([x for x in set(all_paths) if x and not in_windows(x) and os.path.isfile(x)])
    for hn, path, n, v in entries:
        autostart += 1
        _check_autostart(f'run:{hn}:{path}:{n}', f'the registry ({hn}\\...\\{path.rsplit(chr(92), 1)[-1]})', v, out, signs, A('remove_run', 'Remove from startup', f'Remove "{n}" from Windows startup?\n\n{v}\n\nThe program itself is not deleted.', hive=hn, path=path, name=n, value=v), n)
    for x in files:
        autostart += 1
        _check_autostart('startup:' + x, 'the Startup folder', x, out, signs, A('quarantine', 'Move to quarantine', f'Move this startup item to quarantine?\n\n{x}\n\nYou can restore it from the Blocked tab.', path=x), os.path.basename(x))
    for t in tasks:
        cmd = f"{t.get('Exe')} {t.get('Args') or ''}".strip()
        full = str(t.get('Path', '')) + str(t.get('Name', ''))
        autostart += 1
        found = _check_autostart('task:' + full, 'Task Scheduler', cmd, out, signs, A('disable_task', 'Disable task', f'Disable this scheduled task?\n\n{full}\n{cmd}', path=t.get('Path'), name=t.get('Name')), t.get('Name'))
        if not found and t.get('Hidden') and not str(t.get('Path', '')).startswith('\\Microsoft\\'):
            out.append(F('malware', 'hiddentask:' + full, 'medium', f"Hidden scheduled task: {t.get('Name')}", 'This task is set to stay out of the normal Task Scheduler view.', 'Sometimes legitimate software; also how malware stays out of sight.', cmd, 'Disable it if you do not recognise it.', A('disable_task', 'Disable task', f'Disable this scheduled task?\n\n{full}', path=t.get('Path'), name=t.get('Name'))))
    for w in as_list(d.get('wmi')):
        if isinstance(w, dict) and w.get('Name') != 'SCM Event Log Consumer' and (w.get('Cmd') or w.get('Script')):
            out.append(F('malware', 'wmi:' + str(w.get('Name')), 'critical', f"WMI event trigger: {w.get('Name')}", 'WMI can run a command when something happens on the PC. Almost nothing on a home PC uses this.', 'A favourite of advanced malware because it leaves no file in the usual startup places.', w.get('Cmd') or w.get('Script'), 'Have it investigated. Remove it with: Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer.', Active=True))
    ifeo = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    for name in reg_subkeys(HKLM, ifeo):
        dbg = reg_get(HKLM, ifeo + '\\' + name, 'Debugger', '')
        if dbg:
            access = name.lower() in ('sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe')
            sec_tool = name.lower() in ('msmpeng.exe', 'taskmgr.exe', 'procexp.exe', 'procexp64.exe', 'regedit.exe', 'msconfig.exe')
            out.append(F('malware', 'ifeo:' + name, 'critical' if access or sec_tool else 'medium', f'{name} is hijacked' if access or sec_tool else f'{name} starts through another program', 'Windows has an "Image File Execution Options" setting that runs another program in place of this one.', 'On the accessibility tools this gives anyone a command prompt at the login screen with full control, with no password. This is a classic backdoor.' if access else 'Developer tools use this. So does malware.', dbg, 'Remove the setting.', A('remove_ifeo', 'Remove', f'Remove the redirect on {name}?\n\n{dbg}', name=name), Active=access or sec_tool))
    wl = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    shell, userinit = str(reg_get(HKLM, wl, 'Shell', 'explorer.exe')), str(reg_get(HKLM, wl, 'Userinit', ''))
    if shell.strip().lower() not in ('explorer.exe', r'c:\windows\explorer.exe'):
        out.append(F('malware', 'shell', 'critical', 'The Windows desktop start-up has been changed', 'Winlogon\'s Shell setting decides what runs as your desktop.', 'Malware adds itself here to start with every sign-in.', shell, 'Restore it to explorer.exe.', A('set_reg', 'Restore', 'Restore the Windows shell to explorer.exe?', hive='HKLM', path=wl, name='Shell', value='explorer.exe', kind='sz'), Active=True))
    if userinit and userinit.rstrip(', ').lower() not in (rf'{WINDIR}\system32\userinit.exe'.lower(), 'userinit.exe'):
        out.append(F('malware', 'userinit', 'critical', 'The Windows sign-in sequence has been changed', 'Userinit runs at every sign-in.', 'Malware adds itself to this line.', userinit, 'Restore the original.', A('set_reg', 'Restore', 'Restore the Windows sign-in program?', hive='HKLM', path=wl, name='Userinit', value=rf'{WINDIR}\system32\userinit.exe,', kind='sz'), Active=True))
    appinit = reg_get(HKLM, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'AppInit_DLLs', '')
    if appinit:
        out.append(F('malware', 'appinit', 'high', 'A DLL is loaded into every program (AppInit_DLLs)', 'Windows loads this file into every program that uses the normal Windows interface.', 'A common way to spy on or change every program.', appinit, 'Remove the setting if you do not recognise it.', A('set_reg', 'Clear', 'Clear AppInit_DLLs?', hive='HKLM', path=r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', name='AppInit_DLLs', value='', kind='sz')))
    for tool in ('sethc', 'utilman', 'osk', 'magnify', 'narrator'):
        fp = os.path.join(SYSTEM32, tool + '.exe')
        if os.path.isfile(fp):
            desc = sign_info([fp])[fp].get('Description', '')
            if re.match(r'^(windows command processor|windows powershell)', desc, re.I):
                out.append(F('malware', 'swap:' + tool, 'critical', f'{tool}.exe has been replaced with a command prompt', 'Accessibility tools can be started from the login screen.', 'A replaced tool gives anyone complete control with no password.', fp, f'Run: sfc /scannow in an administrator prompt. Treat this PC as compromised.', Active=True))
    # spy software installed by name; capture ability of unsigned running programs
    for app in ctx.get('inventory') or installed_apps():
        low = app['Name'].lower()
        spy = next((v for k, v in SPYWARE_NAMES.items() if k in low), '')
        if spy:
            out.append(F('malware', 'spy-app:' + app['Name'], 'critical', f"Spy software is installed: {app['Name']}", f'This matches {spy}, a keylogger or monitoring product.', 'It can record what you type, your screen and your messages, and send them to someone else.', app.get('Version', ''), 'If you did not install it for your own use, uninstall it, then change your passwords from another device.', A('open_settings', 'Open installed apps', 'Open Installed apps?', page='ms-settings:appsfeatures'), Active=True))
    names = process_snapshot()
    procs = {}
    for pid, (n, _pp) in names.items():
        if pid > 4:
            pth = process_path(pid)
            if pth and not in_windows(pth) and not is_this_app(pid, pth):   # it may run from a download folder, but it shouldn't report itself
                procs.setdefault(pth, (pid, n))
    signs = sign_info(list(procs))
    checked = 0
    for pth, (pid, n) in procs.items():
        if not is_unsigned(signs.get(pth, {})):
            continue
        checked += 1
        imports = pe_imports(pth)
        keys, inject = imports & KEY_CAPTURE, imports & INJECTION
        if keys and (USER_WRITABLE.search(pth) or APPDATA_RE.search(pth)):
            out.append(F('malware', 'keylog:' + pth, 'high', f'Possible keylogger: {n}', 'An unsigned program in your user folders contains code to watch the keyboard.', 'Many legitimate tools have this ability (games, hotkey tools). Combined with no signature and that location, it deserves a look.', f"{pth}\nUses: {', '.join(sorted(keys))}", 'If you do not recognise it, end it and move it to quarantine.', A('block_process', 'End and block', f'End {n} and block it?\n\n{pth}\n\nIt can\'t connect or start again until you unblock it in the Blocked tab.', pid=pid, name=n, path=pth), Path=pth))
        if len(inject) == 3:
            out.append(F('malware', 'inject:' + pth, 'high', f'Can inject code into other programs: {n}', 'This unsigned program contains the exact functions used to run code inside another program.', 'Malware uses this to hide inside trusted programs. Debuggers and some games do too.', pth, 'If you do not recognise it, end it and block it.', A('block_process', 'End and block', f'End {n} and block it?\n\n{pth}', pid=pid, name=n, path=pth), Path=pth))
    if not any(x['Sev'] in ('critical', 'high') for x in out):
        out.append(F('malware', 'clean', 'ok', 'No signs of malware, spyware or keyloggers', f'Checked {autostart} startup items and {len(procs)} running programs outside Windows ({checked} unsigned).', 'This looks for known warning signs. It is not a guarantee.'))
    if not admin:
        out.append(need_admin('malware', 'Defender detections, WMI triggers and other users\' tasks'))
    return out


# ---------------------------------------------------------------- 8. Downloaded and dropped files

RISKY_EXT = {'.exe', '.msi', '.scr', '.com', '.pif', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.lnk', '.iso', '.img', '.vhd', '.vhdx', '.msc', '.xll', '.jar', '.cpl', '.dll', '.docm', '.xlsm', '.pptm'}
SCRIPT_EXT = {'.scr', '.pif', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.xll', '.cpl', '.msc'}
EXT_EXPLAIN = {'.hta': 'an HTML application, which runs as a program with no browser protections', '.js': 'a script that Windows runs when double-clicked, not a web file', '.vbs': 'a Windows script', '.scr': 'a screensaver, which is a program in disguise', '.lnk': 'a shortcut, which can hide a command',
               '.iso': 'a disk image, often used to get malware past download warnings', '.img': 'a disk image, often used to get malware past download warnings', '.ps1': 'a PowerShell script', '.bat': 'a batch script', '.cmd': 'a batch script', '.exe': 'a program', '.msi': 'an installer', '.docm': 'a Word document with macros', '.xlsm': 'an Excel workbook with macros', '.xll': 'an Excel add-in that runs as a program', '.dll': 'a program library', '.jar': 'a Java program', '.pif': 'an old program format', '.cpl': 'a Control Panel program', '.msc': 'a management console file, recently abused by malware'}
DOUBLE_EXT = re.compile(r'\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|mp4|mp3|zip|rar)\s*\.(exe|scr|com|pif|bat|cmd|js|vbs|hta|lnk|msi)$', re.I)
TRAP_NAMES = re.compile(r'(crack|keygen|patch|activator|kmspico|free.?robux|invoice|payment|voucher|setup_.*_installer|chrome.?update|browser.?update|flash.?player|teams.?update)', re.I)


def _zone(path):
    """(zone number, source URL, referrer) from the mark Windows puts on downloaded files."""
    try:
        with open(path + ':Zone.Identifier', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError:
        return None, '', ''
    get = lambda k: (re.search(rf'^{k}=(.*)$', text, re.M | re.I) or [None, ''])[1].strip()
    return int(get('ZoneId') or 0), get('HostUrl'), get('ReferrerUrl')


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def scan_downloads(ctx):
    home = os.environ.get('USERPROFILE', '')
    roots = [(os.path.join(home, 'Downloads'), 3), (os.path.join(home, 'Desktop'), 1), (os.path.join(home, 'Documents'), 1), (os.environ.get('TEMP', ''), 2), (os.environ.get('PUBLIC', ''), 2)]
    found = []
    for root, depth in roots:
        if not root or not os.path.isdir(root):
            continue
        base = root.rstrip('\\').count('\\')
        for cur, dirs, files in os.walk(root):
            if cur.count('\\') - base >= depth:
                dirs[:] = []
            dirs[:] = [x for x in dirs if x.lower() not in ('node_modules', '.git', '__pycache__', 'venv')]
            for x in files:
                full = os.path.join(cur, x)
                if os.path.splitext(x)[1].lower() in RISKY_EXT:
                    try:
                        found.append((os.path.getmtime(full), full))
                    except OSError:
                        pass
    found.sort(reverse=True)
    found = [p for _m, p in found[:700]]
    signs = sign_info([p for p in found if os.path.splitext(p)[1].lower() in ('.exe', '.msi', '.dll', '.scr', '.ps1', '.cpl', '.msc')])
    out, seen_ok = [], 0
    for p in found:
        name, ext = os.path.basename(p), os.path.splitext(p)[1].lower()
        zone, url, ref = _zone(p)
        info = signs.get(p, {})
        internet = zone in (3, 4)
        signed = info.get('Status') == 'Valid'
        in_temp = bool(re.search(r'\\Temp\\', p, re.I))
        sev, why = '', ''
        if DOUBLE_EXT.search(name):
            sev, why = 'critical', 'The name pretends to be a document, but the real ending makes it a program. This is a classic trick.'
        elif info.get('Status') == 'HashMismatch':
            sev, why = 'critical', 'Its digital signature is broken, so the file was changed after publishing.'
        elif internet and ext in SCRIPT_EXT:
            sev, why = 'high', f'A file downloaded from the internet that is {EXT_EXPLAIN.get(ext, "a program")}. Regular websites have almost no reason to send you this.'
        elif ext in ('.iso', '.img', '.vhd', '.vhdx') and internet:
            sev, why = 'medium', f'This is {EXT_EXPLAIN.get(ext, "a disk image")}. Fine for an operating system or large software you meant to get.'
        elif internet and TRAP_NAMES.search(name) and not signed:
            sev, why = 'high', 'The name matches common lures (cracks, fake updates, invoices), it came from the internet, and it is unsigned.'
        elif internet and ext in ('.exe', '.msi') and not signed and info.get('Status') != 'Unknown':
            sev, why = 'medium', 'A program from the internet with no valid signature, so the publisher can\'t be verified.'
        elif internet and ext in ('.lnk', '.ps1', '.bat', '.cmd', '.docm', '.xlsm', '.pptm', '.jar'):
            sev, why = 'medium', f'A file from the internet that is {EXT_EXPLAIN.get(ext, "able to run code")}.'
        elif in_temp and ext in ('.exe', '.scr', '.ps1', '.vbs', '.js', '.hta', '.bat') and not signed and os.path.getmtime(p) > time.time() - 7 * 86400 and ext != '.dll' and info.get('Status') != 'Unknown':
            sev, why = 'low', 'An unsigned script or program was recently left in a temporary folder. Installers do this; so does malware.'
        if not sev:
            seen_ok += 1
            continue
        src = url or ref
        try:
            sha = file_sha256(p) if os.path.getsize(p) < 300 * 1024 * 1024 else ''
        except OSError:
            sha = ''
        what = f'{name} is {EXT_EXPLAIN.get(ext, "a file type that can run code")}.' + (f' Signed by {info["Publisher"]}.' if signed and info.get('Publisher') else '')
        out.append(F('downloads', 'file:' + p, sev, name, what, why, p + (f'\nDownloaded from: {src}' if src else '') + (f'\nSHA-256: {sha}' if sha else ''), 'Move it to quarantine if you do not recognise it. Check the fingerprint on VirusTotal first if you want a second opinion.',
                     A('quarantine', 'Quarantine', f'Move this file to quarantine?\n\n{p}\n\nYou can restore it from the Blocked tab.', path=p), Path=p, Sha=sha, Link=f'https://www.virustotal.com/gui/file/{sha}' if sha else ''))
    out.append(F('downloads', 'summary', 'ok', f'{len(found)} program-type files checked', f'Looked in Downloads, Desktop, Documents, your Temp folder and the Public folder. {seen_ok} looked fine.'))
    return out


# ---------------------------------------------------------------- 9. Patches and outdated apps

UPDATES_PS = r'''
$s = New-Object -ComObject Microsoft.Update.Session
$r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$list = foreach ($u in $r.Updates) { [pscustomobject]@{ Title = [string]$u.Title; Severity = [string]$u.MsrcSeverity; KB = (@($u.KBArticleIDs) -join ','); Date = $u.LastDeploymentChangeTime.ToString('yyyy-MM-dd'); Url = [string](@($u.MoreInfoUrls)[0]); Cve = (@($u.CveIDs) -join ', ') } }
ConvertTo-Json -InputObject @{ ok = $true; updates = @($list) } -Depth 3 -Compress
'''
HOTFIX_PS = r'''
$h = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 5 | ForEach-Object { [pscustomobject]@{ KB = [string]$_.HotFixID; On = $_.InstalledOn.ToString('yyyy-MM-dd'); Desc = [string]$_.Description } })
ConvertTo-Json -InputObject @($h) -Compress
'''
# build: (name, last day of security updates for Home and Pro)
WINDOWS_SUPPORT = {19041: ('Windows 10 2004', '2021-12-14'), 19042: ('Windows 10 20H2', '2022-05-10'), 19043: ('Windows 10 21H1', '2022-12-13'), 19044: ('Windows 10 21H2', '2023-06-13'), 19045: ('Windows 10 22H2', '2025-10-14'),
                   22000: ('Windows 11 21H2', '2023-10-10'), 22621: ('Windows 11 22H2', '2024-10-08'), 22631: ('Windows 11 23H2', '2025-11-11'), 26100: ('Windows 11 24H2', '2026-10-13'), 26200: ('Windows 11 25H2', '2027-10-12')}


def windows_build():
    cv = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    return int(reg_get(HKLM, cv, 'CurrentBuildNumber', 0) or 0), reg_get(HKLM, cv, 'UBR', 0), reg_get(HKLM, cv, 'DisplayVersion', '')


def last_hotfix():
    rows = [r for r in run_powershell(HOTFIX_PS, timeout=45) if isinstance(r, dict)]
    return rows[0] if rows else {}


def scan_patches(ctx):
    out = []
    build, ubr, disp = windows_build()
    supp = WINDOWS_SUPPORT.get(build)
    today = dt.date.today().isoformat()
    edition = str(reg_get(HKLM, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'EditionID', ''))
    if supp and supp[1] < today:
        ent = edition.lower().startswith(('enterprise', 'education', 'iot'))
        out.append(F('patches', 'eol', 'high' if ent else 'critical', f'{supp[0]} no longer gets security updates', f'Support for {edition or "this edition"} ended on {supp[1]}' + (' for Home and Pro. Enterprise and Education editions get longer, so check your date.' if ent else '.'), 'New Windows vulnerabilities will stay open on this PC.', f'Build {build}.{ubr}', 'Upgrade to a supported version of Windows.', A('open_settings', 'Open Windows Update', 'Open Windows Update?', page='ms-settings:windowsupdate'), Active=not ent))
    else:
        out.append(F('patches', 'version', 'ok', f'Windows {disp or build} is supported', f'Build {build}.{ubr}' + (f', security updates until {supp[1]}.' if supp else '.')))
    hf = last_hotfix()
    ctx['last_hotfix'] = hf.get('On', '')
    wu_act = A('open_settings', 'Open Windows Update', 'Open Windows Update?', page='ms-settings:windowsupdate')
    if hf.get('On'):
        age = (dt.date.today() - dt.date.fromisoformat(hf['On'])).days
        if age > 60:
            out.append(F('patches', 'stale', 'critical', f'Windows was last updated {age} days ago', f"The last installed update is {hf.get('KB')} ({hf['On']}). Microsoft ships security fixes every month.", 'Every month adds more publicly known holes.', fix='Open Windows Update and install everything.', action=wu_act, Active=True))
        elif age > 35:
            out.append(F('patches', 'stale', 'high', f'Windows was last updated {age} days ago', f"The last installed update is {hf.get('KB')} ({hf['On']}).", 'At least one monthly security update has been missed.', fix='Open Windows Update and install everything.', action=wu_act))
        else:
            out.append(F('patches', 'recent', 'ok', f'Windows was updated {age} days ago', f"The last installed update is {hf.get('KB')}."))
    pending = next((n for n, h, k in (('Windows Update', HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'), ('Servicing', HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')) if _key_exists(h, k)), '')
    if pending:
        out.append(F('patches', 'reboot', 'high', 'A restart is needed to finish installing updates', 'Downloaded updates only protect you after a restart.', 'The holes remain open until then.', pending, 'Save your work and restart when convenient, today if you can.'))
    r = ps_one(UPDATES_PS, timeout=300)
    if not r.get('ok'):
        out.append(F('patches', 'wu-fail', 'medium', 'Windows Update could not be checked', 'My Security could not get an answer from Windows Update in five minutes.', 'Missing patches could not be listed.', fix='Open Windows Update and check by hand.', action=wu_act))
    updates = [u for u in as_list(r.get('updates')) if isinstance(u, dict)]
    for u in updates:
        s = u.get('Severity') or ''
        sev = {'Critical': 'critical', 'Important': 'high', 'Moderate': 'medium', 'Low': 'low'}.get(s, 'medium' if re.search(r'security|cumulative', u.get('Title', ''), re.I) else 'low')
        out.append(F('patches', 'kb:' + (u.get('KB') or u.get('Title', '')), sev, u.get('Title', 'Update'), f"Microsoft rates this {s.lower() or 'update'}, released {u.get('Date')}.", 'Fixes: ' + u['Cve'][:300] if u.get('Cve') else 'A missing Windows or driver update.', f"KB{u.get('KB')}", 'Install it from Windows Update.', wu_act, Link=u.get('Url', '')))
    if r.get('ok') and not updates:
        out.append(F('patches', 'none', 'ok', 'No Windows updates are waiting', 'Windows Update has nothing to install.'))
    return out


def _key_exists(hive, path):
    try:
        winreg.OpenKey(hive, path).Close()
        return True
    except OSError:
        return False


def winget_path():
    """winget from the admin-only WindowsApps folder when elevated; the per-user alias is writable by anything the user runs."""
    pat = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'WindowsApps', 'Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe', 'winget.exe')
    found = sorted(glob.glob(pat))
    if found:
        return found[-1]
    if is_admin():
        return ''
    alias = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'WindowsApps', 'winget.exe')
    return alias if os.path.exists(alias) else ''


def winget_outdated():
    exe = winget_path()
    if not exe:
        return None
    try:
        r = subprocess.run([exe, 'upgrade', '--source', 'winget', '--include-unknown', '--disable-interactivity'], capture_output=True, timeout=180, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = r.stdout.decode('utf-8', 'replace').replace('\r', '\n').split('\n')
    dash = next((i for i, x in enumerate(lines) if re.match(r'^-{10,}\s*$', x)), None)
    if dash is None or dash == 0:
        return []
    header = next((x for x in reversed(lines[:dash]) if x.strip()), '')
    pos = [m.start() for m in re.finditer(r'\S+', header)]
    if len(pos) < 4:
        return []
    out = []
    for line in lines[dash + 1:]:
        if len(line) <= pos[3] or not line[pos[1]:pos[2]].strip() or line[pos[1] - 1] != ' ':
            continue
        out.append({'Name': line[:pos[1]].strip(), 'Id': line[pos[1]:pos[2]].strip(), 'Version': line[pos[2]:pos[3]].strip(), 'Available': (line[pos[3]:pos[4]] if len(pos) > 4 else line[pos[3]:]).strip()})
    return out


def installed_apps():
    seen, out = set(), []
    un = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    for hive, path in ((HKLM, un), (HKLM, un.replace('SOFTWARE\\', 'SOFTWARE\\WOW6432Node\\')), (HKCU, un)):
        for sub in reg_subkeys(hive, path):
            k = path + '\\' + sub
            name = reg_get(hive, k, 'DisplayName', '')
            if not name or name in seen or reg_get(hive, k, 'SystemComponent', 0) == 1:
                continue
            seen.add(name)
            out.append({'Name': str(name), 'Version': str(reg_get(hive, k, 'DisplayVersion', '')), 'Publisher': str(reg_get(hive, k, 'Publisher', '')), 'Installed': str(reg_get(hive, k, 'InstallDate', ''))})
    return out


CRITICAL_APPS = re.compile(r'(chrome|firefox|edge|opera|brave|vivaldi|acrobat|reader|office|outlook|java|jre|zoom|teams|vlc|7-zip|winrar|putty|openssh|anydesk|teamviewer|node\.?js|python|git\b)', re.I)


def scan_apps(ctx):
    out, apps = [], installed_apps()
    ctx['inventory'] = apps
    rows = winget_outdated()
    ctx['outdated'] = rows or []
    if rows is None:
        out.append(F('apps', 'no-winget', 'info', 'Outdated apps could not be checked', 'My Security uses Windows Package Manager (winget), which was not found on this PC.', fix='Install "App Installer" from the Microsoft Store.'))
        return out
    for r in rows:
        name = r['Name']
        crit = bool(CRITICAL_APPS.search(name))
        sev = 'high' if re.search(r'(chrome|firefox|edge|opera|brave|vivaldi|acrobat)', name, re.I) else 'medium' if crit else 'low'
        out.append(F('apps', r['Id'], sev, name, f"Version {r['Version']} is installed. Version {r['Available']} is available.", 'Attackers target apps that open files or web content the most.' if crit else 'Old versions can have known security holes.', r['Id'], 'Update it. The app should be closed first.', A('winget_upgrade', 'Update', f"Update {name} to {r['Available']}?\n\nClose it first. This accepts the app's licence terms on your behalf.", pkg=r['Id'], name=name), Version=r['Version'], Available=r['Available']))
    if not rows:
        out.append(F('apps', 'current', 'ok', 'Your apps are up to date', f'Windows Package Manager found nothing to update among {len(apps)} installed programs.'))
    return out


# ---------------------------------------------------------------- 10. Published threats and attacks on this PC

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CHROMIUM = re.compile(r'\b(google chrome|microsoft edge|brave|opera|vivaldi|chromium)\b', re.I)
GENERIC_PRODUCTS = {'windows', 'multiple products', 'multiple', 'server', 'client', 'agent', 'gateway', 'firewall', 'browser', 'office'}


def fetch_kev():
    cache = os.path.join(APP_DIR, 'kev-cache.json')
    try:
        if time.time() - os.path.getmtime(cache) < 6 * 3600:
            with open(cache, encoding='utf-8') as f:
                return json.load(f), 'cached'
    except (OSError, ValueError):
        pass
    try:
        req = urllib.request.Request(KEV_URL, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) MySecurity'})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        os.makedirs(APP_DIR, exist_ok=True)
        with open(cache, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        return data, 'live'
    except (OSError, ValueError):
        try:
            with open(cache, encoding='utf-8') as f:
                return json.load(f), 'old'
        except (OSError, ValueError):
            return None, 'failed'


def _ymd(s):
    s = str(s or '')
    return f'{s[:4]}-{s[4:6]}-{s[6:8]}' if re.match(r'^\d{8}$', s) else ''


def match_kev(v, apps, outdated, hotfix):
    """('exposed'|'patched'|'check'|'none', the installed app it matched)."""
    vendor, product, added = str(v.get('vendorProject', '')), str(v.get('product', '')), str(v.get('dateAdded', ''))
    pl, vl = product.lower(), vendor.lower()
    if vl == 'microsoft' and pl.startswith('windows'):
        if hotfix and hotfix >= added:
            return 'patched', f'Windows (updated {hotfix})'
        return ('exposed', f'Windows (last updated {hotfix})') if hotfix else ('check', 'Windows')
    if pl.startswith('chromium'):
        hits = [a for a in apps if CHROMIUM.search(a['Name'])]
    elif pl in GENERIC_PRODUCTS or pl == vl:   # the feed sometimes gives only the vendor as the product, which says nothing about what's affected
        hits = []
    else:
        rx = re.compile(r'(?<![a-z0-9])' + re.escape(pl) + r'(?![a-z0-9])')
        hits = [a for a in apps if rx.search(a['Name'].lower()) and (vl in (a['Name'] + ' ' + a['Publisher']).lower() or vl.split(' ')[0] in (a['Name'] + ' ' + a['Publisher']).lower())]
    if not hits:
        return 'none', ''
    a = hits[0]
    if any(o['Name'].lower() == a['Name'].lower() or a['Name'].lower().startswith(o['Name'].lower()) for o in outdated):
        return 'exposed', f"{a['Name']} {a['Version']} (an update is available)"
    when = _ymd(a.get('Installed'))
    if when and when >= added:
        return 'patched', f"{a['Name']} {a['Version']} (updated {when})"
    if not when and pl.startswith('chromium'):
        return 'patched', f"{a['Name']} {a['Version']} (no update waiting)"
    return 'check', f"{a['Name']} {a['Version']}" + (f' (installed {when})' if when else '')


def scan_threats(ctx):
    data, source = fetch_kev()
    if not data:
        return [F('threats', 'feed', 'medium', 'Published-threat list could not be fetched', 'My Security could not reach CISA\'s list of vulnerabilities being exploited right now.', 'Published threats were not checked.', fix='Check the internet connection and run this scan again.')]
    apps = ctx.get('inventory') or installed_apps()
    outdated = ctx.get('outdated') or []
    hotfix = ctx.get('last_hotfix') or last_hotfix().get('On', '')
    vulns = sorted([v for v in data.get('vulnerabilities', []) if isinstance(v, dict)], key=lambda v: str(v.get('dateAdded')), reverse=True)
    cutoff = (dt.date.today() - dt.timedelta(days=730)).isoformat()
    out, latest, here = [], [], 0
    for i, v in enumerate(vulns):
        added = str(v.get('dateAdded'))
        if added < cutoff and i >= 50:
            break
        state, match = match_kev(v, apps, outdated, hotfix)
        if state != 'none':
            here += 1
        if i < 50:
            latest.append({'Cve': v.get('cveID'), 'Vendor': v.get('vendorProject'), 'Product': v.get('product'), 'Name': v.get('vulnerabilityName'), 'Added': added, 'Desc': v.get('shortDescription'), 'Ransomware': v.get('knownRansomwareCampaignUse') == 'Known', 'State': state, 'Match': match})
        if state in ('exposed', 'check') and added >= (dt.date.today() - dt.timedelta(days=365)).isoformat():
            ransom = v.get('knownRansomwareCampaignUse') == 'Known'
            sev = ('critical' if ransom or added >= (dt.date.today() - dt.timedelta(days=60)).isoformat() else 'high') if state == 'exposed' else 'medium'
            title = f"{v.get('cveID')}: {v.get('vulnerabilityName')}"
            act = None
            pkg = next((o for o in outdated if match.lower().startswith(o['Name'].lower())), None)
            if pkg:
                act = A('winget_upgrade', 'Update', f"Update {pkg['Name']} to {pkg['Available']}?\n\nThis accepts the app's licence terms on your behalf.", pkg=pkg['Id'], name=pkg['Name'])
            elif 'Windows' in match:
                act = A('open_settings', 'Open Windows Update', 'Open Windows Update?', page='ms-settings:windowsupdate')
            out.append(F('threats', 'kev:' + str(v.get('cveID')), sev, title, str(v.get('shortDescription') or ''), ('Criminals are using this in ransomware attacks. ' if ransom else 'Attackers are exploiting this right now. ') + ('Your copy looks unpatched.' if state == 'exposed' else 'My Security could not confirm your version is fixed.'), f'On this PC: {match}', 'Update it.' if state == 'exposed' else 'Update the app, then compare your version with the vendor\'s advisory.', act, Link=f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}", Active=state == 'exposed'))
    out.append(F('threats', 'summary', 'ok', f"Checked this PC against CISA's list of {len(vulns)} exploited vulnerabilities", f"Feed date: {str(data.get('dateReleased', ''))[:10]} ({source}). {here} recent entries apply to software on this PC, and those that look unpatched are listed.", Latest=latest))
    return out


EVENTS_PS = r'''
function Ev($log, $ids, $days, $max) { try { @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $ids; StartTime = (Get-Date).AddDays(-$days) } -MaxEvents $max -ErrorAction Stop) } catch { @() } }
function D($e) { $d = @{}; foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }; $d }
$fail = foreach ($e in (Ev 'Security' 4625 7 3000)) { $d = D $e; [pscustomobject]@{ When = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); User = $d['TargetUserName']; Ip = $d['IpAddress']; Type = $d['LogonType'] } }
$rdp = foreach ($e in (Ev 'Security' 4624 7 3000)) { $d = D $e; if ($d['LogonType'] -in '3','10' -and $d['IpAddress'] -notin '-','::1','127.0.0.1','') { [pscustomobject]@{ When = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); User = $d['TargetUserName']; Ip = $d['IpAddress']; Type = $d['LogonType'] } } }
$acct = foreach ($e in (Ev 'Security' @(4720,4732,1102) 30 100)) { $d = D $e; [pscustomobject]@{ When = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Id = $e.Id; User = $d['TargetUserName']; Member = $d['MemberName']; By = $d['SubjectUserName'] } }
$svc = foreach ($e in (Ev 'System' 7045 30 60)) { $d = D $e; [pscustomobject]@{ When = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Name = $d['ServiceName']; File = $d['ImagePath']; By = [string]$e.UserId } }
$sysclr = @(Ev 'System' 104 30 5).Count
$def = foreach ($e in (Ev 'Microsoft-Windows-Windows Defender/Operational' @(1006,1116,1117) 30 50)) { [pscustomobject]@{ When = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Id = $e.Id; Text = ([string]$e.Message).Substring(0, [Math]::Min(400, ([string]$e.Message).Length)) } }
ConvertTo-Json -InputObject @{ ok = $true; fail = @($fail); rdp = @($rdp); acct = @($acct); svc = @($svc); sysclr = $sysclr; def = @($def) } -Depth 4 -Compress
'''


def scan_attacks(ctx):
    if not ctx['admin']:
        return [need_admin('attacks', 'The Windows Security log (failed sign-ins, new accounts, new services)')]
    d, out = ps_one(EVENTS_PS, timeout=120), []
    if not d.get('ok'):
        return [F('attacks', 'failed', 'info', 'The event logs could not be read', 'Windows did not return its Security log.', fix='Run the scan again.')]
    groups = {}
    for e in as_list(d.get('fail')):
        if isinstance(e, dict):
            groups.setdefault(e.get('Ip') or '-', []).append(e)
    for ip, evs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        users = sorted({str(x.get('User')) for x in evs})[:8]
        remote = ip not in ('-', '::1', '127.0.0.1', '')
        public = False
        try:
            public = ipaddress.ip_address(ip.split('%')[0]).is_global
        except ValueError:
            pass
        if remote and len(evs) >= 5:
            sev = 'critical' if public and len(evs) >= 20 else 'high' if public else 'medium'
            out.append(F('attacks', 'brute:' + ip, sev, f'{len(evs)} failed sign-ins from {ip}', 'Someone tried to sign in to this PC from another computer and failed. Many tries in a row means password guessing.', 'From the internet.' if public else 'From a device on your own network, which could be a mistyped saved password or a compromised device.', f"Accounts tried: {', '.join(users)}\nLast try: {evs[0].get('When')}", 'Block this address and turn off whatever service they are reaching.', A('block_ip', 'Block address', f'Block {ip} in Windows Firewall?', ip=ip) if public else None, Active=public, Link=f'https://www.abuseipdb.com/check/{ip}' if public else ''))
        elif not remote and len(evs) >= 10:
            out.append(F('attacks', 'localfail', 'low', f'{len(evs)} failed sign-ins on this PC', 'Someone typed a wrong password at this PC, or an app is using an old one.', '', f"Accounts: {', '.join(users)}", 'If it was not you, change your password.'))
    logins = {}
    for e in as_list(d.get('rdp')):
        if isinstance(e, dict):
            logins.setdefault((e.get('Ip'), e.get('User'), e.get('Type')), []).append(e)
    for (ip, user, typ), evs in logins.items():
        try:
            public = ipaddress.ip_address(str(ip).split('%')[0]).is_global
        except ValueError:
            public = False
        if public or typ == '10':
            out.append(F('attacks', f'login:{ip}:{user}', 'critical' if public else 'medium', f'Remote sign-in by {user} from {ip}', 'A remote sign-in succeeded in the last 7 days.', 'If it was not you, someone has your password.', f'{len(evs)} sign-ins. Last: {evs[0].get("When")}', 'If this was not you: disconnect the PC from the network, change the password from another device.', Active=public))
    for e in as_list(d.get('acct')):
        if not isinstance(e, dict):
            continue
        when, eid = e.get('When'), int(e.get('Id') or 0)
        if eid == 4720:
            out.append(F('attacks', f'newuser:{e.get("User")}:{when}', 'high', f"A new account was created: {e.get('User')}", f"Created by {e.get('By')} on {when}.", 'Intruders create accounts to keep access. Fine if you made it.', fix='If you did not create it, turn it off in the Accounts tab.'))
        elif eid == 4732 and re.search(r'S-1-5-32-544|admin', str(e.get('User')) + str(e.get('Member')), re.I):
            out.append(F('attacks', f'newadmin:{e.get("Member")}:{when}', 'high', 'An account was added to Administrators', f"Changed by {e.get('By')} on {when}.", 'Intruders give themselves admin rights.', e.get('Member'), 'Check the Accounts tab.'))
        elif eid == 1102:
            out.append(F('attacks', f'logclear:{when}', 'critical', 'The Security log was erased', f"Erased by {e.get('By')} on {when}.", 'Intruders erase logs to cover their tracks. Rarely happens otherwise.', fix='If you did not do this, treat the PC as possibly compromised.', Active=True))
    if int(d.get('sysclr') or 0):
        out.append(F('attacks', 'sysclr', 'high', 'The System log was erased in the last 30 days', 'Windows recorded that its System log was cleared.', 'Intruders do this to cover their tracks.', fix='If you did not do this, get the PC checked.'))
    for e in as_list(d.get('svc')):
        if isinstance(e, dict):
            f = str(e.get('File') or '')
            bad = USER_WRITABLE.search(f) or re.search(LOLBINS, f, re.I)
            if bad:
                out.append(F('attacks', f"newsvc:{e.get('Name')}:{e.get('When')}", 'critical', f"Suspicious new service: {e.get('Name')}", f"Installed on {e.get('When')}.", 'Attackers install services to run with full privileges.', f, 'Check the Services tab, and disable it if you do not recognise it.', Active=True))
    for e in as_list(d.get('def'))[:15]:
        if isinstance(e, dict):
            out.append(F('attacks', f"def:{e.get('When')}:{e.get('Id')}", 'high' if int(e.get('Id') or 0) in (1006, 1116) else 'medium', 'Microsoft Defender stopped something', f"On {e.get('When')}.", 'See what it was, and where it came from.', e.get('Text')))
    if not [x for x in out if x['Sev'] in ('critical', 'high')]:
        out.append(F('attacks', 'none', 'ok', 'No sign of attacks in the Windows logs', 'Looked at failed and remote sign-ins for 7 days, and new accounts and services for 30 days.'))
    return out


# ---------------------------------------------------------------- 11. Browsers

OPEN_TABS_PS = r'''
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$browsers = @{}
Get-Process chrome, msedge, firefox, opera, brave, vivaldi -ErrorAction SilentlyContinue | ForEach-Object { $browsers[$_.Id] = $_.ProcessName }
$isWin = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Window)
$isTab = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::TabItem)
$walker = [Windows.Automation.TreeWalker]::ControlViewWalker
$out = foreach ($w in [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children, $isWin)) {
  $proc = $browsers[[int]$w.Current.ProcessId]
  if (-not $proc) { continue }
  foreach ($t in $w.FindAll([Windows.Automation.TreeScope]::Descendants, $isTab)) {
    if (-not $t.Current.Name) { continue }
    $p = $walker.GetParent($t); $inPage = $false
    while ($p -and -not $p.Equals($w)) { if ($p.Current.ControlType -eq [Windows.Automation.ControlType]::Document) { $inPage = $true; break }; $p = $walker.GetParent($p) }
    if (-not $inPage) { [pscustomobject]@{ Process = $proc; Title = [string]$t.Current.Name } }
  }
}
ConvertTo-Json -InputObject @($out) -Compress
'''
BROWSER_HISTORY = [
    ('Chrome', 'LOCALAPPDATA', r'Google\Chrome\User Data\*\History'), ('Edge', 'LOCALAPPDATA', r'Microsoft\Edge\User Data\*\History'),
    ('Brave', 'LOCALAPPDATA', r'BraveSoftware\Brave-Browser\User Data\*\History'), ('Vivaldi', 'LOCALAPPDATA', r'Vivaldi\User Data\*\History'),
    ('Opera', 'APPDATA', r'Opera Software\Opera Stable\History'), ('Opera', 'APPDATA', r'Opera Software\Opera Stable\*\History'),
    ('Firefox', 'APPDATA', r'Mozilla\Firefox\Profiles\*\places.sqlite')]
BROWSER_NAMES = {'chrome': 'Chrome', 'msedge': 'Edge', 'firefox': 'Firefox', 'opera': 'Opera', 'brave': 'Brave', 'vivaldi': 'Vivaldi'}
TAB_EXTRAS = re.compile(r'\s+-\s+(Audio playing|Playing audio|Muted|Audio muted|Camera or microphone recording|Pinned|Memory usage.*|Network error|Crashed)$', re.I)
SITE_RE = re.compile(r'^(?=.{3,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$')
SECOND_LEVEL = {'co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'ne', 'or', 'go', 'gob', 'nic', 'mil'}
PROTECTED_SITES = ('localhost', 'local', 'microsoft.com', 'windows.com', 'windowsupdate.com', 'microsoftonline.com', 'msftconnecttest.com', 'msftncsi.com', 'live.com', 'windows.net')


def base_site(host):
    labels = host.split('.')
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL else 2
    return '.'.join(labels[-n:])


def _on(host, domains):
    return any(host == d or host.endswith('.' + d) for d in domains)


def _history(path, since):
    tmp = tempfile.mkdtemp(prefix='mysec-')
    try:
        copy = os.path.join(tmp, 'h.sqlite')
        for suffix in ('', '-wal', '-journal'):
            if os.path.exists(path + suffix):
                shutil.copyfile(path + suffix, copy + suffix)
        con = sqlite3.connect(copy)
        try:
            if path.lower().endswith('places.sqlite'):
                return [(u, t or '', w / 1e6) for u, t, w in con.execute('SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date > ? ORDER BY last_visit_date DESC LIMIT 3000', (int(since * 1e6),))]
            return [(u, t or '', w / 1e6 - 11644473600) for u, t, w in con.execute('SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT 3000', (int((since + 11644473600) * 1e6),))]
        finally:
            con.close()
    except (OSError, sqlite3.Error):
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def open_tabs():
    tabs = [t for t in run_powershell(OPEN_TABS_PS, timeout=30) if isinstance(t, dict) and t.get('Title')]
    if not tabs:
        return []
    by_title, since = {}, time.time() - 14 * 86400
    for browser, env, pattern in BROWSER_HISTORY:
        for path in glob.glob(os.path.join(os.environ.get(env, ''), pattern)):
            for url, title, when in _history(path, since):
                if title:
                    key = (browser, title.strip())
                    if key not in by_title or by_title[key][1] < when:
                        by_title[key] = (url, when)
    out = []
    for t in tabs:
        browser = BROWSER_NAMES.get(str(t.get('Process', '')).lower(), str(t.get('Process', '')))
        title = TAB_EXTRAS.sub('', str(t['Title']).strip())
        url = (by_title.get((browser, title)) or ('',))[0]
        if not url:
            match = [(v[1], v[0]) for (b, ti), v in by_title.items() if b == browser and len(title) > 8 and ti.startswith(title)]
            url = max(match)[1] if match else ''
        out.append({'Browser': browser, 'Title': title, 'Url': url})
    return out


def _edit1(a, b):
    """True if the two strings differ by exactly one change (typo-squatting), or one homoglyph swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    if len(a) == len(b):
        return a[i + 1:] == b[i + 1:]
    return a[i:] == b[i + 1:] if len(b) > len(a) else a[i + 1:] == b[i:]


LOGIN_TITLE = re.compile(r'(sign.?in|log.?in|verify|password|account|authenticate|secure)', re.I)
MS_LOGIN_TITLE = re.compile(r'^(sign in to your account|sign in to outlook|sign in to your microsoft account|microsoft 365 (login|sign.?in)|office 365 (login|sign.?in))\b', re.I)
BRAND_WORDS = {'office': r'(office\s*365|microsoft\s+office)', 'wellsfargo': r'wells\s*fargo', 'bankofamerica': r'bank\s+of\s+america', 'microsoft': r'microsoft(\s*365)?'}
SIGNIN = r'(sign[ -]?in|log[ -]?in|login|verify your)'


def _is_login_title(title, brand):
    """True when a tab title reads like the sign-in page of this brand, and not like an article that mentions it."""
    t = title.strip()
    if len(t) > 70 or re.search(r'\b(how to|why|what|guide|tips|news|review|problem|issue|help)\b', t, re.I):
        return False
    word = BRAND_WORDS.get(brand, rf'{brand}')
    return bool(re.search(rf'^\W*{SIGNIN}\b.{{0,35}}\b{word}\b', t, re.I) or re.search(rf'\b{word}\b.{{0,20}}\b{SIGNIN}\b', t, re.I))
SCAM_TITLE = re.compile(r'(your (pc|computer|device) (is|has been) (infected|locked|blocked)|virus(es)? (detected|found)|call (microsoft|support|apple)|windows (defender )?(security )?alert|critical (security )?(alert|update)|update your (browser|chrome)|chrome update|browser update required|you(\'ve| have) won|claim your prize)', re.I)
CLICKFIX_TITLE = re.compile(r'(verify you are human|are you human|captcha|just a moment|checking your browser)', re.I)
TOKEN_URL = re.compile(r'[?#&](access_token|id_token|refresh_token|sessionid|session_token|sid)=[^&]{12,}', re.I)
SSO_HOSTS = ('microsoftonline.com', 'live.com', 'google.com', 'okta.com', 'auth0.com', 'github.com', 'apple.com', 'facebook.com')


def check_url(url, title, cert=None, page=None):
    """[(severity, title, explanation)] for one open tab. Looks only at the address, the tab title and these two optional extras."""
    hits = []
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or '').rstrip('.').lower()
    if not host or parts.scheme not in ('http', 'https'):
        return hits
    site = base_site(host)
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback:
            return hits
        hits.append(('high' if LOGIN_TITLE.search(title) else 'medium', 'The address is a bare IP number', 'Real services use a name. Sites using bare numbers are often short-lived scams or infected servers.'))
    except ValueError:
        if host in ('localhost',) or host.endswith(('.local', '.localhost', '.internal', '.lan')):
            return hits
    if parts.username:
        hits.append(('critical', 'Hidden destination in the address', f'Everything before the @ is decoration. This page is really on {host}.'))
    if 'xn--' in host:
        hits.append(('high', 'International lookalike letters in the name', 'The name uses characters from other alphabets, which can make it look like a real site.'))
    m365 = ('microsoft', 'office', 'outlook', 'onedrive', 'sharepoint')
    trusted = _on(host, TRUSTED_SITES)
    if MS_LOGIN_TITLE.match(title.strip()) and not _on(host, LOGIN_BRANDS['microsoft']) and not trusted:
        hits.append(('critical', 'Fake Microsoft 365 sign-in page', f'The tab says "{title[:80]}", which is the title of Microsoft\'s own sign-in page, but the site is {site}. Do not enter your password. If you did, change it now from another device and sign out of all sessions.'))
    else:
        for brand, domains in LOGIN_BRANDS.items():
            if not trusted and not _on(host, domains) and _is_login_title(title, brand):
                if brand in m365:
                    hits.append(('critical', 'Fake Microsoft 365 sign-in page', f'The tab says "{title[:80]}", but the site is {site}, which does not belong to Microsoft. Do not enter your password. If you did, change it now from another device and sign out of all sessions.'))
                else:
                    hits.append(('critical', f'Possible fake {brand.title()} sign-in page', f'The tab says "{title[:80]}", but the site is {site}, which does not belong to {brand.title()}.'))
                break
    stem = site.split('.')[0]
    for target in LOOKALIKE_TARGETS:
        if site != target and _edit1(stem, target.split('.')[0]) and len(stem) > 4:
            hits.append(('critical', f'Lookalike of {target}', f'{site} is one letter away from {target}. This is called typo-squatting.'))
            break
    for brand, domains in LOGIN_BRANDS.items():
        everyday = brand in ('office', 'outlook', 'google', 'amazon', 'adobe', 'github', 'sharepoint', 'onedrive', 'apple', 'chase')   # ordinary words, or names other companies legitimately include
        if (LOGIN_TITLE.search(title) or not everyday) and len(brand) > 5 and re.search(rf'(^|[.-]){brand}([.-]|$)', host) and stem != brand and not _on(host, domains) and not trusted and not any(h[0] == 'critical' for h in hits):
            hits.append(('high', f'Uses the name {brand.title()}, but is not {brand.title()}', f'The real company name appears in {host}, but the site belongs to someone else.'))
            break
    if _on(host, FREE_HOSTING) and LOGIN_TITLE.search(title):
        hits.append(('high', 'Sign-in page on free web hosting', f'{host} is on a service anyone can publish to in minutes. Real sign-in pages are not hosted there.'))
    if parts.scheme == 'http':
        hits.append(('high' if LOGIN_TITLE.search(title) else 'low', 'Not encrypted (no certificate)', 'This page uses HTTP, so whatever you send or read can be seen and changed on the way.'))
    if host.rsplit('.', 1)[-1] in RISKY_TLDS:
        hits.append(('medium' if LOGIN_TITLE.search(title) else 'low', f'Name ends in .{host.rsplit(".", 1)[-1]}', 'Cheap endings like this are used disproportionately for scams.'))
    if host.count('.') >= 4 and not _on(host, TRUSTED_SITES):
        hits.append(('low', 'Unusually long site name', 'Long chains of sub-names are used to hide the real site.'))
    if SCAM_TITLE.search(title):
        hits.append(('critical', 'Scare-page or fake update', 'Real browsers and Microsoft never warn you through a web page or ask you to call a number. Close the tab.'))
    if TOKEN_URL.search(url) and not _on(host, SSO_HOSTS):
        hits.append(('high', 'A sign-in token is in the address', 'This address contains a credential. Anyone who sees the link can use your session.'))
    if _on(host, ('microsoft.com',)) and parts.path.lower().rstrip('/').endswith('/devicelogin'):
        hits.append(('high', 'Device-code sign-in page is open', 'Only continue if you started this yourself. Attackers send people here with a code, and the real Microsoft page then gives them your account.'))
    if host.startswith('login.microsoftonline.') and re.search(r'prompt=consent', url, re.I):
        hits.append(('medium', 'An app is asking for access to your account', 'Check the app and permissions carefully. Fake apps use this real page to read your mail without your password.'))
    if cert:
        hits.append(cert)
    hits.extend(page or [])
    hits.sort(key=lambda h: -SEV_RANK[h[0]])
    return hits


def check_certificate(host):
    """(severity, title, explanation) if a site's certificate has a problem, else None. Connects like a browser would, sends nothing."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=6) as sock, ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
        left = (ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) / 86400
        return ('medium', 'Certificate about to expire', f'It expires in {int(left)} days.') if left < 3 else None
    except ssl.SSLCertVerificationError as e:
        msg = e.verify_message or str(e)
        if 'unable to get local issuer' in msg or 'unable to get issuer' in msg:
            # Python only knows the roots already on this PC. Windows and browsers fetch missing ones, so ask Windows before calling it bad.
            if _windows_trusts(host):
                return None
            return ('high', 'Certificate is not issued by a trusted authority', 'Windows could not trace it to anyone it trusts, so it proves nothing about who runs this site.')
        if 'expired' in msg:
            return ('high', 'Certificate has expired', 'The site\'s identity can no longer be confirmed. Do not enter passwords.')
        if 'Hostname mismatch' in msg or 'mismatch' in msg:
            return ('high', 'Certificate is for a different site', 'This can mean someone is intercepting the connection.')
        if 'self-signed' in msg or 'self signed' in msg:
            return ('high', 'Certificate is not issued by a trusted authority', 'Anyone can make a certificate like this, so it proves nothing.')
        return ('high', 'Certificate could not be verified', msg[:120])
    except (OSError, ssl.SSLError, ValueError, KeyError):
        return None


CHAIN_PS = r'''
$c = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($env:MS_CERT))
$ch = New-Object Security.Cryptography.X509Certificates.X509Chain
$ch.ChainPolicy.RevocationMode = 'NoCheck'
ConvertTo-Json -InputObject @{ ok = [bool]$ch.Build($c) } -Compress
'''


def _windows_trusts(host):
    """Does Windows' own certificate check accept this site? Unknown counts as yes, so a failed look-up never raises an alarm."""
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=6) as sock, ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return True
    return ps_one(CHAIN_PS, {'MS_CERT': base64.b64encode(der).decode('ascii')}, timeout=30).get('ok', True) is not False


PAGE_RULES = [
    (r'(navigator\.clipboard\.writeText|execCommand\(.copy.\)).{0,800}(powershell|mshta|cmd(\.exe)?\s|curl\s.*\|)', 'critical', 'Page puts a command on your clipboard (ClickFix)', 'This page copies a command for you to paste into Windows. Never press Win+R and paste. This is one of the most common ways PCs get infected today.'),
    (r'(press|hit).{0,40}(windows|win).{0,10}(\+|and).{0,10}r\b.{0,300}(ctrl|paste)', 'critical', 'Page tells you to paste into the Run box (ClickFix)', 'Real "verify you are human" checks never ask this. Close the tab.'),
    (r'(ms-msdt:|search-ms:|ms-officecmd:|mshta(\.exe)?\s)', 'critical', 'Page tries to open a Windows program directly', 'Web pages use these links to launch Windows tools and get code running.'),
    (r'href=["\'][^"\']+\.(hta|scr|vbs|jse|wsf|ps1)["\']', 'high', 'Page offers a script or program to download', 'Normal sites do not hand out these file types.'),
    (r'http-equiv=["\']?refresh["\']?[^>]+url=[^>]+\.(exe|msi|hta|scr|zip|iso)', 'critical', 'Page starts a download by itself (drive-by)', 'This page sends the browser to a program file automatically.'),
    (r'<iframe[^>]+(width=["\']?0|height=["\']?0|display:\s*none|visibility:\s*hidden)[^>]+src=["\']https?://', 'high', 'Hidden frame loading another site', 'Invisible frames are a classic way of delivering drive-by attacks.'),
    (r'document\.write\(\s*unescape\(|eval\(\s*(unescape|atob)\(', 'medium', 'Scrambled script on the page', 'Pages sometimes do this for tracking, and malicious pages do it to hide attacks.'),
    (r'msSaveOrOpenBlob|new\s+Blob\([^)]{0,300}(application/x-msdownload|\.exe|octet-stream).{0,400}\.click\(\)', 'high', 'Page builds a file in the browser and saves it (HTML smuggling)', 'This trick gets malware past mail and web filters.'),
    (r'<input[^>]+type=["\']?password', 'info', 'Has a password box', ''),
]
PAGE_RULES = [(re.compile(p, re.I | re.S), s, t, w) for p, s, t, w in PAGE_RULES]


def check_page(url):
    """Fetch the page once, with no cookies and without its query string, and look for attack patterns. Nothing on it is run."""
    parts = urllib.parse.urlsplit(url)
    bare = urllib.parse.urlunsplit((parts.scheme, parts.netloc.rsplit('@', 1)[-1], parts.path or '/', '', ''))
    req = urllib.request.Request(bare, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36', 'Accept': 'text/html'})
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # only reading the text; the certificate is judged separately
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            if 'html' not in r.headers.get('Content-Type', 'text/html').lower():
                return []
            body = r.read(1500000).decode('utf-8', 'replace')
    except (OSError, ValueError, UnicodeError):
        return []
    hits, password = [], False
    for rx, sev, title, why in PAGE_RULES:
        if rx.search(body):
            if sev == 'info':
                password = True
            else:
                hits.append((sev, title, why))
    if password:
        for m in re.finditer(r'<form[^>]+action=["\'](https?://[^"\']+)', body, re.I):
            target = (urllib.parse.urlsplit(m.group(1)).hostname or '').lower()
            if target and base_site(target) != base_site((parts.hostname or '').lower()):
                hits.append(('critical', 'Password box sends to a different site', f'The form on this page sends what you type to {target}.'))
                break
    return hits


def browser_extensions():
    roots = [('Chrome', 'LOCALAPPDATA', r'Google\Chrome\User Data'), ('Edge', 'LOCALAPPDATA', r'Microsoft\Edge\User Data'), ('Brave', 'LOCALAPPDATA', r'BraveSoftware\Brave-Browser\User Data'), ('Vivaldi', 'LOCALAPPDATA', r'Vivaldi\User Data'), ('Opera', 'APPDATA', r'Opera Software\Opera Stable')]
    out = []
    for browser, env, base in roots:
        base = os.path.join(os.environ.get(env, ''), base)
        for mf in glob.glob(os.path.join(base, '*', 'Extensions', '*', '*', 'manifest.json')) + glob.glob(os.path.join(base, 'Extensions', '*', '*', 'manifest.json')):
            try:
                with open(mf, encoding='utf-8-sig') as f:
                    m = json.load(f)
            except (OSError, ValueError):
                continue
            folder, ext_id = os.path.dirname(mf), os.path.basename(os.path.dirname(os.path.dirname(mf)))
            name = str(m.get('name', ext_id))
            if name.startswith('__MSG_'):
                key = name[6:-2]
                loc = m.get('default_locale', 'en')
                try:
                    with open(os.path.join(folder, '_locales', loc, 'messages.json'), encoding='utf-8-sig') as f:
                        msgs = {k.lower(): v for k, v in json.load(f).items()}
                    name = msgs.get(key.lower(), {}).get('message', name)
                except (OSError, ValueError, AttributeError):
                    pass
            perms = {str(p) for p in as_list(m.get('permissions'))} | {str(p) for p in as_list(m.get('host_permissions'))}
            for cs in as_list(m.get('content_scripts')):
                if isinstance(cs, dict):
                    perms |= {str(x) for x in as_list(cs.get('matches'))}
            out.append({'Browser': browser, 'Id': ext_id, 'Name': name, 'Version': str(m.get('version', '')), 'Perms': perms, 'Store': 'update_url' in m and ('google.com' in str(m['update_url']) or 'microsoft.com' in str(m['update_url']) or 'opera.com' in str(m['update_url']))})
    return out


def scan_browsers(ctx):
    out = []
    seen = set()
    for e in browser_extensions():
        key = (e['Browser'], e['Id'])
        if key in seen or e['Id'] in ('nmmhkkegccagdldgiimedpiccmgmieda', 'ghbmnnjooekpmoecnnnilnnbdlolhkhi', 'jmjflgjpcpepeafmmgdpfkogkghcpiha', 'kmendfapggjehodndflmmgagdbamhnfd'):
            continue
        seen.add(key)
        perms = e['Perms']
        all_sites = bool(perms & {'<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'})
        danger = sorted(perms & {'cookies', 'webRequest', 'webRequestBlocking', 'debugger', 'nativeMessaging', 'proxy', 'clipboardRead', 'management', 'declarativeNetRequest', 'scripting', 'tabs', 'history'})
        strong = perms & {'cookies', 'debugger', 'nativeMessaging', 'proxy', 'webRequestBlocking', 'clipboardRead'}
        page = {'Chrome': 'chrome://extensions', 'Edge': 'edge://extensions', 'Brave': 'brave://extensions', 'Vivaldi': 'vivaldi://extensions', 'Opera': 'opera://extensions'}.get(e['Browser'], 'the browser\'s extensions page')
        if not e['Store']:
            out.append(F('browsers', f"ext:{e['Browser']}:{e['Id']}", 'high' if all_sites else 'medium', f"Not from an extension store: {e['Name']}", f"{e['Browser']} has an extension that was installed from outside its store.", 'Malware installs extensions this way to steal sign-in cookies. Developers do this too.', f"Can use: {', '.join(danger) or 'few permissions'}" + ('; every site' if all_sites else ''), f'If you did not add it, remove it at {page}.'))
        elif all_sites and strong:
            out.append(F('browsers', f"ext:{e['Browser']}:{e['Id']}", 'medium', f"Can read every site: {e['Name']}", f"This {e['Browser']} extension can see and change every page and has powerful permissions.", 'A compromised or sold extension can steal sign-in tokens. Keep only those you need.', f"Can use: {', '.join(danger)}; every site", f'Review it at {page}.'))
    out.append(F('browsers', 'ext-summary', 'ok', f'{len(seen)} browser extensions checked', 'Store-installed extensions without broad permissions are not listed.'))
    return out


SCANS = [
    ('ports', 'Open ports', scan_ports), ('system', 'System protection', scan_system), ('shares', 'Shares and SMB', scan_shares), ('protocols', 'Protocols', scan_protocols),
    ('accounts', 'Accounts and admin rights', scan_accounts), ('services', 'Services and backdoors', scan_services), ('apps', 'Outdated apps', scan_apps), ('malware', 'Malware, spyware, keyloggers', scan_malware),
    ('downloads', 'Downloaded files', scan_downloads), ('patches', 'Missing patches', scan_patches), ('threats', 'Published threats', scan_threats), ('attacks', 'Hack attempts in the logs', scan_attacks), ('browsers', 'Browser extensions', scan_browsers),
]
