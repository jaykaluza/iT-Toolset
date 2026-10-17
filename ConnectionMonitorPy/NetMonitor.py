"""
Connection monitor (Python version).

Live Windows connection dashboard: maps every TCP connection to the app that owns it,
flags internet peers and risky items, lists listening ports, and serves it all on
http://localhost with an End process button.

Uses only the Python standard library. Connections, processes and network counters are
read straight from Windows; Windows' built-in PowerShell is used only for what Python
can't read directly: digital signatures, service details and the DNS cache.

Run (Administrator recommended):  py NetMonitor.py
"""

import argparse
import base64
import csv
import ctypes
import ctypes.wintypes as wt
import datetime as dt
import http.server
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor

if sys.platform != 'win32':
    sys.exit('NetMonitor only runs on Windows.')

HERE = os.path.dirname(os.path.abspath(__file__))
WINDIR = os.environ.get('WINDIR', r'C:\Windows')

# ---------------------------------------------------------------- Windows API

iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)
shell32 = ctypes.WinDLL('shell32')

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
NO_ERROR, ERROR_INSUFFICIENT_BUFFER = 0, 122
ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER = 5, 87
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
WAIT_TIMEOUT = 0x102
TH32CS_SNAPPROCESS = 0x2
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
WM_CLOSE = 0x0010
GW_OWNER = 4
CREATE_NO_WINDOW = 0x08000000

TCP_STATES = {1: 'Closed', 2: 'Listen', 3: 'SynSent', 4: 'SynReceived', 5: 'Established', 6: 'FinWait1',
              7: 'FinWait2', 8: 'CloseWait', 9: 'Closing', 10: 'LastAck', 11: 'TimeWait', 12: 'DeleteTCB'}


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
    _fields_ = [('ucLocalAddr', ctypes.c_ubyte * 16), ('dwLocalScopeId', wt.DWORD), ('dwLocalPort', wt.DWORD),
                ('dwOwningPid', wt.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ProcessID', wt.DWORD),
                ('th32DefaultHeapID', ctypes.c_size_t), ('th32ModuleID', wt.DWORD), ('cntThreads', wt.DWORD),
                ('th32ParentProcessID', wt.DWORD), ('pcPriClassBase', ctypes.c_long), ('dwFlags', wt.DWORD),
                ('szExeFile', ctypes.c_wchar * 260)]


class MIB_IFROW(ctypes.Structure):
    _fields_ = [('wszName', ctypes.c_wchar * 256), ('dwIndex', wt.DWORD), ('dwType', wt.DWORD), ('dwMtu', wt.DWORD),
                ('dwSpeed', wt.DWORD), ('dwPhysAddrLen', wt.DWORD), ('bPhysAddr', ctypes.c_ubyte * 8),
                ('dwAdminStatus', wt.DWORD), ('dwOperStatus', wt.DWORD), ('dwLastChange', wt.DWORD),
                ('dwInOctets', wt.DWORD), ('dwInUcastPkts', wt.DWORD), ('dwInNUcastPkts', wt.DWORD),
                ('dwInDiscards', wt.DWORD), ('dwInErrors', wt.DWORD), ('dwInUnknownProtos', wt.DWORD),
                ('dwOutOctets', wt.DWORD), ('dwOutUcastPkts', wt.DWORD), ('dwOutNUcastPkts', wt.DWORD),
                ('dwOutDiscards', wt.DWORD), ('dwOutErrors', wt.DWORD), ('dwOutQLen', wt.DWORD),
                ('dwDescrLen', wt.DWORD), ('bDescr', ctypes.c_ubyte * 256)]


iphlpapi.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL, wt.ULONG, ctypes.c_int, wt.ULONG]
iphlpapi.GetExtendedUdpTable.argtypes = iphlpapi.GetExtendedTcpTable.argtypes
iphlpapi.GetIfTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.ULONG), wt.BOOL]
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
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.GetWindow.argtypes = [wt.HWND, wt.UINT]
user32.GetWindow.restype = wt.HWND
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]


def _read_table(func, family, table_class, row_type):
    """Call GetExtendedTcpTable/GetExtendedUdpTable and return its rows."""
    size = wt.DWORD(0)
    buf = None
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


def tcp_connections():
    """(state, local address, local port, remote address, remote port, pid) for every TCP socket."""
    rows = [(TCP_STATES.get(r.dwState, str(r.dwState)), _ip4(r.dwLocalAddr), _port(r.dwLocalPort),
             _ip4(r.dwRemoteAddr), _port(r.dwRemotePort), r.dwOwningPid)
            for r in _read_table(iphlpapi.GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL, MIB_TCPROW_OWNER_PID)]
    rows += [(TCP_STATES.get(r.dwState, str(r.dwState)), _ip6(r.ucLocalAddr), _port(r.dwLocalPort),
              _ip6(r.ucRemoteAddr), _port(r.dwRemotePort), r.dwOwningPid)
             for r in _read_table(iphlpapi.GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL, MIB_TCP6ROW_OWNER_PID)]
    return rows


def udp_endpoints():
    """(local address, local port, pid) for every UDP socket."""
    rows = [(_ip4(r.dwLocalAddr), _port(r.dwLocalPort), r.dwOwningPid)
            for r in _read_table(iphlpapi.GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID)]
    rows += [(_ip6(r.ucLocalAddr), _port(r.dwLocalPort), r.dwOwningPid)
             for r in _read_table(iphlpapi.GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID)]
    return rows


def process_names():
    """{pid: name} for every running process, names without .exe like Task Manager's Details tab."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (None, INVALID_HANDLE_VALUE):
        return {}
    names = {}
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            exe = entry.szExeFile
            names[entry.th32ProcessID] = exe[:-4] if exe.lower().endswith('.exe') else exe
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    names[0] = 'System Idle'
    return names


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


def is_running(pid):
    h = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
    if not h:
        # access denied means it exists but we can't open it; anything else means it's gone
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED
    try:
        return kernel32.WaitForSingleObject(h, 0) == WAIT_TIMEOUT
    finally:
        kernel32.CloseHandle(h)


def terminate(pid):
    """Force a process to end. Returns 'ok', 'gone' or 'denied'."""
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


def close_windows(pids):
    """Ask the visible top-level windows of these processes to close, like clicking their X."""
    pids = set(pids)

    def on_window(hwnd, _):
        owner = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value in pids and user32.IsWindowVisible(hwnd) and not user32.GetWindow(hwnd, GW_OWNER):
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        return True

    user32.EnumWindows(WNDENUMPROC(on_window), 0)


def adapter_counters():
    """{MAC: (bytes in, bytes out)} for connected Ethernet/Wi-Fi adapters (32-bit counters)."""
    size = wt.ULONG(0)
    buf = None
    for _ in range(5):
        buf = ctypes.create_string_buffer(max(size.value, 4))
        ret = iphlpapi.GetIfTable(buf, ctypes.byref(size), False)
        if ret == NO_ERROR:
            break
        if ret != ERROR_INSUFFICIENT_BUFFER:
            return {}
    else:
        return {}
    count = wt.DWORD.from_buffer(buf).value
    out = {}
    for r in (MIB_IFROW * count).from_buffer(buf, ctypes.sizeof(wt.DWORD)):
        if r.dwType not in (6, 71) or r.dwOperStatus not in (4, 5) or not r.dwPhysAddrLen:
            continue
        mac = bytes(r.bPhysAddr[:r.dwPhysAddrLen])
        # filter drivers show up as extra rows for the same adapter; keep the busiest
        prev = out.get(mac, (0, 0))
        out[mac] = (max(prev[0], r.dwInOctets), max(prev[1], r.dwOutOctets))
    return out


def is_admin():
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def run_powershell(script, env_extra=None, timeout=90):
    """Run a PowerShell snippet that prints JSON; returns a list. Data goes in via environment
    variables, never into the script text."""
    # PowerShell 7's module path (inherited when started from pwsh) breaks Windows PowerShell's built-in modules
    env = {k: v for k, v in os.environ.items() if k.upper() != 'PSMODULEPATH'}
    env.update(env_extra or {})
    full = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = 'SilentlyContinue'\n" + script
    encoded = base64.b64encode(full.encode('utf-16-le')).decode('ascii')
    try:
        r = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                           capture_output=True, timeout=timeout, env=env, creationflags=CREATE_NO_WINDOW)
        text = r.stdout.decode('utf-8', 'replace').strip()
        if not text:
            return []
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


FILE_INFO_PS = r'''
$paths = $env:NM_PATHS | ConvertFrom-Json   # assign first: PowerShell 5.1 emits the array as one item
$out = foreach ($p in $paths) {
  $s = $null; try { $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop } catch {}
  $v = $null; try { $v = [Diagnostics.FileVersionInfo]::GetVersionInfo($p) } catch {}
  [pscustomobject]@{
    Path        = [string]$p
    Status      = $(if ($s) { [string]$s.Status } else { 'Unknown' })
    Publisher   = $(if ($s -and $s.SignerCertificate) { $s.SignerCertificate.Subject -replace '^CN="?([^",]+).*', '$1' } else { '' })
    Company     = $(if ($v) { [string]$v.CompanyName } else { '' })
    Product     = $(if ($v) { [string]$v.ProductName } else { '' })
    Description = $(if ($v) { [string]$v.FileDescription } else { '' })
  }
}
ConvertTo-Json -InputObject @($out) -Compress
'''

SERVICES_PS = r'''
Get-CimInstance Win32_Service -Filter "State='Running'" |
  Select-Object Name, DisplayName, Description, ProcessId, PathName | ConvertTo-Json -Compress
'''

DNS_CACHE_PS = r'''
Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | Select-Object Entry, Data | ConvertTo-Json -Compress
'''

PUBLIC_NETWORK_PS = r'''
ConvertTo-Json @(Get-NetConnectionProfile | Where-Object NetworkCategory -eq 'Public').Count
'''


def file_info(paths):
    """{path: {Status, Publisher, Company, Product, Description}} via Get-AuthenticodeSignature."""
    paths = sorted(paths)
    out = {}
    for i in range(0, len(paths), 40):
        for row in run_powershell(FILE_INFO_PS, {'NM_PATHS': json.dumps(paths[i:i + 40])}):
            if isinstance(row, dict) and isinstance(row.get('Path'), str):
                out[row['Path']] = row
    for p in paths:
        out.setdefault(p, {'Status': 'Unknown', 'Publisher': '', 'Company': '', 'Product': '', 'Description': ''})
    return out


# ---------------------------------------------------------------- risk rules (same as the PowerShell version)

SCRIPT_HOSTS = {'powershell', 'pwsh', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32',
                'certutil', 'bitsadmin', 'msbuild', 'installutil'}
CORE_PROCS = {'system', 'system idle', 'registry', 'secure system', 'smss', 'csrss', 'wininit', 'services',
              'lsass', 'svchost', 'memcompression', 'memory compression', 'lsaiso'}
LOOKALIKE_NAMES = {'svchost', 'lsass', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'spoolsv', 'taskhostw',
                   'dllhost', 'conhost', 'runtimebroker', 'rundll32', 'explorer', 'searchindexer', 'lsm'}
BAD_PORTS = {4444: 'the default port of the Metasploit hacking tool', 1337: 'a classic backdoor port',
             31337: 'a classic backdoor port', 12345: 'the NetBus trojan port', 6666: 'IRC, used by botnets',
             6667: 'IRC, used by botnets', 6697: 'IRC, used by botnets', 9001: 'the Tor network',
             9030: 'the Tor network', 9050: 'the Tor network'}
EXPOSED_PORT_RISK = {
    3389: ('high', "Remote Desktop is ON and your firewall allows it, so anyone on your network can try to log in to this PC. Fix (if you don't use it): Settings > System > Remote Desktop > turn it Off."),
    5900: ('high', "A VNC remote-control server is listening. Fix: if you didn't install remote-control software on purpose, uninstall it from Settings > Apps > Installed apps."),
    23: ('high', 'A Telnet server is listening (unencrypted remote login). Fix: Control Panel > Programs > Turn Windows features on or off > untick "Telnet Server", or uninstall the app that opened it.'),
    21: ('medium', "An FTP server is listening (passwords travel unencrypted). Fix: stop or uninstall the FTP app if you don't need it."),
    22: ('medium', 'An SSH server is listening for remote logins. Fix: if you didn\'t set this up, Settings > System > Optional features > uninstall "OpenSSH Server".'),
}
UNUSUAL_FOLDER = re.compile(r'\\(AppData\\Local\\Temp|Windows\\Temp|Temp)\\|\\Downloads\\|\\Users\\Public\\|\$Recycle\.Bin', re.I)


def in_windows(path):
    return path.lower().startswith(WINDIR.lower())


def is_external(ip):
    try:
        addr = ipaddress.ip_address(ip.split('%')[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def issue(level, text):
    return {'Level': level, 'Text': text}


def app_issues(info, admin):
    issues = []
    p, name = info['Path'], info['Name']
    if p:
        if UNUSUAL_FOLDER.search(p):
            issues.append(issue('high', f"Runs from an unusual folder ({p}). Real programs live in Program Files or Windows. Fix: in File Explorer right-click the file > 'Scan with Microsoft Defender'. If you don't recognise it, end it in Task Manager and delete or uninstall it."))
        if name.lower() in LOOKALIKE_NAMES and not in_windows(p):
            issues.append(issue('high', f"Uses the name of a Windows system file ({name}.exe) but runs from outside the Windows folder ({p}). This is a common malware disguise. Fix: run a full Defender scan (Windows Security > Virus & threat protection > Scan options > Full scan) and a Microsoft Defender Offline scan."))
        if info['Signature'] == 'HashMismatch':
            issues.append(issue('high', "The file's digital signature is broken, so it may have been tampered with. Fix: run a full scan (Windows Security > Virus & threat protection > Scan options > Full scan), then reinstall the app from its official website."))
        elif info['Signature'] in ('NotSigned', 'NotTrusted', 'UnknownError'):
            issues.append(issue('medium', f"Not signed by a known publisher. Not always bad (small and open-source tools often aren't), but most malware isn't signed. Fix: if you don't recognise '{name}', scan it with Microsoft Defender and uninstall it from Settings > Apps."))
    elif admin and name.lower() not in CORE_PROCS:
        issues.append(issue('medium', f"Windows won't reveal where this program lives, even to an Administrator. Fix: Task Manager > Details > right-click '{name}' > Open file location, then scan that file with Microsoft Defender."))
    if name.lower() in SCRIPT_HOSTS:
        issues.append(issue('medium', f"A Windows scripting tool ({name}) is using the network. That's fine if you or a trusted tool just ran a script; attackers also abuse these. Fix: Task Manager > Details > right-click a column header > Select columns > 'Command line' to see what it runs. End it if you didn't start it, then run a full Defender scan."))
    return issues


def risk_level(issues):
    if any(i['Level'] == 'high' for i in issues):
        return 'high'
    return 'medium' if issues else ''


def origin_of(info):
    """windows / microsoft / thirdparty / unsigned / unknown, from the file's signature and folder."""
    p, sig, pub = info['Path'], info['Signature'], info['Publisher']
    if p:
        if sig in ('NotSigned', 'HashMismatch', 'NotTrusted'):
            return 'unsigned'
        if sig != 'Valid':
            return 'windows' if in_windows(p) and info['Company'].startswith('Microsoft') else 'unknown'
        if 'Hardware Compatibility' in pub:   # other vendors' drivers, countersigned by Microsoft
            return 'thirdparty'
        if pub.startswith('Microsoft Windows') or (in_windows(p) and pub.startswith('Microsoft')):
            return 'windows'
        return 'microsoft' if pub.startswith('Microsoft') else 'thirdparty'
    return 'windows' if info['Name'].lower() in CORE_PROCS else 'unknown'


# ---------------------------------------------------------------- End process rules

NO_KILL = {**{n: 'core' for n in ('system', 'system idle', 'registry', 'secure system', 'memcompression',
                                  'memory compression', 'smss', 'csrss', 'wininit', 'winlogon', 'services',
                                  'lsass', 'lsaiso', 'fontdrvhost', 'dwm')},
           'svchost': 'svc',
           **{n: 'av' for n in ('msmpeng', 'nissrv', 'mpdefendercoreservice', 'securityhealthservice', 'smartscreen')}}
NO_KILL_REASON = {
    'core': "{0} is a core part of Windows. Ending it would crash or freeze the PC, so NetMonitor won't do it.",
    'svc': 'svchost runs several Windows services at once (hover its name to see them). Stop the specific service instead: press Win+R, type services.msc, find the service and click Stop.',
    'av': "{0} is part of Microsoft Defender. Ending it would switch off your virus protection, so NetMonitor won't do it.",
}
# shared by many apps: ending every copy could close unrelated things, so only the selected one is ended
SHARED_HOSTS = {'powershell', 'pwsh', 'cmd', 'conhost', 'msedgewebview2', 'dllhost', 'rundll32', 'runtimebroker',
                'backgroundtaskhost', 'taskhostw', 'wscript', 'cscript', 'sihost', 'wudfhost', 'searchprotocolhost',
                'explorer', 'python', 'pythonw', 'py'}
SKIP_STATES = {'Listen', 'Bound', 'TimeWait', 'Closed', 'DeleteTCB'}


def now_iso():
    return dt.datetime.now().astimezone().isoformat()


def csv_safe(value):
    """Prefix text Excel would run as a formula; remote hostnames come from reverse DNS, which
    the remote server's owner controls."""
    if isinstance(value, str) and value[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value


def append_csv(path, fields, rows):
    new = not os.path.exists(path)
    try:
        with open(path, 'a', newline='', encoding='utf-8-sig' if new else 'utf-8') as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            if new:
                w.writeheader()
            for r in rows:
                w.writerow({k: csv_safe(r.get(k, '')) for k in fields})
    except OSError:
        pass


# ---------------------------------------------------------------- monitor

class Monitor:
    def __init__(self, args):
        self.args = args
        self.admin = is_admin()
        self.out_dir = args.outdir
        os.makedirs(self.out_dir, exist_ok=True)
        self.csv_path = os.path.join(self.out_dir, f'connections-{dt.date.today():%Y%m%d}.csv')
        self.kill_log = os.path.join(self.out_dir, 'ended-processes.csv')
        self.lock = threading.RLock()
        self.names = {}
        self.proc_cache = {}
        self.file_cache = {}
        self.conns = {}
        self.dns_names = {}
        self.rdns = {}
        self.rdns_pool = ThreadPoolExecutor(max_workers=8)
        self.svc_map, self.svc_path, self.svc_info = {}, {}, {}
        self.svc_refreshed = 0.0
        self.dns_refreshed = 0.0
        self.prev_counters, self.prev_time = None, None
        self.on_public = bool(next(iter(run_powershell(PUBLIC_NETWORK_PS)), 0))
        self.latest_json = '{}'
        self.dashboard_pids = frozenset()

    # ---- background lookups

    def refresh_services(self):
        svc_map, svc_path, svc_info = {}, {}, {}
        by_pid = {}
        for s in run_powershell(SERVICES_PS):
            if not isinstance(s, dict) or not s.get('Name'):
                continue
            by_pid.setdefault(int(s.get('ProcessId') or 0), []).append(s)
            desc = s.get('Description') or ''
            if desc.startswith('@'):   # unresolved resource string
                desc = ''
            if len(desc) > 220:
                desc = desc[:217] + '...'
            svc_info[s['Name']] = {'d': s.get('DisplayName') or s['Name'], 's': desc}
        for pid, group in by_pid.items():
            svc_map[pid] = ', '.join(sorted(g['Name'] for g in group))
            exe = group[0].get('PathName') or ''
            m = re.match(r'^"([^"]+)"', exe) or re.match(r'^(.+?\.exe)\b', exe, re.I)
            exe = os.path.expandvars(m.group(1)) if m else ''
            if exe and os.path.isfile(exe):
                svc_path[pid] = exe
        self.svc_map, self.svc_path, self.svc_info = svc_map, svc_path, svc_info
        self.svc_refreshed = time.time()

    def refresh_dns_cache(self):
        for row in run_powershell(DNS_CACHE_PS):
            if isinstance(row, dict) and row.get('Data'):
                self.dns_names[str(row['Data'])] = row.get('Entry') or ''
        self.dns_refreshed = time.time()

    def host_for(self, ip, external):
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

    # ---- process details

    def ensure_proc_infos(self, pids):
        new = [p for p in pids if p not in self.proc_cache]
        for pid in new:
            name = self.names.get(pid, f'PID {pid}')
            path = '' if pid in (0, 4) else (process_path(pid) or self.svc_path.get(pid, ''))
            self.proc_cache[pid] = {'Name': name, 'Path': path, 'Description': 'Windows kernel' if pid == 4 else '',
                                    'Company': '', 'Product': '', 'Signature': '', 'Publisher': '', 'Origin': ''}
        unknown = {self.proc_cache[p]['Path'] for p in new} - set(self.file_cache) - {''}
        if unknown:
            self.file_cache.update(file_info(unknown))
        for pid in new:
            info = self.proc_cache[pid]
            fi = self.file_cache.get(info['Path'])
            if fi:
                info.update(Signature=fi.get('Status') or 'Unknown', Publisher=fi.get('Publisher') or '',
                            Company=fi.get('Company') or '', Product=fi.get('Product') or '',
                            Description=fi.get('Description') or info['Description'])
            info['Origin'] = origin_of(info)

    # ---- one refresh

    def poll(self):
        with self.lock:
            self._poll()

    def _poll(self):
        now = dt.datetime.now().astimezone()
        stamp = now.isoformat()
        self.names = process_names()
        for pid in [p for p in self.proc_cache if p not in self.names]:   # PIDs get reused
            del self.proc_cache[pid]
        if time.time() - self.svc_refreshed >= 30:
            self.refresh_services()
        if time.time() - self.dns_refreshed >= 10:
            threading.Thread(target=self.refresh_dns_cache, daemon=True).start()
            self.dns_refreshed = time.time()

        tcp = tcp_connections()
        udp = udp_endpoints()
        listen_ports = {lp for (st, la, lp, ra, rp, pid) in tcp if st == 'Listen'}
        self.ensure_proc_infos({row[5] for row in tcp} | {row[2] for row in udp})

        seen, new_rows = set(), []
        for state, laddr, lport, raddr, rport, pid in tcp:
            if state in SKIP_STATES or raddr in ('0.0.0.0', '::'):
                continue
            key = f'TCP|{laddr}|{lport}|{raddr}|{rport}|{pid}'
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
            direction = 'Inbound' if lport in listen_ports else 'Outbound'
            issues = app_issues(info, self.admin)
            if external and direction == 'Inbound':
                issues.append(issue('high', f"A computer on the internet ({raddr}) is connected INTO '{info['Name']}'. Unexpected unless you run a server or game host. Fix: end the app in Task Manager, then Windows Security > Firewall & network protection > Allow an app through firewall > untick it. Also check your router's port-forwarding settings."))
            if external and rport in BAD_PORTS:
                issues.append(issue('high', f"Talking to the internet on port {rport}, which is {BAD_PORTS[rport]}. Fix: unless you recognise this, end '{info['Name']}' in Task Manager and run a full Defender scan (Windows Security > Virus & threat protection > Scan options > Full scan)."))
            if external and rport in (21, 23):
                issues.append(issue('medium', f'Uses an unencrypted login protocol (port {rport}), so passwords can be read in transit. Fix: use an SFTP or SSH client instead.'))
            r = {'Risk': risk_level(issues), 'Issues': issues, 'Publisher': info['Publisher'], 'Direction': direction,
                 'External': external, 'App': info['Name'], 'Description': info['Description'],
                 'Services': self.svc_map.get(pid, ''), 'Path': info['Path'], 'PID': pid, 'Protocol': 'TCP',
                 'LocalAddress': laddr, 'LocalPort': lport, 'RemoteAddress': raddr, 'RemotePort': rport,
                 'RemoteHost': host, 'State': state, 'FirstSeen': stamp, 'LastSeen': stamp, 'Closed': None}
            self.conns[key] = r
            new_rows.append(r)

        for key, r in list(self.conns.items()):   # mark vanished connections closed, prune old ones
            if key in seen:
                continue
            if not r['Closed']:
                r['Closed'] = stamp
            elif (now - dt.datetime.fromisoformat(r['Closed'])).total_seconds() >= self.args.closed_retention * 60:
                del self.conns[key]

        if new_rows:
            append_csv(self.csv_path, ['Time', 'Risk', 'Direction', 'External', 'App', 'PID', 'Services', 'Path',
                                       'Protocol', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort',
                                       'RemoteHost', 'Issues'],
                       [dict(r, Time=r['FirstSeen'], Issues=' | '.join(i['Text'] for i in r['Issues'])) for r in new_rows])

        listeners, lseen = [], set()
        sockets = [('TCP', la, lp, pid) for (st, la, lp, ra, rp, pid) in tcp if st == 'Listen']
        sockets += [('UDP', la, lp, pid) for (la, lp, pid) in udp]
        for proto, addr, port, pid in sockets:
            if (proto, addr, port, pid) in lseen:
                continue
            lseen.add((proto, addr, port, pid))
            info = self.proc_cache[pid]
            loopback = addr.startswith('127.') or addr == '::1'
            issues = []
            if not loopback:
                issues += app_issues(info, self.admin)
                if proto == 'TCP' and port in EXPOSED_PORT_RISK:
                    issues.append(issue(*EXPOSED_PORT_RISK[port]))
                if self.on_public and proto == 'TCP' and port in (139, 445):
                    issues.append(issue('medium', "File sharing is open while you're on a Public network (cafe, hotel). Fix: Settings > Network & internet > Advanced network settings > Advanced sharing settings > turn off File and printer sharing for Public networks."))
            listeners.append({'Risk': risk_level(issues), 'Issues': issues, 'Publisher': info['Publisher'],
                              'App': info['Name'], 'Description': info['Description'],
                              'Services': self.svc_map.get(pid, ''), 'Path': info['Path'], 'PID': pid,
                              'Protocol': proto, 'LocalAddress': addr, 'LocalPort': port, 'Exposed': not loopback})

        rx_rate = tx_rate = None
        counters, t = adapter_counters(), time.time()
        if counters and self.prev_counters and t > self.prev_time:
            secs = t - self.prev_time
            d_in = sum((c[0] - self.prev_counters[m][0]) % 2 ** 32 for m, c in counters.items() if m in self.prev_counters)
            d_out = sum((c[1] - self.prev_counters[m][1]) % 2 ** 32 for m, c in counters.items() if m in self.prev_counters)
            rx_rate, tx_rate = d_in / secs, d_out / secs
        self.prev_counters, self.prev_time = counters, t

        apps = {}
        for info in self.proc_cache.values():
            if info['Name'] in apps and apps[info['Name']]['Path']:
                continue
            apps[info['Name']] = {k: info[k] for k in ('Origin', 'Path', 'Publisher', 'Signature', 'Company', 'Product', 'Description')}

        payload = {'generated': stamp, 'host': socket.gethostname(), 'admin': self.admin, 'interval': self.args.interval,
                   'rxRate': rx_rate, 'txRate': tx_rate, 'connections': list(self.conns.values()),
                   'listeners': listeners, 'apps': apps, 'services': self.svc_info}
        self.latest_json = json.dumps(payload, separators=(',', ':'))
        # only processes currently shown in the dashboard may be ended
        self.dashboard_pids = frozenset([r['PID'] for r in self.conns.values() if not r['Closed']] + [l['PID'] for l in listeners])

    # ---- End process

    def log_kill(self, pids, name, path, msg):
        append_csv(self.kill_log, ['Time', 'PID', 'App', 'Path', 'Result'],
                   [{'Time': now_iso(), 'PID': ' '.join(map(str, pids)), 'App': name, 'Path': path, 'Result': msg}])
        print(msg)

    def end_process(self, pid, name):
        if pid == os.getpid():
            return {'ok': False, 'message': 'That is NetMonitor itself. Press Ctrl+C in its window to stop it.'}
        if pid not in self.dashboard_pids:
            return {'ok': False, 'message': f'PID {pid} is no longer in the dashboard. Nothing was ended.'}
        current = process_names().get(pid)
        if current is None:
            return {'ok': True, 'message': f'{name} (PID {pid}) had already closed.'}
        if current != name:
            return {'ok': False, 'message': f'PID {pid} now belongs to {current}, not {name}. Nothing was ended.'}
        why = NO_KILL.get(name.lower())
        if why:
            return {'ok': False, 'message': NO_KILL_REASON[why].format(name)}
        path = self.proc_cache.get(pid, {}).get('Path', '')
        result = terminate(pid)
        if result == 'denied':
            ok, msg = False, f'Windows refused to end {name} (PID {pid}). Restart NetMonitor as Administrator and try again.'
        else:
            ok, msg = True, f'Ended {name} (PID {pid}).'
        self.log_kill([pid], name, path, msg)
        return {'ok': ok, 'message': msg}

    def end_program(self, pid, name):
        """End the whole app: every copy running from the same file. Windows are asked to close
        normally first (so e.g. Chrome saves its tabs); whatever is left after 5 seconds is forced."""
        with self.lock:
            path = self.proc_cache.get(pid, {}).get('Path', '')
            if name.lower() in SHARED_HOSTS or not path:
                return self.end_process(pid, name)
            if pid not in self.dashboard_pids:
                return {'ok': False, 'message': f'PID {pid} is no longer in the dashboard. Nothing was ended.'}
            why = NO_KILL.get(name.lower())
            if why:
                return {'ok': False, 'message': NO_KILL_REASON[why].format(name)}
            names = process_names()
            if names.get(pid) not in (None, name):
                return {'ok': False, 'message': f'PID {pid} now belongs to {names[pid]}, not {name}. Nothing was ended.'}
            targets = [p for p, n in names.items()
                       if n == name and p != os.getpid() and process_path(p).lower() == path.lower()]
            if not targets:
                return {'ok': True, 'message': f'{name} had already closed.'}

            close_windows(targets)
            deadline = time.time() + 5
            while time.time() < deadline and any(is_running(p) for p in targets):
                time.sleep(0.25)
            refused = sum(1 for p in targets if is_running(p) and terminate(p) == 'denied')
            n = len(targets)
            if refused:
                msg = f'Closed {n - refused} of {n} {name} processes. Windows refused the rest; restart NetMonitor as Administrator and try again.'
            else:
                msg = f'Closed {name}.' if n == 1 else f'Closed {name} completely ({n} processes).'
            self.log_kill(targets, name, path, msg)
            return {'ok': not refused, 'message': msg}


# ---------------------------------------------------------------- local dashboard server
# Served on localhost only. Every request except the page itself must carry a random per-run
# token that is embedded in the page, so other websites can't read the data or end processes.

CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"


def make_handler(monitor, page_bytes, token, port):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'NetMonitor'
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
            self.send_json(404, {'ok': False, 'message': 'Not found'})

        def do_POST(self):
            if not self.host_ok() or not self.token_ok():
                return self.send_json(403, {'ok': False, 'message': 'Not allowed. Reload the dashboard.'})
            if self.path != '/kill':
                return self.send_json(404, {'ok': False, 'message': 'Not found'})
            try:
                length = min(int(self.headers.get('Content-Length', 0)), 10000)
                body = json.loads(self.rfile.read(length) or b'{}')
                pid, name = int(body['pid']), str(body['name'])
            except (ValueError, KeyError, TypeError):
                return self.send_json(400, {'ok': False, 'message': 'Bad request'})
            self.send_json(200, monitor.end_program(pid, name))

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
    sys.exit(f"Couldn't open a local port for the dashboard (tried {port} to {port + 20}).")


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description='Live Windows connection monitor.')
    ap.add_argument('--interval', type=int, default=3, help='seconds between refreshes (default 3)')
    ap.add_argument('--outdir', default=os.path.join(HERE, 'NetMonitorOutput'), help='where logs go')
    ap.add_argument('--closed-retention', type=int, default=10, help='minutes closed connections stay visible')
    ap.add_argument('--no-browser', action='store_true', help="don't open the browser")
    ap.add_argument('--once', action='store_true', help='take one snapshot (data.json) and exit')
    ap.add_argument('--port', type=int, default=8765, help='local dashboard port (default 8765)')
    args = ap.parse_args()

    monitor = Monitor(args)
    if args.once:
        monitor.poll()
        with open(os.path.join(args.outdir, 'data.json'), 'w', encoding='utf-8') as f:
            f.write(monitor.latest_json)
        return

    server, port = start_server(monitor, args.port)
    url = f'http://localhost:{port}/'
    with open(os.path.join(args.outdir, 'dashboard.html'), 'w', encoding='utf-8') as f:   # old bookmarks forward here
        f.write(f'<!doctype html><meta charset=utf-8><meta http-equiv=refresh content="0;url={url}"><a href="{url}">Open the dashboard</a>')
    print(f'NetMonitor running. Dashboard: {url}')
    print(f'CSV log:   {monitor.csv_path}')
    if not monitor.admin:
        print('Tip: run as Administrator to resolve paths for all processes and to end elevated programs.')
    print('Press Ctrl+C to stop.')

    opened = False
    try:
        while True:
            start = time.time()
            monitor.poll()
            if not opened and not args.no_browser:
                webbrowser.open(url)
                opened = True
            time.sleep(max(0.2, args.interval - (time.time() - start)))
    except KeyboardInterrupt:
        print('Stopped.')
    finally:
        server.shutdown()


if __name__ == '__main__':
    main()
