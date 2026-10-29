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

APP_NAME = 'My Windows Network/Internet Connection Monitor'
APP_VERSION = '1.1'
HERE = os.path.dirname(os.path.abspath(__file__))
WINDIR = os.environ.get('WINDIR', r'C:\Windows')
FROZEN = getattr(sys, 'frozen', False)                    # running as the packaged NetMonitor.exe
RESOURCES = getattr(sys, '_MEIPASS', HERE)                # where dashboard.html is
APP_DIR = os.path.join(os.environ.get('LOCALAPPDATA', HERE), 'MyNetworkMonitor')   # logs when run as the app

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


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [('Length', wt.USHORT), ('MaximumLength', wt.USHORT), ('Buffer', ctypes.c_void_p)]


class SYSTEM_PROCESS_ID_INFORMATION(ctypes.Structure):
    _fields_ = [('ProcessId', ctypes.c_void_p), ('ImageName', UNICODE_STRING)]


ntdll = ctypes.WinDLL('ntdll')
ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
ntdll.NtQuerySystemInformation.restype = ctypes.c_long
kernel32.QueryDosDeviceW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]
SystemProcessIdInformation = 88
_device_map = None


def _dos_path(nt_path):
    r"""\Device\HarddiskVolume3\Windows\x.exe -> C:\Windows\x.exe"""
    global _device_map
    if _device_map is None:
        _device_map = {}
        buf = ctypes.create_unicode_buffer(1024)
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            if kernel32.QueryDosDeviceW(f'{letter}:', buf, len(buf)):
                _device_map[buf.value.lower()] = f'{letter}:'
    for device, drive in _device_map.items():
        if nt_path.lower().startswith(device + '\\'):
            return drive + nt_path[len(device):]
    return ''


def _image_name_from_kernel(pid):
    """Program file of any process, including ones Windows protects from being opened (what Task Manager uses)."""
    buf = ctypes.create_unicode_buffer(32767)   # MaximumLength is 16-bit, so at most 65534 bytes
    info = SYSTEM_PROCESS_ID_INFORMATION()
    info.ProcessId = pid
    info.ImageName.MaximumLength = ctypes.sizeof(buf)
    info.ImageName.Buffer = ctypes.addressof(buf)
    if ntdll.NtQuerySystemInformation(SystemProcessIdInformation, ctypes.byref(info), ctypes.sizeof(info), None) != 0:
        return ''
    return _dos_path(ctypes.wstring_at(info.ImageName.Buffer, info.ImageName.Length // 2))


def process_path(pid):
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if h:
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = wt.DWORD(len(buf))
            if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return buf.value
        finally:
            kernel32.CloseHandle(h)
    return '' if pid in (0, 4) else _image_name_from_kernel(pid)


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


# Windows Filtering Platform: turns the filter ID in a firewall-block event into the rule's name
class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [('name', ctypes.c_wchar_p), ('description', ctypes.c_wchar_p)]


class FWPM_FILTER0_START(ctypes.Structure):   # only the leading fields of FWPM_FILTER0 are read
    _fields_ = [('filterKey', ctypes.c_ubyte * 16), ('displayData', FWPM_DISPLAY_DATA0)]


try:
    fwpuclnt = ctypes.WinDLL('fwpuclnt')
    fwpuclnt.FwpmEngineOpen0.argtypes = [wt.LPCWSTR, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wt.HANDLE)]
    fwpuclnt.FwpmEngineOpen0.restype = wt.DWORD
    fwpuclnt.FwpmFilterGetById0.argtypes = [wt.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.POINTER(FWPM_FILTER0_START))]
    fwpuclnt.FwpmFilterGetById0.restype = wt.DWORD
    fwpuclnt.FwpmFreeMemory0.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
except (OSError, AttributeError):
    fwpuclnt = None
RPC_C_AUTHN_WINNT = 10
_wfp_engine = None
_filter_names = {}


def firewall_rule_name(filter_id):
    """Name of the firewall rule / filter that blocked a connection ('' if Windows won't say)."""
    global _wfp_engine
    if not filter_id or fwpuclnt is None:
        return ''
    if filter_id in _filter_names:
        return _filter_names[filter_id]
    if _wfp_engine is None:
        h = wt.HANDLE()
        _wfp_engine = h if fwpuclnt.FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, ctypes.byref(h)) == 0 else False
    name = ''
    if _wfp_engine:
        flt = ctypes.POINTER(FWPM_FILTER0_START)()
        if fwpuclnt.FwpmFilterGetById0(_wfp_engine, filter_id, ctypes.byref(flt)) == 0 and flt:
            name = flt.contents.displayData.name or ''
            p = ctypes.c_void_p(ctypes.cast(flt, ctypes.c_void_p).value)
            fwpuclnt.FwpmFreeMemory0(ctypes.byref(p))
    _filter_names[filter_id] = name
    return name


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

# Connections blocked by Windows Firewall: event 5157 in the Security log, written only when
# "Filtering Platform Connection" failure auditing is on. Newest first; only events after NM_SINCE.
BLOCKED_PS = r'''
$since = [long]$env:NM_SINCE
$filter = @{ LogName = 'Security'; Id = 5157 }
if ($since -le 0) { $filter.StartTime = (Get-Date).AddMinutes(-60) }
try {
  $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction Stop | Where-Object { $_.RecordId -gt $since })
} catch {
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { '[]'; return }
  ConvertTo-Json -InputObject @{ error = $_.Exception.Message } -Compress; return
}
$out = foreach ($e in $events) {
  $d = @{}
  foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
  [pscustomobject]@{ Id = $e.RecordId; Time = $e.TimeCreated.ToString('o'); ProcessId = $d['ProcessID']; FilterId = $d['FilterRTID']
                     Application = $d['Application']; Direction = $d['Direction']; Local = $d['SourceAddress']
                     LocalPort = $d['SourcePort']; Remote = $d['DestAddress']; RemotePort = $d['DestPort']; Protocol = $d['Protocol'] }
}
ConvertTo-Json -InputObject @($out) -Compress
'''

# Is "Filtering Platform Connection" failure auditing on? (GUID works on every Windows language)
AUDIT_PS = r'''
$csv = auditpol /get /subcategory:'{0CCE9226-69AE-11D9-BED3-505054503030}' /r 2>$null
if ($LASTEXITCODE -ne 0 -or -not $csv) { ConvertTo-Json -InputObject @{ ok = $false; setting = '' } -Compress; return }
$row = @($csv | Where-Object { $_ } | ConvertFrom-Csv)[0]
ConvertTo-Json -InputObject @{ ok = $true; setting = [string]@($row.PSObject.Properties)[4].Value } -Compress
'''
PROTOCOLS = {'1': 'ICMP', '6': 'TCP', '17': 'UDP', '58': 'ICMPv6'}

# Apps blocked from the dashboard: Windows Firewall rules in their own "NetMonitor" group, so only
# NetMonitor's rules are ever listed or removed. Program paths come in via environment variables.
FW_GROUP = 'NetMonitor'
FW_LIST_PS = r'''
$out = foreach ($r in @(Get-NetFirewallRule -Group 'NetMonitor' -ErrorAction SilentlyContinue)) {
  [pscustomobject]@{ Program = [string]($r | Get-NetFirewallApplicationFilter).Program; Direction = [string]$r.Direction; Name = [string]$r.DisplayName }
}
ConvertTo-Json -InputObject @($out) -Compress
'''
FW_BLOCK_PS = r'''
try {
  foreach ($dir in 'Outbound', 'Inbound') {
    New-NetFirewallRule -DisplayName ('NetMonitor block: {0} ({1})' -f $env:NM_NAME, $dir.ToLower()) -Group 'NetMonitor' `
      -Direction $dir -Action Block -Program $env:NM_PATH -Profile Any -ErrorAction Stop `
      -Description 'Created by My Windows Network/Internet Connection Monitor (Block app). Use Unblock in its Blocked tab to remove.' | Out-Null
  }
  ConvertTo-Json -InputObject @{ ok = $true } -Compress
} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }
'''
FW_UNBLOCK_PS = r'''
try {
  $rules = @(Get-NetFirewallRule -Group 'NetMonitor' -ErrorAction SilentlyContinue |
             Where-Object { ($_ | Get-NetFirewallApplicationFilter).Program -eq $env:NM_PATH })
  $names = @($rules | ForEach-Object { [string]$_.DisplayName })
  if ($rules.Count) { $rules | Remove-NetFirewallRule -ErrorAction Stop }
  ConvertTo-Json -InputObject @{ ok = $true; removed = $names } -Compress
} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }
'''

PUBLIC_NETWORK_PS = r'''
ConvertTo-Json @(Get-NetConnectionProfile | Where-Object NetworkCategory -eq 'Public').Count
'''


def file_info(paths):
    """{path: {Status, Publisher, Company, Product, Description}} via Get-AuthenticodeSignature."""
    paths = sorted(paths)
    out = {}
    batches = [paths[i:i + 12] for i in range(0, len(paths), 12)]
    # signature checks are slow (catalog lookups), so run a few PowerShell helpers side by side
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = pool.map(lambda batch: run_powershell(FILE_INFO_PS, {'NM_PATHS': json.dumps(batch)}), batches)
    for rows in results:
        for row in rows:
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
        # activity log lives next to NetMonitor.exe (or NetMonitor.py) and keeps the last 10 days
        self.activity_log = os.path.join(os.path.dirname(sys.executable) if FROZEN else HERE, 'activity-log.txt')
        self.activity_pruned = 0.0
        self.prune_activity_log()
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
        self.sig_queue, self.sig_busy = set(), False   # program files waiting for a signature check
        self.blocked, self.blocked_since = {}, 0       # firewall-blocked connections, grouped
        self.blocked_status, self.blocked_error = 'unknown', ''
        self.blocked_busy, self.blocked_refreshed = False, 0.0
        self.audit_on, self.audit_checked = None, 0.0
        self.fw_blocked, self.fw_busy, self.fw_refreshed = [], False, 0.0   # apps blocked from the dashboard
        self.seen_names = {}
        # when each app was unblocked, so its earlier blocked attempts aren't listed again after a restart
        self.unblocked_file = os.path.join(self.out_dir, 'unblocked.json')
        try:
            with open(self.unblocked_file, encoding='utf-8') as f:
                self.unblocked = {k: v for k, v in json.load(f).items() if isinstance(v, str)}
        except (OSError, ValueError, AttributeError):
            self.unblocked = {}
        self.on_public = False
        threading.Thread(target=self._check_public_network, daemon=True).start()
        self.latest_json = '{}'
        self.dashboard_pids = frozenset()
        self.last_client = time.time()     # when a dashboard last asked for data
        self.stop = threading.Event()      # set by the dashboard's Stop monitor button

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

    def refresh_blocked(self):
        """Read new firewall-block events (5157) from the Security log and group repeats."""
        try:
            if not self.admin:
                self.blocked_status = 'admin'
                return
            if time.time() - self.audit_checked > 60:
                row = next(iter(run_powershell(AUDIT_PS)), {})
                setting = str(row.get('setting', '')).strip().lower()
                # auditpol's wording is English-only: anything else means "can't tell", decided by whether events appear
                self.audit_on = True if 'failure' in setting else False if setting in ('no auditing', 'success') else None
                self.audit_checked = time.time()
            rows = run_powershell(BLOCKED_PS, {'NM_SINCE': str(self.blocked_since)})
            if rows and isinstance(rows[0], dict) and 'error' in rows[0]:
                self.blocked_status, self.blocked_error = 'error', str(rows[0]['error'])
                return
            with self.lock:
                for ev in rows:
                    if isinstance(ev, dict):
                        self._add_blocked(ev)
                cutoff = dt.datetime.now().astimezone() - dt.timedelta(hours=1)
                for key in [k for k, b in self.blocked.items() if dt.datetime.fromisoformat(b['LastSeen']) < cutoff]:
                    del self.blocked[key]
                if len(self.blocked) > 500:   # keep the most recent
                    for key in sorted(self.blocked, key=lambda k: self.blocked[k]['LastSeen'])[:len(self.blocked) - 500]:
                        del self.blocked[key]
            if self.audit_on is not None:
                self.blocked_status = 'on' if self.audit_on else 'off'
            else:
                self.blocked_status = 'on' if self.blocked else 'unknown'
        finally:
            self.blocked_busy = False
            self.blocked_refreshed = time.time()

    # ---- Block app: Windows Firewall rules for one program file

    def refresh_fw(self):
        try:
            if not self.admin:
                return
            by_path = {}
            for row in run_powershell(FW_LIST_PS):
                prog = str(row.get('Program') or '') if isinstance(row, dict) else ''
                if not prog or prog.lower() == 'any':
                    continue
                entry = by_path.setdefault(prog.lower(), {'Path': prog, 'Directions': [], 'Rules': []})
                entry['Directions'].append(str(row.get('Direction') or ''))
                entry['Rules'].append(str(row.get('Name') or ''))
            names = {n.lower(): n for n in getattr(self, 'names', {}).values()}
            for entry in by_path.values():
                base = os.path.splitext(os.path.basename(entry['Path']))[0]
                entry['App'] = names.get(base.lower(), base)
                entry['Directions'] = sorted(set(entry['Directions']))
            self.fw_blocked = sorted(by_path.values(), key=lambda e: e['App'].lower())
        finally:
            self.fw_busy = False
            self.fw_refreshed = time.time()

    def block_app(self, pid, name):
        if not self.admin:
            return {'ok': False, 'message': 'Blocking apps needs administrator rights. Start NetMonitor as Administrator.'}
        with self.lock:
            path = self.proc_cache.get(pid, {}).get('Path', '')
            in_dashboard = pid in self.dashboard_pids
        if pid in (os.getpid(), os.getppid()) or (FROZEN and path.lower() == sys.executable.lower()):
            return {'ok': False, 'message': "NetMonitor can't block itself."}
        if not in_dashboard:
            return {'ok': False, 'message': f'PID {pid} is no longer in the dashboard. Nothing was blocked.'}
        if process_names().get(pid) not in (None, name):
            return {'ok': False, 'message': f'PID {pid} now belongs to a different program. Nothing was blocked.'}
        why = NO_KILL.get(name.lower())
        if why == 'av':
            return {'ok': False, 'message': f"{name} is part of Microsoft Defender. Blocking it would stop virus-protection updates, so NetMonitor won't do it."}
        if why or pid == 4:
            return {'ok': False, 'message': f"{name} is a core part of Windows. Blocking it could cut off networking for the whole PC, so NetMonitor won't do it."}
        if name.lower() in SHARED_HOSTS:
            return {'ok': False, 'message': f"{name} is used by many different programs, so blocking it would cut off more than one app. NetMonitor won't block it."}
        if not path:
            return {'ok': False, 'message': f"Windows didn't reveal where {name} lives, so it can't be blocked by its file."}
        if any(e['Path'].lower() == path.lower() for e in self.fw_blocked):
            return {'ok': True, 'message': f'{name} is already blocked.'}
        row = next(iter(run_powershell(FW_BLOCK_PS, {'NM_PATH': path, 'NM_NAME': name})), {})
        if not row.get('ok'):
            return {'ok': False, 'message': f"Windows Firewall didn't accept the block for {name}. {row.get('error', '')}".strip()}
        self.refresh_fw()
        msg = (f"Blocked {name} with Windows Firewall rules 'NetMonitor block: {name} (outbound)' and "
               f"'NetMonitor block: {name} (inbound)': it can't connect in or out.")
        self.log_action('BLOCKED', [pid], name, path, msg)
        # close it too, so connections it already had open end now rather than when it next reconnects
        closed = self.end_program(pid, name)
        if closed.get('ok'):
            return {'ok': True, 'message': f'{msg} {closed["message"]} If you start it again it stays blocked until you unblock it.'}
        return {'ok': False, 'message': f'{msg} But it could not be closed: {closed["message"]}'}

    def unblock_app(self, path):
        if not self.admin:
            return {'ok': False, 'message': 'Unblocking apps needs administrator rights. Start NetMonitor as Administrator.'}
        entry = next((e for e in self.fw_blocked if e['Path'].lower() == str(path).lower()), None)
        if not entry:   # only NetMonitor's own rules can be removed from here
            return {'ok': False, 'message': 'That app is not in the list of apps NetMonitor blocked.'}
        row = next(iter(run_powershell(FW_UNBLOCK_PS, {'NM_PATH': entry['Path']})), {})
        if not row.get('ok'):
            return {'ok': False, 'message': f"Windows Firewall didn't remove the block for {entry['App']}. {row.get('error', '')}".strip()}
        self.refresh_fw()
        with self.lock:   # its earlier blocked attempts came from this block, so clear them from the list
            for key in [k for k, b in self.blocked.items() if b['Path'] and b['Path'].lower() == entry['Path'].lower()]:
                del self.blocked[key]
            cutoff = dt.datetime.now().astimezone() - dt.timedelta(hours=2)
            self.unblocked = {k: v for k, v in self.unblocked.items() if dt.datetime.fromisoformat(v) > cutoff}
            self.unblocked[entry['Path'].lower()] = now_iso()
            try:
                with open(self.unblocked_file, 'w', encoding='utf-8') as f:
                    json.dump(self.unblocked, f)
            except OSError:
                pass
        removed = row.get('removed') or []
        removed = [removed] if isinstance(removed, str) else removed
        rules = ' and '.join(f"'{r}'" for r in removed) or 'its NetMonitor rules'
        msg = f"Unblocked {entry['App']}: removed Windows Firewall {'rule' if len(removed) == 1 else 'rules'} {rules}; it can connect again."
        self.log_action('UNBLOCKED', [], entry['App'], entry['Path'], msg)
        return {'ok': True, 'message': msg}

    def set_audit(self, enable):
        """Turn Windows' blocked-connection recording on or off (the dashboard's button). Only this one setting."""
        if not self.admin:
            return {'ok': False, 'message': 'Changing this needs administrator rights. Start NetMonitor as Administrator.'}
        auditpol = os.path.join(WINDIR, 'System32', 'auditpol.exe')
        try:
            r = subprocess.run([auditpol, '/set', '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}',
                                '/failure:enable' if enable else '/failure:disable'],
                               capture_output=True, timeout=30, creationflags=CREATE_NO_WINDOW)
        except (OSError, subprocess.SubprocessError) as e:
            return {'ok': False, 'message': f"Couldn't run Windows' auditpol tool: {e}"}
        if r.returncode != 0:
            detail = (r.stdout or r.stderr or b'').decode('utf-8', 'replace').strip()
            return {'ok': False, 'message': f'Windows refused the change. {detail}'.strip()}
        self.audit_on, self.audit_checked = enable, time.time()
        self.blocked_status = 'on' if enable else 'off'
        self.blocked_refreshed = 0.0   # read the log again on the next refresh
        msg = ('Blocked-connection recording is on. Blocked connections will appear here as they happen.' if enable
               else 'Blocked-connection recording is off.')
        print(msg)
        return {'ok': True, 'message': msg}

    def _add_blocked(self, ev):
        self.blocked_since = max(self.blocked_since, int(ev.get('Id') or 0))
        app = str(ev.get('Application') or '')
        path = _dos_path(app) if app.lower().startswith('\\device\\') else app
        name = os.path.splitext(os.path.basename(path or app))[0] or 'System'
        # the log writes paths in lowercase; use the program's own spelling if it has been seen running
        name = getattr(self, 'seen_names', {}).get(name.lower(), name)
        direction = 'Inbound' if ev.get('Direction') == '%%14592' else 'Outbound'
        remote, rport, lport = str(ev.get('Remote') or ''), int(ev.get('RemotePort') or 0), int(ev.get('LocalPort') or 0)
        proto = PROTOCOLS.get(str(ev.get('Protocol')), str(ev.get('Protocol') or ''))
        when = str(ev.get('Time') or now_iso())
        unblocked_at = self.unblocked.get(path.lower())
        if unblocked_at and dt.datetime.fromisoformat(when) <= dt.datetime.fromisoformat(unblocked_at):
            return   # blocked by a NetMonitor rule that has since been removed
        # outbound blocks repeat from new local ports, inbound ones target the same local port
        key = (name.lower(), direction, remote, rport if direction == 'Outbound' else lport, proto)
        b = self.blocked.get(key)
        if not b:
            b = self.blocked[key] = {'App': name, 'Path': path if ':' in path else '',
                                     'Direction': direction, 'RemoteAddress': remote, 'RemotePort': rport,
                                     'LocalPort': lport, 'Protocol': proto, 'External': is_external(remote),
                                     'Count': 0, 'FirstSeen': when, 'LastSeen': when, 'PID': 0}
        b['Count'] += 1
        b['FirstSeen'], b['LastSeen'] = min(b['FirstSeen'], when), max(b['LastSeen'], when)
        if when >= b['LastSeen']:
            b['PID'], b['LocalPort'] = int(ev.get('ProcessId') or 0), lport
            try:
                b['Rule'] = firewall_rule_name(int(ev.get('FilterId') or 0)) or b.get('Rule', '')
            except (ValueError, OSError):
                b.setdefault('Rule', '')
        b.setdefault('Rule', '')

    def _check_public_network(self):
        self.on_public = bool(next(iter(run_powershell(PUBLIC_NETWORK_PS)), 0))

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
        # signature checks are slow, so they run in the background and fill in when done
        unknown = {self.proc_cache[p]['Path'] for p in new} - set(self.file_cache) - self.sig_queue - {''}
        if unknown:
            self.sig_queue |= unknown
            if not self.sig_busy:
                self.sig_busy = True
                threading.Thread(target=self._check_signatures, daemon=True).start()
        for pid in new:
            self._apply_file_info(self.proc_cache[pid])

    def _apply_file_info(self, info):
        fi = self.file_cache.get(info['Path'])
        if fi:
            info.update(Signature=fi.get('Status') or 'Unknown', Publisher=fi.get('Publisher') or '',
                        Company=fi.get('Company') or '', Product=fi.get('Product') or '',
                        Description=fi.get('Description') or info['Description'])
        info['Origin'] = 'checking' if info['Path'] and not fi else origin_of(info)

    def _check_signatures(self):
        while True:
            with self.lock:
                batch = self.sig_queue - set(self.file_cache)
                if not batch:
                    self.sig_queue.clear()
                    self.sig_busy = False
                    return
            results = file_info(batch)   # slow; runs outside the lock so the dashboard keeps refreshing
            with self.lock:
                self.file_cache.update(results)
                self.sig_queue -= set(results)
                for info in self.proc_cache.values():
                    if info['Path'] in results:
                        self._apply_file_info(info)

    # ---- one refresh

    def poll(self):
        with self.lock:
            self._poll()

    def _poll(self):
        now = dt.datetime.now().astimezone()
        stamp = now.isoformat()
        self.names = process_names()
        self.seen_names.update({n.lower(): n for n in self.names.values()})   # proper spelling, even after a program closes
        for pid in [p for p in self.proc_cache if p not in self.names]:   # PIDs get reused
            del self.proc_cache[pid]
        if time.time() - self.svc_refreshed >= 30:
            self.svc_refreshed = time.time()
            threading.Thread(target=self.refresh_services, daemon=True).start()
        if time.time() - self.fw_refreshed >= 15 and not self.fw_busy:
            self.fw_busy = True
            threading.Thread(target=self.refresh_fw, daemon=True).start()
        if time.time() - self.blocked_refreshed >= 10 and not self.blocked_busy:
            self.blocked_busy = True
            threading.Thread(target=self.refresh_blocked, daemon=True).start()
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
            issues = []   # issues about this connection itself; the app's own issues are added below
            if external and direction == 'Inbound':
                issues.append(issue('high', f"A computer on the internet ({raddr}) is connected INTO '{info['Name']}'. Unexpected unless you run a server or game host. Fix: end the app in Task Manager, then Windows Security > Firewall & network protection > Allow an app through firewall > untick it. Also check your router's port-forwarding settings."))
            if external and rport in BAD_PORTS:
                issues.append(issue('high', f"Talking to the internet on port {rport}, which is {BAD_PORTS[rport]}. Fix: unless you recognise this, end '{info['Name']}' in Task Manager and run a full Defender scan (Windows Security > Virus & threat protection > Scan options > Full scan)."))
            if external and rport in (21, 23):
                issues.append(issue('medium', f'Uses an unencrypted login protocol (port {rport}), so passwords can be read in transit. Fix: use an SFTP or SSH client instead.'))
            r = {'Risk': '', 'Issues': [], 'Publisher': '', 'Direction': direction,
                 'External': external, 'App': info['Name'], 'Description': '',
                 'Services': '', 'Path': '', 'PID': pid, 'Protocol': 'TCP',
                 'LocalAddress': laddr, 'LocalPort': lport, 'RemoteAddress': raddr, 'RemotePort': rport,
                 'RemoteHost': host, 'State': state, 'FirstSeen': stamp, 'LastSeen': stamp, 'Closed': None,
                 '_conn_issues': issues}
            self.conns[key] = r
            new_rows.append(r)

        # keep each open connection's app details and risk current (signature checks finish in the background)
        for r in self.conns.values():
            info = self.proc_cache.get(r['PID'])
            if info and not r['Closed']:
                r['Issues'] = app_issues(info, self.admin) + r['_conn_issues']
                r.update(Risk=risk_level(r['Issues']), Publisher=info['Publisher'], Description=info['Description'],
                         Path=info['Path'], Services=self.svc_map.get(r['PID'], r['Services']))

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
                   'rxRate': rx_rate, 'txRate': tx_rate, 'connections': [{k: v for k, v in r.items() if not k.startswith('_')} for r in self.conns.values()],
                   'listeners': listeners, 'apps': apps, 'services': self.svc_info,
                   # only attempts by apps blocked from the dashboard, not everything the firewall blocks
                   'blocked': sorted((b for b in self.blocked.values()
                                      if b['Path'].lower() in {e['Path'].lower() for e in self.fw_blocked}),
                                     key=lambda b: b['LastSeen'], reverse=True),
                   'blockedStatus': self.blocked_status, 'blockedError': self.blocked_error,
                   'fwBlocked': self.fw_blocked}
        self.latest_json = json.dumps(payload, separators=(',', ':'))
        # only processes currently shown in the dashboard may be ended
        self.dashboard_pids = frozenset([r['PID'] for r in self.conns.values() if not r['Closed']] + [l['PID'] for l in listeners])

    # ---- End process

    def log_action(self, action, pids, name, path, msg):
        """One line per Block / Unblock / End process in activity-log.txt."""
        who = name + (f" (PID {', '.join(map(str, pids))})" if pids else '')
        line = f"{dt.datetime.now():%Y-%m-%d %H:%M:%S}  {action:<9}  {who}  {path or '(location unknown)'}  {msg}\n"
        if time.time() - self.activity_pruned > 3600:
            self.prune_activity_log()
        try:
            with open(self.activity_log, 'a', encoding='utf-8') as f:
                f.write(line)
        except OSError:
            # can't write next to the app (e.g. a read-only folder): keep the log with the other logs instead
            self.activity_log = os.path.join(self.out_dir, 'activity-log.txt')
            try:
                with open(self.activity_log, 'a', encoding='utf-8') as f:
                    f.write(line)
            except OSError:
                pass
        print(msg)

    def open_activity_log(self):
        """Open activity-log.txt in the user's text editor (the dashboard's Activity log button)."""
        try:
            if not os.path.exists(self.activity_log):
                with open(self.activity_log, 'a', encoding='utf-8'):
                    pass
        except OSError:
            self.activity_log = os.path.join(self.out_dir, 'activity-log.txt')
            with open(self.activity_log, 'a', encoding='utf-8'):
                pass
        try:
            # via Explorer, so the editor runs as the signed-in user rather than with NetMonitor's admin rights
            subprocess.Popen([os.path.join(WINDIR, 'explorer.exe'), self.activity_log], creationflags=CREATE_NO_WINDOW)
        except OSError as e:
            return {'ok': False, 'message': f"Couldn't open the activity log ({self.activity_log}): {e}"}
        return {'ok': True, 'message': f'Opened the activity log: {self.activity_log}'}

    def prune_activity_log(self, days=10):
        """Drop activity-log lines older than `days`."""
        self.activity_pruned = time.time()
        try:
            with open(self.activity_log, encoding='utf-8') as f:
                lines = f.readlines()
        except OSError:
            return
        cutoff = f'{dt.datetime.now() - dt.timedelta(days=days):%Y-%m-%d %H:%M:%S}'
        keep = [ln for ln in lines if ln[:19] >= cutoff]   # lines start with a sortable timestamp
        if len(keep) != len(lines):
            try:
                with open(self.activity_log, 'w', encoding='utf-8') as f:
                    f.writelines(keep)
            except OSError:
                pass

    def end_process(self, pid, name):
        if pid in (os.getpid(), os.getppid()):   # the .exe runs as a small launcher plus this process
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
        self.log_action('ENDED', [pid], name, path, msg)
        return {'ok': ok, 'message': msg}

    def end_program(self, pid, name):
        """End the whole app: every copy running from the same file. Windows are asked to close
        normally first (so e.g. Chrome saves its tabs); whatever is left after 5 seconds is forced."""
        with self.lock:
            path = self.proc_cache.get(pid, {}).get('Path', '')
            if pid in (os.getpid(), os.getppid()) or (FROZEN and path.lower() == sys.executable.lower()):
                return {'ok': False, 'message': 'That is NetMonitor itself. Use the Stop monitor button to stop it.'}
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
            self.log_action('ENDED', targets, name, path, msg)
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
                monitor.last_client = time.time()
                return self.send(200, 'application/json; charset=utf-8', monitor.latest_json.encode('utf-8'))
            self.send_json(404, {'ok': False, 'message': 'Not found'})

        def do_POST(self):
            if not self.host_ok() or not self.token_ok():
                return self.send_json(403, {'ok': False, 'message': 'Not allowed. Reload the dashboard.'})
            if self.path in ('/block', '/unblock'):
                try:
                    length = min(int(self.headers.get('Content-Length', 0)), 10000)
                    body = json.loads(self.rfile.read(length) or b'{}')
                    if self.path == '/block':
                        result = monitor.block_app(int(body['pid']), str(body['name']))
                    else:
                        result = monitor.unblock_app(str(body['path']))
                except (ValueError, KeyError, TypeError):
                    return self.send_json(400, {'ok': False, 'message': 'Bad request'})
                return self.send_json(200, result)
            if self.path == '/openlog':
                return self.send_json(200, monitor.open_activity_log())
            if self.path == '/audit':
                try:
                    length = min(int(self.headers.get('Content-Length', 0)), 1000)
                    enable = bool(json.loads(self.rfile.read(length) or b'{}')['enable'])
                except (ValueError, KeyError, TypeError):
                    return self.send_json(400, {'ok': False, 'message': 'Bad request'})
                return self.send_json(200, monitor.set_audit(enable))
            if self.path == '/quit':
                self.send_json(200, {'ok': True, 'message': 'NetMonitor has stopped. You can close this tab.'})
                monitor.stop.set()
                return None
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
    with open(os.path.join(RESOURCES, 'dashboard.html'), encoding='utf-8') as f:
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

kernel32.CreateMutexW.restype = wt.HANDLE
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.LPCWSTR]
ERROR_ALREADY_EXISTS = 183
_instance_mutex = None


def another_copy_running():
    """True if NetMonitor is already running as the app (one copy per Windows session)."""
    global _instance_mutex
    _instance_mutex = kernel32.CreateMutexW(None, False, 'Local\\MyWindowsNetworkMonitor')
    return ctypes.get_last_error() == ERROR_ALREADY_EXISTS


def show_error(message):
    user32.MessageBoxW(None, message, APP_NAME, 0x10)   # MB_ICONERROR


def main():
    ap = argparse.ArgumentParser(description='Live Windows connection monitor.')
    ap.add_argument('--interval', type=int, default=3, help='seconds between refreshes (default 3)')
    ap.add_argument('--outdir', default=None, help='where logs go')
    ap.add_argument('--closed-retention', type=int, default=10, help='minutes closed connections stay visible')
    ap.add_argument('--no-browser', action='store_true', help="don't open the browser")
    ap.add_argument('--once', action='store_true', help='take one snapshot (data.json) and exit')
    ap.add_argument('--port', type=int, default=8765, help='local dashboard port (default 8765)')
    ap.add_argument('--app', action='store_true', default=FROZEN,
                    help='app mode (default for NetMonitor.exe): one copy only, logs in %%LOCALAPPDATA%%, '
                         'stops a few minutes after the dashboard is closed')
    ap.add_argument('--idle-exit', type=int, default=3, help='app mode: minutes without an open dashboard before stopping')
    args = ap.parse_args()
    if not args.outdir:
        args.outdir = os.path.join(APP_DIR if args.app else HERE, 'NetMonitorOutput')
    url_file = os.path.join(APP_DIR, 'running.url')

    if args.app and not args.once and another_copy_running():
        # already running: just bring its dashboard back
        try:
            with open(url_file, encoding='utf-8') as f:
                webbrowser.open(f.read().strip())
        except OSError:
            show_error('NetMonitor is already running, but its dashboard address could not be found. '
                       'Wait a minute and try again.')
        return

    monitor = Monitor(args)
    if args.once:
        monitor.poll()
        deadline = time.time() + 60   # a snapshot should include signatures and services, so wait for them
        while (monitor.sig_busy or not monitor.svc_map) and time.time() < deadline:
            time.sleep(0.5)
        monitor.poll()
        with open(os.path.join(args.outdir, 'data.json'), 'w', encoding='utf-8') as f:
            f.write(monitor.latest_json)
        return

    server, port = start_server(monitor, args.port)
    url = f'http://localhost:{port}/'
    with open(os.path.join(args.outdir, 'dashboard.html'), 'w', encoding='utf-8') as f:   # old bookmarks forward here
        f.write(f'<!doctype html><meta charset=utf-8><meta http-equiv=refresh content="0;url={url}"><a href="{url}">Open the dashboard</a>')
    if args.app:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(url_file, 'w', encoding='utf-8') as f:
            f.write(url)
    print(f'NetMonitor running. Dashboard: {url}')
    print(f'CSV log:   {monitor.csv_path}')
    if not monitor.admin:
        print('Tip: run as Administrator to resolve paths for all processes and to end elevated programs.')
    print('Press Ctrl+C or use Stop monitor on the dashboard to stop.')

    opened = False
    try:
        while not monitor.stop.is_set():
            start = time.time()
            monitor.poll()
            if not opened and not args.no_browser:
                webbrowser.open(url)
                opened = True
                monitor.last_client = time.time()
            # app mode has no window to close, so it stops once no dashboard has been open for a while
            if args.app and time.time() - monitor.last_client > args.idle_exit * 60:
                break
            monitor.stop.wait(max(0.2, args.interval - (time.time() - start)))
    except KeyboardInterrupt:
        pass
    finally:
        print('Stopped.')
        server.shutdown()
        monitor.rdns_pool.shutdown(wait=False, cancel_futures=True)
        if args.app:
            try:
                os.remove(url_file)
            except OSError:
                pass
    if args.app:
        os._exit(0)   # don't wait for slow hostname lookups still in flight; nothing is left unsaved


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
        import traceback
        os.makedirs(APP_DIR, exist_ok=True)
        log = os.path.join(APP_DIR, 'error.log')
        with open(log, 'a', encoding='utf-8') as f:
            f.write(f'{now_iso()}\n{traceback.format_exc()}\n')
        show_error(f'NetMonitor stopped because of an unexpected error. Details were saved to:\n{log}')
