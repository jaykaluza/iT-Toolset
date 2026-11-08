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
import glob
import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import winreg
from concurrent.futures import ThreadPoolExecutor

if sys.platform != 'win32':
    sys.exit('This app only runs on Windows.')

APP_NAME = "My Connections"
EXE_NAME = 'MyConnections.exe'   # the packaged app's file name
APP_VERSION = '1.7'
HERE = os.path.dirname(os.path.abspath(__file__))
WINDIR = os.environ.get('WINDIR', r'C:\Windows')
FROZEN = getattr(sys, 'frozen', False)                    # running as the packaged MyConnections.exe
RESOURCES = getattr(sys, '_MEIPASS', HERE)                # where dashboard.html is
APP_DIR = os.path.join(os.environ.get('LOCALAPPDATA', HERE), 'MyConnections')   # logs when run as the app

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


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [('dwState', wt.DWORD), ('dwLocalAddr', wt.DWORD), ('dwLocalPort', wt.DWORD),
                ('dwRemoteAddr', wt.DWORD), ('dwRemotePort', wt.DWORD)]


iphlpapi.SetTcpEntry.argtypes = [ctypes.POINTER(MIB_TCPROW)]
MIB_TCP_STATE_DELETE_TCB = 12
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


def close_tcp_to(nets, pids=None):
    """End open IPv4 TCP connections to any of these networks (optionally only those owned by pids).
    Windows Firewall only stops new connections, so this cuts ones that were already open. Needs admin."""
    closed = 0
    for r in _read_table(iphlpapi.GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL, MIB_TCPROW_OWNER_PID):
        if r.dwState == 2 or not r.dwRemoteAddr or (pids is not None and r.dwOwningPid not in pids):
            continue
        ip = ipaddress.ip_address(_ip4(r.dwRemoteAddr))
        if any(ip in n for n in nets):
            row = MIB_TCPROW(MIB_TCP_STATE_DELETE_TCB, r.dwLocalAddr, r.dwLocalPort, r.dwRemoteAddr, r.dwRemotePort)
            closed += iphlpapi.SetTcpEntry(ctypes.byref(row)) == NO_ERROR
    return closed


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

# Apps blocked from the dashboard: Windows Firewall rules in their own "MyConnections" group, so only
# this app's rules are ever listed or removed. Program paths come in via environment variables.
# Rules made before the renames are in the old "NetMonitor" or "WhatsMyPCConnectingTo" groups: they are still read and removed, and
# renamed to the new name and group whenever the list is read with administrator rights.
FW_GROUP = 'MyConnections'
FW_LIST_PS = r'''
foreach ($r in @(Get-NetFirewallRule -Group 'WhatsMyPCConnectingTo', 'NetMonitor' -ErrorAction SilentlyContinue)) {
  try {
    $r.Group = 'MyConnections'
    $r.DisplayName = ([string]$r.DisplayName) -replace '^(NetMonitor|MyConnections) block', 'MyConnections block'
    $r.Description = ([string]$r.Description) -replace 'My Windows Network/Internet Connection Monitor|What''s My PC Connecting To\?', 'My Connections'
    Set-NetFirewallRule -InputObject $r -ErrorAction Stop
  } catch { }
}
$out = foreach ($r in @(Get-NetFirewallRule -Group 'MyConnections', 'WhatsMyPCConnectingTo', 'NetMonitor' -ErrorAction SilentlyContinue)) {
  [pscustomobject]@{ Id = [string]$r.Name; Program = [string]($r | Get-NetFirewallApplicationFilter).Program
                     Remote = @(($r | Get-NetFirewallAddressFilter).RemoteAddress) -join ','; Direction = [string]$r.Direction; Name = [string]$r.DisplayName
                     Description = [string]$r.Description }
}
ConvertTo-Json -InputObject @($out) -Compress
'''
FW_BLOCK_PS = r'''
try {
  foreach ($dir in 'Outbound', 'Inbound') {
    New-NetFirewallRule -DisplayName ('MyConnections block: {0} ({1})' -f $env:NM_NAME, $dir.ToLower()) -Group 'MyConnections' `
      -Direction $dir -Action Block -Program $env:NM_PATH -Profile Any -ErrorAction Stop `
      -Description 'Created by What''s My PC Connecting To? (Block app). Use Unblock in its Blocked tab to remove.' | Out-Null
  }
  ConvertTo-Json -InputObject @{ ok = $true } -Compress
} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }
'''
FW_UNBLOCK_PS = r'''
try {
  $rules = @(Get-NetFirewallRule -Group 'MyConnections', 'WhatsMyPCConnectingTo', 'NetMonitor' -ErrorAction SilentlyContinue |
             Where-Object { ($_ | Get-NetFirewallApplicationFilter).Program -eq $env:NM_PATH })
  $names = @($rules | ForEach-Object { [string]$_.DisplayName })
  if ($rules.Count) { $rules | Remove-NetFirewallRule -ErrorAction Stop }
  ConvertTo-Json -InputObject @{ ok = $true; removed = $names } -Compress
} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }
'''
# Block address: the same kind of rules, for a remote IP address or range instead of a program
FW_BLOCK_IP_PS = r'''
try {
  foreach ($dir in 'Outbound', 'Inbound') {
    New-NetFirewallRule -DisplayName ('MyConnections block address: {0} ({1})' -f $env:NM_ADDR, $dir.ToLower()) -Group 'MyConnections' `
      -Direction $dir -Action Block -RemoteAddress $env:NM_ADDR -Profile Any -ErrorAction Stop `
      -Description $env:NM_DESC | Out-Null
  }
  ConvertTo-Json -InputObject @{ ok = $true } -Compress
} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }
'''
# removes this app's rules by their IDs; rules outside its groups (new and old name) are never touched
FW_REMOVE_PS = r'''
try {
  $ids = $env:NM_IDS | ConvertFrom-Json
  $ids = @($ids)
  $rules = @(Get-NetFirewallRule -Group 'MyConnections', 'WhatsMyPCConnectingTo', 'NetMonitor' -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.Name })
  $names = @($rules | ForEach-Object { [string]$_.DisplayName })
  if ($rules.Count) { $rules | Remove-NetFirewallRule -ErrorAction Stop }
  ConvertTo-Json -InputObject @{ ok = $true; removed = $names } -Compress
} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }
'''
# this PC's own addresses, its router(s) and DNS servers: blocking those would cut off the network
NET_ESSENTIALS_PS = r'''
ConvertTo-Json -InputObject @{
  own = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress })
  router = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.NextHop })
  dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | ForEach-Object { [string]$_ })
} -Compress
'''

# The tabs open in each browser window right now: their titles, read from the windows' tab strips through
# Windows UI Automation (what screen readers use). Addresses aren't shown there; they're matched from history.
# every Windows Firewall rule that blocks something, from any program (read-only)
ALL_BLOCKS_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$rules = @(Get-NetFirewallRule -Action Block)
function Index($cmd) {
  $h = @{}
  try { & $cmd -All -ErrorAction Stop | ForEach-Object { $h[$_.InstanceID] = $_ } }
  catch { $rules | & $cmd | ForEach-Object { $h[$_.InstanceID] = $_ } }
  $h
}
$af = Index Get-NetFirewallAddressFilter
$ap = Index Get-NetFirewallApplicationFilter
$pf = Index Get-NetFirewallPortFilter
$rules | ForEach-Object {
  [pscustomobject]@{
    Name = $_.DisplayName; Direction = "$($_.Direction)"; Enabled = "$($_.Enabled)"; Group = "$($_.Group)"
    Program = "$($ap[$_.Name].Program)"; Remote = (@($af[$_.Name].RemoteAddress) -join ', ')
    Port = (@($pf[$_.Name].RemotePort) -join ', '); Protocol = "$($pf[$_.Name].Protocol)"
  }
} | ConvertTo-Json -Compress
'''

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
    # only the browser's own tab bar: skip tab-like controls inside web pages (carousels, page switchers)
    $p = $walker.GetParent($t); $inPage = $false
    while ($p -and -not $p.Equals($w)) {
      if ($p.Current.ControlType -eq [Windows.Automation.ControlType]::Document) { $inPage = $true; break }
      $p = $walker.GetParent($p)
    }
    if (-not $inPage) { [pscustomobject]@{ Process = $proc; Title = [string]$t.Current.Name } }
  }
}
ConvertTo-Json -InputObject @($out) -Compress
'''
BROWSER_NAMES = {'chrome': 'Chrome', 'msedge': 'Edge', 'firefox': 'Firefox', 'opera': 'Opera', 'brave': 'Brave', 'vivaldi': 'Vivaldi'}
# what browsers add to a tab's title in the tab strip
TAB_TITLE_EXTRAS = re.compile(r'\s+-\s+(Audio playing|Playing audio|Muted|Audio muted|Camera or microphone recording|Pinned|Memory usage.*|Network error|Crashed)$', re.I)

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


def is_this_pc(remote, local):
    """True when both ends of a connection are on this PC, so it never leaves the computer."""
    try:
        addr = ipaddress.ip_address(remote.split('%')[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_loopback or remote == local


def parse_address(text):
    """An IP address or range typed or picked in the dashboard, as an ip_network. ValueError says what's wrong."""
    t = str(text).strip().split('%')[0]
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        raise ValueError(f'"{text}" is not an IP address or range. Examples: 203.0.113.7 or 203.0.113.0/24.') from None
    if net.version == 6 and net.num_addresses == 1 and net.network_address.ipv4_mapped:
        net = ipaddress.ip_network(net.network_address.ipv4_mapped)
    a = net.network_address
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local or net == ipaddress.ip_network('255.255.255.255'):
        raise ValueError(f"{net_label(net)} is a special address (this PC itself, broadcast or local link), so the app won't block it.")
    if net.prefixlen < (16 if net.version == 4 else 32):
        raise ValueError(f'{net_label(net)} is too big a range: it would block a huge part of the internet. '
                         f'Use /16 or smaller for IPv4, /32 or smaller for IPv6.')
    return net


def net_label(net):
    """203.0.113.7 for a single address, 203.0.113.0/24 for a range."""
    return str(net.network_address) if net.num_addresses == 1 else str(net)


# Block site: Windows' hosts file sends the site's names to 0.0.0.0, so Windows and browsers can't find it.
# Only lines this app added (marked with one of HOSTS_MARKS) are ever read back or removed.
HOSTS_FILE = os.path.join(WINDIR, 'System32', 'drivers', 'etc', 'hosts')
HOSTS_MARK = '# MyConnections block: '
HOSTS_MARKS = (HOSTS_MARK, '# WhatsMyPCConnectingTo block: ', '# NetMonitor block: ')   # lines added before the renames are still read and removed
SITE_RE = re.compile(r'^(?=.{3,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$')
# Windows itself needs these to sign in, update and check the connection
PROTECTED_SITES = ('localhost', 'local', 'microsoft.com', 'windows.com', 'windowsupdate.com', 'microsoftonline.com',
                   'msftconnecttest.com', 'msftncsi.com', 'live.com', 'windows.net')
# two-part endings such as co.uk, so the site is bbc.co.uk rather than co.uk
SECOND_LEVEL = {'co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'ne', 'or', 'go', 'gob', 'nic', 'mil'}
BROWSERS = {'chrome', 'msedge', 'firefox', 'opera', 'brave', 'vivaldi', 'iexplore', 'chromium', 'librewolf', 'waterfox', 'arc', 'browser'}


# hosting services where each customer has their own name (jaykaluza.github.io), so that's the site, not github.io
SHARED_HOSTING = {'github.io', 'gitlab.io', 'blogspot.com', 'wordpress.com', 'netlify.app', 'pages.dev', 'vercel.app',
                  'herokuapp.com', 'azurewebsites.net', 'web.app', 'firebaseapp.com', 'appspot.com', 'workers.dev',
                  'cloudfront.net', 'substack.com', 'tumblr.com', 'sharepoint.com', 'myshopify.com', 'wixsite.com'}


def base_site(host):
    labels = host.split('.')
    n = 3 if len(labels) >= 3 and (len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL or '.'.join(labels[-2:]) in SHARED_HOSTING) else 2
    return '.'.join(labels[-n:])


def parse_site(text):
    """A site typed or picked in the dashboard (name or web address) as a plain name like example.com."""
    t = str(text).strip().lower()
    try:
        host = urllib.parse.urlsplit(t if '://' in t else 'http://' + t).hostname or ''
        host = host.rstrip('.').encode('idna').decode('ascii')
    except (ValueError, UnicodeError):
        host = ''
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValueError(f'{host} is an IP address: use Block address for that.')
    if host.startswith('www.'):
        host = host[4:]
    if not SITE_RE.match(host):
        raise ValueError(f'"{text}" doesn\'t look like a website. Examples: example.com or https://www.example.com/page.')
    if any(host == p or host.endswith('.' + p) for p in PROTECTED_SITES):
        raise ValueError(f"{host} is used by Windows itself (sign-in, updates or connection checks), so the app won't block it.")
    return host


def read_hosts():
    # latin-1 reads and writes every byte back unchanged, whatever encoding the file uses
    with open(HOSTS_FILE, encoding='latin-1', newline='') as f:
        return f.read()


def hosts_sites():
    """{site: [names]} for the sites this app blocked in the hosts file."""
    sites = {}
    try:
        text = read_hosts()
    except OSError:
        return sites
    for line in text.splitlines():
        mark = next((m for m in HOSTS_MARKS if m in line), '')
        if mark:
            site = line.split(mark, 1)[1].strip()
            parts = line.split('#', 1)[0].split()
            if site and len(parts) >= 2 and parts[1] not in sites.setdefault(site, []):
                sites[site].append(parts[1])
    return sites


def write_hosts(text):
    with open(HOSTS_FILE, 'w', encoding='latin-1', newline='') as f:
        f.write(text)
    try:   # forget names Windows already looked up, so the change works straight away
        ctypes.WinDLL('dnsapi').DnsFlushResolverCache()
    except (OSError, AttributeError):
        pass


# Browsers look sites up themselves (not through Windows' DNS cache), so the sites open in them are
# read from each browser's own history file: only the last hour, only when asked, and nothing is kept.
BROWSER_HISTORY = [
    ('Chrome', 'LOCALAPPDATA', r'Google\Chrome\User Data\*\History'),
    ('Edge', 'LOCALAPPDATA', r'Microsoft\Edge\User Data\*\History'),
    ('Brave', 'LOCALAPPDATA', r'BraveSoftware\Brave-Browser\User Data\*\History'),
    ('Vivaldi', 'LOCALAPPDATA', r'Vivaldi\User Data\*\History'),
    ('Opera', 'APPDATA', r'Opera Software\Opera Stable\History'),
    ('Opera', 'APPDATA', r'Opera Software\Opera Stable\*\History'),
    ('Opera GX', 'APPDATA', r'Opera Software\Opera GX Stable\History'),
    ('Opera GX', 'APPDATA', r'Opera Software\Opera GX Stable\*\History'),
    ('Firefox', 'APPDATA', r'Mozilla\Firefox\Profiles\*\places.sqlite'),
]


def _history_visits(path, since):
    """[(url, title, unix time)] visited after since, from a copy of one browser history database (the browser keeps it locked)."""
    tmp = tempfile.mkdtemp(prefix='netmon-')
    try:
        copy = os.path.join(tmp, 'h.sqlite')
        for suffix in ('', '-wal', '-journal'):
            if os.path.exists(path + suffix):
                shutil.copyfile(path + suffix, copy + suffix)
        con = sqlite3.connect(copy)
        try:
            if path.lower().endswith('places.sqlite'):   # Firefox: microseconds since 1970
                rows = con.execute('SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date > ? '
                                   'ORDER BY last_visit_date DESC LIMIT 5000', (int(since * 1e6),)).fetchall()
                return [(u, ti or '', t / 1e6) for u, ti, t in rows]
            # Chromium browsers: microseconds since 1601
            rows = con.execute('SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > ? '
                               'ORDER BY last_visit_time DESC LIMIT 5000', (int((since + 11644473600) * 1e6),)).fetchall()
            return [(u, ti or '', t / 1e6 - 11644473600) for u, ti, t in rows]
        finally:
            con.close()
    except (OSError, sqlite3.Error):
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def site_of(url):
    """(host, site) of a web address, or ('', '') for anything that isn't a normal website."""
    if not str(url).lower().startswith(('http://', 'https://')):
        return '', ''
    try:
        host = (urllib.parse.urlsplit(url).hostname or '').rstrip('.')
    except ValueError:
        return '', ''
    if not SITE_RE.match(host):
        return '', ''
    return host, base_site(host[4:] if host.startswith('www.') else host)


def open_browser_tabs():
    """[{Browser, Title, Url, Host, Site}] for every tab open in a browser window right now."""
    tabs = [t for t in run_powershell(OPEN_TABS_PS, timeout=30) if isinstance(t, dict) and t.get('Title')]
    if not tabs:
        return [], set()
    # title -> most recent address, per browser, from the last 30 days of history
    by_title, hosts = {}, set()
    since = time.time() - 30 * 86400
    for browser, env, pattern in BROWSER_HISTORY:
        for path in glob.glob(os.path.join(os.environ.get(env, ''), pattern)):
            for url, title, when in _history_visits(path, since):
                if title:
                    key = (browser.split()[0], title.strip())
                    if key not in by_title or by_title[key][1] < when:
                        by_title[key] = (url, when)
                if when > time.time() - 3600:
                    hosts.add(site_of(url)[0])
    out = []
    for t in tabs:
        browser = BROWSER_NAMES.get(str(t.get('Process', '')).lower(), str(t.get('Process', '')))
        title = TAB_TITLE_EXTRAS.sub('', str(t['Title']).strip())
        url = (by_title.get((browser, title)) or (None,))[0]
        if not url:   # long titles may be cut short in the tab strip: match the start
            match = [(v[1], v[0]) for (b, ti), v in by_title.items() if b == browser and len(title) > 8 and ti.startswith(title)]
            url = max(match)[1] if match else ''
        failed = False
        if not url and SITE_RE.match(title.lower()):   # error page: the title is the name the tab is trying to reach
            url, failed = f'https://{title.lower()}/', True
        host, site = site_of(url)
        if not failed and host and title.lower() in (host, host.removeprefix('www.')):
            failed = True   # an error page's title is just the site's name, even when history knows the address
        protected = any(site == p or site.endswith('.' + p) for p in PROTECTED_SITES)
        out.append({'Browser': browser, 'Title': title, 'Url': url, 'Host': host, 'Site': site, 'Protected': protected, 'Failed': failed})
    return out, hosts - {''}


def issue(level, text):
    return {'Level': level, 'Text': text}


# ---- "Is this the original app?": compares this .exe with the fingerprint GitHub lists for its version.
# Only runs when someone hovers over the app's own name; a tampered copy could fake it, and the popup says so.
RELEASE_API = 'https://api.github.com/repos/jaykaluza/iT-Toolset/releases/tags/web-v{}'
_self_check = None
_self_check_lock = threading.Lock()


def self_exe():
    """This app's program file, or '' when running from source."""
    return sys.executable if FROZEN else ''


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def published_digest(version):
    """The SHA-256 GitHub lists for this version's .exe, or '' if that version isn't published."""
    req = urllib.request.Request(RELEASE_API.format(version), headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'MyConnections'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            release = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return ''
        raise
    asset = next((a for a in release.get('assets', []) if a.get('name') == EXE_NAME), {})
    m = re.match(r'^sha256:([a-f0-9]{64})$', str(asset.get('digest') or ''), re.I)
    return m.group(1).lower() if m else ''


def verify_self():
    """match / mismatch / unpublished / unknown (GitHub couldn't be reached, so it's tried again next time)."""
    global _self_check
    with _self_check_lock:
        if _self_check:
            return _self_check
        exe = self_exe()
        if not exe:
            return {'state': 'unknown', 'version': APP_VERSION, 'sha256': ''}
        result = {'version': APP_VERSION, 'sha256': ''}
        try:
            result['sha256'] = file_sha256(exe)
            published = published_digest(APP_VERSION)
        except (OSError, ValueError):
            return dict(result, state='unknown')
        result['state'] = 'unpublished' if not published else 'match' if published == result['sha256'] else 'mismatch'
        _self_check = result
        return result


def is_this_app(pid, path):
    """True only for this running app: its own process, or the small launcher the .exe starts it from."""
    return pid == os.getpid() or (FROZEN and pid == os.getppid() and path.lower() == sys.executable.lower())


def app_issues(info, admin, pid):
    issues = []
    p, name = info['Path'], info['Name']
    if is_this_app(pid, p):   # it may be running from a download folder, but it shouldn't warn about itself
        return issues
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
    'core': "{0} is a core part of Windows. Ending it would crash or freeze the PC, so the app won't do it.",
    'svc': 'svchost runs several Windows services at once (hover its name to see them). Stop the specific service instead: press Win+R, type services.msc, find the service and click Stop.',
    'av': "{0} is part of Microsoft Defender. Ending it would switch off your virus protection, so the app won't do it.",
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
        # activity log lives next to the exe (or NetMonitor.py) and keeps the last 10 days
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
        self.blocked_status, self.blocked_error = 'checking', ''   # until the first look at the Security log
        self.blocked_busy, self.blocked_refreshed = False, 0.0
        self.audit_on, self.audit_checked = None, 0.0
        self.fw_blocked, self.fw_busy, self.fw_refreshed = [], False, 0.0   # apps blocked from the dashboard
        self.fw_ips, self.fw_nets, self.fw_sites = [], [], []   # addresses and sites blocked from the dashboard
        self.fw_changes = 0   # bumped on every block/unblock, so a background list read from before it is thrown away
        self.browser_hosts = set()   # names seen in browser history, so Block site covers a site's other names too
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
        self.tab_closed_at = 0             # when a dashboard tab last said it was closing
        self.stop = threading.Event()      # set by the dashboard's Stop monitor button
        self.stopping = False              # the website's STOP: dashboards close their tab, then the app exits
        self.site_changed = threading.Condition()   # guards the two below
        self.site_tabs = 0                 # landing pages open now (each keeps a /site-events connection)
        self.site_refreshes = 0            # raised by the dashboard to make open landing pages refresh

    def stop_from_site(self):
        """Stop at the website's request: give open dashboards a few seconds to see it and close their tabs."""
        if self.stopping:
            return
        self.stopping = True
        threading.Timer(max(4.0, self.args.interval + 1.5), self.stop.set).start()

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
            gen = self.fw_changes
            by_path, by_addr = {}, {}
            for row in run_powershell(FW_LIST_PS):
                if not isinstance(row, dict):
                    continue
                prog, remote = str(row.get('Program') or ''), str(row.get('Remote') or '')
                if prog and prog.lower() != 'any':
                    entry = by_path.setdefault(prog.lower(), {'Path': prog, 'Directions': [], 'Rules': []})
                elif remote and remote.lower() != 'any':   # a Block address rule
                    try:
                        key = net_label(ipaddress.ip_network(remote.split(',')[0], strict=False))
                    except ValueError:
                        continue
                    entry = by_addr.setdefault(key, {'Address': key, 'Directions': [], 'Rules': [], 'Ids': [], 'App': '', 'Name': '', 'When': ''})
                    entry['Ids'].append(str(row.get('Id') or ''))
                    desc = str(row.get('Description') or '')
                    for field, pattern in (('When', r'Blocked on ([\d-]+ [\d:]+)'), ('App', r'App: ([^|;]*)'), ('Name', r'Name: ([^|;]*)')):   # ';' now, '|' in older rules
                        m = re.search(pattern, desc)
                        if m and not entry[field]:
                            entry[field] = m.group(1).strip()
                else:
                    continue
                entry['Directions'].append(str(row.get('Direction') or ''))
                entry['Rules'].append(str(row.get('Name') or ''))
            for entry in by_addr.values():
                entry['Directions'] = sorted(set(entry['Directions']))
            self.fw_ips = sorted(by_addr.values(), key=lambda e: (':' in e['Address'], e['Address']))
            self.fw_nets = [ipaddress.ip_network(e['Address']) for e in self.fw_ips]
            self.fw_sites = [{'Site': k, 'Names': v} for k, v in sorted(hosts_sites().items())]
            if gen != self.fw_changes:   # something was blocked or unblocked while this was being read
                return
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
            return {'ok': False, 'message': 'Blocking apps needs administrator rights. Start the app as Administrator.'}
        with self.lock:
            path = self.proc_cache.get(pid, {}).get('Path', '')
            in_dashboard = pid in self.dashboard_pids
        if pid in (os.getpid(), os.getppid()) or (FROZEN and path.lower() == sys.executable.lower()):
            return {'ok': False, 'message': "The app can't block itself."}
        if not in_dashboard:
            return {'ok': False, 'message': f'PID {pid} is no longer in the dashboard. Nothing was blocked.'}
        if process_names().get(pid) not in (None, name):
            return {'ok': False, 'message': f'PID {pid} now belongs to a different program. Nothing was blocked.'}
        why = NO_KILL.get(name.lower())
        if why == 'av':
            return {'ok': False, 'message': f"{name} is part of Microsoft Defender. Blocking it would stop virus-protection updates, so the app won't do it."}
        if why or pid == 4:
            return {'ok': False, 'message': f"{name} is a core part of Windows. Blocking it could cut off networking for the whole PC, so the app won't do it."}
        if name.lower() in SHARED_HOSTS:
            return {'ok': False, 'message': f"{name} is used by many different programs, so blocking it would cut off more than one app. The app won't block it."}
        if not path:
            return {'ok': False, 'message': f"Windows didn't reveal where {name} lives, so it can't be blocked by its file."}
        if any(e['Path'].lower() == path.lower() for e in self.fw_blocked):
            return {'ok': True, 'message': f'{name} is already blocked.'}
        row = next(iter(run_powershell(FW_BLOCK_PS, {'NM_PATH': path, 'NM_NAME': name})), {})
        if not row.get('ok'):
            return {'ok': False, 'message': f"Windows Firewall didn't accept the block for {name}. {row.get('error', '')}".strip()}
        self.fw_changes += 1
        self.refresh_fw()
        msg = (f"Blocked {name} with Windows Firewall rules 'MyConnections block: {name} (outbound)' and "
               f"'MyConnections block: {name} (inbound)': it can't connect in or out.")
        self.log_action('BLOCKED', [pid], name, path, msg)
        # close it too, so connections it already had open end now rather than when it next reconnects
        closed = self.end_program(pid, name)
        if closed.get('ok'):
            return {'ok': True, 'message': f'{msg} {closed["message"]} If you start it again it stays blocked until you unblock it.'}
        return {'ok': False, 'message': f'{msg} But it could not be closed: {closed["message"]}'}

    def unblock_app(self, path):
        if not self.admin:
            return {'ok': False, 'message': 'Unblocking apps needs administrator rights. Start the app as Administrator.'}
        entry = next((e for e in self.fw_blocked if e['Path'].lower() == str(path).lower()), None)
        if not entry:   # only this app's own rules can be removed from here
            return {'ok': False, 'message': 'That app is not in the list of apps you blocked.'}
        row = next(iter(run_powershell(FW_UNBLOCK_PS, {'NM_PATH': entry['Path']})), {})
        if not row.get('ok'):
            return {'ok': False, 'message': f"Windows Firewall didn't remove the block for {entry['App']}. {row.get('error', '')}".strip()}
        self.fw_changes += 1
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
        rules = ' and '.join(f"'{r}'" for r in removed) or 'its firewall rules'
        msg = f"Unblocked {entry['App']}: removed Windows Firewall {'rule' if len(removed) == 1 else 'rules'} {rules}; it can connect again."
        self.log_action('UNBLOCKED', [], entry['App'], entry['Path'], msg)
        return {'ok': True, 'message': msg}

    # ---- Block address: Windows Firewall rules for a remote IP address or range

    def _essentials(self):
        """{address: why} for addresses that must never be blocked: this PC, its router and DNS servers."""
        row = next(iter(run_powershell(NET_ESSENTIALS_PS)), {})
        out = {}
        for key, why in (('dns', 'one of your DNS servers (it turns site names into addresses)'),
                         ('router', 'your router (the way out to the internet)'), ('own', 'this PC\'s own address')):
            items = row.get(key) if isinstance(row, dict) else []
            for a in [items] if isinstance(items, str) else items or []:
                try:
                    out[ipaddress.ip_address(str(a).split('%')[0])] = why
                except ValueError:
                    pass
        return out

    def block_ip(self, text, app='', host=''):
        if not self.admin:
            return {'ok': False, 'message': 'Blocking addresses needs administrator rights. Start the app as Administrator.'}
        try:
            net = parse_address(text)
        except ValueError as e:
            return {'ok': False, 'message': str(e)}
        label = net_label(net)
        if any(e['Address'] == label for e in self.fw_ips):
            return {'ok': True, 'message': f'{label} is already blocked.'}
        for addr, why in self._essentials().items():
            if addr in net:
                inside = '' if net.num_addresses == 1 else f' contains {addr}, which is'
                return {'ok': False, 'message': f"{label}{inside or ' is'} {why}. Blocking it could cut off this PC's network, so the app won't do it."}
        if not (app and host):   # typed in: take what it was from the connections seen to it
            with self.lock:
                seen = [r for r in self.conns.values() if self._in_nets(r.get('RemoteAddress'), [net])]
            app = app or ', '.join(sorted({str(r.get('App') or '') for r in seen} - {''}))
            host = host or next((r['RemoteHost'] for r in seen if r.get('RemoteHost')), '')
        if not host and net.num_addresses == 1:
            try:
                host = socket.gethostbyaddr(str(net.network_address))[0]
            except OSError:
                pass
        # Windows Firewall refuses descriptions containing '|', so the fields are separated with ';'
        clean = lambda v: re.sub(r'[|;\r\n]', ' ', str(v)).strip()[:120]
        desc = (f"Created by My Connections (Block address). Blocked on {dt.datetime.now():%Y-%m-%d %H:%M}; "
                f'App: {clean(app)}; Name: {clean(host)}; Use Unblock in its Blocked tab to remove.')
        row = next(iter(run_powershell(FW_BLOCK_IP_PS, {'NM_ADDR': label, 'NM_DESC': desc})), {})
        if not row.get('ok'):
            return {'ok': False, 'message': f"Windows Firewall didn't accept the block for {label}. {row.get('error', '')}".strip()}
        closed = close_tcp_to([net])
        self.fw_changes += 1
        self.refresh_fw()
        msg = (f"Blocked {label} with Windows Firewall rules 'MyConnections block address: {label} (outbound)' and "
               f"'MyConnections block address: {label} (inbound)': nothing on this PC can connect to it, or be reached from it.")
        if closed:
            msg += f" Closed {closed} open connection{'s' if closed != 1 else ''} to it."
        what = ' · '.join(x for x in (host, app and f'used by {app}') if x)
        self.log_action('BLOCKED', [], f'Address {label}' + (f' ({what})' if what else ''), 'Windows Firewall', msg)
        return {'ok': True, 'message': msg}

    def unblock_ip(self, text):
        if not self.admin:
            return {'ok': False, 'message': 'Unblocking addresses needs administrator rights. Start the app as Administrator.'}
        entry = next((e for e in self.fw_ips if e['Address'] == str(text)), None)
        if not entry:   # only this app's own rules can be removed from here
            return {'ok': False, 'message': 'That address is not in the list of addresses you blocked.'}
        row = next(iter(run_powershell(FW_REMOVE_PS, {'NM_IDS': json.dumps(entry['Ids'])})), {})
        if not row.get('ok'):
            return {'ok': False, 'message': f"Windows Firewall didn't remove the block for {entry['Address']}. {row.get('error', '')}".strip()}
        net = ipaddress.ip_network(entry['Address'])
        with self.lock:   # its earlier blocked attempts came from this block, so clear them from the list
            for key in [k for k, b in self.blocked.items() if self._in_nets(b['RemoteAddress'], [net])]:
                del self.blocked[key]
        self.fw_changes += 1
        self.refresh_fw()
        removed = row.get('removed') or []
        removed = [removed] if isinstance(removed, str) else removed
        rules = ' and '.join(f"'{r}'" for r in removed) or 'its firewall rules'
        msg = f"Unblocked {entry['Address']}: removed Windows Firewall {'rule' if len(removed) == 1 else 'rules'} {rules}."
        self.log_action('UNBLOCKED', [], f"Address {entry['Address']}", 'Windows Firewall', msg)
        return {'ok': True, 'message': msg}

    @staticmethod
    def _in_nets(ip, nets):
        try:
            addr = ipaddress.ip_address(str(ip).split('%')[0])
        except ValueError:
            return False
        return any(addr in n for n in nets)

    # ---- Block site: lines in Windows' hosts file

    def block_site(self, text):
        if not self.admin:
            return {'ok': False, 'message': 'Blocking sites needs administrator rights. Start the app as Administrator.'}
        try:
            site = parse_site(text)
        except ValueError as e:
            return {'ok': False, 'message': str(e)}
        if any(e['Site'] == site for e in self.fw_sites):
            return {'ok': True, 'message': f'{site} is already blocked.'}
        # the site and www., plus any of its other names seen recently (hosts files can't block "everything under" a site)
        seen = self.browser_hosts | set(self.dns_names.values())
        names = [site, 'www.' + site] + sorted(h for h in seen if isinstance(h, str) and h.endswith('.' + site) and h != 'www.' + site and SITE_RE.match(h))
        names = names[:60]
        # where it is now, so tabs that already have it open can be cut off
        ips = set()
        for n in names[:10]:
            try:
                ips |= {ipaddress.ip_address(i[4][0].split('%')[0]) for i in socket.getaddrinfo(n, 443, proto=socket.IPPROTO_TCP)}
            except (OSError, ValueError):
                pass
        try:
            text = read_hosts()
            if text and not text.endswith(('\n', '\r')):
                text += '\r\n'
            text += ''.join(f'{ip} {n}  {HOSTS_MARK}{site}\r\n' for n in names for ip in ('0.0.0.0', '::'))
            write_hosts(text)
        except OSError as e:
            return {'ok': False, 'message': f"Couldn't change Windows' hosts file ({HOSTS_FILE}): {e.strerror or e}. "
                                            'Some security programs lock it; nothing was blocked.'}
        browser_pids = {pid for pid, name in self.names.items() if str(name).lower() in BROWSERS}
        closed = close_tcp_to([ipaddress.ip_network(i) for i in ips if not i.is_loopback and not i.is_unspecified], browser_pids)
        self.fw_changes += 1
        self.refresh_fw()
        msg = (f'Blocked {site} in the Windows hosts file ({len(names)} names: {", ".join(names[:4])}'
               f'{" and more" if len(names) > 4 else ""}): this PC can no longer find it.')
        if closed:
            msg += f" Closed {closed} open browser connection{'s' if closed != 1 else ''} to it."
        self.log_action('BLOCKED', [], f'Site {site}', HOSTS_FILE, msg)
        return {'ok': True, 'message': msg + ' If a tab still shows it, close the tab and open the site again; if it still loads, restart the browser and check its Secure DNS setting.'}

    def unblock_site(self, site):
        if not self.admin:
            return {'ok': False, 'message': 'Unblocking sites needs administrator rights. Start the app as Administrator.'}
        site = str(site)
        if not any(e['Site'] == site for e in self.fw_sites):
            return {'ok': False, 'message': 'That site is not in the list of sites you blocked.'}
        try:
            lines = read_hosts().splitlines(keepends=True)
            kept = [ln for ln in lines if not any(m in ln and ln.split(m, 1)[1].strip() == site for m in HOSTS_MARKS)]
            write_hosts(''.join(kept))
        except OSError as e:
            return {'ok': False, 'message': f"Couldn't change Windows' hosts file ({HOSTS_FILE}): {e.strerror or e}."}
        self.fw_changes += 1
        self.refresh_fw()
        msg = f'Unblocked {site}: removed its {len(lines) - len(kept)} lines from the Windows hosts file.'
        self.log_action('UNBLOCKED', [], f'Site {site}', HOSTS_FILE, msg)
        return {'ok': True, 'message': msg + ' Reload its tab to open it again.'}

    def all_blocks(self):
        """Everything blocked on this PC: all firewall block rules and all hosts-file entries, whoever made them."""
        if not self.admin:
            return {'ok': False, 'message': 'Listing every firewall rule needs administrator rights. Start the app as Administrator.'}
        rules = []
        for r in run_powershell(ALL_BLOCKS_PS, timeout=60):
            if not isinstance(r, dict):
                continue
            rules.append({k: str(r.get(k) or '') for k in ('Name', 'Direction', 'Enabled', 'Group', 'Program', 'Remote', 'Port', 'Protocol')})
        hosts = []
        try:
            text = read_hosts()
        except OSError:
            text = ''
        for line in text.splitlines():
            data, _, comment = line.partition('#')
            parts = data.split()
            if len(parts) < 2:
                continue
            ip, names = parts[0], [n for n in parts[1:] if n.lower() != 'localhost']
            if not names:
                continue
            blocks = ip in ('0.0.0.0', '127.0.0.1', '::', '::1')
            for n in names:
                hosts.append({'Name': n, 'Address': ip, 'Blocks': blocks, 'Ours': any(m in line for m in HOSTS_MARKS)})
        return {'ok': True, 'rules': rules, 'hosts': hosts}

    def browser_sites(self):
        """The tabs open in this PC's browsers right now (only while the dashboard's Open tabs tab is shown)."""
        tabs, hosts = open_browser_tabs()
        self.browser_hosts = hosts | {t['Host'] for t in tabs if t['Host']}
        return {'ok': True, 'tabs': tabs}

    def set_audit(self, enable):
        """Turn Windows' blocked-connection recording on or off (the dashboard's button). Only this one setting."""
        if not self.admin:
            return {'ok': False, 'message': 'Changing this needs administrator rights. Start the app as Administrator.'}
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
            return   # blocked by one of this app's rules that has since been removed
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
            direction = 'This PC' if is_this_pc(raddr, laddr) else 'Inbound' if lport in listen_ports else 'Outbound'
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
                r['Issues'] = app_issues(info, self.admin, r['PID']) + r['_conn_issues']
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
                issues += app_issues(info, self.admin, pid)
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
                                      if b['Path'].lower() in {e['Path'].lower() for e in self.fw_blocked}
                                      or self._in_nets(b['RemoteAddress'], self.fw_nets)),
                                     key=lambda b: b['LastSeen'], reverse=True),
                   'blockedStatus': self.blocked_status, 'blockedError': self.blocked_error,
                   'fwBlocked': self.fw_blocked, 'fwIps': [{**{k: e[k] for k in ('Address', 'Directions', 'Rules', 'App', 'When')},
                              'Name': e['Name'] or ('' if '/' in e['Address'] else self.host_for(e['Address'], True))} for e in self.fw_ips],
                   'fwSites': self.fw_sites, 'siteOpen': self.site_tabs > 0, 'selfPath': self_exe()}
        self.latest_json = json.dumps(payload, separators=(',', ':'))
        # only processes currently shown in the dashboard may be ended
        self.dashboard_pids = frozenset([r['PID'] for r in self.conns.values() if not r['Closed']] + [l['PID'] for l in listeners])

    # ---- End process

    def log_action(self, action, pids, name, path, msg):
        """One line per Block / Unblock / End process in activity-log.txt (for addresses and sites, path says where the block lives)."""
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
            # via Explorer, so the editor runs as the signed-in user rather than with the app's admin rights
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
            return {'ok': False, 'message': 'That is this app itself. Press Ctrl+C in its window to stop it.'}
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
            ok, msg = False, f'Windows refused to end {name} (PID {pid}). Restart the app as Administrator and try again.'
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
                return {'ok': False, 'message': 'That is this app itself. Use the Stop monitor button to stop it.'}
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
                msg = f'Closed {n - refused} of {n} {name} processes. Windows refused the rest; restart the app as Administrator and try again.'
            else:
                msg = f'Closed {name}.' if n == 1 else f'Closed {name} completely ({n} processes).'
            self.log_action('ENDED', targets, name, path, msg)
            return {'ok': not refused, 'message': msg}


# ---------------------------------------------------------------- local dashboard server
# Served on localhost only. Every request except the page itself must carry a random per-run
# token that is embedded in the page, so other websites can't read the data or end processes.

CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'"
# The Nesiam.com website may ask "is the app running?" (/status) and stop it (/site-stop), so its RUN
# button can switch to STOP. Browsers only let these origins read the answer or send the stop.
SITE_ORIGINS = ('https://nesiam.com', 'https://www.nesiam.com', 'https://jaykaluza.github.io')


def make_handler(monitor, page_bytes, token, port):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'MyConnections'
        sys_version = ''

        def log_message(self, *args):
            pass

        def send(self, status, ctype, body, extra=None):
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', CSP)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status, obj, extra=None):
            self.send(status, 'application/json; charset=utf-8', json.dumps(obj).encode('utf-8'), extra)

        def site_origin(self):
            """The Nesiam.com website's origin if this request comes from it, else None."""
            origin = self.headers.get('Origin')
            return origin if origin in SITE_ORIGINS else None

        def site_headers(self, origin):
            return {'Access-Control-Allow-Origin': origin, 'Vary': 'Origin'}

        def do_OPTIONS(self):
            # browsers check first before letting the website talk to an app on this PC
            origin = self.site_origin()
            if not self.host_ok() or not origin or self.path not in ('/status', '/site-stop', '/site-events'):
                return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
            self.send(204, 'text/plain', b'', {**self.site_headers(origin), 'Access-Control-Allow-Methods': 'GET, POST',
                                               'Access-Control-Allow-Headers': 'Content-Type',
                                               'Access-Control-Allow-Private-Network': 'true',
                                               'Access-Control-Max-Age': '600'})

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
            if self.path == '/status':
                # only "it's running" and the version; readable by the Nesiam.com website alone
                origin = self.site_origin()
                if not origin:
                    return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
                return self.send_json(200, {'app': 'MyConnections', 'version': APP_VERSION, 'stopping': monitor.stopping},
                                      self.site_headers(origin))
            if self.path == '/site-events':
                origin = self.site_origin()
                if not origin:
                    return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
                return self.site_events(origin)
            if not self.token_ok():
                return self.send_json(403, {'ok': False, 'message': 'Not allowed. Reload the dashboard.'})
            if self.path == '/data':
                monitor.last_client = time.time()
                if monitor.stopping:   # the dashboard closes its tab when it sees this
                    return self.send_json(200, {'stopping': True})
                return self.send(200, 'application/json; charset=utf-8', monitor.latest_json.encode('utf-8'))
            self.send_json(404, {'ok': False, 'message': 'Not found'})

        def site_events(self, origin):
            """Held open by each landing page: shows the app it is open, and tells it when to refresh."""
            self.close_connection = True
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-store')
            for k, v in self.site_headers(origin).items():
                self.send_header(k, v)
            self.end_headers()
            with monitor.site_changed:
                monitor.site_tabs += 1
                seen = monitor.site_refreshes
            try:
                self.wfile.write(b': connected\n\n')
                while not monitor.stop.is_set():
                    with monitor.site_changed:
                        monitor.site_changed.wait(5)   # the regular ping also reveals a closed tab
                        refresh = monitor.site_refreshes != seen
                        seen = monitor.site_refreshes
                    self.wfile.write(b'data: refresh\n\n' if refresh else b': ping\n\n')
            except OSError:
                pass   # the tab was closed
            finally:
                with monitor.site_changed:
                    monitor.site_tabs -= 1

        def do_POST(self):
            if self.path == '/tab-closed':
                # a dashboard tab is closing or reloading (browsers can't add the usual header here, so the key is the body)
                length = min(int(self.headers.get('Content-Length', 0)), 200)
                origin = self.headers.get('Origin')
                if (self.host_ok() and secrets.compare_digest(self.rfile.read(length), token.encode())
                        and (not origin or origin in (f'http://localhost:{port}', f'http://127.0.0.1:{port}'))):
                    monitor.tab_closed_at = time.time()
                    return self.send(204, 'text/plain', b'')
                return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
            if self.path == '/site-stop':
                # the website's STOP button: only from the Nesiam.com site, and only stopping this app itself
                origin = self.site_origin()
                if not self.host_ok() or not origin:
                    return self.send_json(403, {'ok': False, 'message': 'Forbidden'})
                monitor.stop_from_site()
                return self.send_json(200, {'ok': True, 'message': 'The app is stopping.'}, self.site_headers(origin))
            if not self.host_ok() or not self.token_ok():
                return self.send_json(403, {'ok': False, 'message': 'Not allowed. Reload the dashboard.'})
            if self.path == '/site-refresh':
                with monitor.site_changed:
                    monitor.site_refreshes += 1
                    monitor.site_changed.notify_all()
                return self.send_json(200, {'ok': True})
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
            if self.path == '/all-blocks':
                return self.send_json(200, monitor.all_blocks())
            if self.path in ('/block-ip', '/unblock-ip', '/block-site', '/unblock-site', '/browser-sites'):
                try:
                    length = min(int(self.headers.get('Content-Length', 0)), 10000)
                    body = json.loads(self.rfile.read(length) or b'{}')
                    if self.path == '/browser-sites':
                        return self.send_json(200, monitor.browser_sites())
                    action = {'/block-ip': monitor.block_ip, '/unblock-ip': monitor.unblock_ip,
                              '/block-site': monitor.block_site, '/unblock-site': monitor.unblock_site}[self.path]
                    if self.path == '/block-ip':
                        result = monitor.block_ip(str(body['address']), str(body.get('app') or ''), str(body.get('host') or ''))
                    else:
                        result = action(str(body['address' if self.path.endswith('-ip') else 'site']))
                except (ValueError, KeyError, TypeError):
                    return self.send_json(400, {'ok': False, 'message': 'Bad request'})
                return self.send_json(200, result)
            if self.path == '/verify-self':
                return self.send_json(200, verify_self())
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
                self.send_json(200, {'ok': True, 'message': 'The app has stopped. You can close this tab.'})
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
    """True if the app is already running as the app (one copy per Windows session)."""
    global _instance_mutex
    _instance_mutex = kernel32.CreateMutexW(None, False, 'Local\\MyConnections')
    return ctypes.get_last_error() == ERROR_ALREADY_EXISTS


# ---- myconnections:// link, so a web page's RUN button can start the app (per-user, no admin needed)
LINK_SCHEME = 'myconnections'
OLD_LINK_SCHEMES = ('whatsmypcconnectingto', 'netmonitor')   # the links versions before the renames set up; removed along with the new one
LINK_PATTERN = re.compile(r'^(myconnections|whatsmypcconnectingto|netmonitor):(//)?(run|unregister)?/?$', re.I)   # start the app, or remove the link


def _link_key(scheme):
    return rf'Software\Classes\{scheme}'


def link_command(exe):
    return f'"{exe}" "%1"'


def link_registered(exe, scheme=LINK_SCHEME):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _link_key(scheme) + r'\shell\open\command') as k:
            return winreg.QueryValueEx(k, '')[0] == link_command(exe)
    except OSError:
        return False


def register_link(exe, scheme=LINK_SCHEME):
    """Make myconnections:// links open this exe, for the signed-in Windows user only."""
    base = _link_key(scheme)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'URL:{APP_NAME}')
        winreg.SetValueEx(k, 'URL Protocol', 0, winreg.REG_SZ, '')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r'\DefaultIcon') as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'"{exe}",0')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r'\shell\open\command') as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, link_command(exe))


class VS_FIXEDFILEINFO(ctypes.Structure):
    _fields_ = [('dwSignature', wt.DWORD), ('dwStrucVersion', wt.DWORD), ('dwFileVersionMS', wt.DWORD),
                ('dwFileVersionLS', wt.DWORD), ('dwProductVersionMS', wt.DWORD), ('dwProductVersionLS', wt.DWORD),
                ('dwFileFlagsMask', wt.DWORD), ('dwFileFlags', wt.DWORD), ('dwFileOS', wt.DWORD),
                ('dwFileType', wt.DWORD), ('dwFileSubtype', wt.DWORD), ('dwFileDateMS', wt.DWORD), ('dwFileDateLS', wt.DWORD)]


version_dll = ctypes.WinDLL('version')
version_dll.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.DWORD)]
version_dll.GetFileVersionInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p]
version_dll.VerQueryValueW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wt.UINT)]


def file_version(path):
    """(major, minor, build, revision) from a program file's version details, or None."""
    size = version_dll.GetFileVersionInfoSizeW(path, None)
    if not size:
        return None
    buf = ctypes.create_string_buffer(size)
    ptr, length = ctypes.c_void_p(), wt.UINT()
    if not version_dll.GetFileVersionInfoW(path, 0, size, buf) or \
            not version_dll.VerQueryValueW(buf, '\\', ctypes.byref(ptr), ctypes.byref(length)) or not length.value:
        return None
    ffi = VS_FIXEDFILEINFO.from_address(ptr.value)
    return (ffi.dwFileVersionMS >> 16, ffi.dwFileVersionMS & 0xFFFF, ffi.dwFileVersionLS >> 16, ffi.dwFileVersionLS & 0xFFFF)


def own_version():
    return tuple((list(map(int, re.findall(r'\d+', APP_VERSION))) + [0, 0, 0, 0])[:4])


def link_target(scheme=LINK_SCHEME):
    """The program file the myconnections:// link currently opens ('' if none)."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _link_key(scheme) + r'\shell\open\command') as k:
            command = winreg.QueryValueEx(k, '')[0]
    except OSError:
        return ''
    m = re.match(r'^"([^"]+)"', command)
    return m.group(1) if m else ''


def should_take_link(exe, scheme=LINK_SCHEME):
    """Whether this copy should take over the RUN link, so an older or temporary copy never replaces a newer one."""
    target = link_target(scheme)
    if not target or not os.path.isfile(target):
        return True                                   # no link yet, or it points to a deleted file
    norm = lambda p: os.path.normcase(os.path.realpath(p))
    if norm(target) == norm(exe):
        return False
    temp = norm(os.environ.get('TEMP', '') or os.environ.get('TMP', ''))
    in_temp = lambda p: bool(temp) and norm(p).startswith(temp + os.sep)
    if in_temp(target) != in_temp(exe):
        return in_temp(target)                        # a saved copy beats one running from a download's temp folder
    return own_version() >= (file_version(target) or (0,))


def unregister_link(scheme=LINK_SCHEME):
    base = _link_key(scheme)
    for sub in (r'\shell\open\command', r'\shell\open', r'\shell', r'\DefaultIcon', ''):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + sub)
        except OSError:
            pass
    return not link_registered('', scheme) and not _key_exists(base)


def _key_exists(path):
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, path).Close()
        return True
    except OSError:
        return False


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
                    help='app mode (default for the packaged .exe): one copy only, logs in %%LOCALAPPDATA%%, '
                         'stops a few minutes after the dashboard is closed')
    ap.add_argument('--idle-exit', type=int, default=3, help='app mode: minutes without an open dashboard before stopping')
    ap.add_argument('--register-link', action='store_true', help='let myconnections:// links (a website RUN button) start this app')
    ap.add_argument('--unregister-link', action='store_true', help='remove the myconnections:// link')
    ap.add_argument('link', nargs='?', help=argparse.SUPPRESS)   # myconnections://run, passed by Windows
    args = ap.parse_args()

    exe = sys.executable if FROZEN else os.path.abspath(__file__)
    if args.link and not LINK_PATTERN.match(args.link):
        sys.exit(f'The app was started from an unsupported link ({args.link[:80]}). Links can only start the app or remove the link.')
    if args.link and (LINK_PATTERN.match(args.link).group(3) or '').lower() == 'unregister':
        args.unregister_link = True   # a website's "Remove the RUN link" button
    if args.unregister_link:
        unregister_link()
        for old in OLD_LINK_SCHEMES:   # and the links from before the renames
            unregister_link(old)
        if FROZEN:
            user32.MessageBoxW(None, 'The RUN button link was removed. Websites can no longer start this app on this PC.\n\n'
                                     f'Running {EXE_NAME} again sets it up again.', APP_NAME, 0x40)
        print('myconnections:// link removed.')
        return
    if args.register_link:
        if not FROZEN:
            sys.exit(f'The myconnections:// link can only be set up from {EXE_NAME}.')
        register_link(exe)
        user32.MessageBoxW(None, 'Done. A RUN button on a web page can now start this app on this PC.', APP_NAME, 0x40)
        return
    # the app sets up its RUN-button link (for this Windows user), unless an equal or newer saved copy already has it
    if FROZEN and args.app and not link_registered(exe) and should_take_link(exe):
        try:
            register_link(exe)
        except OSError:
            pass
    if not args.outdir:
        args.outdir = os.path.join(APP_DIR if args.app else HERE, 'MyConnectionsOutput')
    url_file = os.path.join(APP_DIR, 'running.url')

    if args.app and not args.once and another_copy_running():
        # already running: just bring its dashboard back
        try:
            with open(url_file, encoding='utf-8') as f:
                webbrowser.open(f.read().strip())
        except OSError:
            show_error('The app is already running, but its dashboard address could not be found. '
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
    print(f'{APP_NAME} is running. Dashboard: {url}')
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
            # app mode has no window to close, so it stops once the dashboard is closed: within seconds if the tab said so
            # (a reload says so too, but the reloaded page asks for data straight away), or after a while if it couldn't
            closed_at = monitor.tab_closed_at
            if args.app and closed_at > monitor.last_client and time.time() - closed_at > args.interval * 2 + 1:
                break
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
        show_error(f'The app stopped because of an unexpected error. Details were saved to:\n{log}')
