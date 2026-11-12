"""Blocked attempts: what tried to get through the blocks you made.

Windows Firewall can write every connection it refuses to pfirewall.log ("log dropped packets"), which is off by default.
This module turns that on and off, reads the log as it grows, and matches the refused connections against the ports,
addresses and programs blocked in My Security.
"""
import ipaddress
import json
import os
import threading

import scans_win as S

PROFILE_PS = r'''
$out = foreach ($p in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
  [pscustomobject]@{ Name = [string]$p.Name; Enabled = [string]$p.Enabled; LogBlocked = [string]$p.LogBlocked; File = [Environment]::ExpandEnvironmentVariables([string]$p.LogFileName); Size = [int]$p.LogMaxSizeKilobytes }
}
ConvertTo-Json -InputObject @($out) -Compress
'''

SET_PS = r'''
$ErrorActionPreference = 'Stop'
try {
  # assign first: in Windows PowerShell 5.1, @($x | ConvertFrom-Json) wraps a JSON list inside another list, which made [int]$p.Size fail
  $list = $env:MS_J | ConvertFrom-Json
  foreach ($p in @($list)) { Set-NetFirewallProfile -Name $p.Name -LogBlocked $p.LogBlocked -LogMaxSizeKilobytes ([int]$p.Size) }
  ConvertTo-Json -InputObject @{ ok = $true } -Compress
} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }
'''

RECORD_KB = 16384      # 16 MB per file, about a week of refusals on a busy home network
MAX_GROUPS = 50000     # memory cap for the summary


def profiles():
    return [p for p in S.run_powershell(PROFILE_PS, timeout=30) if isinstance(p, dict) and p.get('Name')]


def is_on(rows):
    on = [p for p in rows if p.get('Enabled') == 'True']
    return bool(on) and all(p.get('LogBlocked') == 'True' for p in on)


def _set(rows):
    return S.ps_one(SET_PS, {'MS_J': json.dumps(rows)}, timeout=60)


def start(rows):
    want = [{'Name': p['Name'], 'LogBlocked': 'True', 'Size': max(int(p.get('Size') or 0), RECORD_KB)} for p in rows]
    r = _set(want)
    if not r.get('ok'):
        return {'ok': False, 'message': f"Windows refused to start recording. {r.get('error', '')}".strip()}
    return {'ok': True, 'message': 'Recording started. Windows Firewall now writes down every connection it refuses, and this list fills in as attempts happen.'}


def stop(prev):
    """Puts back what was there before recording started; without that, Windows' default (off)."""
    rows = prev or [{'Name': p['Name'], 'LogBlocked': 'False', 'Size': p.get('Size') or 4096} for p in profiles()]
    rows = [{'Name': p['Name'], 'LogBlocked': p['LogBlocked'] if p['LogBlocked'] in ('True', 'False', 'NotConfigured') else 'False', 'Size': int(p.get('Size') or 4096)} for p in rows]
    r = _set(rows)
    if not r.get('ok'):
        return {'ok': False, 'message': f"Windows refused to stop recording. {r.get('error', '')}".strip()}
    return {'ok': True, 'message': 'Recording stopped. What was recorded so far stays in the list until My Security closes.'}


class Reader:
    """Reads pfirewall.log as it grows and keeps a running summary of refused connections."""

    def __init__(self):
        self.lock = threading.Lock()
        self.pos = {}       # file -> bytes read so far
        self.fields = {}    # file -> column names from its #Fields line
        self.groups = {}    # (dir, proto, remote, port, program) -> [count, first, last]
        self.pids = {}      # pid -> program path, looked up when first seen
        self.since = None

    def _header(self, path):
        try:
            with open(path, 'r', encoding='ascii', errors='replace') as f:
                for _ in range(10):
                    line = f.readline()
                    if line.startswith('#Fields:'):
                        return line[8:].split()
        except OSError:
            pass
        return ['date', 'time', 'action', 'protocol', 'src-ip', 'dst-ip', 'src-port', 'dst-port', 'size', 'tcpflags', 'tcpsyn', 'tcpack', 'tcpwin', 'icmptype', 'icmpcode', 'info', 'path']

    def _program(self, pid):
        if not pid or not pid.isdigit() or pid == '0' or pid == '4':
            return ''
        if pid not in self.pids:
            self.pids[pid] = (S.process_path(int(pid)) or '').lower()
        return self.pids[pid]

    def _line(self, cols, idx):
        if len(cols) < len(idx) or cols[idx['action']] != 'DROP':
            return
        way = cols[idx['path']] if 'path' in idx else ''
        if way not in ('RECEIVE', 'SEND'):
            return
        proto, src, dst = cols[idx['protocol']], cols[idx['src-ip']], cols[idx['dst-ip']]
        sport, dport = cols[idx['src-port']], cols[idx['dst-port']]
        when = f"{cols[idx['date']]} {cols[idx['time']]}"
        if way == 'RECEIVE':
            remote, port = src, dport     # someone reaching this PC: the port they tried here
        else:
            remote, port = dst, dport     # this PC reaching out: the port it tried there
        prog = self._program(cols[idx['pid']]) if 'pid' in idx else ''
        key = (way, proto, remote, port if port.isdigit() else '', prog)
        g = self.groups.get(key)
        if g:
            g[0] += 1
            g[2] = max(g[2], when)
            g[1] = min(g[1], when)
        elif len(self.groups) < MAX_GROUPS:
            self.groups[key] = [1, when, when]
        if self.since is None or when < self.since:
            self.since = when

    def _read(self, path, start_at):
        try:
            size = os.path.getsize(path)
        except OSError:
            return start_at
        if size < start_at:   # Windows started a new file
            start_at = 0
            self.fields.pop(path, None)
        if size == start_at:
            return start_at
        if path not in self.fields:
            self.fields[path] = self._header(path)
        idx = {n: i for i, n in enumerate(self.fields[path])}
        if not {'date', 'time', 'action', 'protocol', 'src-ip', 'dst-ip', 'src-port', 'dst-port'} <= idx.keys():
            return size
        try:
            with open(path, 'rb') as f:
                f.seek(start_at)
                data = f.read(size - start_at)
        except OSError:
            return start_at
        cut = data.rfind(b'\n') + 1   # keep a half-written last line for next time
        for raw in data[:cut].decode('ascii', 'replace').splitlines():
            if raw and not raw.startswith('#'):
                self._line(raw.split(), idx)
        return start_at + cut

    def update(self, files):
        with self.lock:
            for path in files:
                if path not in self.pos and os.path.exists(path + '.old'):
                    self.pos[path + '.old'] = self._read(path + '.old', 0)   # what came before the last rollover, read once
                self.pos[path] = self._read(path, self.pos.get(path, 0))

    def match(self, blocks):
        """The refused connections that hit one of your blocks, newest first."""
        ports = {(str(p['Proto']).upper(), str(p['Port'])): p for p in blocks.get('ports', [])}
        ips = {}
        for b in blocks.get('ips', []):
            for a in str(b['Address']).split(','):
                try:
                    ips[str(ipaddress.ip_address(a.strip()))] = b['Address']
                except ValueError:
                    pass
        progs = {str(p['Path']).lower(): p for p in blocks.get('programs', [])}
        out = {}
        with self.lock:
            items = list(self.groups.items())
        for (way, proto, remote, port, prog), (n, first, last) in items:
            hit = None
            if prog and prog in progs:
                hit = ('program', progs[prog]['Name'], progs[prog]['Path'])
            elif remote in ips:
                hit = ('address', ips[remote], ips[remote])
            elif way == 'RECEIVE' and (proto, port) in ports:
                p = ports[(proto, port)]
                hit = ('port', f"{p['Port']} {p['Proto']} ({p['Name']})", p['Key'])
            if not hit:
                continue
            k = (hit[0], hit[2], way, remote)
            e = out.get(k)
            if not e:
                e = out[k] = {'Kind': hit[0], 'Blocked': hit[1], 'Direction': 'in' if way == 'RECEIVE' else 'out', 'Remote': remote, 'Local': _is_local(remote),
                              'Ports': set(), 'Count': 0, 'First': first, 'Last': last}
            e['Count'] += n
            e['First'] = min(e['First'], first)
            e['Last'] = max(e['Last'], last)
            if port:
                e['Ports'].add(port)
        rows = sorted(out.values(), key=lambda x: x['Last'], reverse=True)[:300]
        for r in rows:
            r['Ports'] = sorted(r['Ports'], key=int)[:6]
        return rows


def _is_local(addr):
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not a.is_global
