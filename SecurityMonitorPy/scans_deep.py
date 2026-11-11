"""
Deeper checks for My Security: weak admin setup, per-user apps, PC health, Event Viewer, firewall rules, hacker tricks, lateral movement,
a pentest from inside and outside, and browser extensions against a live list of known-bad ones.
Like scans_win.py, nothing here changes the PC. The pentest only looks: it exploits nothing, reads no secrets out, and never reports a password or key.
Importing this module adds its scans to scans_win.SCANS and its process rules to the live watcher.
"""

import base64
import ctypes
import ctypes.wintypes as wt
import datetime as dt
import glob
import http.client
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import winreg
from concurrent.futures import ThreadPoolExecutor

import scans_win as S
from knowledge import BACKDOOR_PORTS, REMOTE_CONTROL_PORTS, REMOTE_TOOLS, port_info
from scans_win import A, F, HKCU, HKLM, as_list, need_admin, ps_one, reg_get, reg_subkeys, reg_values

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) MySecurity'}
GB = 1024 ** 3


def _private(ip):
    try:
        return ipaddress.ip_address(str(ip).split('%')[0]).is_private
    except ValueError:
        return False


def _run(*cmd, timeout=20):
    try:
        r = subprocess.run(list(cmd), capture_output=True, timeout=timeout, creationflags=S.CREATE_NO_WINDOW)
        return r.stdout.decode('utf-8', 'replace')
    except (OSError, subprocess.SubprocessError):
        return ''


# ---------------------------------------------------------------- weak administrator setup

GROUPS_PS = r'''
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$groups = foreach ($sid in 'S-1-5-32-544','S-1-5-32-555','S-1-5-32-551','S-1-5-32-578','S-1-5-32-580','S-1-5-32-547','S-1-5-32-562') {
  $g = Get-LocalGroup -SID $sid
  if ($g) { $m = @(); try { $m = @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Sid = [string]$_.SID.Value; Class = [string]$_.ObjectClass } }) } catch {}
    [pscustomobject]@{ Sid = $sid; Name = [string]$g.Name; Members = @($m) } }
}
ConvertTo-Json -InputObject @{ me = $me; groups = @($groups)
  users = @(Get-LocalUser | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Sid = [string]$_.SID.Value; Enabled = [bool]$_.Enabled; Last = $(if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { '' }) } })
} -Depth 5 -Compress
'''
EXTRA_GROUPS = {
    'S-1-5-32-555': ('Remote Desktop Users', 'Members can sign in to this PC from another computer.', 'Each member is one more password that opens this PC remotely.'),
    'S-1-5-32-551': ('Backup Operators', 'Members can read every file, whatever its permissions, in order to back it up.', 'This is effectively administrator: they can copy the Windows password database.'),
    'S-1-5-32-578': ('Hyper-V Administrators', 'Members fully control virtual machines on this PC.', 'A well-known way to gain full control of the host.'),
    'S-1-5-32-580': ('Remote Management Users', 'Members can run commands on this PC through Windows Remote Management.', 'A common path for attackers moving between PCs.'),
    'S-1-5-32-547': ('Power Users', 'A legacy group with extra rights.', 'Rarely needed today. It can change some system settings.'),
    'S-1-5-32-562': ('Distributed COM Users', 'Members can start programs on this PC remotely through DCOM.', 'A known path for moving between PCs.'),
}
OPEN_GROUPS = {'S-1-1-0': 'Everyone', 'S-1-5-11': 'Authenticated Users', 'S-1-5-32-545': 'Users', 'S-1-5-4': 'Interactive', 'S-1-5-7': 'Anonymous'}


def password_policy():
    """(minimum length, lockout threshold), or None if Windows does not say. Read directly, because the text of 'net accounts' depends on the language."""
    try:
        net = S.system_dll('netapi32')
        net.NetUserModalsGet.argtypes = [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(ctypes.POINTER(wt.DWORD))]
        net.NetApiBufferFree.argtypes = [ctypes.c_void_p]
        p0, p3 = ctypes.POINTER(wt.DWORD)(), ctypes.POINTER(wt.DWORD)()
        if net.NetUserModalsGet(None, 0, ctypes.byref(p0)) or net.NetUserModalsGet(None, 3, ctypes.byref(p3)):
            return None
        out = (p0[0], p3[2])   # USER_MODALS_INFO_0.min_passwd_len, USER_MODALS_INFO_3.lockout_threshold
        net.NetApiBufferFree(p0)
        net.NetApiBufferFree(p3)
        return out
    except (OSError, AttributeError, ValueError):
        return None


def scan_adminsetup(ctx):
    d, out = ps_one(GROUPS_PS, timeout=45), []
    me = d.get('me', '')
    groups = {g.get('Sid'): g for g in as_list(d.get('groups')) if isinstance(g, dict)}
    users = {u.get('Sid'): u for u in as_list(d.get('users')) if isinstance(u, dict)}
    admins = [m for m in as_list(groups.get('S-1-5-32-544', {}).get('Members')) if isinstance(m, dict)]
    for m in admins:
        if m.get('Sid') in OPEN_GROUPS:
            out.append(F('adminsetup', 'open:' + m['Sid'], 'critical', f"{OPEN_GROUPS[m['Sid']]} is in the Administrators group", 'Anyone in that group has full control of this PC.', 'Every account, and everything they run, is an administrator. Standard-user protection does not exist here.', m.get('Name'), 'Remove it from Administrators.', A('remove_admin', 'Remove', f"Remove {m.get('Name')} from Administrators?", member=m.get('Name')), Active=True))
    if any(m.get('Sid') == me for m in admins):
        out.append(F('adminsetup', 'daily-admin', 'medium', 'You use an administrator account every day', 'The account you are signed in with is an administrator.', 'Malware that fools you into clicking Yes once gets full control. A standard account would have to ask for a separate password, which stops most silent escalation.', fix='Create a second administrator account for installing things, then make your everyday account a standard user. Do this yourself, in order, so you are not locked out.', action=A('open_settings', 'Open accounts', 'Open account settings?', page='ms-settings:otherusers')))
    cutoff = (dt.date.today() - dt.timedelta(days=180)).isoformat()
    for m in admins:
        u = users.get(m.get('Sid'))
        if u and u.get('Enabled') and m.get('Sid') != me and not str(m.get('Sid')).endswith('-500') and u.get('Last', '') < cutoff:
            when = f"last used on {u['Last']}" if u.get('Last') else 'never used'
            out.append(F('adminsetup', 'stale:' + m['Sid'], 'medium', f"Unused administrator: {m.get('Name')}", f'This administrator account is {when}.', 'Forgotten admin accounts keep old passwords and nobody notices if they are used.', m.get('Name'), 'Remove its admin rights, or turn it off in the Accounts section above.', A('remove_admin', 'Remove admin rights', f"Remove administrator rights from {m.get('Name')}?\n\nThe account stays, as a standard user.", member=m.get('Name'))))
    for sid, (name, what, risk) in EXTRA_GROUPS.items():
        for m in as_list(groups.get(sid, {}).get('Members')):
            if isinstance(m, dict) and m.get('Name'):
                out.append(F('adminsetup', f"grp:{sid}:{m.get('Sid')}", 'high' if sid == 'S-1-5-32-551' else 'medium', f"{m.get('Name')} is in {name}", what, risk, fix='Remove it with lusrmgr.msc if this account does not need it.'))
    pol = password_policy()
    if pol:
        minlen, lockout = pol
        if minlen < 8:
            out.append(F('adminsetup', 'minlen', 'medium', 'Windows allows short passwords' if minlen else 'Windows has no minimum password length', f'The minimum password length is {minlen}. This is the Windows default on a home PC.', 'Short passwords on local accounts fall quickly to guessing tools.', fix='In an administrator prompt run: net accounts /minpwlen:12'))
        if lockout == 0:
            out.append(F('adminsetup', 'lockout', 'medium', 'Unlimited password guesses are allowed', 'Windows never locks an account after wrong passwords.', 'An attacker on your network can keep guessing for as long as they like.', fix='In an administrator prompt run: net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15'))
        if minlen >= 8 and lockout:
            out.append(F('adminsetup', 'policy', 'ok', 'Password rules are sensible', f'Minimum length {minlen}. Accounts lock after {lockout} wrong passwords.'))
    else:
        out.append(F('adminsetup', 'policy-unknown', 'info', 'Password rules could not be read', 'Windows did not return its password policy.'))
    pol_sys, lsa = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', r'SYSTEM\CurrentControlSet\Control\Lsa'
    if reg_get(HKLM, pol_sys, 'LocalAccountTokenFilterPolicy', 0) == 1:
        out.append(F('adminsetup', 'latfp', 'high', 'Local admins get full rights over the network', 'Windows normally strips admin rights from local accounts that connect over the network. That protection is off here.', 'Attackers can use a stolen password hash to take over this PC remotely. This is the classic pass-the-hash path.', 'LocalAccountTokenFilterPolicy = 1', 'Turn it off.', A('set_reg', 'Turn off', 'Turn the protection back on?\n\nRemote management tools that use a local account may stop working.', hive='HKLM', path=pol_sys, name='LocalAccountTokenFilterPolicy', value=0, kind='dword'), Active=True))
    if reg_get(HKLM, pol_sys, 'PromptOnSecureDesktop', 1) == 0:
        out.append(F('adminsetup', 'securedesktop', 'medium', 'Admin prompts can be faked or clicked by programs', 'The Yes/No prompt normally appears on a protected screen that programs cannot touch. That is off here.', 'Malware can draw over the prompt or press Yes by itself.', fix='Turn the protected screen back on.', action=A('set_reg', 'Turn on', 'Show admin prompts on the protected screen?', hive='HKLM', path=pol_sys, name='PromptOnSecureDesktop', value=1, kind='dword')))
    if reg_get(HKLM, lsa, 'LimitBlankPasswordUse', 1) == 0:
        out.append(F('adminsetup', 'blankremote', 'high', 'Accounts with no password can be used over the network', 'Windows normally refuses this.', 'Anyone on your network can sign in to any account with an empty password.', fix='Turn the restriction back on.', action=A('set_reg', 'Restrict', 'Stop accounts with no password from being used over the network?', hive='HKLM', path=lsa, name='LimitBlankPasswordUse', value=1, kind='dword'), Active=True))
    return out


# ---------------------------------------------------------------- apps installed only for this user

UN = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
OPENS_CONTENT = re.compile(r'(chrome|firefox|edge|opera|brave|vivaldi|browser|discord|slack|zoom|teams|telegram|whatsapp|signal|skype|reader|pdf|torrent|code|cursor|notepad|vlc|media|player|ssh|putty|winscp|filezilla|node|python|git)', re.I)
PER_USER_RISK = 'It lives in your own profile, so anything running under your account can change or replace it without an admin prompt. Installing it needed no administrator, so nobody approved it. Machine-wide patching usually misses it.'


def _user_hives(ctx):
    hives = [(HKCU, 'you', '')]
    if ctx.get('admin'):
        for sid in reg_subkeys(winreg.HKEY_USERS, ''):
            if sid.startswith('S-1-5-21-') and not sid.endswith('_Classes'):
                hives.append((winreg.HKEY_USERS, 'another signed-in user', sid + '\\'))
    return hives


def _exe_of(hive, key):
    icon = str(reg_get(hive, key, 'DisplayIcon', '') or '').split(',')[0].strip('" ')
    if icon.lower().endswith('.exe') and os.path.isfile(os.path.expandvars(icon)):
        return os.path.expandvars(icon)
    un = S.exe_from_command(reg_get(hive, key, 'UninstallString', ''))
    return un if un.lower().endswith('.exe') and os.path.isfile(un) else ''


def scan_userapps(ctx):
    rows, out, seen = [], [], set()
    for hive, who, prefix in _user_hives(ctx):
        for sub in reg_subkeys(hive, prefix + UN):
            k = prefix + UN + '\\' + sub
            name = str(reg_get(hive, k, 'DisplayName', '') or '')
            if name and name not in seen and reg_get(hive, k, 'SystemComponent', 0) != 1:
                seen.add(name)
                rows.append({'Name': name, 'Version': str(reg_get(hive, k, 'DisplayVersion', '') or ''), 'Publisher': str(reg_get(hive, k, 'Publisher', '') or ''), 'Exe': _exe_of(hive, k), 'Who': who, 'Loc': str(reg_get(hive, k, 'InstallLocation', '') or '')})
    programs = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs')
    known_dirs = {os.path.normcase(r['Loc'].rstrip('\\')) for r in rows if r['Loc']} | {os.path.normcase(os.path.dirname(r['Exe'])) for r in rows if r['Exe']}
    try:
        for d in sorted(os.listdir(programs)):
            full = os.path.join(programs, d)
            if os.path.isdir(full) and os.path.normcase(full) not in known_dirs and d.lower() not in ('common', 'python') and d not in seen:
                exes = sorted(glob.glob(os.path.join(glob.escape(full), '*.exe')))
                if exes:
                    rows.append({'Name': d, 'Version': '', 'Publisher': '', 'Exe': exes[0], 'Who': 'you', 'Loc': full, 'NoEntry': True})
    except OSError:
        pass
    signs = S.sign_info([r['Exe'] for r in rows if r['Exe']])
    for r in rows:
        info, name = signs.get(r['Exe'], {}), r['Name']
        unsigned = bool(r['Exe']) and S.is_unsigned(info)
        tool = next((v for k, v in REMOTE_TOOLS.items() if k in name.lower().replace(' ', '')), '')
        sev, why = 'info', PER_USER_RISK
        if tool:
            sev, why = 'high', f'{tool} is remote-control or tunnel software, installed with no administrator approval. Scammers ask people to install exactly this. ' + PER_USER_RISK
        elif unsigned:
            sev, why = 'medium', 'Its program file has no valid digital signature, so nothing proves who made it or that it has not been altered. ' + PER_USER_RISK
        elif OPENS_CONTENT.search(name):
            sev, why = 'low', 'It opens content from the internet, which makes it a frequent target, and it keeps itself updated only while you use it. ' + PER_USER_RISK
        ev = '\n'.join(x for x in (f"Version {r['Version']}" if r['Version'] else '', f"Publisher: {info.get('Publisher') or r['Publisher'] or 'unknown'}", r['Exe'] or r['Loc'], f"Installed by {r['Who']}" if r['Who'] != 'you' else '', 'Has no entry in Installed apps' if r.get('NoEntry') else '') if x)
        out.append(F('userapps', 'app:' + name, sev, name, 'Installed for this user only, not for the whole PC.', why, ev, 'Remove it if you do not use it. Otherwise keep it updated, or reinstall the all-users version, which standard accounts cannot tamper with.', A('open_settings', 'Open installed apps', 'Open the Installed apps page?', page='ms-settings:appsfeatures'), Path=r['Exe']))
    if not rows:
        out.append(F('userapps', 'none', 'ok', 'No apps are installed only for this user', 'Everything is installed for the whole PC.'))
    return out


# ---------------------------------------------------------------- performance, memory leaks, disks

HEALTH_PS = r'''
$cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
$cores = [Math]::Max(1, [int]$cs.NumberOfLogicalProcessors)
$a = @{}; Get-Process | ForEach-Object { $a[$_.Id] = $_.CPU }; $t = Get-Date
$load = @(); $dq = @{}
foreach ($i in 1..4) { Start-Sleep -Milliseconds 1100; $load += [int](Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
  foreach ($d in Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk) { if ($d.Name -ne '_Total') { if (-not $dq[$d.Name]) { $dq[$d.Name] = @() }; $dq[$d.Name] += [int]$d.PercentIdleTime } } }
$el = [Math]::Max(0.5, ((Get-Date) - $t).TotalSeconds)
$procs = @(Get-Process | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Name = [string]$_.ProcessName; Cpu = $(if ($a.ContainsKey($_.Id) -and $_.CPU -ne $null) { [Math]::Round(($_.CPU - $a[$_.Id]) / $el / $cores * 100, 1) } else { 0 }); Mem = [int64]$_.PrivateMemorySize64; Handles = [int]$_.HandleCount } })
$m = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
function Since($log, $prov, $ids, $days) { try { @(Get-WinEvent -FilterHashtable @{ LogName = $log; ProviderName = $prov; Id = $ids; StartTime = (Get-Date).AddDays(-$days) } -MaxEvents 200 -ErrorAction Stop) } catch { @() } }
$diskEv = @(Since 'System' @('disk','Ntfs','Microsoft-Windows-Ntfs','volmgr','stornvme','storahci') @(7,11,15,51,52,55,98,129,153,157) 30 | Where-Object { $_.Level -in 1,2,3 })
$exh = Since 'System' 'Microsoft-Windows-Resource-Exhaustion-Detector' 2004 30
$boot = @(); try { $boot = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 5 -ErrorAction Stop | ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'BootTime' } | ForEach-Object { [int]$_.'#text' } }) } catch {}
ConvertTo-Json -InputObject @{ ok = $true; ram = [int64]$cs.TotalPhysicalMemory; free = [int64]$os.FreePhysicalMemory * 1024; boot = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'); up = [int]((Get-Date) - $os.LastBootUpTime).TotalDays; load = $load
  commit = [int64]$m.CommittedBytes; limit = [int64]$m.CommitLimit; nonpaged = [int64]$m.PoolNonpagedBytes; paged = [int64]$m.PoolPagedBytes
  idle = @($dq.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Key; Idle = [int]($_.Value | Measure-Object -Average).Average } })
  cpuTop = @($procs | Where-Object { $_.Name -ne 'Idle' } | Sort-Object Cpu -Descending | Select-Object -First 6); memTop = @($procs | Sort-Object Mem -Descending | Select-Object -First 6); handleTop = @($procs | Sort-Object Handles -Descending | Select-Object -First 4)
  volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [pscustomobject]@{ Name = [string]$_.DeviceID; Size = [int64]$_.Size; Free = [int64]$_.FreeSpace; Fs = [string]$_.FileSystem; Dirty = [bool]$_.VolumeDirty } })
  disks = @(Get-PhysicalDisk | ForEach-Object { $r = $null; try { $r = $_ | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}; [pscustomobject]@{ Name = [string]$_.FriendlyName; Media = [string]$_.MediaType; Bus = [string]$_.BusType; Health = [string]$_.HealthStatus; Status = [string]($_.OperationalStatus -join ','); Wear = $(if ($r) { $r.Wear } else { $null }); Temp = $(if ($r) { $r.Temperature } else { $null }); ReadErr = $(if ($r) { $r.ReadErrorsUncorrected } else { $null }) } })
  diskEv = @($diskEv | ForEach-Object { [pscustomobject]@{ When = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Id = $_.Id; Src = [string]$_.ProviderName; Text = ([string]$_.Message).Substring(0, [Math]::Min(180, ([string]$_.Message).Length)) } })
  exhausted = @($exh | Select-Object -First 3 | ForEach-Object { [pscustomobject]@{ When = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Text = ([string]$_.Message).Substring(0, [Math]::Min(420, ([string]$_.Message).Length)) } }); bootMs = @($boot)
} -Depth 4 -Compress
'''
SAMPLE_PS = "ConvertTo-Json -InputObject @(Get-Process | ForEach-Object { [pscustomobject]@{ I = $_.Id; N = [string]$_.ProcessName; M = [int64]$_.PrivateMemorySize64; H = [int]$_.HandleCount } }) -Compress"
_history = {}
HISTORY_STEP = 300


def memory_sampler(stop):
    """Runs while the app is open. A leak only shows as a trend, so this records each program's memory every five minutes."""
    while not stop.is_set():
        now, live = time.time(), set()
        for r in S.run_powershell(SAMPLE_PS, timeout=40):
            if isinstance(r, dict) and r.get('M') is not None:
                key = (r.get('I'), r.get('N'))
                live.add(key)
                _history.setdefault(key, []).append((now, r['M'], r.get('H') or 0))
                del _history[key][:-48]
        for k in [k for k in _history if k not in live]:
            del _history[k]
        stop.wait(HISTORY_STEP)


def leak_suspects():
    out = []
    for (pid, name), h in list(_history.items()):
        if len(h) < 6:
            continue
        for idx, label, unit, least in ((1, 'memory', GB, 300 * 1024 * 1024), (2, 'handles', 1, 3000)):
            vals = [x[idx] for x in h]
            ups = sum(1 for a, b in zip(vals, vals[1:]) if b >= a)
            if vals[-1] - vals[0] >= least and vals[-1] >= vals[0] * 1.4 and ups >= (len(vals) - 1) * 0.8:
                out.append((name, pid, label, vals[0] / unit, vals[-1] / unit, (h[-1][0] - h[0][0]) / 60))
    return out


def _fmt_top(rows, field, fmt):
    return '\n'.join(f"{r.get('Name')} (PID {r.get('Id')}): {fmt(r.get(field) or 0)}" for r in as_list(rows) if isinstance(r, dict))


def scan_health(ctx):
    d, out = ps_one(HEALTH_PS, timeout=120), []
    if not d.get('ok'):
        return [F('health', 'failed', 'info', 'Performance data could not be read', 'Windows did not return its counters.', fix='Run the scan again.')]
    ram, free = d.get('ram') or 1, d.get('free') or 0
    used = 100 - free * 100 / ram
    load = [int(x) for x in as_list(d.get('load'))]
    cpu = sum(load) / max(1, len(load))
    top_cpu, top_mem = _fmt_top(d.get('cpuTop'), 'Cpu', lambda v: f'{v}% of the whole CPU'), _fmt_top(d.get('memTop'), 'Mem', lambda v: f'{v / GB:.1f} GB')
    if cpu >= 85:
        out.append(F('health', 'cpu', 'medium', f'The processor is overloaded ({cpu:.0f}%)', 'Measured over about four seconds.', 'Everything slows down. Unexplained constant load is also how hidden crypto miners show up.', top_cpu, 'If the top program is not something you are using, look it up, then end it from the Processes tab.'))
    elif cpu >= 60:
        out.append(F('health', 'cpu', 'low', f'The processor is busy ({cpu:.0f}%)', 'Measured over about four seconds.', 'Could be normal if you are working.', top_cpu))
    if used >= 90:
        out.append(F('health', 'ram', 'medium', f'Memory is nearly full ({used:.0f}% of {ram / GB:.0f} GB)', 'Windows has little room left and starts using the disk as memory.', 'This is the most common cause of a slow PC.', top_mem, 'Close what you do not need. If this happens often, add memory.'))
    elif ram < 8 * GB:
        out.append(F('health', 'smallram', 'low', f'This PC has only {ram / GB:.0f} GB of memory', 'Windows 11 and a browser together use most of that.', 'A likely bottleneck.', fix='Add memory if the PC allows it.'))
    commit, limit = d.get('commit') or 0, d.get('limit') or 1
    if commit / limit >= 0.9:
        out.append(F('health', 'commit', 'high', f'Windows is close to running out of memory ({commit / GB:.0f} of {limit / GB:.0f} GB promised)', 'Programs have reserved nearly everything Windows can provide, including the page file.', 'Programs start crashing when this reaches 100%.', top_mem, 'Close the largest programs, or make the page file larger.'))
    nonpaged, paged = d.get('nonpaged') or 0, d.get('paged') or 0
    if nonpaged >= 2 * GB or paged >= 6 * GB:
        out.append(F('health', 'pool', 'medium', 'A driver may be leaking memory', f'Windows kernel memory is unusually large: {nonpaged / GB:.1f} GB non-paged, {paged / GB:.1f} GB paged.', 'Only drivers use this memory, and it grows until the PC becomes unstable.', fix='Update network, graphics, antivirus and VPN drivers. A restart clears it for a while.'))
    for name, pid, label, a, b, mins in leak_suspects():
        amount = f'{a:.2f} GB to {b:.2f} GB' if label == 'memory' else f'{a:.0f} to {b:.0f}'
        out.append(F('health', f'leak:{name}:{label}', 'medium', f'Possible memory leak: {name}', f'Its {label} kept rising for {mins:.0f} minutes, from {amount}, without coming back down.', 'A leak keeps eating resources until the program or PC gets slow or crashes.', f'PID {pid}', 'Restart that program and check for an update.'))
    for r in as_list(d.get('handleTop')):
        if isinstance(r, dict) and (r.get('Handles') or 0) >= 50000:
            out.append(F('health', f"handles:{r.get('Name')}", 'medium', f"{r.get('Name')} holds {r.get('Handles'):,} handles", 'Handles are Windows resources a program has opened. Tens of thousands usually means it never closes them.', 'A classic leak. The PC becomes sluggish.', f"PID {r.get('Id')}", 'Restart that program and check for an update.'))
    for e in as_list(d.get('exhausted')):
        if isinstance(e, dict):
            out.append(F('health', 'exhausted:' + str(e.get('When')), 'high', f"Windows ran out of memory on {e.get('When')}", 'Windows recorded a low-memory emergency and named the largest programs.', 'The program at the top of this list is the likely leak.', e.get('Text'), 'Update or replace that program.'))
    for i in as_list(d.get('idle')):
        if isinstance(i, dict) and (i.get('Idle') or 100) <= 15:
            out.append(F('health', 'diskbusy:' + str(i.get('Name')), 'medium', f"Disk {i.get('Name')} is running flat out", f"It was idle only {i.get('Idle')}% of the time during the test.", 'A saturated disk makes the whole PC freeze in bursts. Ransomware encrypting files looks like this too.', fix='See which program is writing in Task Manager > Performance > Open Resource Monitor > Disk. If you do not recognise it, end it.'))
    for v in as_list(d.get('volumes')):
        if not isinstance(v, dict) or not v.get('Size'):
            continue
        pct, free_gb = v.get('Free', 0) * 100 / v['Size'], v.get('Free', 0) / GB
        name = v.get('Name')
        is_sys = str(name).upper() == os.environ.get('SystemDrive', 'C:').upper()
        if pct < 5 or free_gb < 5:
            out.append(F('health', 'space:' + str(name), 'high' if is_sys else 'low', f'Drive {name} is almost full ({free_gb:.1f} GB free)', 'Windows and programs need free space to work.' if is_sys else 'This is a data drive, so Windows itself is not affected.', 'Updates fail, including security updates. Programs can crash and lose data.' if is_sys else 'Anything saving to it may fail.', fix='Free up space with Storage settings.', action=A('open_settings', 'Open storage', 'Open storage settings?', page='ms-settings:storagesense')))
        elif pct < 12:
            out.append(F('health', 'space:' + str(name), 'low', f'Drive {name} is getting full ({pct:.0f}% free)', 'Performance drops as a drive fills up.', '', fix='Free up space with Storage settings.', action=A('open_settings', 'Open storage', 'Open storage settings?', page='ms-settings:storagesense')))
        if v.get('Dirty'):
            out.append(F('health', 'dirty:' + str(name), 'high', f'Drive {name} is marked as having errors', 'Windows flagged its file system as needing repair.', 'Files can be damaged or lost.', fix=f'Back up first, then in an administrator prompt run: chkdsk {name} /scan'))
    for k in as_list(d.get('disks')):
        if not isinstance(k, dict):
            continue
        name = k.get('Name')
        if k.get('Health') not in ('Healthy', None, ''):
            out.append(F('health', 'smart:' + str(name), 'critical', f'Disk is failing: {name}', f"Windows reports its health as {k.get('Health')}.", 'It can stop working at any time and take your files with it.', f"Status: {k.get('Status')}", 'Back up today and replace the disk.', Active=True))
        if k.get('Wear') is not None and k['Wear'] >= 80:
            out.append(F('health', 'wear:' + str(name), 'high', f"SSD is {k['Wear']}% worn: {name}", 'SSDs last a set number of writes.', 'It will start failing as this nears 100%.', fix='Back up and plan to replace it.'))
        if k.get('ReadErr'):
            out.append(F('health', 'readerr:' + str(name), 'high', f"Disk has {k['ReadErr']} unrecoverable read errors: {name}", 'The disk could not read data back.', 'Usually an early sign of failure.', fix='Back up today and test the disk.'))
        if k.get('Media') == 'HDD' and k.get('Bus') != 'USB':
            out.append(F('health', 'hdd:' + str(name), 'low', f'Mechanical hard drive: {name}', 'Far slower than an SSD.', 'If Windows is on this drive, it is the biggest bottleneck on the PC.', fix='Move Windows to an SSD.'))
    evs = [e for e in as_list(d.get('diskEv')) if isinstance(e, dict)]
    if evs:
        ids = {int(e.get('Id') or 0) for e in evs}
        bad = ids & {7, 11, 51, 55, 98, 153}
        out.append(F('health', 'diskev', 'high' if bad else 'medium', f'{len(evs)} disk errors in the last 30 days', 'Windows logged disk or file-system trouble.', 'Repeated errors usually come before a failure. A loose cable can also cause them.', '\n'.join(f"{e.get('When')} {e.get('Src')} {e.get('Id')}: {e.get('Text')}" for e in evs[:5]), 'Back up, then check the disk with the drive maker\'s tool.'))
    if (d.get('up') or 0) >= 30:
        out.append(F('health', 'uptime', 'low', f"Not restarted for {d.get('up')} days", f"Last start: {d.get('boot')}.", 'Many security updates only take effect after a restart, and leaks build up.', fix='Restart the PC.'))
    boots = [int(x) for x in as_list(d.get('bootMs')) if x]
    if boots and max(boots) >= 120000:
        out.append(F('health', 'boot', 'low', f'Startup is slow ({max(boots) // 1000} seconds)', 'From Windows\' own boot timing.', 'Usually too many programs starting with Windows.', fix='Turn off what you do not need in Settings > Apps > Startup.', action=A('open_settings', 'Open startup apps', 'Open startup settings?', page='ms-settings:startupapps')))
    if not [x for x in out if x['Sev'] in ('critical', 'high', 'medium')]:
        out.append(F('health', 'good', 'ok', 'No performance or disk problems found', f'Processor {cpu:.0f}%, memory {used:.0f}% used.'))
    if not ctx['admin']:
        out.append(need_admin('health', 'Disk wear, disk temperature and boot timing'))
    out.append(F('health', 'leak-note', 'info', 'Memory leak tracking', f'My Security has {max([len(h) for h in _history.values()] or [0])} samples so far, one every five minutes. It needs about 30 minutes of history to spot a leak, so leave it open and re-scan.'))
    return out


# ---------------------------------------------------------------- Event Viewer

EVENT_LOG_PS = r'''
$e = @(); try { $e = @(Get-WinEvent -FilterHashtable @{ LogName = 'System','Application'; Level = 1,2; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 3000 -ErrorAction Stop) } catch {}
$g = @($e | Group-Object LogName, ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 80 | ForEach-Object { $x = $_.Group[0]; $m = [string]$x.Message
  [pscustomobject]@{ Log = [string]$x.LogName; Src = [string]$x.ProviderName; Id = [int]$x.Id; Level = [int]$x.Level; Count = [int]$_.Count; Last = $x.TimeCreated.ToString('yyyy-MM-dd HH:mm'); First = $_.Group[-1].TimeCreated.ToString('yyyy-MM-dd HH:mm'); Text = $m.Substring(0, [Math]::Min(420, $m.Length)) } })
ConvertTo-Json -InputObject @{ ok = $true; total = $e.Count; groups = $g } -Depth 3 -Compress
'''
NOISE = {('distributedcom', 10016), ('distributedcom', 10010), ('distributedcom', 10005), ('windows search service', 3104), ('microsoft-windows-time-service', 129), ('microsoft-windows-gpsvc', 1129)}
EVENT_KB = {
    ('kernel-power', 41): ('high', 'The PC restarted without shutting down properly', 'It crashed, froze or lost power.', 'If this repeats, suspect power, overheating or a bad driver.', 'Check for Windows and driver updates. If it repeats, test the memory and power supply.'),
    ('eventlog', 6008): ('medium', 'Windows was not shut down cleanly', 'The previous shutdown was unexpected.', 'Occasional power cuts are harmless. Repeats are not.', 'If you did not hold the power button or lose power, check the crash entries here.'),
    ('wer-systemerrorreporting', 1001): ('high', 'Blue-screen crash', 'Windows stopped with a fatal error.', 'Usually a driver or failing hardware. Rootkits and kernel exploits can cause it too.', 'Note the stop code below and update drivers.'),
    ('whea-logger', 17): ('medium', 'Corrected hardware error', 'The hardware detected and corrected an error.', 'A sign of a device or PCIe link beginning to struggle.', 'Update BIOS and chipset drivers.'),
    ('whea-logger', 18): ('high', 'Fatal hardware error', 'The processor, memory or a device reported a failure.', 'The hardware is likely faulty or overheating.', 'Check temperatures and test memory.'),
    ('whea-logger', 19): ('medium', 'Corrected processor error', 'The processor corrected an internal error.', 'Repeats point to instability or overheating.', 'Remove any overclock. Update the BIOS.'),
    ('whea-logger', 1): ('high', 'Hardware error recorded', 'Windows recorded a hardware fault.', 'The hardware may be failing.', 'Check temperatures and test memory.'),
    ('service control manager', 7031): ('medium', 'A service crashed', 'A background service ended unexpectedly.', 'If it is a security service, something may be attacking it.', 'If it repeats, update or reinstall what it belongs to.'),
    ('service control manager', 7034): ('medium', 'A service crashed', 'A background service ended unexpectedly.', 'If it is a security service, something may be attacking it.', 'If it repeats, update or reinstall what it belongs to.'),
    ('service control manager', 7000): ('low', 'A service could not start', 'Windows tried to start a service and failed.', 'Often leftovers from removed software.', 'If you recognise it, reinstall it. Otherwise it is usually harmless.'),
    ('service control manager', 7009): ('low', 'A service took too long to start', 'Windows gave up waiting for it.', 'Usually a slow disk or heavy startup.', 'If it repeats, reduce startup programs.'),
    ('service control manager', 7023): ('low', 'A service stopped with an error', 'It ended with a failure.', 'Often harmless. Worth checking if something stopped working.', ''),
    ('service control manager', 7024): ('low', 'A service stopped with an error', 'It ended with a failure.', 'Often harmless. Worth checking if something stopped working.', ''),
    ('application error', 1000): ('low', 'A program keeps crashing', 'A program ended with a fault.', 'A browser or document app that crashes on particular content can be a sign of an exploit attempt.', 'Update the program.'),
    ('application hang', 1002): ('low', 'A program keeps freezing', 'A program stopped responding and was closed.', 'Usually a bug or a slow disk.', 'Update the program.'),
    ('.net runtime', 1026): ('low', 'A .NET program crashed', 'It ended with an unhandled error.', 'Usually a bug.', 'Update the program.'),
    ('windowsupdateclient', 20): ('high', 'A Windows update failed to install', 'Windows Update could not finish.', 'The security holes that update fixes are still open on this PC.', 'Run Windows Update again. Details are in the Patches tab.'),
    ('tpm-wmi', 1796): ('medium', 'Secure Boot certificates could not be updated', 'Windows tried to update them and failed.', 'Microsoft\'s older Secure Boot certificates expire, and PCs that miss the update stop getting boot security fixes.', 'Install the latest BIOS and Windows updates.'),
    ('tpm-wmi', 1801): ('medium', 'Secure Boot certificates need updating', 'Windows says the certificates on this PC are not updated yet.', 'PCs that miss the update stop getting boot security fixes.', 'Install the latest BIOS and Windows updates.'),
    ('schannel', 36871): ('low', 'Secure connection errors', 'Windows could not set up an encrypted connection.', 'Often a server using old encryption.', 'If a program stopped connecting, update it.'),
    ('disk', 7): ('high', 'Bad disk blocks', 'The disk reported damaged areas.', 'Data loss is likely.', 'Back up today and replace the disk.'),
    ('disk', 11): ('high', 'Disk controller errors', 'The disk or its cable reported a fault.', 'Data can be lost.', 'Back up, then check the cable and the disk.'),
    ('disk', 51): ('medium', 'Disk paging errors', 'Windows had trouble reading from the disk.', 'Can come before failure.', 'Back up and test the disk.'),
    ('ntfs', 55): ('high', 'File system corruption', 'Files or folders on this drive are damaged.', 'Data can be lost.', 'Back up, then run: chkdsk /scan'),
    ('ntfs', 98): ('medium', 'A drive needs a file-system check', 'Windows found damage on the volume.', 'Files can be lost.', 'Back up, then run: chkdsk /scan'),
}
SECURITY_SERVICE = re.compile(r'(defender|windefend|firewall|mpssvc|security center|falcon|crowdstrike|sense\b|eventlog|bits)', re.I)


def scan_events(ctx):
    d, out = ps_one(EVENT_LOG_PS, timeout=120), []
    if not d.get('ok'):
        return [F('events', 'failed', 'info', 'The event logs could not be read', 'Windows did not return them.', fix='Run the scan again.')]
    other, noise = 0, 0
    for g in as_list(d.get('groups')):
        if not isinstance(g, dict):
            continue
        src, eid = str(g.get('Src', '')).lower(), int(g.get('Id') or 0)
        short = src.replace('microsoft-windows-', '')
        count, level = int(g.get('Count') or 0), int(g.get('Level') or 2)
        if (src, eid) in NOISE or (short, eid) in NOISE:
            noise += count
            continue
        kb = EVENT_KB.get((short, eid))
        where = f"{count} times in 7 days. Last: {g.get('Last')}\n{g.get('Text')}"
        fid = f'{src}:{eid}'
        if kb:
            sev, title, what, risk, fix = kb
            if eid in (7031, 7034) and SECURITY_SERVICE.search(str(g.get('Text'))):
                sev, risk = 'high', 'This is a security service. Malware often tries to crash or stop these.'
            if eid == 1000 and count >= 10:
                sev = 'medium'
            if eid == 20 and re.search(r'0x80073D02|\b9[A-Z0-9]{11}\b', str(g.get('Text'))):
                sev, title, what, risk, fix = 'low', 'A Microsoft Store app could not update', 'The app was probably open at the time.', 'This is not a Windows security update. Store retries by itself.', 'Close the app. Store will update it later.'
            out.append(F('events', fid, sev, f'{title} ({count}x)', what, risk, where, fix, Link=f'https://www.google.com/search?q=event+id+{eid}+{urllib.parse.quote(short)}'))
        elif level == 1:
            out.append(F('events', fid, 'medium', f"Critical event: {g.get('Src')} {eid} ({count}x)", 'Windows marked this as critical.', 'My Security has no specific explanation for this one.', where, 'Look up the event ID.', Link=f'https://www.google.com/search?q=event+id+{eid}+{urllib.parse.quote(short)}'))
        elif count >= 25:
            out.append(F('events', fid, 'low', f"Repeating error: {g.get('Src')} {eid} ({count}x)", 'Windows logged this error many times.', 'Repeating errors waste resources and can hide a real fault.', where, 'Look up the event ID if something misbehaves.', Link=f'https://www.google.com/search?q=event+id+{eid}+{urllib.parse.quote(short)}'))
        else:
            other += count
    out.append(F('events', 'summary', 'info', f"{d.get('total')} errors in Event Viewer in the last 7 days", f'{noise} are known harmless Windows noise and {other} are isolated errors, so they are not listed. A few errors are normal on any PC.', 'The Security log is checked separately, under Threats and Lateral.'))
    return out


# ---------------------------------------------------------------- firewall rules

FIREWALL_PS = r'''
$rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow)
function Index($cmd) { $h = @{}; try { & $cmd -All -ErrorAction Stop | ForEach-Object { $h[$_.InstanceID] = $_ } } catch {}; $h }
$pf = Index Get-NetFirewallPortFilter; $ap = Index Get-NetFirewallApplicationFilter; $ad = Index Get-NetFirewallAddressFilter
$out = foreach ($r in $rules) { [pscustomobject]@{ Id = [string]$r.Name; Name = [string]$r.DisplayName; F = [string]$r.Profile; P = [string]$pf[$r.Name].Protocol; L = (@($pf[$r.Name].LocalPort) -join ','); A = [string]$ap[$r.Name].Program; K = [string]$ap[$r.Name].Package; O = [string]$r.Owner; R = (@($ad[$r.Name].RemoteAddress) -join ',') } }
ConvertTo-Json -InputObject @{ ok = $true; rules = @($out)
  profiles = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; Notify = [string]$_.NotifyOnListen; LogBlocked = [string]$_.LogBlocked; Inbound = [string]$_.DefaultInboundAction } })
} -Depth 4 -Compress
'''
SENSITIVE_PORTS = {'21': 'FTP', '23': 'Telnet', '135': 'RPC', '139': 'NetBIOS', '445': 'SMB file sharing', '3389': 'Remote Desktop', '5900': 'VNC', '5985': 'Windows Remote Management', '5986': 'Windows Remote Management'}
LOCAL_SCOPE = re.compile(r'^(localsubnet|local subnet|fe80|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)', re.I)


def scan_firewall(ctx):
    d, out = ps_one(FIREWALL_PS, timeout=90), []
    rules = [r for r in as_list(d.get('rules')) if isinstance(r, dict)]
    if not rules:
        return [F('firewall', 'failed', 'info', 'Firewall rules could not be read', 'Windows did not return its firewall rules.', fix='Run My Security as Administrator.')]
    for p in as_list(d.get('profiles')):
        if isinstance(p, dict) and p.get('Enabled') == 'True':
            if p.get('Notify') == 'False':
                out.append(F('firewall', 'notify:' + str(p.get('Name')), 'low', f"The {p.get('Name')} firewall blocks programs silently", 'You are not told when a program is blocked from listening.', 'A blocked backdoor would go unnoticed.', fix='Turn notifications on in Windows Security > Firewall > Notification settings.'))
            if p.get('LogBlocked') != 'True':
                out.append(F('firewall', 'log:' + str(p.get('Name')), 'info', f"The {p.get('Name')} firewall does not log blocked connections", 'No record is kept of who tried to connect.', 'Makes an attack harder to investigate.', fix='Optional: turn logging on in wf.msc.'))
    paths = {os.path.expandvars(r['A']) for r in rules if r.get('A') not in (None, '', 'Any', 'System') and not S.in_windows(os.path.expandvars(r['A']))}
    signs = S.sign_info([p for p in paths if os.path.isfile(p)])
    seen, counted = set(), 0
    for r in rules:
        prog = os.path.expandvars(str(r.get('A') or 'Any'))
        remote_any = str(r.get('R') or 'Any') in ('Any', '*')
        is_public = r.get('F') == 'Any' or 'Public' in str(r.get('F'))
        ports = [x.strip() for x in str(r.get('L') or 'Any').split(',')]
        name = str(r.get('Name') or r.get('Id'))
        sev, title, why = '', '', ''
        lower = prog.lower()
        if re.search(rf'\\{S.LOLBINS}(\.exe)?$', lower):
            sev, title, why = 'high', f'Firewall lets the network reach {os.path.basename(prog)}', 'Script tools should never accept network connections. Attackers add rules like this to reach a shell.'
        elif prog not in ('Any', 'System', '') and not S.in_windows(prog):
            if not os.path.isfile(prog):
                sev, title, why = 'low', f'Firewall rule for a missing program: {name}', 'The program has gone but the opening is still there. Whatever is later placed at this path gets through.'
            elif S.USER_WRITABLE.search(prog):
                sev, title, why = 'high', f'Firewall rule for a program in a temporary folder: {name}', 'Trusted software does not run from these folders.'
            elif S.is_unsigned(signs.get(prog, {})) and S.APPDATA_RE.search(prog):
                sev, title, why = 'medium', f'Firewall rule for an unsigned program: {name}', 'It is in your profile, unsigned, and allowed in from the network.'
        elif r.get('K') or r.get('O'):
            pass   # a Store app's rule: Windows limits it to that one app, even though its program and ports read Any
        elif prog in ('Any', '') and str(r.get('P')) == 'Any' and 'Any' in ports and remote_any:
            sev, title, why = 'high', f'Firewall rule allows everything: {name}', 'It lets any program be reached on any port. This effectively turns the firewall off.'
        else:
            hit = sorted({SENSITIVE_PORTS[p] for p in ports if p in SENSITIVE_PORTS})
            if hit and is_public and not LOCAL_SCOPE.match(str(r.get('R'))):
                sev, title, why = 'high', f"{', '.join(hit)} is allowed on public networks", 'On a café or hotel Wi-Fi, anyone can reach this.'
        if not sev or title in seen:
            continue
        seen.add(title)
        counted += 1
        out.append(F('firewall', 'rule:' + str(r.get('Id')), sev, title, 'An inbound rule in Windows Firewall.', why, f"Rule: {name}\nProgram: {prog}\nPorts: {r.get('L')}\nFrom: {r.get('R')}\nNetworks: {r.get('F')}", 'Turn this rule off if you do not recognise it.', A('disable_fw_rules', 'Turn rule off', f'Turn off this firewall rule?\n\n{name}\n\nYou can undo this in the Blocked tab.', names=[r.get('Id')], what=name)))
    if not counted:
        out.append(F('firewall', 'clean', 'ok', 'No suspicious firewall rules', f'Checked {len(rules)} active inbound rules.'))
    return out


# ---------------------------------------------------------------- hacker tricks and backdoors

TRICKS_PS = r'''
ConvertTo-Json -InputObject @{
  drivers = @(Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Path = [string]$_.PathName } })
  svcdll = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object { $p = Join-Path $_.PSPath 'Parameters'; $v = (Get-ItemProperty -LiteralPath $p -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll; if ($v) { [pscustomobject]@{ Name = [string]$_.PSChildName; Dll = [string]$v } } })
  bits = @(Get-BitsTransfer | ForEach-Object { [pscustomobject]@{ Name = [string]$_.DisplayName; Cmd = [string]$_.NotifyCmdLine; State = [string]$_.JobState } })
  dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
} -Depth 3 -Compress
'''
LSA_OK = {'', 'msv1_0', 'scecli', 'rassfm', 'wdigest', 'kerberos', 'tspkg', 'pku2u', 'schannel', 'cloudap', 'negoexts', 'livessp', 'msoidssp', 'credssp', 'negotiate', 'ntlmshared'}
UAC_KEYS = ('ms-settings', 'mscfile', 'exefile', 'Folder', 'AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2')
GOOD_DNS = {'1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15', '1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3'}
DOWNLOAD_CODE = re.compile(r'(downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|\birm\b|\biex\b|invoke-expression|frombase64string)', re.I)
_TRICK_COUNT = 24
# every check the Hacker-tricks scan runs, with the finding-id prefixes it produces when that check finds something
_TRICK_CHECKS = [
    ('Hidden port forwards (netsh portproxy)', ['portproxy:']),
    ('Sign-in system DLLs (LSA packages)', ['lsa:']),
    ('Forced DLLs in new programs (AppCertDlls)', ['appcert']),
    ('Launch-on-exit triggers (SilentProcessExit)', ['spe:']),
    ('Per-user sign-in run keys (Winlogon/Load/Run)', ['hkcu:']),
    ('Office test startup DLL', ['officetest']),
    ('.NET profiler injection (COR_PROFILER)', ['cor']),
    ('Screensaver program location', ['scr']),
    ('Admin-prompt bypass keys (UAC bypass)', ['uacb:']),
    ('Hidden policy startup entries', ['polrun:']),
    ('Active Setup stub programs', ['stub:']),
    ('Netsh helper DLLs', ['netsh:']),
    ('Anonymous shares and pipes (null sessions)', ['null:']),
    ('Remote Desktop port', ['rdpport']),
    ('Remote Desktop silent shadowing', ['shadow']),
    ('Vulnerable-driver blocklist', ['byovd']),
    ('PowerShell execution policy', ['execpol']),
    ('PowerShell script logging', ['sbl']),
    ('PowerShell profile scripts', ['psprofile:']),
    ('Kernel drivers (location and signature)', ['drv:']),
    ('Service DLL locations', ['svcdll:']),
    ('BITS download jobs', ['bits:']),
    ('DNS servers', ['dns:']),
]


def scan_tricks(ctx):
    d, out = ps_one(TRICKS_PS, timeout=90), []
    add = out.append
    # traffic relays: netsh makes this PC forward connections to another machine
    for proto_key in ('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6'):
        key = rf'SYSTEM\CurrentControlSet\Services\PortProxy\{proto_key}\tcp'
        for listen, target in reg_values(HKLM, key):
            add(F('tricks', f'portproxy:{proto_key}:{listen}', 'high', f'Hidden port forward: {listen} to {target}', 'Windows is silently passing connections from one address to another.', 'Intruders use this to reach machines behind this PC. It appears in no normal settings page.', f'{listen} -> {target}', 'Remove it if you did not set it up.', A('remove_portproxy', 'Remove', f'Remove the port forward {listen} -> {target}?', family=proto_key, listen=listen), Active=True))
    lsa = r'SYSTEM\CurrentControlSet\Control\Lsa'
    for val in ('Authentication Packages', 'Notification Packages', 'Security Packages'):
        extra = [str(p) for p in as_list(reg_get(HKLM, lsa, val, [])) if str(p).strip('"').lower() not in LSA_OK]
        if extra:
            add(F('tricks', 'lsa:' + val, 'high', f'Extra component in the Windows sign-in system: {", ".join(extra)}', f'{val} tells Windows which DLLs handle passwords.', 'A DLL added here sees every password as it is typed or changed. Some security and password-sync tools use this too.', ', '.join(extra), 'If you do not recognise it, have the PC checked.', Active=True))
    if reg_values(HKLM, r'SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'):
        add(F('tricks', 'appcert', 'high', 'A DLL is forced into new programs (AppCertDlls)', 'Windows loads these DLLs whenever a program starts.', 'A rarely used place, favoured for hiding.', str(reg_values(HKLM, r'SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls')), 'Remove it if you do not recognise it.', Active=True))
    spe = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    for name in reg_subkeys(HKLM, spe):
        mon = reg_get(HKLM, spe + '\\' + name, 'MonitorProcess', '')
        if mon:
            add(F('tricks', 'spe:' + name, 'high', f'A program launches whenever {name} closes', 'SilentProcessExit starts another program when this one exits.', 'A quiet way to keep malware running.', str(mon), 'Remove it if you do not recognise it.', Active=True))
    for k, n, tag in ((r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Shell', 'your account\'s desktop start-up'), (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Userinit', 'your account\'s sign-in sequence'), (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'Load', 'the old Windows Load setting'), (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'Run', 'the old Windows Run setting'), ('Environment', 'UserInitMprLogonScript', 'a sign-in script')):
        v = reg_get(HKCU, k, n, '')
        if v:
            add(F('tricks', 'hkcu:' + n, 'critical', f'Something is attached to {tag}', 'A per-user setting that runs a program at every sign-in, with no entry in Startup apps.', 'A classic way to survive restarts unnoticed.', str(v), 'Remove it if you do not recognise it.', A('set_reg', 'Clear', f'Clear this setting?\n\n{v}', hive='HKCU', path=k, name=n, value='', kind='sz'), Active=True))
    v = reg_get(HKCU, r'Software\Microsoft\Office test\Special\Perf', '', '')
    if v:
        add(F('tricks', 'officetest', 'critical', 'A DLL loads every time Office starts', 'The hidden "Office test" registry key.', 'Used by known espionage groups. Nothing legitimate uses it.', str(v), 'Have the PC checked.', Active=True))
    if str(reg_get(HKCU, 'Environment', 'COR_ENABLE_PROFILING', '0')) == '1':
        prof = reg_get(HKCU, 'Environment', 'COR_PROFILER', '')
        add(F('tricks', 'cor', 'high', 'A DLL is injected into every .NET program', 'The .NET profiler variable is set for your account.', 'Used as a way to run code and bypass admin prompts. Performance tools set it too.', str(prof), 'Remove it if you do not use a profiling tool.', A('set_reg', 'Turn off', 'Turn off the .NET profiler setting?', hive='HKCU', path='Environment', name='COR_ENABLE_PROFILING', value='0', kind='sz'), Active=True))
    scr = str(reg_get(HKCU, r'Control Panel\Desktop', 'SCRNSAVE.EXE', '') or '')
    if scr and not S.in_windows(os.path.expandvars(scr)) and '\\' in scr:
        add(F('tricks', 'scr', 'high', 'Screensaver points outside Windows', 'Screensavers are programs, and start by themselves.', 'A known way to get malware to run automatically.', scr, 'Choose a different screensaver if you did not install this one.', Active=True))
    for cls in UAC_KEYS:
        k = rf'Software\Classes\{cls}\shell\open\command'
        v = reg_get(HKCU, k, '', None)
        de = reg_get(HKCU, k, 'DelegateExecute', None)
        if v or de is not None:
            add(F('tricks', 'uacb:' + cls, 'critical', f'Admin prompt bypass planted: {cls}', 'Some Windows programs auto-elevate and read this key first.', 'This makes Windows run a program as administrator with no prompt. It is one of the most used privilege-escalation tricks.', str(v or '(delegated)'), 'Remove it.', A('remove_user_key', 'Remove', f'Delete this key?\n\nHKCU\\{k}\nValue: {v}', path=k), Active=True))
    for run in (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',):
        for hive, hn in ((HKLM, 'HKLM'), (HKCU, 'HKCU')):
            for n, v in reg_values(hive, run):
                add(F('tricks', f'polrun:{hn}:{n}', 'high', f'Hidden startup entry: {n}', 'Programs here start at sign-in, but Startup apps does not show them.', 'A quieter alternative to the usual startup keys.', str(v), 'Remove it if you do not recognise it.', A('remove_run', 'Remove from startup', f'Remove "{n}" from startup?\n\n{v}', hive=hn, path=run, name=n, value=str(v)), Active=True))
    for sub in reg_subkeys(HKLM, r'SOFTWARE\Microsoft\Active Setup\Installed Components'):
        stub = str(reg_get(HKLM, r'SOFTWARE\Microsoft\Active Setup\Installed Components' + '\\' + sub, 'StubPath', '') or '')
        if S.USER_WRITABLE.search(os.path.expandvars(stub)) or S.APPDATA_RE.search(stub):
            add(F('tricks', 'stub:' + sub, 'high', 'Active Setup runs a program from a personal folder', 'Active Setup runs once for each new sign-in.', 'A known startup trick.', stub, 'Have it investigated if you do not recognise it.', Active=True))
    for n, v in reg_values(HKLM, r'SOFTWARE\Microsoft\NetSh'):
        if v and ('\\' in str(v)) and not S.in_windows(os.path.expandvars(str(v))):
            add(F('tricks', 'netsh:' + n, 'high', f'Extra helper loaded by netsh: {n}', 'Netsh loads helper DLLs each time it runs.', 'A known way to run code with admin rights.', str(v), 'Remove it if you do not recognise it.'))
    for n, cat_text in ((r'NullSessionShares', 'shares'), (r'NullSessionPipes', 'pipes')):
        vals = [x for x in as_list(reg_get(HKLM, r'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', n, [])) if x]
        if vals:
            add(F('tricks', 'null:' + n, 'high', f'Anonymous users can open these {cat_text}', 'Listed items can be reached with no account.', 'Lets anyone on the network probe this PC.', ', '.join(map(str, vals)), 'Clear this setting unless old software needs it.'))
    ts = r'SYSTEM\CurrentControlSet\Control\Terminal Server'
    port = reg_get(HKLM, ts + r'\WinStations\RDP-Tcp', 'PortNumber', 3389)
    if port != 3389:
        add(F('tricks', 'rdpport', 'high', f'Remote Desktop was moved to port {port}', 'Remote Desktop normally uses 3389.', 'Sometimes done on purpose to hide it. Intruders do this as well.', fix='If you did not do this, set it back and turn Remote Desktop off.'))
    if reg_get(HKLM, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'Shadow', 0) in (2, 4):
        add(F('tricks', 'shadow', 'critical', 'Remote Desktop can watch your screen without asking', 'Shadow sessions are set to need no consent.', 'Someone could silently view or control your session.', fix='Remove this policy.', action=A('set_reg', 'Require consent', 'Require consent before anyone can view your session?', hive='HKLM', path=r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', name='Shadow', value=1, kind='dword'), Active=True))
    if reg_get(HKLM, r'SYSTEM\CurrentControlSet\Control\CI\Config', 'VulnerableDriverBlocklistEnable', 1) == 0:
        add(F('tricks', 'byovd', 'high', 'The vulnerable-driver blocklist is off', 'Windows normally refuses drivers known to be exploitable.', 'Attackers load an old signed driver to switch off antivirus. This is known as "bring your own vulnerable driver".', fix='Turn it back on.', action=A('set_reg', 'Turn on', 'Turn the vulnerable-driver blocklist back on? A restart is needed.', hive='HKLM', path=r'SYSTEM\CurrentControlSet\Control\CI\Config', name='VulnerableDriverBlocklistEnable', value=1, kind='dword', reboot=True)))
    if str(reg_get(HKLM, r'SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell', 'ExecutionPolicy', '')) in ('Bypass', 'Unrestricted'):
        add(F('tricks', 'execpol', 'medium', 'PowerShell runs any script', 'The execution policy for this PC is set to allow everything.', 'Removes a small but useful barrier against a script double-clicked by accident.', fix='In an administrator prompt run: Set-ExecutionPolicy RemoteSigned'))
    if not reg_get(HKLM, r'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging', 0):
        add(F('tricks', 'sbl', 'low', 'PowerShell script logging is off', 'Windows is not recording the scripts it runs.', 'Attackers use PowerShell constantly, and without this an investigation has little to go on.', fix='Turn it on to keep a record.', action=A('set_reg', 'Turn on', 'Turn on PowerShell script logging?', hive='HKLM', path=r'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', name='EnableScriptBlockLogging', value=1, kind='dword')))
    docs = os.path.join(os.environ.get('USERPROFILE', ''), 'Documents')
    for prof in (os.path.join(docs, 'WindowsPowerShell', 'profile.ps1'), os.path.join(docs, 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1'), os.path.join(docs, 'PowerShell', 'profile.ps1'), os.path.join(docs, 'PowerShell', 'Microsoft.PowerShell_profile.ps1'), os.path.join(S.SYSTEM32, r'WindowsPowerShell\v1.0\profile.ps1')):
        try:
            with open(prof, encoding='utf-8', errors='replace') as f:
                if DOWNLOAD_CODE.search(f.read(200000)):
                    add(F('tricks', 'psprofile:' + prof, 'high', 'Your PowerShell profile downloads or decodes code', 'This script runs every time PowerShell starts.', 'A favourite spot for hiding a persistent script.', prof, 'Open and review it.', A('quarantine', 'Move to quarantine', f'Move this profile to quarantine?\n\n{prof}', path=prof) if not S.in_windows(prof) else None, Path=prof))
        except OSError:
            pass
    drivers = [r for r in as_list(d.get('drivers')) if isinstance(r, dict)]
    fix_path = lambda p: os.path.expandvars(re.sub(r'^\\\?\?\\', '', re.sub(r'^\\SystemRoot', lambda _m: S.WINDIR, str(p), flags=re.I)))
    foreign = [(r['Name'], fix_path(r['Path'])) for r in drivers if r.get('Path') and not S.in_windows(fix_path(r['Path']))]
    signs = S.sign_info([p for _n, p in foreign if os.path.isfile(p)])
    for n, p in foreign:
        if S.USER_WRITABLE.search(p) or S.APPDATA_RE.search(p):
            add(F('tricks', 'drv:' + n, 'critical', f'Kernel driver running from a personal folder: {n}', 'Drivers have the highest possible privilege.', 'Real drivers live in the Windows folder. This location is what vulnerable-driver attacks look like.', p, 'Have the PC checked.', Active=True))
        elif S.is_unsigned(signs.get(p, {})):
            add(F('tricks', 'drv:' + n, 'high', f'Unsigned kernel driver running: {n}', 'Nothing proves who made this driver.', 'Rootkits are drivers.', p, 'Have it investigated.', Active=True))
    for s in as_list(d.get('svcdll')):
        if isinstance(s, dict) and (S.USER_WRITABLE.search(os.path.expandvars(str(s.get('Dll')))) or S.APPDATA_RE.search(str(s.get('Dll')))):
            add(F('tricks', 'svcdll:' + str(s.get('Name')), 'critical', f"Service DLL in a personal folder: {s.get('Name')}", 'Windows services load DLLs with full privileges.', 'Real services keep them in the Windows folder.', s.get('Dll'), 'Disable that service in the Services tab.', Active=True))
    for b in as_list(d.get('bits')):
        if isinstance(b, dict) and b.get('Cmd'):
            add(F('tricks', 'bits:' + str(b.get('Name')), 'high', f"Download job runs a command: {b.get('Name')}", 'Windows\' background download service can start a program when a transfer ends.', 'Malware uses this to survive restarts.', b.get('Cmd'), 'In PowerShell: Get-BitsTransfer | Remove-BitsTransfer, if you do not recognise it.'))
    for ip in as_list(d.get('dns')):
        try:
            if ipaddress.ip_address(str(ip)).is_global and str(ip) not in GOOD_DNS:
                add(F('tricks', 'dns:' + str(ip), 'low', f'DNS server: {ip}', 'DNS turns site names into addresses. This server is on the internet, and is not one of the big public services.', 'Usually your internet provider\'s. A malicious one can send you to fake sites.', str(ip), 'If it isn\'t your provider\'s, change it. Look it up at the link.', Link=f'https://www.abuseipdb.com/check/{ip}'))
        except ValueError:
            pass
    checks = []
    for cname, prefixes in _TRICK_CHECKS:
        titles = list(dict.fromkeys(f['Title'] for f in out if any(f['Id'].startswith('tricks:' + p) for p in prefixes)))
        checks.append({'Name': cname, 'Ok': not titles, 'Detail': '; '.join(titles)})
    n_ok = sum(1 for c in checks if c['Ok'])
    add(F('tricks', 'clean', 'ok', f'Hacker-tricks check: {n_ok} of {len(checks)} hiding places are clear', f'Checked {_TRICK_COUNT} places that attackers use to hide or survive a restart, alongside the checks in the Malware and Services tabs. Nothing was changed.', Checks=checks))
    return out


# ---------------------------------------------------------------- lateral movement

LATERAL_PS = r'''
function Ev($log, $ids, $days, $max) { try { @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $ids; StartTime = (Get-Date).AddDays(-$days) } -MaxEvents $max -ErrorAction Stop) } catch { @() } }
function D($e) { $d = @{}; foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }; $d }
$dg = $null; try { $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop } catch {}
$fwNames = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Where-Object { $_.Name -match '^(WMI-|RemoteSvcAdmin|RemoteTask|RemoteEventLogSvc|WINRM-HTTP-In|Wininit-Shutdown|PerfLogsAlerts)' } | ForEach-Object { [pscustomobject]@{ Id = [string]$_.Name; Name = [string]$_.DisplayName } })
$out = @{ cg = $(if ($dg) { @($dg.SecurityServicesRunning) -contains 1 } else { $null }); fw = $fwNames; shares = @(Get-CimInstance Win32_Share | Where-Object { $_.Name -match '^(ADMIN|[A-Z])\$$' } | ForEach-Object { [string]$_.Name }); adminLogs = $false }
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  $out.adminLogs = $true
  $out.explicit = @(foreach ($e in (Ev 'Security' 4648 7 400)) { $d = D $e; if ($d['TargetServerName'] -notin 'localhost','-','',$env:COMPUTERNAME) { [pscustomobject]@{ When = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); User = $d['TargetUserName']; Server = $d['TargetServerName']; Proc = $d['ProcessName'] } } })
  $out.ntlm = @(foreach ($e in (Ev 'Security' 4624 7 2500)) { $d = D $e; if ($d['LogonType'] -eq '3' -and $d['AuthenticationPackageName'] -eq 'NTLM' -and $d['IpAddress'] -notin '-','::1','127.0.0.1','') { [pscustomobject]@{ When = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); User = $d['TargetUserName']; Ip = $d['IpAddress'] } } })
  $out.sessions = @(Get-SmbSession | ForEach-Object { [pscustomobject]@{ Client = [string]$_.ClientComputerName; User = [string]$_.ClientUserName; Files = [int]$_.NumOpens } })
  $out.winrm = @(Ev 'Microsoft-Windows-WinRM/Operational' 91 7 50 | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') })
}
ConvertTo-Json -InputObject $out -Depth 4 -Compress
'''
LATERAL_PORTS = {445: 'file sharing', 135: 'remote procedure calls', 3389: 'Remote Desktop', 5985: 'Windows Remote Management', 5986: 'Windows Remote Management', 22: 'SSH'}
PSEXEC_NAMES = re.compile(r'^(psexesvc|paexec|csexec|remcomsvc|winexesvc|smbexec)', re.I)
_live = []


def scan_lateral(ctx):
    d, out = ps_one(LATERAL_PS, timeout=120), []
    add, admin = out.append, ctx['admin']
    names = {p: n[0] for p, n in S.process_snapshot().items()}
    moves, comes = {}, {}
    for st, addr, port, ra, rp, pid in S.tcp_rows():
        if st != 5 or not _private(ra) or ra.startswith('127.') or ra == '::1':
            continue
        if rp in LATERAL_PORTS and pid > 4:
            moves.setdefault((names.get(pid, f'PID {pid}'), ra, rp), pid)
        elif port in LATERAL_PORTS:
            comes.setdefault((ra, port), names.get(pid, f'PID {pid}'))
    for (app, ra, rp), pid in moves.items():
        add(F('lateral', f'out:{app}:{ra}:{rp}', 'low' if rp == 22 else 'medium', f'{app} is connected to {ra} over {LATERAL_PORTS[rp]}', 'This PC is talking to another device on your network, on a port used to control other computers.', 'Normal for a file share, or a tool you are using. If you do not recognise it, this is what an intruder spreading from this PC looks like.', f'Process ID {pid}', 'If you did not start this, end it from the Processes tab.'))
    for (ra, port), app in comes.items():
        add(F('lateral', f'in:{ra}:{port}', 'high' if port in (135, 5985, 5986) else 'medium', f'{ra} is connected to this PC over {LATERAL_PORTS[port]}', 'Another device on your network is connected to this PC right now.', 'Fine if it is yours. If not, someone may already be moving through your network.', f'Handled by {app}', 'If you do not recognise this device, disconnect the PC from the network.', A('block_ip', 'Block address', f'Block {ra} in Windows Firewall?', ip=ra), Active=port in (135, 5985, 5986)))
    if d.get('cg') is False:
        add(F('lateral', 'credguard', 'medium', 'Credential Guard is off', 'Credential Guard keeps sign-in secrets in a protected area that even administrators can\'t read.', 'Without it, an attacker with admin rights can lift password hashes and reuse them on your other PCs. This is how a single infected PC becomes the whole network.', fix='Turn on Memory integrity under Core isolation. Credential Guard itself needs Windows Pro or Enterprise, and is set in Group Policy.', action=A('open_settings', 'Open Core isolation', 'Open Core isolation?', page='windowsdefender://coreisolation')))
    srv, wks = r'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', r'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    shares = [str(x) for x in as_list(d.get('shares'))]
    if shares and reg_get(HKLM, srv, 'AutoShareWks', 1) != 0:
        add(F('lateral', 'adminshares', 'medium', f"Hidden admin shares are on: {', '.join(shares)}", 'Windows quietly shares every drive with administrators.', 'A single stolen admin password lets an attacker copy tools here and run them remotely. Almost all network worms and ransomware use these.', ', '.join(shares), 'Turn them off if nothing manages this PC remotely. On a work PC, ask IT first, since their tools may rely on them.', A('set_reg', 'Turn off', 'Stop Windows creating hidden admin shares?\n\nA restart is needed. Remote management tools, including ones your workplace uses, may stop working.', hive='HKLM', path=srv, name='AutoShareWks', value=0, kind='dword', reboot=True)))
    if reg_get(HKLM, wks, 'RequireSecuritySignature', 0) != 1:
        add(F('lateral', 'smbclient-sign', 'medium', 'This PC does not insist on signed file sharing when connecting out', 'Signing proves that file-sharing traffic has not been tampered with.', 'Without it, a device on your network can intercept your connection and relay your identity to another PC.', fix='Require it. Very old NAS devices may stop connecting.', action=A('set_reg', 'Require signing', 'Require signing when this PC connects to file shares?\n\nVery old NAS devices may stop connecting.', hive='HKLM', path=wks, name='RequireSecuritySignature', value=1, kind='dword')))
    fw = [r for r in as_list(d.get('fw')) if isinstance(r, dict)]
    if fw:
        add(F('lateral', 'remote-admin-fw', 'high', f'{len(fw)} firewall openings for remote administration', 'Windows Firewall lets other computers manage this PC through WMI, remote services, scheduled tasks, or Remote Management.', 'These are the exact doors used to run commands on another PC. Home PCs do not need them.', '\n'.join(str(r.get('Name')) for r in fw[:12]), 'Close them. On a work PC, ask IT first.', A('disable_fw_rules', 'Close them', f'Turn off these {len(fw)} firewall rules?\n\nRemote management tools may stop working. You can undo this in the Blocked tab.', names=[r.get('Id') for r in fw], what='Remote administration rules'), Fixes='lateral'))
    psx = [s for s in reg_subkeys(HKLM, r'SYSTEM\CurrentControlSet\Services') if PSEXEC_NAMES.match(s)]
    psx_files = [p for p in glob.glob(os.path.join(S.WINDIR, '*.exe')) if PSEXEC_NAMES.match(os.path.basename(p))]
    for s in psx:
        add(F('lateral', 'psexec:' + s, 'critical', f'Remote-execution tool is installed as a service: {s}', 'PsExec-style tools copy a small service to a target PC to run commands on it.', 'Intruders use this to spread. IT staff do too.', s, 'If nobody in IT did this, disable the service, and treat the PC as compromised.', A('disable_service', 'Disable', f'Disable the service {s}?', name=s, display=s), Active=True))
    for p in psx_files:
        add(F('lateral', 'psexecfile:' + p, 'high', f'Leftovers from a remote-execution tool: {os.path.basename(p)}', 'Left behind when this PC was controlled from another computer.', 'Means someone ran commands here from elsewhere.', p, 'If you do not know who did that, have the PC checked.', Active=True))
    for s, label in (('RemoteRegistry', 'Remote Registry'), ('WinRM', 'Windows Remote Management')):
        k = rf'SYSTEM\CurrentControlSet\Services\{s}'
        if reg_get(HKLM, k, 'Start', 4) in (0, 1, 2):
            add(F('lateral', 'svc:' + s, 'high', f'{label} starts automatically', f'{label} lets other computers read or control this PC.', 'Used by attackers moving between PCs.', fix='Turn it off unless your workplace needs it.', action=A('disable_service', 'Disable', f'Disable {label}?', name=s, display=label)))
    servers = reg_subkeys(HKCU, r'Software\Microsoft\Terminal Server Client\Servers')
    if servers:
        add(F('lateral', 'rdp-history', 'low', f'This PC remembers {len(servers)} Remote Desktop targets', 'Windows keeps the addresses you connected to.', 'An attacker reads this list to find the next computer to attack.', ', '.join(servers[:10]), 'Clear the ones you no longer use in the Remote Desktop app.'))
    ssh = os.path.join(os.environ.get('USERPROFILE', ''), '.ssh')
    for key in sorted(glob.glob(os.path.join(glob.escape(ssh), 'id_*'))):
        if key.endswith('.pub'):
            continue
        try:
            with open(key, 'rb') as f:
                text = f.read(8192)
            body = b''.join(x for x in text.splitlines() if not x.startswith(b'-----'))
            bare = b'ENCRYPTED' not in text and b'bcrypt' not in base64.b64decode(body + b'===', validate=False)[:64]
        except (OSError, ValueError):
            continue
        if bare:
            add(F('lateral', 'sshkey:' + key, 'medium', f'SSH key has no passphrase: {os.path.basename(key)}', 'This key signs you in to other servers.', 'Anything running as you can copy it and sign in wherever it is accepted, with no password.', key, f'Add a passphrase with: ssh-keygen -p -f "{key}"'))
    if d.get('adminLogs'):
        grp = {}
        for e in as_list(d.get('ntlm')):
            if isinstance(e, dict):
                grp.setdefault((e.get('Ip'), e.get('User')), []).append(e.get('When'))
        for (ip, user), whens in sorted(grp.items(), key=lambda kv: -len(kv[1]))[:12]:
            if not str(user).endswith('$'):
                add(F('lateral', f'ntlm:{ip}:{user}', 'medium', f'{user} signed in from {ip} over NTLM', 'A network sign-in using the older NTLM method happened in the last 7 days.', 'Stolen hashes work only with NTLM, so unexpected entries are a strong signal.', f'{len(whens)} times. Last: {whens[0]}', 'If you do not recognise this device, change that password.'))
        grp = {}
        for e in as_list(d.get('explicit')):
            if isinstance(e, dict):
                grp.setdefault((e.get('Server'), e.get('User'), e.get('Proc')), []).append(e.get('When'))
        for (srv_name, user, proc), whens in list(grp.items())[:12]:
            add(F('lateral', f'expl:{srv_name}:{user}', 'medium', f'{user}\'s password was used against {srv_name}', 'A program on this PC used specific credentials to reach another computer.', 'How attackers use stolen passwords. Normal for some admin tools.', f'Program: {proc}\n{len(whens)} times. Last: {whens[0]}', 'If you do not recognise it, change that password.'))
        for s in as_list(d.get('sessions')):
            if isinstance(s, dict):
                add(F('lateral', 'smb:' + str(s.get('Client')), 'info', f"File-sharing session from {s.get('Client')}", f"{s.get('User')} has {s.get('Files')} files open.", 'Check that you recognise this device.'))
        if d.get('winrm'):
            add(F('lateral', 'winrm-use', 'high', f"Remote commands ran on this PC ({len(as_list(d.get('winrm')))} in 7 days)", 'Windows Remote Management logged incoming sessions.', 'If nobody manages this PC remotely, someone else ran commands here.', f"Last: {as_list(d.get('winrm'))[0]}", 'If this was not you or IT, disconnect and investigate.', Active=True))
    else:
        add(need_admin('lateral', 'The Security log (who signed in from where) and open file-sharing sessions'))
    out.extend(_live)
    if not [x for x in out if x['Sev'] in ('critical', 'high')]:
        add(F('lateral', 'clean', 'ok', 'No sign of anyone moving between PCs', 'Checked live connections, remote-execution tools and the usual remote-control doors.'))
    return out


# the live watcher sees these on every new process
LATERAL_RULES = [
    (r'psexec(64)?(\.exe)?["\s].*\\\\', 'high', 'Running a program on another PC (PsExec)', 'Used by IT staff, and by intruders spreading across a network.'),
    (r'\b(paexec|csexec|remcom)\b', 'high', 'Remote-execution tool', 'Copies itself to another PC and runs commands there.'),
    (r'wmic(\.exe)?["\s].*/node:', 'high', 'Controlling another PC (WMI)', 'Runs commands on a remote computer.'),
    (r'winrs(\.exe)?["\s].*-r(emote)?:', 'high', 'Controlling another PC (WinRS)', 'Runs commands on a remote computer.'),
    (r'(invoke-command|enter-pssession|new-pssession)\b.*-computername', 'high', 'PowerShell session to another PC', 'Runs commands on a remote computer.'),
    (r'\bsc(\.exe)?["\s]+\\\\\S+\s+(create|config|start)', 'high', 'Creating a service on another PC', 'A standard way of spreading across a network.'),
    (r'schtasks.*/s\s+\S+.*/create', 'high', 'Creating a scheduled task on another PC', 'A standard way of spreading across a network.'),
    (r'(net1?(\.exe)?["\s]+use|copy|xcopy|robocopy)\b.*\\\\\S+\\(admin|[a-z])\$', 'high', 'Reaching another PC\'s hidden admin share', 'This is how tools get copied to the next victim.'),
    (r'runas(\.exe)?["\s].*/netonly', 'medium', 'Using other credentials for network access', 'Fine for admins. Attackers use this with stolen passwords.'),
    (r'\[adsisearcher\]|new-object\s+system\.directoryservices\.directorysearcher', 'low', 'Quiet Active Directory search', 'Looking accounts and groups up straight through LDAP skips the usual tools and leaves fewer traces. Administrators do this too, but it is also how an intruder maps a domain without being noticed.'),
    (r'\b(get-net(user|group|computer|domain|session|loggedon|localgroup)|get-domain(user|group|computer|controller|policy|trust)|get-objectacl|invoke-userhunter|find-localadminaccess|invoke-(blood|sharp)hound)\b', 'high', 'Active Directory attack-mapping tool', 'These PowerView and BloodHound commands map a Windows domain to find a path to Domain Admin.'),
    (r'nltest\s+/(domain_trusts|dclist|dsgetdc)|dsquery\s+\*|net1?(\.exe)?\s+group\s+"?domain admins"?\s+/domain', 'medium', 'Mapping the Windows domain', 'Listing domain trusts, domain controllers or the Domain Admins group is a common early step for an intruder. Administrators run these too.'),
    (r'reg(\.exe)?\s+add.*\\(ms-settings|mscfile|exefile)\\shell\\open\\command', 'critical', 'Planting an admin prompt bypass', 'This registry change makes Windows run a program as administrator without asking.'),
    (r'(cmd|powershell|pwsh).*\b(fodhelper|computerdefaults|sdclt|wsreset)(\.exe)?\b', 'high', 'Possible admin prompt bypass', 'These Windows programs raise their own rights, and are abused to skip the prompt.'),
    (r'\b(juicypotato|printspoofer|godpotato|roguepotato|sweetpotato|rubeus|sharpup|winpeas|powerup\.ps1|seatbelt|bloodhound|sharphound|crackmapexec|netexec|impacket|wmiexec|smbexec|atexec|lazagne)\b', 'critical', 'Known attack tool', 'This name belongs to a tool for stealing credentials, raising privileges or spreading.'),
    (r'ntdsutil.*ifm|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)\b', 'critical', 'Copying the Windows password database', 'Copies hashes so that they can be cracked or reused elsewhere.'),
    (r'net1?(\.exe)?["\s]+localgroup\s+"?(remote desktop users|backup operators)"?\s+\S+\s+/add', 'high', 'Adding an account to a powerful group', 'Grants remote access or admin-level file access.'),
]
S.COMMAND_RULES.extend((re.compile(p, re.I | re.S), s, t, w) for p, s, t, w in LATERAL_RULES)


# ---------------------------------------------------------------- live escalation guard

ADMINS_PS = "$g = Get-LocalGroup -SID 'S-1-5-32-544'; $m = @(); try { $m = @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Sid = [string]$_.SID.Value } }) } catch {}; ConvertTo-Json -InputObject @{ ok = ($m.Count -gt 0); me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; m = @($m) } -Compress"


def privilege_state():
    """Who is an administrator and which services exist. None if Windows didn't answer, so a failed read never looks like a change."""
    d = ps_one(ADMINS_PS, timeout=30)
    if not d.get('ok'):
        return None
    svc_root = r'SYSTEM\CurrentControlSet\Services'
    services = {}
    for n in reg_subkeys(HKLM, svc_root):
        img = reg_get(HKLM, svc_root + '\\' + n, 'ImagePath', None)
        if img and reg_get(HKLM, svc_root + '\\' + n, 'Type', 0) in (16, 32, 80, 96):
            services[n] = str(img)
    return {'admins': {m['Sid']: m['Name'] for m in as_list(d.get('m')) if isinstance(m, dict)}, 'me': d.get('me'), 'services': services}


def new_admin_finding(sid, name):
    f = F('lateral', f'live-admin:{sid}', 'critical', f'New administrator while My Security was watching: {name}', 'This account just gained full control of the PC.', 'Giving themselves admin rights is what intruders do right after getting in. If you or an installer did not do this, act now.', f'{name}\n{sid}\nSeen at {dt.datetime.now():%Y-%m-%d %H:%M}', 'Remove its admin rights.', A('remove_admin', 'Remove admin rights', f'Remove administrator rights from {name}?', member=name), Active=True, Live=True)
    _live.append(f)
    return f


def new_service_finding(name, image):
    bad = S.USER_WRITABLE.search(os.path.expandvars(image)) or re.search(S.LOLBINS, image, re.I) or S.APPDATA_RE.search(image) or PSEXEC_NAMES.match(name)
    if not bad:
        return None
    f = F('lateral', f'live-svc:{name}', 'critical', f'Suspicious new service while My Security was watching: {name}', 'A new service appeared, and it starts from a personal folder or a script tool.', 'Services run with full privileges. This is how attackers go from a normal account to total control.', image, 'Disable it unless you just installed something that explains it.', A('disable_service', 'Disable', f'Disable the service {name}?\n\n{image}', name=name, display=name), Active=True, Live=True)
    _live.append(f)
    return f


# ---------------------------------------------------------------- pentest: from the inside

PRIVESC_PS = r'''
$open = 'S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4'
$mask = [long]0x000C0002 -bor [long]0x10000000 -bor [long]0x40000000
function Writable($p) {
  try { $a = Get-Acl -LiteralPath $p -ErrorAction Stop } catch { return '' }
  foreach ($r in $a.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -eq 'Allow' -and $open -contains $r.IdentityReference.Value -and ([long]$r.FileSystemRights -band $mask) -and -not ($r.PropagationFlags -band 2)) { return $r.IdentityReference.Translate([Security.Principal.NTAccount]).Value }
  }; ''
}
function WritableReg($p) {
  try { $a = Get-Acl -LiteralPath $p -ErrorAction Stop } catch { return '' }
  foreach ($r in $a.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -eq 'Allow' -and $open -contains $r.IdentityReference.Value -and ([long]$r.RegistryRights -band $mask) -and -not ($r.PropagationFlags -band 2)) { return $r.IdentityReference.Translate([Security.Principal.NTAccount]).Value }
  }; ''
}
function ExeOf($c) { $c = [Environment]::ExpandEnvironmentVariables([string]$c).Trim(); if ($c -match '^"([^"]+)"') { $Matches[1] } elseif ($c -match '^(.+?\.(exe|bat|cmd|ps1|dll))(\s|$)') { $Matches[1] } else { ($c -split ' ')[0] } }
$hits = New-Object Collections.ArrayList
function Check($kind, $name, $path, $run) { if (-not $path -or $path.StartsWith($env:windir, 'OrdinalIgnoreCase')) { return }
  if (Test-Path -LiteralPath $path -PathType Leaf) { $w = Writable $path; if ($w) { [void]$hits.Add([pscustomobject]@{ Kind = $kind; Name = $name; Path = $path; Who = $w; Run = $run; What = 'file' }) }
    $dir = Split-Path -LiteralPath $path; $w = Writable $dir; if ($w) { [void]$hits.Add([pscustomobject]@{ Kind = $kind; Name = $name; Path = $dir; Who = $w; Run = $run; What = 'folder' }) } }
  elseif ($path -match '\\') { $dir = Split-Path -LiteralPath $path; if (Test-Path -LiteralPath $dir -PathType Container) { $w = Writable $dir; if ($w) { [void]$hits.Add([pscustomobject]@{ Kind = $kind; Name = $name; Path = $path; Who = $w; Run = $run; What = 'missing' }) } } } }
$weak = New-Object Collections.ArrayList
foreach ($s in Get-CimInstance Win32_Service) { $e = ExeOf $s.PathName; Check 'service' ([string]$s.Name) $e ([string]$s.StartName)
  $via = ''
  try { if (WritableReg "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)") { $via = 'registry' } } catch {}
  if (-not $via -and $e -and -not $e.StartsWith($env:windir, 'OrdinalIgnoreCase')) { $sd = (& "$env:windir\System32\sc.exe" sdshow $s.Name) -join ''
    if ($sd -match '\(A;[^;]*;[A-Z]*(DC|WD|WO|GA|FA)[A-Z]*;;;(WD|AU|BU|IU)\)') { $via = 'permissions' } }
  if ($via) { [void]$weak.Add([pscustomobject]@{ Name = [string]$s.Name; Display = [string]$s.DisplayName; Run = [string]$s.StartName; Via = $via }) } }
foreach ($t in Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.Principal.UserId -match 'SYSTEM|S-1-5-18' }) { foreach ($a in @($t.Actions)) { if ($a.Execute) { Check 'task' ([string]($t.TaskPath + $t.TaskName)) (ExeOf $a.Execute) 'SYSTEM' } } }
$path = New-Object Collections.ArrayList
foreach ($d in ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';')) { $d = [Environment]::ExpandEnvironmentVariables($d).Trim().TrimEnd('\'); if ($d -and -not $d.StartsWith($env:windir, 'OrdinalIgnoreCase') -and (Test-Path -LiteralPath $d)) { $w = Writable $d; if ($w) { [void]$path.Add([pscustomobject]@{ Path = $d; Who = $w }) } } }
$sam = ''; try { foreach ($r in (Get-Acl -LiteralPath "$env:windir\System32\config\SAM" -ErrorAction Stop).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) { if ($r.IdentityReference.Value -eq 'S-1-5-32-545' -and $r.AccessControlType -eq 'Allow') { $sam = 'yes' } } } catch {}
ConvertTo-Json -InputObject @{ ok = $true; hits = @($hits); weak = @($weak); path = @($path); sam = $sam; spooler = [string](Get-Service Spooler).Status } -Depth 3 -Compress
'''
ESCALATION_PRIVS = {'SeImpersonatePrivilege': 'impersonate other accounts', 'SeDebugPrivilege': 'read and control any program', 'SeBackupPrivilege': 'read every file', 'SeRestorePrivilege': 'overwrite every file', 'SeTakeOwnershipPrivilege': 'take over any file', 'SeLoadDriverPrivilege': 'load kernel drivers', 'SeTcbPrivilege': 'act as part of Windows', 'SeCreateTokenPrivilege': 'forge sign-in tokens', 'SeAssignPrimaryTokenPrivilege': 'start programs as another account', 'SeManageVolumePrivilege': 'read raw disk volumes and bypass file permissions'}
UNATTEND = [r'Panther\Unattend.xml', r'Panther\Unattend\Unattend.xml', r'Panther\Unattended.xml', r'System32\Sysprep\sysprep.xml', r'System32\Sysprep\Unattend.xml', r'System32\Sysprep\Panther\Unattend.xml']
SECRET_LINE = re.compile(r'(-password\b|-credential\b.*-asplaintext|converto-securestring.*-asplaintext|\bpassword\s*=|\bpasswd\b|api[_-]?key|net\s+use\s.*/user:|authorization:\s*bearer|\btoken\s*=|cmdkey\s+/add)', re.I)
_TEST_NAMES = ['Always-elevated installers', 'Writable service files', 'Writable SYSTEM task files', 'Weak service permissions', 'Writable system PATH folders', 'Password database permissions', 'Dangerous account privileges', 'Answer files with passwords', 'Passwords in command history', 'Saved Windows credentials', 'Print driver settings', 'What your network can reach']
# the finding-id prefixes each test produces when it fails, so the checklist can show what needs fixing
_CHECK_IDS = [['aie'], ['write:service:'], ['write:task:'], ['svcperm:'], ['path:'], ['hive'], ['privs'], ['unattend:'], ['pshist'], ['cmdkey'], ['printnightmare'], ['lan-view']]


def scan_pentest(ctx):
    d, out = ps_one(PRIVESC_PS, timeout=150), []
    add, ok_tests = out.append, []
    if not d.get('ok'):
        return [F('pentest', 'failed', 'info', 'The inside test could not finish', 'Windows did not answer.', fix='Run the scan again.')]
    inst = r'SOFTWARE\Policies\Microsoft\Windows\Installer'
    if reg_get(HKLM, inst, 'AlwaysInstallElevated', 0) == 1 and reg_get(HKCU, inst, 'AlwaysInstallElevated', 0) == 1:
        add(F('pentest', 'aie', 'critical', 'Any user can run installers as SYSTEM', 'AlwaysInstallElevated is on for both the PC and this user.', 'A standard user, or malware, can instantly become SYSTEM with one small .msi file.', fix='Turn it off.', action=A('set_regs', 'Turn off', 'Turn off AlwaysInstallElevated?', items=[dict(hive='HKLM', path=inst, name='AlwaysInstallElevated', value=0, kind='dword'), dict(hive='HKCU', path=inst, name='AlwaysInstallElevated', value=0, kind='dword')]), Active=True))
    else:
        ok_tests.append(_TEST_NAMES[0])
    hits = [h for h in as_list(d.get('hits')) if isinstance(h, dict)]
    system_run = re.compile(r'(localsystem|system|^$)', re.I)
    for h in hits:
        sys_ = bool(system_run.search(str(h.get('Run') or '')))
        kind, what, who, run, path = h.get('Kind'), h.get('What'), h.get('Who'), h.get('Run') or 'SYSTEM', h.get('Path')
        if what == 'missing':
            folder = os.path.dirname(str(path))
            add(F('pentest', f"write:{kind}:{h.get('Name')}:missing", 'critical' if sys_ else 'high', f"{str(kind).capitalize()} {h.get('Name')} looks for a file that is not there, and a standard user can supply it", f"It runs as {run}, the file {path} does not exist, and {who} can create it in that folder.", 'Create the missing program or DLL there and it loads with full control at the next start. This is a "phantom DLL" hijack.', path, 'Remove write access to that folder for normal users, or reinstall the software so the file is present.', A('lock_path', 'Lock the folder', f"Remove write access for normal users?\n\n{folder}\n\nYou can undo this in the Blocked tab.", path=folder), Active=sys_))
        else:
            word = 'program file' if what == 'file' else 'folder'
            add(F('pentest', f"write:{kind}:{h.get('Name')}:{what}", 'critical' if sys_ and what == 'file' else 'high', f"Standard users can change the {word} of {kind} {h.get('Name')}", f"It runs as {run}, and {who} can write to it.", ('Replace the program and it runs with full control at the next start.' if what == 'file' else 'Drop a DLL next to the program and it loads with full control at the next start.') + ' Privilege escalation in one step.', path, 'Remove write access for normal users.', A('lock_path', 'Lock it down', f"Remove write access for normal users?\n\n{path}\n\nYou can undo this in the Blocked tab.", path=path), Active=sys_))
    ok_tests.extend(t for t, used in ((_TEST_NAMES[1], any(h.get('Kind') == 'service' for h in hits)), (_TEST_NAMES[2], any(h.get('Kind') == 'task' for h in hits))) if not used)
    weak = [w for w in as_list(d.get('weak')) if isinstance(w, dict)]
    for w in weak:
        how = 'Its registry key can be edited by standard users.' if w.get('Via') == 'registry' else 'Its security settings let standard users change what it runs.'
        add(F('pentest', 'svcperm:' + str(w.get('Name')), 'critical', f"Standard users can reconfigure the service {w.get('Display')}", f"It runs as {w.get('Run')}. {how}", 'Point the service at any program, restart it, and that program runs with full control.', w.get('Name'), 'Reinstall or update the software, and report it to its maker. Its permissions are wrong.', Active=True))
    if not weak:
        ok_tests.append(_TEST_NAMES[3])
    paths = [p for p in as_list(d.get('path')) if isinstance(p, dict)]
    for p in paths:
        add(F('pentest', 'path:' + str(p.get('Path')), 'high', f"Standard users can write to a system PATH folder", f"{p.get('Who')} can add files here.", 'Windows services search these folders for DLLs. A planted DLL gets loaded with full control.', p.get('Path'), 'Remove write access for normal users.', A('lock_path', 'Lock it down', f"Remove write access for normal users?\n\n{p.get('Path')}\n\nYou can undo this in the Blocked tab.", path=p.get('Path'))))
    if not paths:
        ok_tests.append(_TEST_NAMES[4])
    if d.get('sam'):
        add(F('pentest', 'hive', 'critical', 'Standard users can read the Windows password database', 'The SAM file\'s permissions are wrong. This is the "HiveNightmare" flaw.', 'With a shadow copy, any user can extract every local password hash.', 'BUILTIN\\Users has read access to config\\SAM', 'Run in an administrator prompt: icacls %windir%\\system32\\config\\*.* /inheritance:e, then delete old shadow copies.', Active=True))
    else:
        ok_tests.append(_TEST_NAMES[5])
    privs = {}
    for row in re.findall(r'"(Se\w+)","[^"]*","([^"]*)"', _run(os.path.join(S.SYSTEM32, 'whoami.exe'), '/priv', '/fo', 'csv')):
        privs[row[0]] = row[1]
    risky = sorted(p for p in privs if p in ESCALATION_PRIVS)
    if risky and not ctx['admin'] and any(p != 'SeImpersonatePrivilege' or True for p in risky):
        add(F('pentest', 'privs', 'high', f"This session holds powerful privileges: {', '.join(risky)}", 'Without being an administrator, this account can ' + '; '.join(ESCALATION_PRIVS[p] for p in risky) + '.', 'Attackers turn each of these into full control.', fix='Remove the account from whichever group gave it these rights.', Active=True))
    else:
        ok_tests.append(_TEST_NAMES[6])
    found = []
    for rel in UNATTEND:
        p = os.path.join(S.WINDIR, rel)
        try:
            with open(p, encoding='utf-8', errors='replace') as f:
                if re.search(r'<(?:Administrator)?Password>\s*<Value>\s*[^<\s]', f.read(2000000), re.I):
                    found.append(p)
        except OSError:
            pass
    for p in found:
        add(F('pentest', 'unattend:' + p, 'high', 'A Windows setup file contains an account password', 'It was left over from automated installation. The value is only lightly encoded.', 'Anyone able to read it gets an admin password.', p, 'Delete the file and change that password.'))
    if not found:
        ok_tests.append(_TEST_NAMES[7])
    hist = os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
    n = 0
    try:
        with open(hist, encoding='utf-8', errors='replace') as f:
            n = sum(1 for line in f if SECRET_LINE.search(line))
    except OSError:
        pass
    if n:
        add(F('pentest', 'pshist', 'high', f'PowerShell history has {n} lines that look like passwords or keys', 'PowerShell saves everything typed into a plain text file. My Security counted the lines, and did not read out or store them.', 'Standard post-compromise step: read the history and get passwords for free.', hist, 'Change those passwords, then clear the history.', A('quarantine', 'Move to quarantine', f'Move your PowerShell history to quarantine?\n\n{hist}', path=hist), Path=hist))
    else:
        ok_tests.append(_TEST_NAMES[8])
    targets = sorted(set(re.findall(r':target=([^\r\n]+)', _run(os.path.join(S.SYSTEM32, 'cmdkey.exe'), '/list'))))
    targets = [t for t in targets if not t.startswith(('WindowsLive:', 'MicrosoftAccount:', 'MicrosoftOffice', 'OneDrive', 'XboxLive', 'msTeams', 'Adobe'))]
    if targets:
        add(F('pentest', 'cmdkey', 'low', f'{len(targets)} saved Windows sign-ins', 'Windows Credential Manager holds these. Only the names are shown.', 'Malware running as you can reuse them to reach those places without knowing the password.', '\n'.join(targets[:12]), 'Open Credential Manager and remove the Windows Credentials you no longer need.', A('open_settings', 'Open Credential Manager', 'Open Windows Credential Manager?', page='credmgr')))
    else:
        ok_tests.append(_TEST_NAMES[9])
    pp = r'SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    if d.get('spooler') == 'Running' and (reg_get(HKLM, pp, 'NoWarningNoElevationOnInstall', 0) == 1 or reg_get(HKLM, pp, 'RestrictDriverInstallationToAdministrators', 1) == 0):
        add(F('pentest', 'printnightmare', 'critical', 'Any user can install print drivers (PrintNightmare)', 'The Point and Print settings have the protection turned off.', 'Print drivers load as SYSTEM, so a standard user gets full control.', fix='Restore the restriction.', action=A('set_regs', 'Restore', 'Allow only administrators to install print drivers?', items=[dict(hive='HKLM', path=pp, name='RestrictDriverInstallationToAdministrators', value=1, kind='dword'), dict(hive='HKLM', path=pp, name='NoWarningNoElevationOnInstall', value=0, kind='dword')]), Active=True))
    else:
        ok_tests.append(_TEST_NAMES[10])
    ports = [f for f in S.scan_ports(ctx) if f.get('Exposed') and f.get('Allowed') and f['Sev'] != 'ok' and f.get('Proto') == 'TCP']
    if ports:
        lines = [f"TCP {f['Port']} {port_info(f['Port'])[0]}: {f.get('App')}" for f in sorted(ports, key=lambda f: f['Port'])]
        worst = 'high' if any(f['Sev'] in ('critical', 'high') for f in ports) else 'medium'
        add(F('pentest', 'lan-view', worst, f'An attacker on your network can reach {len(ports)} services here', 'These ports are open on your network addresses, and the firewall lets them through.', 'This is exactly what someone on your Wi-Fi would see.', '\n'.join(lines[:25]), 'Open the Ports tab, where each of these is explained and has its own Block button, and block anything you do not need.', Goto='ports'))
    else:
        ok_tests.append(_TEST_NAMES[11])
    # one status line per test: OK when closed, otherwise the heading(s) of the problem(s) it found
    checklist = []
    for i, name in enumerate(_TEST_NAMES):
        if name in ok_tests:
            checklist.append({'Name': name, 'Ok': True, 'Detail': ''})
        else:
            titles = []
            for f in out:
                if any(f['Id'].startswith('pentest:' + pre) for pre in _CHECK_IDS[i]) and f['Title'] not in titles:
                    titles.append(f['Title'])
            checklist.append({'Name': name, 'Ok': False, 'Detail': '; '.join(titles) or 'needs attention'})
    add(F('pentest', 'passed', 'ok', f'Inside test: {len(ok_tests)} of {len(_TEST_NAMES)} attack paths are closed', 'Each test checks whether a known route to more privileges is open. Nothing was exploited or changed. The full list is below.', Checks=checklist))
    return out


# ---------------------------------------------------------------- pentest: from the outside

NET_PS = r'''
$c = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1)
if ($c) { $i = $c[0]; ConvertTo-Json -InputObject @{ gw = [string]$i.IPv4DefaultGateway.NextHop; ip = [string]$i.IPv4Address.IPAddress; name = [string]$i.InterfaceAlias; cat = [string]$i.NetProfile.NetworkCategory
  v6 = @(Get-NetIPAddress -InterfaceIndex $i.InterfaceIndex -AddressFamily IPv6 -AddressState Preferred | Where-Object { $_.IPAddress -match '^[23]' -and $_.SuffixOrigin -ne 'Random' } | ForEach-Object { [string]$_.IPAddress }) } -Compress } else { '{}' }
'''
GATEWAY_PORTS = {21: ('FTP', 'high'), 22: ('SSH', 'info'), 23: ('Telnet', 'high'), 80: ('web admin page without encryption', 'low'), 443: ('web admin page', 'info'), 445: ('file sharing', 'medium'), 7547: ('ISP remote management (TR-069)', 'medium'), 8080: ('alternate web admin page', 'low')}
EXPOSED_BAD = {21: 'high', 23: 'critical', 135: 'critical', 139: 'critical', 445: 'critical', 3389: 'critical', 5900: 'critical', 5985: 'critical', 5986: 'critical', 1433: 'critical', 3306: 'critical', 5432: 'critical', 6379: 'critical', 27017: 'critical', 7547: 'high'}


def _http(url, body=None, headers=None, limit=300000):
    u = urllib.parse.urlparse(url)
    if u.scheme != 'http' or not u.hostname:
        return 0, ''
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=3)
    try:
        c.request('POST' if body else 'GET', u.path + ('?' + u.query if u.query else ''), body, headers or {})
        r = c.getresponse()
        return r.status, r.read(limit).decode('utf-8', 'replace')
    finally:
        c.close()


def upnp(gateway):
    """Ask the router, using its own protocol, which ports it forwards in from the internet."""
    result = {'found': False, 'maps': [], 'ext': ''}
    if not _private(gateway):
        return result
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.2)
    location = ''
    try:
        msg = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n'
        s.sendto(msg.encode('ascii'), ('239.255.255.250', 1900))
        end = time.time() + 2.5
        while time.time() < end and not location:
            data, src = s.recvfrom(4096)
            m = re.search(r'^location:\s*(\S+)', data.decode('ascii', 'replace'), re.I | re.M)
            if m and src[0] == gateway:   # only the gateway is believed, and only the gateway is contacted
                location = m.group(1)
    except OSError:
        pass
    finally:
        s.close()
    if not location or urllib.parse.urlparse(location).hostname != gateway:
        return result
    try:
        _, xml = _http(location)
        m = re.search(r'<serviceType>(urn:[^<]*WAN(?:IP|PPP)Connection:\d)</serviceType>.*?<controlURL>([^<]+)</controlURL>', xml, re.S)
        if not m:
            return result
        svc, ctrl = m.group(1), urllib.parse.urljoin(location, m.group(2))
        if urllib.parse.urlparse(ctrl).hostname != gateway:
            return result
        result['found'] = True

        def soap(action, inner=''):
            body = f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action} xmlns:u="{svc}">{inner}</u:{action}></s:Body></s:Envelope>'
            return _http(ctrl, body, {'Content-Type': 'text/xml; charset="utf-8"', 'SOAPAction': f'"{svc}#{action}"'})
        st, text = soap('GetExternalIPAddress')
        m = re.search(r'<NewExternalIPAddress>([^<]*)<', text)
        result['ext'] = m.group(1) if st == 200 and m else ''
        for i in range(64):
            st, text = soap('GetGenericPortMappingEntry', f'<NewPortMappingIndex>{i}</NewPortMappingIndex>')
            if st != 200:
                break
            result['maps'].append({k: (re.search(rf'<New{k}>([^<]*)<', text) or [None, ''])[1] for k in ('ExternalPort', 'Protocol', 'InternalPort', 'InternalClient', 'Enabled', 'PortMappingDescription', 'LeaseDuration')})
    except (OSError, http.client.HTTPException, ValueError):
        pass
    return result


def _open(host, port):
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return port
    except OSError:
        return None


def public_ip():
    try:
        with urllib.request.urlopen(urllib.request.Request('https://api.ipify.org', headers=UA), timeout=10) as r:
            ip = r.read(64).decode('ascii', 'replace').strip()
        return ip if ipaddress.ip_address(ip).is_global else ''
    except (OSError, ValueError):
        return ''


def internet_view(ip):
    """What Shodan's internet-wide scans have recorded for this address. Returns None if the service could not be reached."""
    try:
        with urllib.request.urlopen(urllib.request.Request(f'https://internetdb.shodan.io/{ip}', headers=UA), timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {'ports': [], 'vulns': [], 'tags': [], 'hostnames': []} if e.code == 404 else None
    except (OSError, ValueError):
        return None


def scan_outside(ctx):
    net, out = ps_one(NET_PS, timeout=30), []
    add = out.append
    gw, cat, mine = net.get('gw', ''), net.get('cat', ''), net.get('ip', '')
    if cat == 'Public':
        add(F('outside', 'cat', 'info', f"{net.get('name')} is set as a Public network", 'Good: Windows treats everyone on it as a stranger.', ''))
    elif cat == 'Private':
        add(F('outside', 'cat', 'low', f"{net.get('name')} is set as a Private network", 'Windows trusts devices on this network and allows more connections.', 'Fine at home. On any shared Wi-Fi, this exposes the PC to strangers.', fix='Choose Public in network settings if you do not control this network.', action=A('open_settings', 'Open Wi-Fi settings', 'Open network settings?', page='ms-settings:network-status')))
    if gw and _private(gw):
        with ThreadPoolExecutor(max_workers=8) as pool:
            ports = [p for p in pool.map(lambda p: _open(gw, p), GATEWAY_PORTS) if p]
        for p in ports:
            name, sev = GATEWAY_PORTS[p]
            if sev != 'info':
                add(F('outside', f'gw:{p}', sev, f'Your router has {name} open (port {p})', f'Router {gw} accepts connections on this port from inside your network.', 'Anyone on your Wi-Fi, or malware on any device, can try the router\'s password. Most routers still use the default one.', f'{gw}:{p}', 'Change the router\'s admin password, and turn this off in its settings.'))
        add(F('outside', 'gw-seen', 'info', f"Router {gw}: {len(ports)} common ports open", 'Only these eight common ports were tried on your router. No login was attempted, and no other device on the network was touched.', evidence=', '.join(f'{p} ({GATEWAY_PORTS[p][0]})' for p in ports)))
    u = upnp(gw) if gw else {'found': False, 'maps': []}
    if u['found']:
        for m in u['maps']:
            ext, client = int(m.get('ExternalPort') or 0), m.get('InternalClient')
            sev = EXPOSED_BAD.get(ext, 'high') if m.get('Enabled') != '0' else 'low'
            here = ' on this PC' if client == mine else f' on {client}'
            add(F('outside', f"map:{m.get('Protocol')}:{ext}", sev, f"Router forwards internet port {ext}/{m.get('Protocol')} to {client}", f"Anyone on the internet who connects to port {ext} is sent straight to a device on your network{here}.", 'Created automatically through UPnP, which means any program or malware on your network can open holes like this.', f"Description: {m.get('PortMappingDescription') or 'none'}\nInternal port: {m.get('InternalPort')}", 'Remove it in your router, and turn off UPnP if nothing needs it.', Active=sev == 'critical'))
        if not u['maps']:
            add(F('outside', 'upnp-on', 'low', 'UPnP is on at your router', 'Programs can ask the router to open ports to the internet by themselves. None are open now.', 'Malware can use this to make itself reachable.', fix='Turn off UPnP in the router, unless games or apps need it.'))
    else:
        add(F('outside', 'upnp-off', 'ok', 'Your router is not offering UPnP', 'Programs on your network can\'t automatically open ports to the internet.'))
    v6 = as_list(net.get('v6'))
    if v6:
        add(F('outside', 'ipv6', 'medium', 'This PC has a public IPv6 address', 'IPv6 usually has no router in between, so this PC can be reached directly from the internet.', 'Windows Firewall is then the only barrier. Any allowed port is open to the world, unless your router filters IPv6.', '\n'.join(map(str, v6[:3])), 'Keep the firewall on and check that your router blocks incoming IPv6.'))
    ip = public_ip()
    if not ip:
        add(F('outside', 'noip', 'info', 'The view from the internet could not be checked', 'Your public address could not be found.', fix='Check the internet connection and scan again.'))
        return out
    if ipaddress.ip_address(ip) in ipaddress.ip_network('100.64.0.0/10'):
        add(F('outside', 'cgnat', 'ok', 'Your provider shares your internet address', 'Your connection is behind carrier NAT, so strangers can\'t start connections to it.'))
    if u.get('ext') and _private(u['ext']):
        add(F('outside', 'double-nat', 'info', 'Your router is behind another router', f"The router's outside address is {u['ext']}, a private one. The real internet edge is the next device up.", 'Port forwards on this router do not reach the internet on their own.'))
    view = internet_view(ip)
    if view is None:
        add(F('outside', 'noview', 'info', 'The internet-scan database could not be reached', 'My Security asks Shodan what it has seen at your address.', fix='Scan again later.'))
        return out
    seen, vulns = sorted(int(p) for p in as_list(view.get('ports'))), sorted(as_list(view.get('vulns')))
    for p in seen:
        name, how, risk, _ = port_info(p)
        sev = EXPOSED_BAD.get(p, 'critical' if p in BACKDOOR_PORTS or p in REMOTE_CONTROL_PORTS else 'medium')
        add(F('outside', f'seen:{p}', sev, f'Visible from the internet: port {p} ({name})', how, risk or 'Anyone on the internet can try to connect.', f'Seen at {ip} by Shodan', 'Close this on your router. If it is your router\'s own service, turn off remote access in its settings.', Active=sev == 'critical'))
    if vulns:
        add(F('outside', 'vulns', 'high', f'{len(vulns)} published vulnerabilities are linked to your internet address', 'Shodan matched the software answering at your address with known flaws. This is usually your router or a device you forward to, and the match is by version only.', 'Attackers search this same data to choose targets.', ', '.join(vulns[:20]), 'Update the router\'s firmware, and close the ports listed here.', Active=True))
    if view.get('tags'):
        add(F('outside', 'tags', 'info', f"Shodan tags for your address: {', '.join(map(str, view['tags']))}", 'How the scanner classifies this address.', ''))
    if not seen and not vulns:
        add(F('outside', 'clean', 'ok', 'Nothing is visible from the internet', f'Shodan has no open ports on record for {ip}.', evidence='This is a record of past internet-wide scans, not a live attack. It can be some days old. If you are on a VPN, it describes the VPN and not your home connection.'))
    else:
        add(F('outside', 'how', 'info', 'How the outside test works', f'It uses your public address ({ip}), found with ipify, and asks Shodan what its internet-wide scans have recorded there, and your router what it forwards.', 'Shodan\'s records can be some days old. If you are on a VPN, they describe the VPN and not your home connection. A full live attack needs a machine outside your network.'))
    return out


# ---------------------------------------------------------------- browser extensions: known-bad list and code inspection

EXT_FEED = 'https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/Malicious-Extensions.csv'
EXT_ID = re.compile(r'\b[a-p]{32}\b')
# from vendor reports; the live list above covers the rest
EXT_KNOWN = {'fnmihdojmnkclgjpcoonokmkhjpjechg': 'Microsoft, March 2026: fake AI sidebar that collects ChatGPT and DeepSeek conversations', 'inhcgfpbfdjbjogdfjbclgolkmhnooop': 'Microsoft, March 2026: fake AI sidebar that collects ChatGPT and DeepSeek conversations'}
EXT_CODE = [
    (re.compile(r'discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot', re.I), 'high', 'Sends data to a private chat channel', 'Discord webhooks and Telegram bots are a cheap way for thieves to collect stolen data. Honest extensions have no reason to do this.'),
    (re.compile(r'chrome\.cookies\.getAll\s*\(\s*\{\s*\}\s*[,)]', re.I), 'medium', 'Code asks for every cookie from every site', 'Sign-in cookies let a thief enter your accounts with no password or second factor. This does not prove misuse, since some shopping and privacy tools do it, but the extension is trusted with a lot.'),
    (re.compile(r'(?:eval|new\s+Function)\s*\(\s*(?:await\s+)?(?:atob|decodeURIComponent\s*\(\s*escape\s*\(\s*atob)\s*\(', re.I), 'high', 'Runs code hidden inside scrambled text', 'A common way to get past the store\'s review.'),
    (re.compile(r'writeText\s*\([^)]{0,200}(?:powershell|mshta|cmd\s*/c)', re.I), 'critical', 'Puts a command on your clipboard', 'This is the "ClickFix" trick: a page asks you to paste and run it.'),
    (re.compile(r'chrome\.debugger\.attach', re.I), 'medium', 'Attaches a debugger to tabs', 'Lets it see and alter anything on a page, including passwords as they are typed. A few legitimate developer tools need it.'),
]
EXT_POLICY = {'Chrome': r'SOFTWARE\Policies\Google\Chrome', 'Edge': r'SOFTWARE\Policies\Microsoft\Edge', 'Brave': r'SOFTWARE\Policies\BraveSoftware\Brave'}
EXT_NEWS = 'Socket, Aug 2026: a Chrome and Edge framework that stole crypto, login sessions and form data, and showed fake update lures.\nMalwarebytes, Jun 2026 (StegoAd): 119 Edge extensions, about 2.6 million users, that later stole Google sign-ins and two-factor codes.\nMicrosoft, Mar 2026: fake AI sidebars that collected ChatGPT and DeepSeek conversations.\nKoi, Dec 2025 (ShadyPanda): about 4.3 million installs of long-trusted extensions that turned malicious in an update.'
EXT_NEWS_FIX = 'Remove anything you do not use. If an extension here was on the known-bad list: remove it, sign out of all sessions, change passwords for important accounts from another device, and move any crypto to a new wallet. Then run a full antivirus scan.'


def fetch_extension_list():
    cache = os.path.join(S.APP_DIR, 'ext-cache.txt')
    try:
        if time.time() - os.path.getmtime(cache) < 12 * 3600:
            with open(cache, encoding='ascii') as f:
                return set(EXT_ID.findall(f.read())), 'cached'
    except OSError:
        pass
    try:
        with urllib.request.urlopen(urllib.request.Request(EXT_FEED, headers=UA), timeout=30) as r:
            ids = set(EXT_ID.findall(r.read(8000000).decode('ascii', 'replace')))   # only well-formed IDs are ever taken from the download
        if len(ids) > 1000:
            os.makedirs(S.APP_DIR, exist_ok=True)
            with open(cache, 'w', encoding='ascii') as f:
                f.write('\n'.join(sorted(ids)))
            return ids, 'live'
    except (OSError, ValueError):
        pass
    try:
        with open(cache, encoding='ascii') as f:
            return set(EXT_ID.findall(f.read())), 'old'
    except OSError:
        return set(), 'failed'


def _ext_code_hits(base):
    seen, budget = [], 6000000
    for root, _d, files in os.walk(base):
        for fn in files:
            if fn.lower().endswith(('.js', '.html')) and budget > 0:
                try:
                    with open(os.path.join(root, fn), encoding='utf-8', errors='replace') as f:
                        text = f.read(1500000)
                except OSError:
                    continue
                budget -= len(text)
                seen.extend((sev, t, w) for rx, sev, t, w in EXT_CODE if t not in [x[1] for x in seen] and rx.search(text))
    return seen


def _ext_dirs(browser, ext_id):
    roots = {'Chrome': ('LOCALAPPDATA', r'Google\Chrome\User Data'), 'Edge': ('LOCALAPPDATA', r'Microsoft\Edge\User Data'), 'Brave': ('LOCALAPPDATA', r'BraveSoftware\Brave-Browser\User Data'), 'Vivaldi': ('LOCALAPPDATA', r'Vivaldi\User Data'), 'Opera': ('APPDATA', r'Opera Software\Opera Stable')}
    env, base = roots[browser]
    base = os.path.join(os.environ.get(env, ''), base)
    return glob.glob(os.path.join(glob.escape(base), '*', 'Extensions', ext_id, '*')) + glob.glob(os.path.join(glob.escape(base), 'Extensions', ext_id, '*'))


def scan_extensions(ctx):
    bad, state = fetch_extension_list()
    out, seen = [], set()
    add = out.append
    exts = S.browser_extensions()
    known_hits = 0
    for e in exts:
        key = (e['Browser'], e['Id'])
        if key in seen:
            continue
        seen.add(key)
        name, ext_id, br = e['Name'], e['Id'], e['Browser']
        page = {'Chrome': 'chrome://extensions', 'Edge': 'edge://extensions', 'Brave': 'brave://extensions', 'Vivaldi': 'vivaldi://extensions', 'Opera': 'opera://extensions'}[br]
        block = A('block_extension', 'Block extension', f'Block "{name}" in {br}?\n\nThe browser removes it and will not let it back. {br} will show "managed by your organization", which is normal. You can undo this in the Blocked tab.', browser=br, ext_id=ext_id, name=name) if br in EXT_POLICY else None
        if ext_id in bad or ext_id in EXT_KNOWN:
            known_hits += 1
            src = EXT_KNOWN.get(ext_id, 'MalExt Sentry list of extensions removed for malicious behaviour')
            add(F('extensions', f'bad:{br}:{ext_id}', 'critical', f'Known malicious extension: {name}', f'{br} has an extension on the published list of malicious ones.', 'It may have already taken your sign-in cookies, passwords and browsing history.', f'{ext_id}\nVersion {e["Version"]}\nSource: {src}', f'Remove it at {page}. Then sign out of all sessions and change your important passwords from another device.', block, Active=True))
            continue
        for sev, title, why in _ext_code_hits_for(br, ext_id):
            add(F('extensions', f'code:{br}:{ext_id}:{title}', sev, f'{title}: {name}', f'Found in the code of this {br} extension.', why, f'{ext_id}\nVersion {e["Version"]}', f'If you do not fully trust it, remove it at {page}.', block, Active=sev == 'critical'))
    for br, path in EXT_POLICY.items():
        for hive, hn in ((HKLM, 'HKLM'), (HKCU, 'HKCU')):
            for _n, val in reg_values(hive, path + r'\ExtensionInstallForcelist'):
                ext_id, _, url = str(val).partition(';')
                store = not url or 'google.com' in url or 'microsoft.com' in url
                add(F('extensions', f'force:{br}:{ext_id}', 'info' if store and hive == HKLM else 'high', f'{br} is forced to install an extension', 'A policy installs this extension and stops you removing it.', 'Normal on a work PC. Malware does exactly this to make itself permanent.', f'{hn}\\{path}\\ExtensionInstallForcelist\n{val}', 'If your workplace does not manage this PC, remove the policy.', Active=not store))
    for prof in glob.glob(os.path.join(glob.escape(os.environ.get('APPDATA', '')), 'Mozilla', 'Firefox', 'Profiles', '*', 'extensions.json')):
        try:
            with open(prof, encoding='utf-8') as f:
                addons = json.load(f).get('addons', [])
        except (OSError, ValueError):
            continue
        for ad in addons:
            if isinstance(ad, dict) and ad.get('location') == 'app-profile' and ad.get('type') == 'extension':
                seen.add(('Firefox', ad.get('id')))
                nm = str((ad.get('defaultLocale') or {}).get('name') or ad.get('id'))
                if int(ad.get('signedState') or 0) <= 0:
                    add(F('extensions', f"ff:{ad.get('id')}", 'high', f'Unsigned Firefox add-on: {nm}', 'Mozilla has not signed it.', 'Firefox normally refuses these. Its presence means something changed that behaviour.', str(ad.get('id')), 'Remove it at about:addons.', Active=True))
    note = {'live': 'downloaded just now', 'cached': 'downloaded within the last 12 hours', 'old': 'an older saved copy, because the download failed', 'failed': 'unavailable, so only built-in checks ran'}[state]
    if state == 'failed':
        add(F('extensions', 'feedfail', 'info', 'The list of malicious extensions could not be downloaded', 'Your extensions could not be compared with it.', fix='Check the internet connection and scan again.'))
    if not known_hits:
        add(F('extensions', 'clean', 'ok', f'None of your {len(seen)} extensions are on the known-bad list', f'Compared with {len(bad):,} published malicious extension IDs from MalExt Sentry (CC BY 4.0), {note}. Code of each extension was also inspected.'))
    add(F('extensions', 'news', 'info', 'Recently disclosed extension attacks', 'Trusted extensions can be sold or hijacked, then turn malicious in a silent update.', 'That is why a list has to stay current, and why fewer extensions is safer.', EXT_NEWS, EXT_NEWS_FIX))
    return out


def _ext_code_hits_for(browser, ext_id):
    dirs = sorted(_ext_dirs(browser, ext_id))
    return _ext_code_hits(dirs[-1]) if dirs else []


# ----------------------------------------------------------------

S.SCANS.extend([
    ('adminsetup', 'Weak administrator setup', scan_adminsetup), ('userapps', 'Apps installed only for you', scan_userapps), ('firewall', 'Firewall rules', scan_firewall), ('tricks', 'Hacker tricks and backdoors', scan_tricks),
    ('lateral', 'Lateral movement', scan_lateral), ('pentest', 'Pentest from inside', scan_pentest), ('outside', 'Pentest from outside', scan_outside), ('extensions', 'Extensions against known threats', scan_extensions),
    ('events', 'Event Viewer', scan_events), ('health', 'Performance and disks', scan_health),
])
