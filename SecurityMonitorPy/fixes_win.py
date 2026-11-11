"""
Everything My Security can change on the PC. Each fix returns {'ok', 'message'} and, when it can be reversed, 'undo': [fn, args, label].
Arguments come from the app's own scan results, never from the web page, and reach PowerShell through environment variables.
"""

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
import winreg

import scans_win as S
from knowledge import NEVER_BLOCK_PORTS

GROUP = 'MySecurity'
HOSTS_MARK = '# MySecurity block: '
EVERYONE = '*S-1-1-0'
ICACLS = os.path.join(S.SYSTEM32, 'icacls.exe')
NO_TOUCH_PROCS = {'system', 'system idle', 'registry', 'secure system', 'memcompression', 'memory compression', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'lsaiso', 'fontdrvhost', 'dwm', 'svchost',
                  'msmpeng', 'nissrv', 'mpdefendercoreservice', 'securityhealthservice', 'smartscreen', 'csfalconservice', 'csfalconcontainer', 'explorer'}
SHARED_HOSTS = {'powershell', 'pwsh', 'cmd', 'conhost', 'msedgewebview2', 'dllhost', 'rundll32', 'runtimebroker', 'backgroundtaskhost', 'taskhostw', 'wscript', 'cscript', 'sihost', 'wudfhost', 'searchprotocolhost', 'python', 'pythonw', 'py', 'mshta', 'regsvr32'}
SETTINGS_PAGES = ('ms-settings:windowsupdate', 'ms-settings:appsfeatures', 'ms-settings:otherusers', 'ms-settings:network-proxy', 'ms-settings:storagesense', 'ms-settings:startupapps', 'ms-settings:network-status', 'windowsdefender://threatsettings', 'windowsdefender://coreisolation')
QUARANTINE = os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), 'MySecurity', 'Quarantine') if S.is_admin() else os.path.join(S.APP_DIR, 'Quarantine')


def ok(message, undo=None, reboot=False):
    return {'ok': True, 'message': message + (' Restart the PC to finish.' if reboot else ''), 'undo': undo, 'reboot': reboot}


def bad(message):
    return {'ok': False, 'message': message}


def ps(script, **env):
    row = S.ps_one(script, {f'MS_{k.upper()}': (v if isinstance(v, str) else json.dumps(v)) for k, v in env.items()}, timeout=180)
    return row


def ps_try(body):
    return "try {\n" + body + "\nConvertTo-Json -InputObject @{ ok = $true } -Compress\n} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }"


def result(row, done, undo=None, reboot=False):
    if row.get('ok'):
        return ok(done, undo, reboot)
    return bad(f"Windows refused the change. {row.get('error', '')}".strip())


HIVES = {'HKLM': winreg.HKEY_LOCAL_MACHINE, 'HKCU': winreg.HKEY_CURRENT_USER}
KINDS = {'dword': winreg.REG_DWORD, 'sz': winreg.REG_SZ}
MISSING = '__missing__'

# A Windows System Restore point, made once before the first system-config change of a session, so those
# registry/service/firewall changes have a one-click rollback. Turns on System Protection if it is off, and
# steps past Windows' "one restore point per 24 hours" limit just for this call, then puts that setting back.
RESTORE_PS = r'''
$drive = "$env:SystemDrive\"
try { Enable-ComputerRestore -Drive $drive -ErrorAction Stop } catch {}
$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
$old = $null
try { $old = (Get-ItemProperty -Path $k -Name SystemRestorePointCreationFrequency -ErrorAction Stop).SystemRestorePointCreationFrequency } catch {}
try { New-ItemProperty -Path $k -Name SystemRestorePointCreationFrequency -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null } catch {}
try { Checkpoint-Computer -Description 'My Security: before a fix' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop; $res = @{ ok = $true } }
catch { $res = @{ ok = $false; error = [string]$_.Exception.Message } }
if ($old -ne $null) { try { Set-ItemProperty -Path $k -Name SystemRestorePointCreationFrequency -Value $old -ErrorAction SilentlyContinue } catch {} }
else { try { Remove-ItemProperty -Path $k -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue } catch {} }
ConvertTo-Json -InputObject $res -Compress
'''

# The fixes that make a lasting change to Windows' own settings, where a restore point is worth having first.
# Quick, already-reversible actions (blocking an address or port, quarantining a file) are left out so they stay instant.
RESTORE_BEFORE = {'set_reg', 'set_regs', 'disable_tls', 'disable_smb1', 'smb_signing', 'disable_netbios', 'disable_feature', 'remove_share',
                  'disable_account', 'remove_admin', 'disable_autologon', 'disable_service', 'quote_service', 'remove_run', 'remove_ifeo',
                  'disable_task', 'defender_remove_exclusion', 'firewall_on', 'disable_fw_rules', 'lock_path', 'remove_hosts_line', 'remove_portproxy'}


def create_restore_point():
    """Make a System Restore point. Needs admin and working System Protection; returns {'ok', 'message'}."""
    if not S.is_admin():
        return {'ok': False, 'message': 'needs Administrator rights'}
    row = S.ps_one(RESTORE_PS, timeout=180)
    if row.get('ok'):
        return {'ok': True, 'message': 'restore point created'}
    return {'ok': False, 'message': str(row.get('error') or 'System Protection may be turned off')[:200]}


def set_reg(hive, path, name, value, kind='dword', reboot=False):
    h = HIVES[hive]
    old = S.reg_get(h, path, name, MISSING)
    try:
        with winreg.CreateKeyEx(h, path, 0, winreg.KEY_SET_VALUE) as k:
            if value == MISSING:
                winreg.DeleteValue(k, name)
            else:
                winreg.SetValueEx(k, name, 0, KINDS[kind], value)
    except OSError as e:
        return bad(f'Windows refused the change ({hive}\\{path}\\{name}): {e.strerror or e}')
    shown = '(removed)' if value == MISSING else value
    return ok(f'Set {name} to {shown}. It was {"not set" if old == MISSING else old}.', ['set_reg', {'hive': hive, 'path': path, 'name': name, 'value': old, 'kind': kind, 'reboot': reboot}, f'Restore {name}'], reboot)


def disable_tls(proto):
    if proto not in ('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1'):
        return bad('That protocol can\'t be changed here.')
    base = rf'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{proto}'
    undo = []
    for side in ('Client', 'Server'):
        for name, value in (('Enabled', 0), ('DisabledByDefault', 1)):
            r = set_reg('HKLM', f'{base}\\{side}', name, value, 'dword')
            if not r['ok']:
                return r
            undo.append(r['undo'][1])
    return ok(f'{proto} is off.', ['set_regs', {'items': undo}, f'Turn {proto} back on'], True)


def set_regs(items):
    for it in items:
        r = set_reg(**it)
        if not r['ok']:
            return r
    return ok('Restored the previous settings.', reboot=any(i.get('reboot') for i in items))


def disable_smb1():
    return result(ps(ps_try("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null")), 'SMBv1 is off.', reboot=True)


def smb_signing():
    return result(ps(ps_try('Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop')), 'SMB signing is now required.', ['smb_signing_off', {}, 'Stop requiring SMB signing'])


def smb_signing_off():
    return result(ps(ps_try('Set-SmbServerConfiguration -RequireSecuritySignature $false -Force -ErrorAction Stop')), 'SMB signing is no longer required.')


def disable_netbios():
    return result(ps(ps_try("Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null }")), 'NetBIOS is off on every network adapter.', ['enable_netbios', {}, 'Turn NetBIOS back on'])


def enable_netbios():
    return result(ps(ps_try("Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]0 } | Out-Null }")), 'NetBIOS is back to the Windows default.')


def disable_feature(feature):
    if feature not in ('MicrosoftWindowsPowerShellV2Root', 'TelnetClient', 'TFTP'):
        return bad('That feature can\'t be changed here.')
    return result(ps(ps_try('Disable-WindowsOptionalFeature -Online -FeatureName $env:MS_F -NoRestart -ErrorAction Stop | Out-Null'), f=feature), f'Removed {feature}.', reboot=True)


def remove_share(name):
    if name.upper() in ('IPC$', 'ADMIN$', 'PRINT$') or re.match(r'^[A-Za-z]\$$', name):
        return bad('That is a built-in Windows share.')
    return result(ps(ps_try('Remove-SmbShare -Name $env:MS_N -Force -ErrorAction Stop'), n=name), f'Stopped sharing {name}. The files are still there.')


def disable_account(name, sid):
    if sid == S.ps_one("ConvertTo-Json -InputObject @{ me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } -Compress").get('me'):
        return bad('That is the account you are signed in with, so My Security won\'t turn it off.')
    return result(ps(ps_try('Disable-LocalUser -SID $env:MS_S -ErrorAction Stop'), s=sid), f'Turned off the account {name}.', ['enable_account', {'name': name, 'sid': sid}, f'Turn {name} back on'])


def enable_account(name, sid):
    return result(ps(ps_try('Enable-LocalUser -SID $env:MS_S -ErrorAction Stop'), s=sid), f'Turned on the account {name}.')


def remove_admin(member):
    return result(ps(ps_try('''
$grp = Get-LocalGroup -SID 'S-1-5-32-544'
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
if ($env:MS_M -eq $me) { throw 'That is the account you are signed in with.' }
$left = @(Get-LocalGroupMember -Group $grp | Where-Object { $_.Name -ne $env:MS_M -and $_.ObjectClass -eq 'User' })
if ($left.Count -lt 1) { throw 'It is the last administrator on this PC.' }
Remove-LocalGroupMember -Group $grp -Member $env:MS_M -ErrorAction Stop'''), m=member), f'{member} is now a standard user.', ['add_admin', {'member': member}, f'Give {member} admin rights again'])


def add_admin(member):
    return result(ps(ps_try("$grp = Get-LocalGroup -SID 'S-1-5-32-544'; Add-LocalGroupMember -Group $grp -Member $env:MS_M -ErrorAction Stop"), m=member), f'{member} is an administrator again.')


def disable_autologon():
    wl = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    r = set_reg('HKLM', wl, 'AutoAdminLogon', '0', 'sz')
    if not r['ok']:
        return r
    if S.reg_get(S.HKLM, wl, 'DefaultPassword', MISSING) != MISSING:
        set_reg('HKLM', wl, 'DefaultPassword', MISSING)
    return ok('Windows will ask for a password at start-up, and any stored password was deleted.')


def disable_service(name, display, old_start=None, was_running=False):
    if name.lower() in S.NO_DISABLE_SERVICES:
        return bad(f'{display} is needed by Windows or your security software.')
    row = ps(ps_try("Set-Service -Name $env:MS_N -StartupType Disabled -ErrorAction Stop\nStop-Service -Name $env:MS_N -Force -ErrorAction SilentlyContinue"), n=name)
    start = {'Auto': 'Automatic', 'Manual': 'Manual'}.get(old_start, 'Manual')
    return result(row, f'Stopped and disabled {display}.', ['enable_service', {'name': name, 'display': display, 'start': start, 'run': bool(was_running)}, f'Turn {display} back on'])


def enable_service(name, display, start, run):
    row = ps(ps_try("Set-Service -Name $env:MS_N -StartupType $env:MS_T -ErrorAction Stop\nif ($env:MS_R -eq 'true') { Start-Service -Name $env:MS_N -ErrorAction Stop }"), n=name, t=start, r='true' if run else 'false')
    return result(row, f'{display} is back on.')


def quote_service(name, path):
    key = rf'SYSTEM\CurrentControlSet\Services\{name}'
    cur = str(S.reg_get(S.HKLM, key, 'ImagePath', ''))
    if not cur.startswith(path):
        return bad('The service has changed since the scan. Run the scan again.')
    return set_reg('HKLM', key, 'ImagePath', f'"{path}"{cur[len(path):]}', 'sz')


def remove_run(hive, path, name, value):
    h = HIVES[hive]
    if str(S.reg_get(h, path, name, '')) != value:
        return bad('This startup entry has changed since the scan. Run the scan again.')
    return set_reg(hive, path, name, MISSING, 'sz') | {'message': f'Removed "{name}" from Windows startup. The program itself was not deleted.'}


def remove_ifeo(name):
    if not re.match(r'^[\w.\- ]+\.exe$', name, re.I):
        return bad('Unexpected program name.')
    return set_reg('HKLM', rf'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{name}', 'Debugger', MISSING, 'sz')


def disable_task(path, name):
    return result(ps(ps_try('Disable-ScheduledTask -TaskPath $env:MS_P -TaskName $env:MS_N -ErrorAction Stop | Out-Null'), p=path, n=name), f'Disabled the scheduled task {name}.', ['enable_task', {'path': path, 'name': name}, f'Turn task {name} back on'])


def enable_task(path, name):
    return result(ps(ps_try('Enable-ScheduledTask -TaskPath $env:MS_P -TaskName $env:MS_N -ErrorAction Stop | Out-Null'), p=path, n=name), f'Turned on the scheduled task {name}.')


def defender_on():
    return result(ps(ps_try('Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop')), 'Microsoft Defender real-time protection is on.')


def _mpcmd():
    base = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'Windows Defender', 'MpCmdRun.exe')
    return base if os.path.isfile(base) else ''


def defender_update():
    exe = _mpcmd()
    if not exe:
        return bad('Microsoft Defender was not found.')
    subprocess.Popen([exe, '-SignatureUpdate'], creationflags=S.CREATE_NO_WINDOW)
    return ok('Updating Defender definitions in the background. Run this scan again in a few minutes.')


def defender_scan(kind):
    exe = _mpcmd()
    if not exe:
        return bad('Microsoft Defender was not found, so it can\'t run a scan.')
    subprocess.Popen([exe, '-Scan', '-ScanType', '2' if kind == 'full' else '1'], creationflags=S.CREATE_NO_WINDOW)
    return ok(f'Microsoft Defender started a {kind} scan in the background. Run the Malware scan again when it finishes to see the results.')


def defender_remove():
    return result(ps(ps_try('Remove-MpThreat -ErrorAction Stop')), 'Microsoft Defender removed the active threats.')


def defender_remove_exclusion(value):
    return result(ps(ps_try('Remove-MpPreference -ExclusionPath $env:MS_V -ErrorAction SilentlyContinue\nRemove-MpPreference -ExclusionProcess $env:MS_V -ErrorAction SilentlyContinue\nRemove-MpPreference -ExclusionExtension $env:MS_V -ErrorAction SilentlyContinue'), v=value), f'Removed the Defender exclusion: {value}')


def firewall_on(profiles):
    return result(ps(ps_try('Set-NetFirewallProfile -Name ($env:MS_P | ConvertFrom-Json) -Enabled True -ErrorAction Stop'), p=profiles), f"Windows Firewall is on: {', '.join(profiles)}.")


def open_settings(page):
    try:
        if page == 'bitlocker':
            subprocess.Popen([os.path.join(S.SYSTEM32, 'control.exe'), '/name', 'Microsoft.BitLockerDriveEncryption'], creationflags=S.CREATE_NO_WINDOW)
        elif page in SETTINGS_PAGES:
            os.startfile(page)
        else:
            return bad('That page can\'t be opened from here.')
    except OSError as e:
        return bad(f'Could not open it: {e}')
    return ok('Opened the Windows page.')


def winget_upgrade(pkg, name):
    exe = S.winget_path()
    if not exe:
        return bad('Windows Package Manager was not found.')
    try:
        r = subprocess.run([exe, 'upgrade', '--id', pkg, '--exact', '--silent', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity'],
                           capture_output=True, timeout=1500, creationflags=S.CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as e:
        return bad(f'The update did not finish: {e}')
    if r.returncode == 0:
        return ok(f'Updated {name}.')
    tail = [x.strip() for x in r.stdout.decode('utf-8', 'replace').replace('\r', '\n').split('\n') if x.strip()][-1:]
    return bad(f"The update of {name} failed. Close the app and try again. {' '.join(tail)}")


# ---- firewall blocks, all in their own group so only this app's rules are ever listed or removed

FW_LIST_PS = r'''
$out = foreach ($r in @(Get-NetFirewallRule -Group 'MySecurity' -ErrorAction SilentlyContinue)) {
  $p = $r | Get-NetFirewallPortFilter; $a = $r | Get-NetFirewallApplicationFilter; $d = $r | Get-NetFirewallAddressFilter
  [pscustomobject]@{ Id = [string]$r.Name; Name = [string]$r.DisplayName; Direction = [string]$r.Direction; Proto = [string]$p.Protocol; Port = [string]$p.LocalPort; Program = [string]$a.Program; Remote = (@($d.RemoteAddress) -join ','); Description = [string]$r.Description }
}
ConvertTo-Json -InputObject @($out) -Compress
'''


def firewall_blocks():
    """{'ports': [...], 'programs': [...], 'ips': [...]}: what this app has blocked."""
    ports, programs, ips = {}, {}, {}
    for r in S.run_powershell(FW_LIST_PS, timeout=60):
        if not isinstance(r, dict):
            continue
        prog, remote = str(r.get('Program') or 'Any'), str(r.get('Remote') or 'Any')
        if prog not in ('Any', ''):
            e = programs.setdefault(prog.lower(), {'Path': prog, 'Name': os.path.splitext(os.path.basename(prog))[0], 'Ids': []})
        elif remote not in ('Any', ''):
            e = ips.setdefault(remote, {'Address': remote, 'Ids': []})
        elif str(r.get('Port') or '').isdigit():
            key = f"{r.get('Proto')}:{r.get('Port')}"
            e = ports.setdefault(key, {'Key': key, 'Proto': r.get('Proto'), 'Port': int(r['Port']), 'Name': S.port_info(int(r['Port']))[0], 'Ids': []})
        else:
            continue
        e['Ids'].append(str(r.get('Id') or ''))
    return {'ports': sorted(ports.values(), key=lambda x: x['Port']), 'programs': sorted(programs.values(), key=lambda x: x['Name'].lower()), 'ips': sorted(ips.values(), key=lambda x: x['Address'])}


def block_port(port, proto):
    port, proto = int(port), str(proto).upper()
    if proto not in ('TCP', 'UDP') or not 1 <= port <= 65535:
        return bad('That is not a valid port.')
    if (proto, port) in NEVER_BLOCK_PORTS:
        return bad(f'{proto} {port} is how this PC gets its network address. Blocking it could cut the PC off, so My Security won\'t do it.')
    if any(p['Key'] == f'{proto}:{port}' for p in firewall_blocks()['ports']):
        return ok(f'{proto} port {port} is already blocked.')
    row = ps(ps_try("New-NetFirewallRule -DisplayName ('MySecurity block port {0} {1}' -f $env:MS_R, $env:MS_P) -Group 'MySecurity' -Direction Inbound -Action Block -Protocol $env:MS_R -LocalPort ([int]$env:MS_P) -Profile Any -Description 'Created by My Security. Use Unblock in its Blocked tab to remove.' -ErrorAction Stop | Out-Null"), r=proto, p=str(port))
    return result(row, f'Blocked incoming {proto} port {port}. Other devices can no longer connect to it.')


REMOVE_RULES_PS = ps_try("$ids = @($env:MS_I | ConvertFrom-Json); Get-NetFirewallRule -Group 'MySecurity' -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.Name } | Remove-NetFirewallRule -ErrorAction Stop")


def unblock_port(key):
    e = next((p for p in firewall_blocks()['ports'] if p['Key'] == key), None)
    if not e:
        return bad('That port is not in the list of ports you blocked.')
    return result(ps(REMOVE_RULES_PS, i=e['Ids']), f"Unblocked {e['Proto']} port {e['Port']}.")


LAN_BLOCK_PS = """
$mine = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
$gw = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop })
if ($mine -contains $env:MS_A) { throw "That is this PC's own address." }
if ($gw -contains $env:MS_A) { throw "That is your router. Blocking it would cut this PC off the internet." }
New-NetFirewallRule -DisplayName ('MySecurity block address {0} (Inbound)' -f $env:MS_A) -Group 'MySecurity' -Direction Inbound -Action Block -RemoteAddress $env:MS_A -Profile Any -ErrorAction Stop | Out-Null
"""


def block_ip(ip, lan=False):
    try:
        addr = ipaddress.ip_address(str(ip).split('%')[0])
    except ValueError:
        return bad(f'{ip} is not an IP address.')
    if addr.is_global:
        row = ps(ps_try("foreach ($d in 'Inbound','Outbound') { New-NetFirewallRule -DisplayName ('MySecurity block address {0} ({1})' -f $env:MS_A, $d) -Group 'MySecurity' -Direction $d -Action Block -RemoteAddress $env:MS_A -Profile Any -ErrorAction Stop | Out-Null }"), a=str(addr))
        return result(row, f'Blocked {addr} in Windows Firewall, in both directions.')
    if not lan or addr.is_loopback or addr.is_multicast or addr.is_unspecified:
        return bad(f'{ip} is a private address, so My Security won\'t block it from here.')
    # a device on your own network: refuse only what it sends in, so this PC can still reach it (a printer, a NAS)
    row = ps(ps_try(LAN_BLOCK_PS), a=str(addr))
    return result(row, f'Blocked connections from {addr} to this PC. This PC can still reach it, for example to print.')


def unblock_ip(address):
    e = next((p for p in firewall_blocks()['ips'] if p['Address'] == address), None)
    if not e:
        return bad('That address is not in the list you blocked.')
    return result(ps(REMOVE_RULES_PS, i=e['Ids']), f'Unblocked {address}.')


def _refuse_process(name, path):
    low = str(name).lower()
    if low in NO_TOUCH_PROCS:
        return f'{name} is a core part of Windows or your security software, so My Security won\'t touch it.'
    if low in SHARED_HOSTS:
        return f'{name} is a shared Windows tool. Blocking it would break other programs, so only this one process can be ended.'
    if not path:
        return f'Windows did not reveal where {name} lives, so it can\'t be blocked by its file.'
    if S.in_windows(path):
        return 'That file is in the Windows folder. Blocking it could stop Windows from working.'
    self_exe = sys.executable.lower() if getattr(sys, 'frozen', False) else ''
    if path.lower() == self_exe:
        return 'That is My Security itself.'
    return ''


def end_copies(name, path):
    """End every running copy of this program file. Returns how many were ended and how many Windows refused."""
    ended, refused = 0, 0
    for pid, (n, _pp) in S.process_snapshot().items():
        if n == name and pid != os.getpid() and S.process_path(pid).lower() == path.lower():
            if S.terminate(pid) == 'denied':
                refused += 1
            else:
                ended += 1
    return ended, refused


def block_process(pid, name, path):
    why = _refuse_process(name, path)
    if why:
        return bad(why)
    row = ps(ps_try("foreach ($d in 'Outbound','Inbound') { New-NetFirewallRule -DisplayName ('MySecurity block program {0} ({1})' -f $env:MS_N, $d) -Group 'MySecurity' -Direction $d -Action Block -Program $env:MS_P -Profile Any -ErrorAction Stop | Out-Null }"), n=name, p=path)
    if not row.get('ok'):
        return bad(f"Windows Firewall did not accept the block for {name}. {row.get('error', '')}".strip())
    ended, refused = end_copies(name, path)
    denied = subprocess.run([ICACLS, path, '/deny', f'{EVERYONE}:(X)'], capture_output=True, creationflags=S.CREATE_NO_WINDOW).returncode != 0
    msg = f'Blocked {name}: it can\'t connect in or out' + (', and Windows will refuse to start it' if not denied else '') + f'. Ended {ended} running cop{"y" if ended == 1 else "ies"}.'
    if refused:
        msg += f' Windows refused to end {refused}.'
    if denied:
        msg += ' Its file could not be locked, so it could still start.'
    return {'ok': not refused, 'message': msg}


def unblock_process(path):
    e = next((p for p in firewall_blocks()['programs'] if p['Path'].lower() == str(path).lower()), None)
    if not e:
        return bad('That program is not in the list you blocked.')
    subprocess.run([ICACLS, e['Path'], '/remove:d', EVERYONE], capture_output=True, creationflags=S.CREATE_NO_WINDOW)
    return result(ps(REMOVE_RULES_PS, i=e['Ids']), f"Unblocked {e['Name']}. It can start and connect again.")


# ---- sites: lines in the Windows hosts file that this app marks as its own

def _flush_dns():
    try:
        S.system_dll('dnsapi').DnsFlushResolverCache()
    except (OSError, AttributeError):
        pass


def _read_hosts():
    with open(S.HOSTS_FILE, encoding='latin-1', newline='') as f:
        return f.read()


def _write_hosts(text):
    with open(S.HOSTS_FILE, 'w', encoding='latin-1', newline='') as f:
        f.write(text)
    _flush_dns()


def blocked_sites():
    sites = {}
    try:
        for line in _read_hosts().splitlines():
            if HOSTS_MARK in line:
                sites.setdefault(line.split(HOSTS_MARK, 1)[1].strip(), None)
    except OSError:
        pass
    return sorted(sites)


def block_site(site):
    site = str(site).lower().removeprefix('www.')
    if not S.SITE_RE.match(site) or any(site == p or site.endswith('.' + p) for p in S.PROTECTED_SITES):
        return bad(f'{site} is used by Windows or is not a site name, so My Security won\'t block it.')
    if site in blocked_sites():
        return ok(f'{site} is already blocked.')
    try:
        text = _read_hosts()
        if text and not text.endswith(('\n', '\r')):
            text += '\r\n'
        text += ''.join(f'{ip} {n}  {HOSTS_MARK}{site}\r\n' for n in (site, 'www.' + site) for ip in ('0.0.0.0', '::'))
        _write_hosts(text)
    except OSError as e:
        return bad(f"Couldn't change Windows' hosts file: {e.strerror or e}. Security software sometimes locks it, and nothing was blocked.")
    return ok(f'Blocked {site}. Close its tab and it can\'t be opened again in any browser. If a browser has Secure DNS on, turn that off too.')


def unblock_site(site):
    if site not in blocked_sites():
        return bad('That site is not in the list you blocked.')
    try:
        _write_hosts(''.join(x for x in _read_hosts().splitlines(keepends=True) if not (HOSTS_MARK in x and x.split(HOSTS_MARK, 1)[1].strip() == site)))
    except OSError as e:
        return bad(f"Couldn't change Windows' hosts file: {e.strerror or e}.")
    return ok(f'Unblocked {site}.')


def remove_hosts_line(name):
    try:
        lines = _read_hosts().splitlines(keepends=True)
        kept = [x for x in lines if name not in x.split('#', 1)[0].split()[1:]]
        _write_hosts(''.join(kept))
    except OSError as e:
        return bad(f"Couldn't change Windows' hosts file: {e.strerror or e}.")
    return ok(f'Removed {len(lines) - len(kept)} line(s) for {name} from the hosts file.')


# ---- quarantine: a file is moved here under a harmless name and can be put back

def _qindex_path():
    return os.path.join(QUARANTINE, 'index.json')


def quarantine_list():
    try:
        with open(_qindex_path(), encoding='utf-8') as f:
            rows = json.load(f)
        return [r for r in rows if isinstance(r, dict) and os.path.isfile(os.path.join(QUARANTINE, str(r.get('Id', ''))))]
    except (OSError, ValueError):
        return []


def _qsave(rows):
    with open(_qindex_path(), 'w', encoding='utf-8') as f:
        json.dump(rows, f)


# A file's permissions, read before it moves and written back when it is restored. 'Access' and 'Owner' are separate,
# because putting back an owner other than this account can be refused while the permissions themselves still work.
GET_SD_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $i = Get-Item -LiteralPath $env:MS_P -Force
  ConvertTo-Json -InputObject @{ ok = $true; access = $i.GetAccessControl('Access').GetSecurityDescriptorSddlForm('Access'); owner = $i.GetAccessControl('Owner').GetSecurityDescriptorSddlForm('Owner') } -Compress
} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }
"""
SET_SD_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $i = Get-Item -LiteralPath $env:MS_P -Force
  $a = $i.GetAccessControl('Access'); $a.SetSecurityDescriptorSddlForm($env:MS_A, 'Access'); $i.SetAccessControl($a)
  $ownerOk = $true
  if ($env:MS_O) { try { $o = $i.GetAccessControl('Owner'); $o.SetSecurityDescriptorSddlForm($env:MS_O, 'Owner'); $i.SetAccessControl($o) } catch { $ownerOk = $false } }
  ConvertTo-Json -InputObject @{ ok = $true; access = $i.GetAccessControl('Access').GetSecurityDescriptorSddlForm('Access'); ownerOk = $ownerOk } -Compress
} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }
"""
ATTR_KEEP = 0x1 | 0x2 | 0x4 | 0x20   # read-only, hidden, system, archive


def _set_attributes(path, attrs):
    import ctypes
    return bool(ctypes.windll.kernel32.SetFileAttributesW(str(path), int(attrs) or 0x80))


def _read_zone(path):
    """The "downloaded from the internet" mark Windows keeps beside a file (Mark of the Web)."""
    try:
        with open(path + ':Zone.Identifier', 'r', encoding='utf-8', errors='replace') as f:
            return f.read(4096)
    except OSError:
        return ''


def _sha256(path, limit=1024 * 1024 * 1024):
    import hashlib
    try:
        if os.path.getsize(path) > limit:
            return ''
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest().upper()
    except OSError:
        return ''


def quarantine(path, why='', source=''):
    low = os.path.abspath(path).lower()
    if S.in_windows(low) or low.startswith((os.environ.get('ProgramFiles', r'C:\Program Files').lower() + '\\', os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)').lower() + '\\')):
        return bad("That file is in a system folder, so My Security won't move it. Uninstall the program it belongs to.")
    if not os.path.isfile(path):
        return bad('That file is no longer there.')
    os.makedirs(QUARANTINE, exist_ok=True)
    if S.is_admin():
        subprocess.run([ICACLS, QUARANTINE, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'], capture_output=True, creationflags=S.CREATE_NO_WINDOW)
    # everything needed to put it back exactly as it was
    sd = ps(GET_SD_PS, p=path)
    try:
        st = os.stat(path)
        attrs, size = getattr(st, 'st_file_attributes', 0) & ATTR_KEEP, st.st_size
    except OSError:
        attrs, size = 0, 0
    zone, sha = _read_zone(path), _sha256(path)
    qid = uuid.uuid4().hex + '.quarantined'
    dest = os.path.join(QUARANTINE, qid)
    try:
        if attrs & 0x1:
            _set_attributes(path, attrs & ~0x1)   # a read-only file can't be moved to another drive
        shutil.move(path, dest)
    except OSError as e:
        if attrs & 0x1:
            _set_attributes(path, attrs)
        return bad(f'Could not move it: {e.strerror or e}. If it is running, end it first.')
    # while it is here, only the quarantine folder's permissions apply: Administrators and Windows
    locked = S.is_admin() and subprocess.run([ICACLS, dest, '/reset'], capture_output=True, creationflags=S.CREATE_NO_WINDOW).returncode == 0
    rows = quarantine_list() + [{'Id': qid, 'Path': path, 'Name': os.path.basename(path), 'When': time.strftime('%Y-%m-%d %H:%M'), 'Size': size, 'Sha256': sha,
                                 'Why': str(why)[:300], 'Source': str(source), 'Access': sd.get('access', '') if sd.get('ok') else '',
                                 'Owner': sd.get('owner', '') if sd.get('ok') else '', 'Attrs': attrs, 'Zone': zone, 'Locked': bool(locked)}]
    _qsave(rows)
    return ok(f"Moved {os.path.basename(path)} to quarantine ({QUARANTINE}). It can't run from there. Its permissions were saved and come back if you restore it.")


def quarantine_restore(qid):
    rows = quarantine_list()
    e = next((r for r in rows if r['Id'] == qid), None)
    if not e:
        return bad('That item is not in quarantine.')
    if os.path.exists(e['Path']):
        return bad('A file with that name is back in the original place. Nothing was restored.')
    if S.in_windows(e['Path']):
        return bad("That path is in the Windows folder, so My Security won't write there.")
    os.makedirs(os.path.dirname(e['Path']), exist_ok=True)
    try:
        shutil.move(os.path.join(QUARANTINE, qid), e['Path'])
    except OSError as x:
        return bad(f'Could not put it back: {x.strerror or x}.')
    _qsave([r for r in rows if r['Id'] != qid])
    notes = []
    if e.get('Access'):
        r = ps(SET_SD_PS, p=e['Path'], a=e['Access'], o=e.get('Owner', ''))
        if not r.get('ok'):
            notes.append(f"its original permissions could not be put back ({r.get('error', 'Windows refused')})")
        elif not r.get('ownerOk'):
            notes.append('its permissions are back, but Windows kept you as its owner')
    else:
        notes.append('its original permissions were not saved (an older version quarantined it), so it has the permissions of the folder it is in')
    if e.get('Zone') and not _read_zone(e['Path']):
        try:
            with open(e['Path'] + ':Zone.Identifier', 'w', encoding='utf-8') as f:
                f.write(e['Zone'])
        except OSError:
            notes.append('its "downloaded from the internet" mark could not be put back')
    if e.get('Attrs'):
        _set_attributes(e['Path'], e['Attrs'])
    return {'ok': True, 'message': f"Restored {e['Name']} to {e['Path']}" + (' with its original permissions.' if not notes else '. Note: ' + '; '.join(notes) + '.')}


def quarantine_delete(qid):
    rows = quarantine_list()
    e = next((r for r in rows if r['Id'] == qid), None)
    if not e:
        return bad('That item is not in quarantine.')
    try:
        os.remove(os.path.join(QUARANTINE, qid))
    except OSError as x:
        return bad(f'Could not delete it: {x.strerror or x}.')
    _qsave([r for r in rows if r['Id'] != qid])
    return ok(f"Permanently deleted {e['Name']}.")


def disable_fw_rules(names, what):
    return result(ps(ps_try('$n = $env:MS_N | ConvertFrom-Json; foreach ($x in @($n)) { Disable-NetFirewallRule -Name $x -ErrorAction Stop }'), n=list(names)), f'Turned off: {what}.', ['enable_fw_rules', {'names': list(names), 'what': what}, f'Turn back on: {what}'])


def enable_fw_rules(names, what):
    return result(ps(ps_try('$n = $env:MS_N | ConvertFrom-Json; foreach ($x in @($n)) { Enable-NetFirewallRule -Name $x -ErrorAction Stop }'), n=list(names)), f'Turned back on: {what}.')


def remove_portproxy(family, listen):
    if family not in ('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6') or '/' not in listen:
        return bad('That is not a port forward My Security recognises.')
    addr, port = listen.rsplit('/', 1)
    if not port.isdigit():
        return bad('That is not a port forward My Security recognises.')
    r = subprocess.run([os.path.join(S.SYSTEM32, 'netsh.exe'), 'interface', 'portproxy', 'delete', family, f'listenport={port}', f'listenaddress={addr}'], capture_output=True, creationflags=S.CREATE_NO_WINDOW)
    return ok(f'Removed the port forward on {listen}.') if r.returncode == 0 else bad('Windows refused the change.')


USER_HIJACK_KEY = re.compile(r'^Software\\Classes\\(ms-settings|mscfile|exefile|Folder|AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2)\\shell\\open\\command$')


def remove_user_key(path):
    if not USER_HIJACK_KEY.match(path):
        return bad('My Security only removes known admin-prompt bypass keys.')
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except OSError as e:
        return bad(f'Windows refused the change. {e.strerror or ""}'.strip())
    return ok('Removed the admin prompt bypass.')


LOCK_PS = r'''
$ErrorActionPreference = 'Stop'
$open = 'S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4'
$item = Get-Item -LiteralPath $env:MS_P -Force
# 'Access' reads and writes only the permissions; touching the owner as well would be refused
$a = $item.GetAccessControl('Access')
$old = $a.GetSecurityDescriptorSddlForm('Access')
$a.SetAccessRuleProtection($true, $true)
$item.SetAccessControl($a)
$a = $item.GetAccessControl('Access')
foreach ($r in @($a.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
  if ($open -contains $r.IdentityReference.Value) { [void]$a.RemoveAccessRuleSpecific($r) } }
$u = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
$a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($u, 'ReadAndExecute', $(if ($item.PSIsContainer) { 'ContainerInherit,ObjectInherit' } else { 'None' }), 'None', 'Allow')))
$item.SetAccessControl($a)
foreach ($r in (Get-Item -LiteralPath $env:MS_P -Force).GetAccessControl('Access').GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
  if ($r.AccessControlType -eq 'Allow' -and $open -contains $r.IdentityReference.Value -and ([long]$r.FileSystemRights -band [long]0x000C0002)) { throw 'Normal users can still write here.' } }
ConvertTo-Json -InputObject @{ ok = $true; old = $old } -Compress
'''
RESTORE_ACL_PS = "$ErrorActionPreference = 'Stop'; $i = Get-Item -LiteralPath $env:MS_P -Force; $a = $i.GetAccessControl('Access'); $a.SetSecurityDescriptorSddlForm($env:MS_S, 'Access'); $i.SetAccessControl($a)"


def lock_path(path):
    """Stop normal users writing to a file or folder that something privileged runs from."""
    if S.in_windows(path) or len(os.path.abspath(path)) <= 3 or not os.path.exists(path):
        return bad('My Security won\'t change the permissions of that location.')
    row = ps("try {\n" + LOCK_PS + "\n} catch { ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress }", p=path)
    return result(row, f'Normal users can no longer write to {path}.', ['restore_acl', {'path': path, 'sddl': row.get('old', '')}, f'Restore permissions on {path}'])


def restore_acl(path, sddl):
    return result(ps(ps_try(RESTORE_ACL_PS), p=path, s=sddl), f'Restored the permissions on {path}.')


BROWSER_POLICY = {'Chrome': r'SOFTWARE\Policies\Google\Chrome', 'Edge': r'SOFTWARE\Policies\Microsoft\Edge', 'Brave': r'SOFTWARE\Policies\BraveSoftware\Brave'}


def block_extension(browser, ext_id, name):
    if browser not in BROWSER_POLICY or not re.fullmatch(r'[a-p]{32}', ext_id):
        return bad('My Security can\'t block that extension.')
    key = BROWSER_POLICY[browser] + r'\ExtensionInstallBlocklist'
    used = {n: v for n, v in S.reg_values(winreg.HKEY_LOCAL_MACHINE, key)}
    if ext_id not in used.values():
        slot = str(next(i for i in range(1, 100000) if str(i) not in used))
        try:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, slot, 0, winreg.REG_SZ, ext_id)
        except OSError as e:
            return bad(f'Windows refused the change. {e.strerror or ""}'.strip())
    return ok(f'Blocked {name} in {browser}. It goes away next time {browser} restarts.', ['unblock_extension', {'browser': browser, 'ext_id': ext_id, 'name': name}, f'Allow {name} in {browser} again'])


def unblock_extension(browser, ext_id, name):
    if browser not in BROWSER_POLICY:
        return bad('My Security can\'t change that.')
    key = BROWSER_POLICY[browser] + r'\ExtensionInstallBlocklist'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE) as k:
            for n, v in S.reg_values(winreg.HKEY_LOCAL_MACHINE, key):
                if v == ext_id:
                    winreg.DeleteValue(k, n)
    except OSError as e:
        return bad(f'Windows refused the change. {e.strerror or ""}'.strip())
    return ok(f'{name} is allowed again in {browser}. Reinstall it from the store if you still want it.')


FIXES = {f.__name__: f for f in (disable_fw_rules, remove_portproxy, remove_user_key, lock_path, block_extension, set_reg, set_regs, disable_tls, disable_smb1, smb_signing, smb_signing_off, disable_netbios, enable_netbios, disable_feature, remove_share, disable_account, enable_account, remove_admin, add_admin,
                                 disable_autologon, disable_service, enable_service, quote_service, remove_run, remove_ifeo, disable_task, enable_task, defender_on, defender_update, defender_scan, defender_remove, defender_remove_exclusion,
                                 firewall_on, open_settings, winget_upgrade, block_port, block_ip, block_process, block_site, remove_hosts_line, quarantine)}
FIXES_UNDO = {f.__name__: f for f in (enable_fw_rules, restore_acl, unblock_extension, set_reg, set_regs, smb_signing_off, enable_netbios, enable_account, add_admin, enable_service, enable_task)}
NO_ADMIN_NEEDED = {'open_settings', 'quarantine', 'winget_upgrade', 'remove_user_key'}
