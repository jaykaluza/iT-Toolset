"""More hacker tools and backdoors, added to the Hacker tricks check.

- The login-screen tools (Sticky Keys and friends) swapped for anything that is not the real Microsoft file, or hijacked through Ease of Access.
- Well-known hacking tools on disk or running: password dumpers, credential stealers, scanners and tunnels, and copies of the password store (LSASS dumps).
- Cookie theft: browsers running or started with remote debugging, and shortcuts that load extra extensions.
- Quiet hiding places: COM hijacking, time providers, print monitors and processors, application shims, Office start-up folders, hidden $ accounts.
"""
import ctypes
import glob
import os
import re
from ctypes import wintypes

import scans_win as S
from scans_win import F, HKCU, HKLM, as_list, reg_get, reg_subkeys, reg_values

SYS32 = S.SYSTEM32
USER = os.environ.get('USERPROFILE', '')

# ---- the login-screen tools: each can be started before anyone signs in, with full system rights
LOGIN_TOOLS = {'sethc.exe': 'Sticky Keys (press Shift five times)', 'utilman.exe': 'the Ease of Access button', 'osk.exe': 'the On-Screen Keyboard',
               'magnify.exe': 'Magnifier', 'narrator.exe': 'Narrator', 'displayswitch.exe': 'Windows+P', 'atbroker.exe': 'assistive technology',
               'easeofaccessdialog.exe': 'the Ease of Access dialog'}
WRONG_DESC = re.compile(r'(command processor|powershell|explorer|task manager|registry editor|windows script host|remote desktop|cmd\.exe)', re.I)

# ---- tools that have no business on a home PC. name -> (what it is, severity)
HACK_TOOLS = {
    'mimikatz': ('Mimikatz, which pulls passwords and sign-in tickets out of Windows memory', 'critical'),
    'lazagne': ('LaZagne, which collects every saved password on the PC', 'critical'),
    'rubeus': ('Rubeus, which steals and forges Windows sign-in tickets', 'critical'),
    'sharphound': ('SharpHound, which maps a network to plan an attack', 'high'),
    'pwdump': ('pwdump, which copies the Windows password store', 'critical'), 'fgdump': ('fgdump, which copies the Windows password store', 'critical'),
    'gsecdump': ('gsecdump, which copies stored passwords', 'critical'), 'wce.exe': ('Windows Credentials Editor, a password stealer', 'critical'),
    'procdump': ('ProcDump. A Microsoft tool, but attackers use it to copy the Windows password store (LSASS)', 'medium'),
    'nanodump': ('nanodump, which copies the Windows password store', 'critical'), 'safetykatz': ('SafetyKatz, a Mimikatz variant', 'critical'),
    'seatbelt': ('Seatbelt, which surveys a PC for attack opportunities', 'high'), 'winpeas': ('winPEAS, which looks for ways to become administrator', 'high'),
    'powerup': ('PowerUp, which looks for ways to become administrator', 'high'), 'juicypotato': ('JuicyPotato, a way to take over the system account', 'critical'),
    'printspoofer': ('PrintSpoofer, a way to take over the system account', 'critical'), 'godpotato': ('GodPotato, a way to take over the system account', 'critical'),
    'sweetpotato': ('SweetPotato, a way to take over the system account', 'critical'), 'roguepotato': ('RoguePotato, a way to take over the system account', 'critical'),
    'impacket': ('Impacket, a toolkit for attacking Windows networks', 'high'), 'crackmapexec': ('CrackMapExec, which tries passwords across a network', 'high'),
    'netexec': ('NetExec, which tries passwords across a network', 'high'), 'hashcat': ('hashcat, a password cracker', 'medium'), 'john.exe': ('John the Ripper, a password cracker', 'medium'),
    'nc.exe': ('Netcat, often used as a backdoor that hands out a command prompt', 'high'), 'nc64.exe': ('Netcat, often used as a backdoor that hands out a command prompt', 'high'),
    'ncat.exe': ('Ncat, often used as a backdoor that hands out a command prompt', 'high'), 'socat': ('socat, a traffic relay', 'medium'),
    'chisel': ('Chisel, a tunnel that lets someone outside reach your network', 'high'), 'ligolo': ('Ligolo, a tunnel into your network', 'high'),
    'cobaltstrike': ('Cobalt Strike, a remote-control kit used in most ransomware attacks', 'critical'), 'beacon.exe': ('a Cobalt Strike beacon', 'high'),
    'sliver': ('Sliver, a remote-control kit used by attackers', 'high'), 'meterpreter': ('Meterpreter, a remote-control backdoor', 'critical'),
    'advanced_ip_scanner': ('Advanced IP Scanner. Legitimate, but the first tool ransomware gangs run to find other PCs', 'medium'),
    'netscan': ('a network scanner often used before ransomware', 'medium'), 'angryip': ('Angry IP Scanner, a network scanner', 'low'),
    'bloodhound': ('BloodHound, which maps a network to plan an attack', 'high'), 'kerbrute': ('Kerbrute, which guesses Windows passwords', 'high'),
    'hydra': ('Hydra, which guesses passwords', 'medium'), 'responder': ('Responder, which steals sign-ins on a local network', 'high'),
    'inveigh': ('Inveigh, which steals sign-ins on a local network', 'high'), 'powersploit': ('PowerSploit, an attack toolkit', 'high'),
    'nishang': ('Nishang, an attack toolkit', 'high'), 'watson': ('Watson, which lists Windows holes an attacker can use to become administrator', 'high'),
    'wesng': ('WES-NG, which matches missing updates to known exploits', 'medium'), 'wes.py': ('WES-NG, which matches missing updates to known exploits', 'medium'),
    'sharpup': ('SharpUp, which looks for ways to become administrator', 'high'), 'privesccheck': ('PrivescCheck, which looks for ways to become administrator', 'high'),
    'jaws-enum': ('JAWS, which looks for ways to become administrator', 'high'), 'sherlock.ps1': ('Sherlock, which lists exploitable missing updates', 'high'),
    'adpeas': ('adPEAS, which surveys a Windows domain for attacks', 'high'), 'pingcastle': ('PingCastle. An audit tool, also used by attackers to map a domain', 'low'), 'empire': ('PowerShell Empire, a remote-control kit', 'high'), 'covenant': ('Covenant, a remote-control kit', 'high'),
}
TOOL_RE = re.compile('|'.join(re.escape(k.removesuffix('.exe')) for k in HACK_TOOLS), re.I)
LOOK_IN = [os.path.join(USER, 'Downloads'), os.path.join(USER, 'Desktop'), os.path.join(USER, 'Documents'), os.environ.get('TEMP', ''),
           os.path.join(os.environ.get('PUBLIC', r'C:\Users\Public')), os.environ.get('ProgramData', r'C:\ProgramData'), os.path.splitdrive(SYS32)[0] + '\\',
           os.path.join(USER, r'Documents\WindowsPowerShell\Modules'), os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), r'WindowsPowerShell\Modules')]
CODE_EXT = ('.exe', '.dll', '.ps1', '.psm1', '.py', '.bat', '.cmd', '.zip', '.7z', '.rar', '')


def _tool(name):
    low = name.lower()
    for k, v in HACK_TOOLS.items():
        stem = k.removesuffix('.exe')
        if low == k or low.startswith(stem + '.') or low.startswith(stem + '_') or low.startswith(stem + '-') or low == stem or (len(stem) > 6 and stem in low):
            return k, v
    return None


def _walk(top, depth):
    """Files and folders up to a few levels deep, without following links."""
    if not top or not os.path.isdir(top):
        return
    base = top.rstrip('\\').count('\\')
    for root, dirs, files in os.walk(top):
        for d in dirs:                       # every immediate folder is reported, trick names included
            yield os.path.join(root, d), True
        for f in files:
            yield os.path.join(root, f), False
        # but only descend into ordinary folders: not system ones, and never a dot-only or trailing dot/space
        # name, which normalises back to its parent and would make os.walk loop (an NTFS hiding trick).
        if root.count('\\') - base >= depth:
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if not d.startswith('$') and d.rstrip(' .') == d
                       and d.lower() not in ('windows', 'program files', 'program files (x86)', 'packages', 'microsoft', 'node_modules', '.git')]


# ---- cookie theft and shortcut tricks
LNK_PS = r'''
$sh = New-Object -ComObject WScript.Shell
$out = foreach ($p in ($env:MS_L | ConvertFrom-Json)) { try { $l = $sh.CreateShortcut($p); [pscustomobject]@{ Path = $p; Target = [string]$l.TargetPath; Args = [string]$l.Arguments } } catch {} }
ConvertTo-Json -InputObject @($out) -Compress
'''
BROWSER_EXE = re.compile(r'\\(chrome|msedge|brave|opera|vivaldi|firefox|launcher)\.exe$', re.I)
BAD_ARGS = re.compile(r'(--remote-debugging-port|--remote-debugging-pipe|--load-extension|--disable-extensions-except|--user-data-dir=.*(temp|public|programdata)|https?://\S+|--headless)', re.I)


def scan_more(ctx):
    out = []
    add = out.append
    admin = ctx.get('admin')

    # 1. login-screen tools replaced or redirected
    paths = [os.path.join(SYS32, n) for n in LOGIN_TOOLS if os.path.isfile(os.path.join(SYS32, n))]
    signs = S.sign_info(paths)
    for p in paths:
        n, info = os.path.basename(p).lower(), signs.get(p, {})
        desc, pub, status = info.get('Description', ''), info.get('Publisher', ''), info.get('Status', '')
        if WRONG_DESC.search(desc) or (status == 'Valid' and pub and 'microsoft' not in pub.lower()) or S.is_unsigned(info) and status != 'Unknown':
            add(F('tricks', 'loginswap:' + n, 'critical', f'{n} has been replaced: {desc or "an unknown program"}',
                  f'{n} runs from the Windows sign-in screen through {LOGIN_TOOLS[n]}, before anyone signs in, with full system rights.',
                  'This is the "Sticky Keys backdoor": swapping the file gives anyone at the keyboard, or over Remote Desktop, a full-control window with no password.',
                  f'{p}\nDescription: {desc or "none"}\nSigned by: {pub or "nobody"} ({status})',
                  'Run "sfc /scannow" in an administrator command prompt to put the real file back, then change your passwords and have the PC checked.', Active=True))
    ats = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs'
    for at in reg_subkeys(HKLM, ats):
        exe = str(reg_get(HKLM, ats + '\\' + at, 'StartExe', '') or '')
        if '\\' not in exe and not exe.lower().endswith('.exe'):
            continue   # most entries hold a setting number or a built-in name, not a program
        full = os.path.expandvars(exe) if '\\' in exe else os.path.join(SYS32, exe)
        if WRONG_DESC.search(os.path.basename(full)) or os.path.basename(full).lower() in ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'explorer.exe', 'taskmgr.exe') or not S.in_windows(full):
            add(F('tricks', 'at:' + at, 'critical', f'Ease of Access tool "{at}" starts {os.path.basename(exe)}',
                  'Ease of Access can be opened from the sign-in screen, and starts the program registered here.', 'Pointing it at a command prompt or a foreign program is a sign-in-screen backdoor.', exe,
                  'Have the PC checked. Remove the entry under HKLM\\' + ats + '\\' + at + ' if you did not add it.', Active=True))

    # 2. hacking tools on disk or running
    seen = set()
    for pid, (name, _pp) in S.process_snapshot().items():
        hit = _tool(name)
        if hit and pid != os.getpid():
            path = S.process_path(pid)
            seen.add(path.lower())
            what, sev = hit[1]
            add(F('tricks', f'tool-run:{name}:{pid}', 'critical' if sev in ('critical', 'high') else sev, f'Hacking tool running: {name}', f'This looks like {what}.',
                  'If you or your IT team did not start it, someone is attacking this PC or using it to attack others.', f'{path}\nPID {pid}', 'End and block it in the Processes tab, then change your passwords and have the PC checked.', Active=True))
    found = {}
    for top in LOOK_IN:
        depth = 1 if top.endswith(':\\') or top.lower().endswith('programdata') else 3
        for p, is_dir in _walk(top, depth):
            base = os.path.basename(p)
            if not is_dir and os.path.splitext(base)[1].lower() not in CODE_EXT:
                continue
            hit = _tool(base)
            if hit and p.lower() not in seen and p not in found.get(hit[0], []):
                found.setdefault(hit[0], []).append(p)
    for k, ps in found.items():
        what, sev = HACK_TOOLS[k]
        add(F('tricks', 'tool:' + k, sev, f'Hacking tool on this PC: {os.path.basename(ps[0])}', f'This looks like {what}.',
              'Antivirus normally removes these. Finding one means someone put it here on purpose: you for testing, IT staff, or an intruder getting ready.', '\n'.join(ps[:6]),
              'If you did not put it there, quarantine it in the Malware or Downloads tab, change your passwords and have the PC checked.', Path=ps[0]))
    dumps = {}
    for top in (os.environ.get('TEMP', ''), os.path.join(USER, 'Downloads'), os.path.join(USER, 'Desktop'), os.path.join(USER, 'Documents'), os.environ.get('PUBLIC', ''), os.environ.get('ProgramData', ''), os.path.splitdrive(SYS32)[0] + '\\'):
        for p, is_dir in _walk(top, 2):
            low = os.path.basename(p).lower()
            if not is_dir and low.endswith(('.dmp', '.dump')) and ('lsass' in low or 'lsa' == low[:3]):
                dumps.setdefault(os.path.normcase(os.path.abspath(p)), p)
    for p in list(dumps.values())[:10]:
        add(F('tricks', 'lsassdump:' + p, 'critical', f'Copy of the Windows password store: {os.path.basename(p)}', 'A memory dump of LSASS, the Windows process that holds sign-in secrets.',
              'Anyone with this file can pull out passwords and sign-in hashes on another computer. Making one is a key step in most break-ins.', p,
              'Delete it, change the passwords of everyone who signs in to this PC, and have the PC checked.', Path=p))

    # 3. cookie theft: a browser with remote debugging lets any program on the PC read every cookie
    for pid, (name, _pp) in S.process_snapshot().items():
        if name.lower() in ('chrome.exe', 'msedge.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe'):
            cmd = S.process_cmdline(pid)
            if re.search(r'--remote-debugging-(port|pipe)', cmd, re.I):
                add(F('tricks', f'rdbg:{name}', 'critical', f'{name} is running with remote debugging on', 'Remote debugging lets another program take full control of the browser.',
                      'Info-stealing malware starts the browser this way to copy every sign-in cookie and walk past two-factor sign-in. Developers sometimes use it on purpose.',
                      cmd[:500], 'Close the browser completely. If it comes back this way, check the shortcut and the Startup items, then clear your browsing data in the Health tab and change your passwords.', Active=True))
                break
    lnks = []
    for top in (os.path.join(USER, 'Desktop'), os.path.join(os.environ.get('PUBLIC', ''), 'Desktop'), os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs'),
                os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'), os.path.join(os.environ.get('ProgramData', ''), r'Microsoft\Windows\Start Menu\Programs')):
        lnks += [p for p, is_dir in _walk(top, 2) if not is_dir and p.lower().endswith('.lnk')]
    lnks = list({os.path.normcase(os.path.abspath(p)): p for p in lnks}.values())
    if lnks:
        import json
        for r in S.run_powershell(LNK_PS, {'MS_L': json.dumps(lnks[:400])}, timeout=60):
            if isinstance(r, dict) and BROWSER_EXE.search(str(r.get('Target', ''))) and BAD_ARGS.search(str(r.get('Args', ''))):
                bad = BAD_ARGS.search(r['Args']).group(0)
                sev = 'critical' if 'remote-debugging' in bad.lower() or 'load-extension' in bad.lower() else 'medium'
                add(F('tricks', 'lnk:' + r['Path'], sev, f'Browser shortcut changed: {os.path.basename(r["Path"])}',
                      'This shortcut starts your browser with extra instructions.',
                      'Malware edits browser shortcuts to load its own extension, to open a fake page every time, or to switch on remote debugging and steal cookies.' if sev == 'critical' else 'Adware edits shortcuts so your browser always opens its page.',
                      f"{r['Path']}\n{r['Target']} {r['Args']}", 'Delete the shortcut and make a new one from the Start menu.', Path=r['Path']))

    # 4. quieter hiding places
    clsid = r'Software\Classes\CLSID'
    shadow = []
    for c in reg_subkeys(HKCU, clsid):
        dll = str(reg_get(HKCU, rf'{clsid}\{c}\InprocServer32', '', '') or '')
        if dll and reg_get(HKLM, rf'SOFTWARE\Classes\CLSID\{c}\InprocServer32', '', None):   # it hides a real Windows component
            shadow.append((c, os.path.expandvars(dll)))
    signs = S.sign_info([d for _c, d in shadow if os.path.isfile(d)])
    for c, dll in shadow:
        info = signs.get(dll, {})
        if not os.path.isfile(dll) or S.is_unsigned(info):
            add(F('tricks', 'com:' + c, 'high', f'A Windows component is redirected to {os.path.basename(dll)}', 'Your account has its own setting for a Windows component, which Windows uses instead of the real one ("COM hijacking").',
                  'Malware does this to load itself into Explorer or other programs at every sign-in, without a startup entry.', f'{c}\n{dll}\nSigned by: {info.get("Publisher") or "nobody"}',
                  f'If you do not recognise it, delete HKCU\\{clsid}\\{c}.'))
    for k, label in ((r'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders', 'time provider'), (r'SYSTEM\CurrentControlSet\Control\Print\Monitors', 'print monitor')):
        for sub in reg_subkeys(HKLM, k):
            dll = str(reg_get(HKLM, k + '\\' + sub, 'DllName' if 'Time' in k else 'Driver', '') or '')
            if dll and ('\\' in dll and not S.in_windows(os.path.expandvars(dll))):
                add(F('tricks', f'{label}:{sub}', 'high', f'Extra {label} loaded by Windows: {sub}', f'Windows loads every {label} DLL into a system service with full rights.',
                      'A known way to keep malware running as SYSTEM.', dll, 'Have it investigated if you do not recognise it.'))
    for sub in reg_subkeys(HKLM, r'SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors'):
        dll = str(reg_get(HKLM, rf'SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\{sub}', 'Driver', '') or '')
        if dll and dll.lower() not in ('winprint.dll',) and not os.path.isfile(os.path.join(SYS32, 'spool', 'prtprocs', 'x64', dll)):
            add(F('tricks', 'printproc:' + sub, 'high', f'Unusual print processor: {sub}', 'The print spooler loads this DLL with full rights.', 'A known persistence spot.', dll, 'Have it investigated if you do not recognise it.'))
    for hive, hn in ((HKLM, 'HKLM'), (HKCU, 'HKCU')):
        for sub in reg_subkeys(hive, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB'):
            path = str(reg_get(hive, rf'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{sub}', 'DatabasePath', '') or '')
            name = str(reg_get(hive, rf'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{sub}', 'DatabaseDescription', '') or sub)
            if name.startswith('Microsoft Windows Application Compatibility Fix Database') and '\\apppatch\\customsdb\\' in path.lower():
                continue   # Windows' own, delivered by updates
            add(F('tricks', f'shim:{hn}:{sub}', 'medium', f'Custom compatibility fix installed: {name}', 'A "shim" database changes how particular programs start.',
                  'Some old business software needs one. Attackers use shims to inject code into programs, and almost no home PC has one.', path, 'Have it investigated if you do not recognise it.'))
    for folder in (os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Word\STARTUP'), os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Excel\XLSTART'),
                   os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\AddIns')):
        try:
            files = [f for f in os.listdir(folder) if os.path.splitext(f)[1].lower() in ('.dotm', '.xlam', '.xla', '.xlsm', '.xlsb', '.wll', '.xll', '.dot', '.ppam')]
        except OSError:
            continue
        for f in files:
            add(F('tricks', 'office:' + f, 'medium', f'Office opens this file every time it starts: {f}', 'Files in Office\'s start-up folders load with Word or Excel and can contain macros.',
                  'A known way to run malicious macros each time Office opens. Some add-ins are legitimate.', os.path.join(folder, f), 'Move it out of the folder if you do not recognise it.', Path=os.path.join(folder, f)))
    users = S.run_powershell("ConvertTo-Json -InputObject @(Get-LocalUser | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [bool]$_.Enabled } }) -Compress", timeout=30)
    for u in users:
        if isinstance(u, dict) and str(u.get('Name', '')).endswith('$'):
            add(F('tricks', 'dollar:' + u['Name'], 'critical', f'Hidden account: {u["Name"]}', 'Local accounts ending in $ are hidden from many lists in Windows.',
                  'Attackers create these as a secret way back in. Windows itself never creates them.', f"Enabled: {u.get('Enabled')}", 'Disable it in the Accounts tab and have the PC checked.', Active=bool(u.get('Enabled'))))
    try:
        ntfs_tricks(out)
    except Exception:
        pass
    if not admin:
        out.append(S.need_admin('tricks', 'Some system folders and settings used by these checks'))
    return out

# ---- NTFS name and stream tricks (sec-consult's "Pentester's Windows NTFS Tricks Collection")
# A program can ride inside another file as a hidden "alternate data stream", and folders/files can be named with
# trailing dots or spaces, or nothing but dots, so Explorer and many tools can't open, list or scan them.
HIDE_SPOTS = [
    os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
    os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), r'Microsoft\Windows\Start Menu\Programs\StartUp'),
    os.environ.get('TEMP', ''), os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'),
    os.path.join(USER, 'Downloads'), os.path.join(USER, 'Desktop'),
    os.path.join(os.environ.get('PUBLIC', r'C:\Users\Public')), os.environ.get('ProgramData', r'C:\ProgramData'),
    os.environ.get('APPDATA', ''), os.environ.get('LOCALAPPDATA', ''),
]


class _STREAM(ctypes.Structure):
    _fields_ = [('StreamSize', ctypes.c_longlong), ('cStreamName', ctypes.c_wchar * (260 + 36))]


_k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_k32.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_k32.FindFirstStreamW.restype = ctypes.c_void_p
_k32.FindNextStreamW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_k32.FindNextStreamW.restype = wintypes.BOOL
_k32.FindClose.argtypes = [ctypes.c_void_p]
_k32.FindClose.restype = wintypes.BOOL
_INVALID = ctypes.c_void_p(-1).value


def _streams(path):
    """Yield the names of a file's alternate data streams (not the main ':$DATA' one)."""
    data = _STREAM()
    h = _k32.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
    if not h or h == _INVALID:
        return
    try:
        while True:
            nm = data.cStreamName            # looks like ':Zone.Identifier:$DATA'
            if nm and nm != '::$DATA':
                yield nm[1:].rsplit(':$DATA', 1)[0] if nm.endswith(':$DATA') else nm[1:]
            if not _k32.FindNextStreamW(h, ctypes.byref(data)):
                break
    finally:
        _k32.FindClose(h)


def _name_trick(name):
    if name and all(c == '.' for c in name):
        return 'is made only of dots'
    stripped = name.rstrip(' .')
    if stripped != name:
        tail = name[len(stripped):]
        if ' ' in tail:
            return 'ends with a space'
        return 'ends with an extra dot'
    return ''


def ntfs_tricks(out):
    add = out.append
    seen_dirs, flagged, checked = set(), set(), 0
    for top in HIDE_SPOTS:
        key = os.path.normcase(os.path.abspath(top)) if top else ''
        if not top or key in seen_dirs or not os.path.isdir(top):
            continue
        seen_dirs.add(key)
        for path, is_dir in _walk(top, 2):
            name = os.path.basename(path)
            trick = _name_trick(name)
            if trick:
                fkey = 'name:' + os.path.normcase(path)
                if fkey not in flagged:
                    flagged.add(fkey)
                    add(F('tricks', fkey, 'high', f'A {"folder" if is_dir else "file"} is using a name Windows hides',
                          f'Its name {trick}, so File Explorer and most tools can\'t open, list or scan it properly.',
                          'Names like this are a deliberate hiding trick. Windows and normal programs do not create them.',
                          path, 'Have the PC checked. Removing it may need a special path (\\?\\) or a tool like PowerShell.', Path=path))
                continue
            if is_dir or checked > 6000:
                continue
            checked += 1
            try:
                for st in _streams(path):
                    if st.lower() in ('zone.identifier', 'smartscreen', 'afp_afpinfo', 'oecustomproperty'):
                        continue
                    try:
                        with open(f'{path}:{st}', 'rb') as fh:
                            head = fh.read(2)
                    except OSError:
                        continue
                    if head == b'MZ':
                        fkey = 'ads:' + os.path.normcase(path) + ':' + st
                        if fkey not in flagged:
                            flagged.add(fkey)
                            add(F('tricks', fkey, 'critical', 'A program is hidden inside another file',
                                  f'The file "{name}" carries a hidden stream named "{st}" that contains a Windows program.',
                                  'An "alternate data stream" lets code ride inside an ordinary-looking file, out of sight of Explorer and most antivirus. This is a known way to hide malware.',
                                  f'{path}:{st}', 'Have the PC checked. The hidden stream can be removed without deleting the file it hides in.', Path=path, Active=True))
            except OSError:
                continue



def _install():
    """Run the extra checks as part of the existing Hacker tricks check."""
    for i, (key, label, fn) in enumerate(S.SCANS):
        if key == 'tricks':
            def combined(ctx, _old=fn):
                base = [f for f in _old(ctx) if f['Id'] != 'tricks:clean']
                more = scan_more(ctx)
                have = {f['Id'] for f in base}
                out = base + [f for f in more if f['Id'] not in have]
                if not [x for x in out if x['Sev'] in ('critical', 'high')]:
                    out.append(F('tricks', 'clean', 'ok', 'None of the known hacker tricks or tools were found',
                                 'Checked the places attackers use to hide or survive a restart, the sign-in screen tools (Sticky Keys and others), well-known hacking tools on disk and running, copies of the password store, browser cookie-theft tricks, and quieter hiding places such as COM hijacking, print and time providers, shims and Office start-up folders.'))
                return out
            S.SCANS[i] = (key, label, combined)
            return


_install()


# Disguised commands: carets, pieces of environment variables and delayed expansion hide words such as "powershell" from simple filters.
OBFUSCATION_RULES = [
    (r'(\w\^){3,}\w', 'high', 'Disguised command (^ between letters)', 'Carets split words so that filters looking for "powershell" or "http" miss them. Normal programs never write commands this way.'),
    (r'%[a-z_]+:~-?\d+,?-?\d*%.*%[a-z_]+:~-?\d+,?-?\d*%', 'high', 'Disguised command (built from pieces of variables)', 'The command assembles words from fragments of environment variables, a known way to hide what it runs.'),
    (r'cmd(\.exe)?["\s]+/v(:on)?\b.*![a-z_]+:', 'high', 'Disguised command (delayed expansion tricks)', 'Rebuilds the real command at run time so logs don\'t show it.'),
    (r'(-join\s*\(?\s*\[char|\[char\]\s*\d+\s*\+\s*\[char\]|\.replace\(.{1,6},\s*.{0,3}\).*\.replace\(.{1,6},\s*.{0,3}\).*(iex|invoke))', 'high', 'Disguised PowerShell (built character by character)', 'The script builds its own text at run time so that antivirus and logs don\'t see it.'),
    (r'::\$index_allocation|::\$data\b|\\\\\?\\[a-z]:\\[^"\s]*[\s.]["\\]', 'high', 'Hidden-path trick', 'Uses NTFS stream names or names ending in a dot or space, which normal tools can\'t open or list.'),
]
S.COMMAND_RULES.extend((re.compile(p, re.I | re.S), sv, t, w) for p, sv, t, w in OBFUSCATION_RULES)


# Living-off-the-land: trusted Windows programs used to fetch files, run hidden code, or re-open the PC to the outside.
# These watch newly started programs' command lines; the built-in list already covers certutil -urlcache, mshta/regsvr32 from the web, net-user adds, turning off the firewall and clearing logs.
LOLBIN_RULES = [
    (r'certreq(\.exe)?\s+[^\n]*-post|desktopimgdownldr[^\n]*lockscreenurl|ieexec(\.exe)?\s+["\']?https?:|hh(\.exe)?\s+["\']?https?:|mpcmdrun(\.exe)?[^\n]*-downloadfile|bitsadmin[^\n]*/addfile',
     'high', 'Using a trusted Windows tool to download a file', 'Attackers fetch malware with a built-in Windows program so it looks like ordinary activity instead of a download.'),
    (r'(esentutl|makecab|diantz|expand|extrac32)(\.exe)?\s+[^\n]*\\\\[^\\\s]+\\',
     'high', 'Pulling a file from another computer with a system tool', 'These Windows tools are being pointed at a network share to copy a file in, a way of bringing in malware unnoticed.'),
    (r'[^\s:"\\/]+\.[a-z0-9]{1,4}:[^\s:"\\/]+\.(exe|dll|ps1|vbs|js|jse|bat|cmd|hta|scr|sct|com|wsf)\b',
     'high', 'Running a program hidden inside another file', 'A hidden "alternate data stream" lets code ride inside an ordinary-looking file, out of sight of File Explorer and most tools.'),
    (r'for\s+/f[^\n]+do\s+nslookup\b',
     'high', 'Sending information out through DNS look-ups', 'Feeding the result of a command into nslookup is a way to smuggle data off the PC inside DNS requests, which usually pass straight through firewalls.'),
    (r'reg(\.exe)?\s+add[^\n]*fdenytsconnections[^\n]*/d\s*0\b',
     'high', 'Turning on Remote Desktop', 'This lets the PC be controlled from another computer. Intruders switch it on to keep a way back in.'),
    (r'reg(\.exe)?\s+add[^\n]*fallowtogethelp[^\n]*/d\s*1\b|wmic[^\n]*rdtoggle|setallowtsconnections\s+["\']?1\b',
     'high', 'Turning on Remote Assistance or Remote Desktop', 'This opens the PC to remote control, a common way for an intruder to hold on to access.'),
    (r'net1?\s+localgroup\s+("?remote desktop users"?|"?power users"?|"?debugger users"?)\s+[^\n]*/add',
     'medium', 'Giving an account remote-access or extra rights', 'Adding a user to these groups is sometimes normal IT work, but it is also how an intruder keeps entry to the PC.'),
    (r'runas\s+[^\n]*/savecred',
     'medium', 'Running a program with another account\'s saved password', 'If a powerful account\'s password was once saved, this runs programs as that account without needing to know it.'),
]
S.COMMAND_RULES.extend((re.compile(p, re.I | re.S), sv, t, w) for p, sv, t, w in LOLBIN_RULES)
