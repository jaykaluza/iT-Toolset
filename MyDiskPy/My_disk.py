r"""
My Disk: every disk in this PC, and everything Windows knows about it, on one page.

Standard library only. Windows 10/11.
    py My_disk.py                 asks for Administrator rights (temperature, wear and running hours need them), opens the page
    py My_disk.py --no-elevate    no prompt; everything except temperature, wear, running hours and BitLocker details
    py My_disk.py --demo          made-up disks, to try the page (and for screenshots)

It only reads, except when you resize a partition on the page and confirm it (resize.ps1, Windows' own Resize-Partition,
which needs Administrator rights). The details are read with Windows' own storage commands (inventory.ps1, run every
minute and on Refresh) and its performance counters (live.ps1, every 2 seconds). They stay in memory and are only served
to this run's private local page.
"""

import argparse
import base64
import codecs
import ctypes
import http.server
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import winreg

APP_NAME = 'My Disk'
APP_VERSION = '0.4'
HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = getattr(sys, 'frozen', False)       # running as MyDisk.exe
RESOURCES = getattr(sys, '_MEIPASS', HERE)
WINDIR = os.environ.get('SystemRoot', r'C:\Windows')
POWERSHELL = os.path.join(WINDIR, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
APP_DIR = os.path.join(os.environ.get('LOCALAPPDATA', HERE), 'MyDisk')
SITE_ORIGINS = ('https://nesiam.com', 'https://www.nesiam.com', 'https://jaykaluza.github.io')
LINK_SCHEME = 'mydisk'
HANDOFF_S = 12   # seconds the website's RUN tab has to open the view before the app opens it itself
LINK_PATTERN = re.compile(r'^mydisk:(//)?(run|unregister)?/?$', re.I)
DASHBOARD_URL = re.compile(r'^http://localhost:\d{1,5}/\?k=[\w-]{20,}$')
INVENTORY_EVERY = 60    # seconds between full re-reads
HISTORY = 60            # live readings kept per disk (2 minutes)

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
shell32 = ctypes.WinDLL('shell32', use_last_error=True)

MAKERS = [(r'^(samsung|mz[a-z0-9]{3})', 'Samsung'), (r'^(wdc?\b|wd[a-z0-9]|western digital|wd_)', 'Western Digital'), (r'^(st\d|seagate)', 'Seagate'),
          (r'^(toshiba|kioxia|kxg|thnsn)', 'Kioxia (Toshiba)'), (r'^(ct\d|crucial)', 'Crucial'), (r'^micron', 'Micron'), (r'^kingston|^sa400|^skc|^snv', 'Kingston'),
          (r'^sandisk', 'SanDisk'), (r'^intel|^ssdpe', 'Intel'), (r'^(sk ?hynix|hfs|hfm)', 'SK hynix'), (r'^(hgst|hitachi|hts|hds|hus)', 'HGST (Hitachi)'),
          (r'^lexar', 'Lexar'), (r'^adata|^xpg', 'ADATA'), (r'^transcend|^ts\d', 'Transcend'), (r'^sabrent', 'Sabrent'), (r'^corsair', 'Corsair'), (r'^pny', 'PNY'),
          (r'^verbatim', 'Verbatim'), (r'^lacie', 'LaCie'), (r'^apple', 'Apple'), (r'^(teamgroup|t-force)', 'Team Group'), (r'^phison', 'Phison'), (r'^netac', 'Netac'),
          (r'^(msft|microsoft|virtual)', 'Microsoft (virtual disk)'), (r'^vmware', 'VMware (virtual disk)'), (r'^(vbox|virtualbox)', 'VirtualBox (virtual disk)'), (r'^generic', 'Generic')]
# portable drives whose box says nothing about the inside: these lines are spinning disks
LIKELY_HDD = re.compile(r'elements|expansion|backup ?plus|bup|one touch|my passport|my book|easystore|canvio|game drive|rugged|basic portable|store ?n ?go', re.I)
PART_TYPES = {'System': 'EFI system', 'Reserved': 'Microsoft reserved', 'Recovery': 'Windows recovery', 'Basic': 'Data', 'IFS': 'Data', 'Unknown': 'Unknown'}
GPT_TYPES = {'{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}': 'EFI system partition', '{e3c9e316-0b5c-4db8-817d-f92df00215ae}': 'Microsoft reserved partition',
             '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}': 'Basic data partition', '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}': 'Windows recovery partition',
             '{5808c8aa-7e8f-42e0-85d2-e1e90434cfb3}': 'Dynamic disk data (LDM metadata)', '{af9b60a0-1431-4f62-bc68-3311714a69ad}': 'Dynamic disk data (LDM)',
             '{e75caf8f-f680-4cee-afa3-b001e56efc2d}': 'Storage Spaces', '{0fc63daf-8483-4772-8e79-3d69d8477de4}': 'Linux file system', '{0657fd6d-a4ab-43c4-84e5-0933c84b4f4f}': 'Linux swap',
             '{48465300-0000-11aa-aa11-00306543ecac}': 'Apple HFS+', '{7c3457ef-0000-11aa-aa11-00306543ecac}': 'Apple APFS', '{21686148-6449-6e6f-744e-656564454649}': 'BIOS boot (GRUB)'}
MBR_TYPES = {1: 'FAT12', 4: 'FAT16', 5: 'Extended', 6: 'FAT16', 7: 'NTFS or exFAT', 11: 'FAT32', 12: 'FAT32', 14: 'FAT16', 15: 'Extended', 23: 'Hidden NTFS', 39: 'Windows recovery',
             66: 'Dynamic disk', 130: 'Linux swap', 131: 'Linux', 142: 'Linux LVM', 175: 'Apple HFS+', 238: 'GPT protective', 239: 'EFI system'}
# System.Volume.BitLockerProtection, as Explorer reads it (works without Administrator rights)
BITLOCKER_SHELL = {1: 'On', 2: 'Off', 3: 'Encrypting', 4: 'Decrypting', 5: 'Suspended', 6: 'On (locked)', 8: 'Waiting to be turned on'}
DRIVE_TYPES = {0: 'Unknown', 1: 'No root folder', 2: 'Removable', 4: 'Network drive', 5: 'CD/DVD', 6: 'RAM disk'}


def clean(text, limit=120):
    text = '' if text is None else str(text)
    return re.sub(r'[\x00-\x1f\x7f]', '', text).strip()[:limit]


def maker_of(*names):
    for name in names:
        name = clean(name).lower()
        for pattern, maker in MAKERS:
            if name and re.search(pattern, name):
                return maker
    return ''


def run_powershell(script_name, timeout=90, env_extra=None):
    """Runs one of this app's own read-only scripts, by its full path, with no profile and no inherited modules."""
    with open(os.path.join(RESOURCES, script_name), encoding='utf-8') as f:
        code = f.read()
    env = {k: v for k, v in os.environ.items() if k.upper() != 'PSMODULEPATH'}
    env.update(env_extra or {})
    args = [POWERSHELL, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', base64.b64encode(code.encode('utf-16-le')).decode()]
    return args, env


def read_inventory():
    args, env = run_powershell('inventory.ps1')
    out = subprocess.run(args, env=env, capture_output=True, timeout=120, creationflags=0x08000000).stdout   # CREATE_NO_WINDOW
    return json.loads(out.decode('utf-8', 'replace') or '{}')


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def letter_of(value):
    value = clean(value, 2).rstrip(':')
    return value.upper() if re.fullmatch(r'[A-Za-z]', value) else ''


def trim_state(text):
    """fsutil prints one line per file system, e.g. 'NTFS DisableDeleteNotify = 0  (Allows TRIM operations to be sent to the storage device)'."""
    found = re.search(r'NTFS DisableDeleteNotify\s*=\s*(\d)', text or '')
    return None if not found else found.group(1) == '0'


def build_view(raw):
    """Joins the separate Windows lists into one record per physical disk, in plain words."""
    drives = {d.get('Index'): d for d in as_list(raw.get('drives'))}
    disks = {d.get('Number'): d for d in as_list(raw.get('disks'))}
    volumes = {clean(v.get('Path'), 200).lower(): v for v in as_list(raw.get('volumes'))}
    shell_bl = {letter_of(b.get('Letter')): b.get('Shell') for b in as_list(raw.get('bitlocker'))}
    admin_bl = {letter_of(b.get('Mount')): b for b in as_list(raw.get('bitlockerAdmin'))}
    pagefiles = [clean(p.get('Path'), 260) for p in as_list(raw.get('pagefiles'))]
    trim = trim_state(raw.get('trim'))
    system_drive = letter_of(raw.get('systemDrive'))
    used_paths, out = set(), []

    for p in as_list(raw.get('physical')):
        try:
            number = int(p.get('Id'))
        except (TypeError, ValueError):
            continue
        d, w = disks.get(number, {}), drives.get(number, {})
        bus = clean(p.get('Bus') or d.get('Bus'))
        name = re.sub(r'\s+(USB|SCSI) (Disk )?Device$', '', clean(p.get('Name') or w.get('Model')), flags=re.I)
        media = clean(p.get('Media'))
        kind, kind_sure = (media, True) if media in ('SSD', 'HDD', 'SCM') else ('SSD', True) if bus == 'NVMe' else ('HDD', False) if LIKELY_HDD.search(name) else ('', False)
        spindle = p.get('Spindle')
        external = bus in ('USB', 'SD', 'MMC', '1394') or 'external' in clean(w.get('MediaType')).lower() or 'removable' in clean(w.get('MediaType')).lower()
        size = int(p.get('Size') or 0)
        parts = []
        for q in as_list(raw.get('partitions')):
            if q.get('Disk') != number:
                continue
            paths = [clean(x, 260) for x in as_list(q.get('Paths')) if x]
            vol = next((volumes[x.lower()] for x in paths if x.lower() in volumes), None)
            if vol:
                used_paths.add(clean(vol.get('Path'), 200).lower())
            letter = letter_of(q.get('Letter')) or (letter_of(vol.get('Letter')) if vol else '')
            gpt = clean(q.get('Gpt')).lower()
            kind_name = GPT_TYPES.get(gpt) or (MBR_TYPES.get(q.get('Mbr')) if q.get('Mbr') is not None else '') or PART_TYPES.get(clean(q.get('Type')), clean(q.get('Type')))
            role = 'efi' if clean(q.get('Type')) == 'System' or gpt.startswith('{c12a7328') else 'msr' if clean(q.get('Type')) == 'Reserved' else \
                   'recovery' if clean(q.get('Type')) == 'Recovery' or gpt.startswith('{de94bba4') or q.get('Mbr') == 39 else 'data'
            entry = {'number': q.get('Number'), 'letter': letter, 'role': role, 'type': kind_name, 'gpt': gpt, 'mbr': q.get('Mbr'), 'size': int(q.get('Size') or 0),
                     'offset': int(q.get('Offset') or 0), 'hidden': bool(q.get('Hidden')), 'active': bool(q.get('Active')), 'boot': bool(q.get('Boot')),
                     'system': bool(q.get('System')), 'readOnly': bool(q.get('ReadOnly')), 'mounts': [x for x in paths if not x.startswith('\\\\?\\')], 'volume': None}
            if vol:
                bl_admin = admin_bl.get(letter) if letter else None
                bl = BITLOCKER_SHELL.get(shell_bl.get(letter)) if letter else None
                entry['volume'] = {
                    'label': clean(vol.get('Label')), 'fs': clean(vol.get('FileSystem')), 'size': int(vol.get('Size') or 0), 'free': int(vol.get('Free') or 0),
                    'cluster': vol.get('Cluster'), 'health': clean(vol.get('Health')), 'status': clean(vol.get('Status')), 'dedup': clean(vol.get('Dedup')),
                    'indexing': vol.get('Indexing'), 'dirty': vol.get('Dirty'), 'compressed': vol.get('Compressed'), 'quotas': vol.get('Quotas'),
                    'serial': clean(vol.get('VolumeSerial')), 'windows': letter == system_drive and bool(letter), 'boot': bool(vol.get('SystemVolume')),
                    'pagefile': bool(vol.get('PageFile')) or any(x[:1].upper() == letter for x in pagefiles if letter),
                    'bitlocker': clean(bl_admin.get('Status')) if bl_admin else bl,
                    'bitlockerPercent': bl_admin.get('Percent') if bl_admin else None, 'bitlockerMethod': clean(bl_admin.get('Method')) if bl_admin else '',
                    'bitlockerKeys': [clean(k) for k in as_list(bl_admin.get('Keys'))] if bl_admin else [],
                    'guid': clean(vol.get('Path'), 200)}
            parts.append(entry)
        parts.sort(key=lambda x: x['offset'])
        rel = p.get('Rel') or None
        out.append({
            'number': number, 'name': name, 'maker': maker_of(p.get('Maker'), name, w.get('Model')) or clean(p.get('Maker')), 'model': clean(p.get('Model')) or name,
            'serial': clean(p.get('Serial')).rstrip('.'), 'firmware': clean(p.get('Firmware')), 'kind': kind, 'kindSure': kind_sure, 'bus': bus,
            'rpm': spindle if isinstance(spindle, int) and spindle not in (0, 4294967295) else None, 'external': external,
            'size': size, 'health': clean(p.get('Health')), 'status': [clean(s) for s in as_list(p.get('Status'))],
            'logicalSector': p.get('LogicalSector'), 'physicalSector': p.get('PhysicalSector'), 'usage': clean(p.get('Usage')), 'canPool': p.get('CanPool'),
            'style': clean(d.get('Style')), 'boot': bool(d.get('Boot')), 'system': bool(d.get('System')), 'offline': bool(d.get('Offline')),
            'offlineReason': clean(d.get('OfflineReason')), 'readOnly': bool(d.get('ReadOnly')), 'location': clean(d.get('Location'), 200),
            'uniqueId': clean(d.get('UniqueId'), 200), 'diskId': clean(d.get('Guid')) or (f"{d['Signature']:08X}" if isinstance(d.get('Signature'), int) else ''),
            'largestFree': int(d.get('LargestFree') or 0), 'provisioning': clean(d.get('Provisioning')),
            'interface': clean(w.get('Interface')), 'pnp': clean(w.get('Pnp'), 200), 'driveMedia': clean(w.get('MediaType')),
            'partitions': parts, 'reliability': rel,
        })
    out.sort(key=lambda x: (x['external'], x['number']))
    others = []
    for o in as_list(raw.get('other')):
        others.append({'letter': letter_of(o.get('Letter')), 'type': DRIVE_TYPES.get(o.get('Type'), 'Other'), 'label': clean(o.get('Label')), 'fs': clean(o.get('FileSystem')),
                       'size': int(o.get('Size') or 0), 'free': int(o.get('Free') or 0), 'provider': clean(o.get('Provider'), 260)})
    mode = clean(raw.get('defender'), 40)
    av_names = [clean(x, 80) for x in (raw.get('antivirus') or []) if x and 'defender' not in str(x).lower()][:4]
    antivirus = {'defender': bool(mode) and mode.lower() != 'not running', 'mode': mode, 'others': av_names}   # passive mode still scans on request
    return {'admin': bool(raw.get('admin')), 'disks': out, 'other': others, 'trim': trim, 'pagefiles': pagefiles, 'windowsDrive': system_drive,
            'antivirus': antivirus}


class Disks:
    """What the page shows: the inventory (re-read every minute or on Refresh) and the live activity."""

    def __init__(self, mode):
        self.mode = mode
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.view = None
        self.read_at = 0
        self.error = ''
        self.reading = False
        self.wake = threading.Event()
        self.last_raw = {}
        self.live = {}        # disk number -> list of {t, read, write, active, queue, ms}
        self.free = {}        # drive letter -> free bytes, live
        self.job = None       # the one task that may be running, and how it ended
        self.demo_log = []    # the activity log while trying the demo (never saved)
        self.quit_after = False   # Exit was clicked during a task: stop once it has finished
        self.closing = False      # about to stop: the open page sees this and closes its tab
        self.handoff = None       # started by the website's RUN: (one-time code, expiry) so that browser's tab opens the view

    def close_soon(self):
        """Stop in a few seconds, so the page (it asks every 2 seconds) sees it is closing and closes its tab."""
        self.closing = True
        threading.Timer(3, self.stop.set).start()

    def quit(self):
        """Exit, or during a task, exit once it has finished: never in the middle of one."""
        with self.lock:
            busy = bool(self.job and self.job['status'] == 'running')
            self.quit_after = busy
        if not busy:
            self.close_soon()
        return {'ok': True, 'waiting': busy}
        self.last_client = time.time()

    def refresh(self):
        self.wake.set()

    def state(self):
        with self.lock:
            return {'app': APP_NAME, 'version': APP_VERSION, 'mode': self.mode, 'readAt': self.read_at, 'reading': self.reading, 'error': self.error,
                    'view': self.view, 'live': self.live, 'free': self.free, 'job': self.job, 'quitAfter': self.quit_after, 'closing': self.closing, 'now': time.time()}

    def _target(self, disk, part, need_resizable=True):
        with self.lock:
            d, p = find_partition(self.view, disk, part)
        if need_resizable:
            return d, p, resize_problem(d, p)
        if not d or not p:
            return d, p, 'That partition is no longer there. Refresh and try again.'
        if p['role'] != 'data' or not p['volume'] or not VOLUME_PATH.match(p['volume'].get('guid') or ''):
            return d, p, "Windows' own partitions (start-up, reserved, recovery) are looked after by Windows itself."
        return d, p, ''

    def resize_info(self, disk, part):
        """The smallest and largest size Windows allows for this partition right now."""
        d, p, problem = self._target(disk, part)
        if problem:
            return {'ok': False, 'error': problem}
        if self.mode == 'demo':
            used = p['volume']['size'] - p['volume']['free']
            return {'ok': True, 'size': p['size'], 'min': -(-int(used * 1.05 + 2 * 1024 ** 3) // MIB) * MIB, 'max': p['size'] + space_after(d, p)}
        if not is_admin():
            return {'ok': False, 'admin': True, 'error': 'Resizing a partition needs administrator rights.'}
        return run_resize_script('info', d, p)

    def start_resize(self, disk, part, size):
        d, p, problem = self._target(disk, part)
        if problem:
            return {'ok': False, 'error': problem}
        if self.mode != 'demo' and not is_admin():
            return {'ok': False, 'admin': True, 'error': 'Resizing a partition needs administrator rights.'}
        if not 64 * MIB <= size <= p['size'] + space_after(d, p):   # Windows checks the exact limits again just before it resizes
            return {'ok': False, 'error': 'That size does not fit on the disk.'}
        def work(job):
            if self.mode != 'demo':
                return run_resize_script('resize', d, p, size)
            time.sleep(4)
            with self.lock:
                change = size - p['size']
                p['size'] = size
                p['volume']['size'] += change
                p['volume']['free'] += change
                if p['letter']:
                    self.free[p['letter']] = p['volume']['free']
                self.read_at = time.time()
            return {'ok': True, 'size': size}
        return self._start_job('resize', d, p, work, **{'from': p['size'], 'to': size})

    def start_check(self, disk, part, action):
        """Look for file system errors (scan), repair them now (fix), or have Windows repair the Windows drive at the next restart (atboot)."""
        d, p, problem = self._target(disk, part, need_resizable=False)
        if problem:
            return {'ok': False, 'error': problem}
        if self.mode != 'demo' and not is_admin():
            return {'ok': False, 'admin': True, 'error': 'Checking a drive for errors needs administrator rights.'}
        windows = p['volume']['windows']
        if action == 'fix' and windows:
            return {'ok': False, 'error': "The Windows drive can't be taken offline while Windows runs. Choose to fix it at the next restart."}
        if action == 'atboot' and not windows:
            return {'ok': False, 'error': 'Only the Windows drive needs to wait for a restart.'}

        def work(job):
            if self.mode == 'demo':
                time.sleep(3)
                found = action == 'scan' and p['letter'] == 'E'
                return {'ok': True, 'result': 'ScheduledAtRestart' if action == 'atboot' else 'SpotFixNeeded' if found else 'NoErrorsFound'}
            return run_check_script(action, p)
        return self._start_job(action, d, p, work)

    def start_sfc(self, disk, part):
        """System File Checker: checks Windows' own files against the copies Windows keeps, and replaces damaged ones."""
        d, p, problem = self._target(disk, part, need_resizable=False)
        if problem:
            return {'ok': False, 'error': problem}
        if not p['volume']['windows']:
            return {'ok': False, 'error': 'System File Checker only checks Windows itself, which is on the Windows drive.'}
        if self.mode != 'demo' and not is_admin():
            return {'ok': False, 'admin': True, 'error': 'System File Checker needs administrator rights.'}

        def work(job):
            if self.mode != 'demo':
                return run_sfc(job)
            for pct in range(0, 101, 5):
                if TASK['stop']:
                    break
                job['progress'] = pct
                time.sleep(.5)
            return {'ok': True, 'result': 'clean', 'detail': 'Windows Resource Protection did not find any integrity violations.'}
        return self._start_job('sfc', d, p, work)

    def start_virus(self, disk, part, action):
        """Microsoft Defender: scan the drive's files and its start-up (boot) sectors, or, for the Windows drive,
        restart into Microsoft Defender Offline, which looks for rootkits before Windows loads."""
        d, p, problem = self._target(disk, part, need_resizable=False)
        if problem:
            return {'ok': False, 'error': problem}
        if not p['letter']:
            return {'ok': False, 'error': 'Give this drive a letter first; Microsoft Defender scans drives by their letter.'}
        with self.lock:
            av = (self.view or {}).get('antivirus') or {}
        if self.mode != 'demo' and not av.get('defender'):
            names = ' and '.join(av.get('others') or [])
            return {'ok': False, 'error': f"Microsoft Defender is turned off{f' because {names} protects this PC' if names else ''}. Scan with {names or 'your antivirus'} instead."}
        if action == 'offline' and not p['volume']['windows']:
            return {'ok': False, 'error': 'The deep scan before Windows starts runs from the Windows drive.'}
        if self.mode != 'demo' and not is_admin():
            return {'ok': False, 'admin': True, 'error': 'Scanning for viruses here needs administrator rights.'}

        if action == 'virus':
            self.virus_since = int(time.time())
        since = getattr(self, 'virus_since', int(time.time()))

        def work(job):
            if self.mode == 'demo':
                time.sleep(2 if action != 'virus' else 6)
                test = {'name': 'Virus:DOS/EICAR_Test_File', 'severity': 5, 'status': 1, 'active': True, 'files': [p['letter'] + ':\\Downloads\\eicar_test.com']}
                if action == 'offline':
                    return {'ok': True, 'result': 'scheduled'}
                if action == 'remove':
                    return {'ok': True, 'result': 'removed', 'threats': [{**test, 'status': 4, 'active': False}]}
                return {'ok': True, 'result': 'threats', 'threats': [test]} if p['letter'] == 'E' else {'ok': True, 'result': 'clean'}
            if action == 'offline':
                return run_check_script('offline', p)
            if action == 'remove':
                return run_check_script('remove', p, MD_SINCE=str(since))
            return run_defender(p, since)
        return self._start_job(action, d, p, work)

    def start_health(self, disk, part, action):
        """The deeper checks (structure, permissions, ransomware signs, Windows image) and the fixes they offer."""
        d, p, problem = self._target(disk, part, need_resizable=False)
        if problem:
            return {'ok': False, 'error': problem}
        if action in ('dism', 'dismfix') and not p['volume']['windows']:
            return {'ok': False, 'error': 'The Windows image lives on the Windows drive.'}
        if action in ('perms', 'ransom', 'selfheal', 'permfix', 'shadow') and not p['letter']:
            return {'ok': False, 'error': 'Give this drive a letter first.'}
        with self.lock:
            av = (self.view or {}).get('antivirus') or {}
        if action == 'cfa' and self.mode != 'demo' and not av.get('defender'):
            return {'ok': False, 'error': 'Microsoft Defender is off on this PC, so its ransomware protection can\'t be turned on.'}
        if self.mode != 'demo' and not is_admin():
            return {'ok': False, 'admin': True, 'error': 'This check needs administrator rights.'}

        def work(job):
            return demo_health(job, action, d, p) if self.mode == 'demo' else run_health(job, action, d, p, av)
        return self._start_job(action, d, p, work)

    def activity(self):
        return list(reversed(self.demo_log if self.mode == 'demo' else read_log()))

    def clear_activity(self):
        if self.mode == 'demo':
            self.demo_log.clear()
        else:
            write_log([])
        return {'ok': True}

    def stop_job(self):
        """Ends a running check. Changes (resize, repairs, fixes) are never stopped part-way."""
        with self.lock:
            job = self.job
            if not job or job['status'] != 'running':
                return {'ok': False, 'error': 'Nothing is running.'}
            if job['kind'] not in CAN_STOP:
                return {'ok': False, 'error': "This one changes the drive, so it can't be stopped safely part-way. Let it finish."}
            TASK['stop'] = True
            proc = TASK['proc']
        if proc and proc.poll() is None:
            kill_tree(proc)
        return {'ok': True}

    def _start_job(self, kind, d, p, work, **extra):
        """Runs one change or check at a time, in the background; the page follows it through state.job."""
        with self.lock:
            if self.job and self.job['status'] == 'running':
                return {'ok': False, 'error': f"{JOB_NAMES.get(self.job['kind'], 'Another task')} is still running. Wait for it to finish."}
            TASK['stop'] = False
            job = self.job = {'kind': kind, 'canStop': kind in CAN_STOP, 'disk': d['number'], 'part': p['number'], 'letter': p['letter'], 'label': (p['volume'] or {}).get('label', ''),
                              'status': 'running', 'started': time.time(), 'ended': None, 'message': '', 'result': '', 'detail': '', 'progress': None, 'size': None, 'threats': None, 'findings': None, 'again': '', 'live': '', **extra}

        def run():
            try:
                result = work(job)
            except (OSError, ValueError, subprocess.SubprocessError) as e:
                result = {'ok': False, 'error': clean(e, 300)}
            with self.lock:
                job['status'] = 'stopped' if TASK['stop'] else 'done' if result.get('ok') else 'failed'
                job['message'] = clean(result.get('error'), 600)
                job['result'] = clean(result.get('result'), 60)
                job['detail'] = clean(result.get('detail'), 600)
                job['size'] = result.get('size')
                job['threats'] = clean_threats(result.get('threats'))
                job['findings'] = clean_findings(result.get('findings'))
                if job['findings'] is not None and not job['result']:
                    job['result'] = worst(job['findings'])
                job['again'] = HEALTH_AGAIN.get(kind, '')
                job['ended'] = time.time()
                entry = log_entry(job)
                if self.mode == 'demo':
                    self.demo_log.append(entry)
                else:
                    write_log(read_log() + [entry])
            self.refresh()
            if self.quit_after:   # Exit was clicked while this ran
                self.close_soon()
        threading.Thread(target=run, daemon=True, name=kind).start()
        return {'ok': True}

    def take_live(self, sample, now):
        """Two raw readings make one speed reading."""
        free = {letter_of(f.get('Letter')): int(f.get('Free') or 0) for f in as_list(sample.get('free'))}
        with self.lock:
            self.free = {k: v for k, v in free.items() if k}
            for d in as_list(sample.get('disks')):
                found = re.match(r'^(\d+)', clean(d.get('Name')))
                if not found:
                    continue
                n = int(found.group(1))
                before = self.last_raw.get(n)
                self.last_raw[n] = d
                if not before:
                    continue
                dt = (d['Time'] - before['Time']) / 1e7
                if dt <= 0:
                    continue
                idle = (d['Idle'] - before['Idle']) / 1e7 / dt
                waits = d['WaitBase'] - before['WaitBase']
                ms = ((d['Wait'] - before['Wait']) / (d.get('Freq') or 1e7)) / waits * 1000 if waits > 0 else 0
                point = {'t': round(now, 1), 'read': max(0, round((d['Read'] - before['Read']) / dt)), 'write': max(0, round((d['Write'] - before['Write']) / dt)),
                         'ops': max(0, round((d['Reads'] + d['Writes'] - before['Reads'] - before['Writes']) / dt, 1)),
                         'active': max(0, min(100, round(100 - idle * 100, 1))), 'queue': d.get('Queue', 0), 'ms': round(max(0, ms), 2)}
                self.live.setdefault(str(n), []).append(point)
                del self.live[str(n)][:-HISTORY]


MIB = 1024 * 1024
RESIZABLE_FS = ('NTFS', 'ReFS')


def find_partition(view, disk, part):
    for d in (view or {}).get('disks', []):
        if d['number'] == disk:
            for p in d['partitions']:
                if p['number'] == part:
                    return d, p
    return None, None


def space_after(d, p):
    """Unallocated space directly after this partition: the only room it can grow into."""
    end = p['offset'] + p['size']
    following = [q['offset'] for q in d['partitions'] if q['offset'] >= end]
    return max(0, (min(following) if following else d['size'] - MIB) - end)


def resize_problem(d, p):
    if not d or not p:
        return 'That partition is no longer there. Refresh and try again.'
    if p['role'] != 'data' or not p['volume']:
        return "Windows' own partitions (start-up, reserved, recovery) can't be resized here."
    if p['volume']['fs'] not in RESIZABLE_FS:
        return f"Windows can only resize NTFS and ReFS drives. This one is {p['volume']['fs'] or 'not formatted'}."
    if d['readOnly'] or p['readOnly'] or d['offline']:
        return 'The disk is read-only or offline, so it can’t be changed.'
    if not d.get('uniqueId'):
        return "Windows didn't report an ID for this disk, so My Disk can't make sure it changes the right one."
    return ''


JOB_NAMES = {'resize': 'A resize', 'scan': 'An error check', 'fix': 'A repair', 'atboot': 'A repair', 'sfc': 'System File Checker', 'virus': 'A virus scan', 'offline': 'The deep virus scan', 'remove': 'Removing threats', 'structure': 'A structure check', 'perms': 'A permission check', 'ransom': 'A ransomware check', 'dism': 'The Windows image check', 'dismfix': 'The Windows image repair', 'selfheal': 'A change', 'permfix': 'A permission repair', 'shadow': 'A restore copy', 'cfa': 'A change'}
VOLUME_PATH = re.compile(r'^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$')
SFC_RESULTS = (('did not find any integrity violations', 'clean'), ('successfully repaired', 'repaired'), ('unable to fix', 'unfixed'),
               ('could not perform', 'failed'), ('pending', 'restart'))


# ---------------- activity log: every task My Disk ran, kept on this PC (%LOCALAPPDATA%\MyDisk\activity.json)
LOG_FILE = os.path.join(APP_DIR, 'activity.json')
LOG_KEEP = 500


RESULT_WORDS = {'NoErrorsFound': 'No errors found', 'SpotFixNeeded': 'Small problems found, quick to fix', 'FullRepairNeeded': 'Problems found that need a full repair',
                'ScanNeeded': 'Needs a deeper check', 'ScheduledAtRestart': 'Repair set for the next restart', 'clean': 'No problems found',
                'repaired': 'Damaged files found and repaired', 'unfixed': 'Some damaged files could not be repaired', 'restart': 'A repair is waiting for a restart',
                'scheduled': 'Deep scan set for the next restart', 'removed': 'Threats removed'}


def log_entry(job):
    """One line per finished task: what, where, when, how it ended and what it found."""
    found = job.get('findings') or []
    threats = job.get('threats')
    if job['status'] in ('failed', 'stopped'):
        summary = job['message'] or ('Stopped before it finished.' if job['status'] == 'stopped' else 'It did not finish.')
    elif found:
        summary = '; '.join(f['title'] for f in found if f['level'] != 'good') or found[0]['title']
    elif threats is not None:
        summary = f"{len(threats)} threat{'s' if len(threats) != 1 else ''} found" if threats else 'Nothing found'
    elif job['kind'] == 'resize':
        summary = f"{job.get('from', 0) / 2 ** 30:.1f} GB to {(job.get('size') or job.get('to') or 0) / 2 ** 30:.1f} GB"
    else:
        summary = RESULT_WORDS.get(job['result']) or job['result'] or job['detail'] or 'Done'
    level = job['result'] if job['result'] in LEVELS else 'bad' if job['status'] == 'failed' or (threats and any(t.get('active') for t in threats)) else \
        'watch' if job['status'] == 'stopped' or job['result'] in ('SpotFixNeeded', 'FullRepairNeeded', 'ScanNeeded', 'unfixed', 'restart', 'threats') else 'good'
    return {'kind': job['kind'], 'letter': job['letter'], 'label': job['label'], 'disk': job['disk'], 'part': job['part'], 'started': job['started'],
            'ended': job['ended'], 'status': job['status'], 'level': level, 'summary': clean(summary, 400),
            'findings': [{'level': f['level'], 'title': f['title']} for f in found][:12]}


def read_log():
    try:
        with open(LOG_FILE, encoding='utf-8') as f:
            items = json.load(f)
        return [x for x in items if isinstance(x, dict)][-LOG_KEEP:] if isinstance(items, list) else []
    except (OSError, ValueError):
        return []


def write_log(items):
    """Written only to the app's own folder, and never through a link that points elsewhere."""
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        if is_redirected(APP_DIR):
            return
        tmp = LOG_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(items[-LOG_KEEP:], f)
        os.replace(tmp, LOG_FILE)
    except OSError:
        pass

# ---------------- the running task's process, so Stop can end it (only one task runs at a time)
TASK = {'proc': None, 'stop': False}
CAN_STOP = {'scan', 'virus', 'sfc', 'dism', 'ransom', 'structure', 'perms'}   # checks only: stopping a change part-way could harm the drive


def kill_tree(proc):
    subprocess.run([os.path.join(WINDIR, 'System32', 'taskkill.exe'), '/PID', str(proc.pid), '/T', '/F'], capture_output=True, creationflags=0x08000000)


def run_job_proc(args, env=None, timeout=3600):
    """Like subprocess.run, but registered so Stop can end it (and whatever it started)."""
    proc = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=0x08000000)
    TASK['proc'] = proc
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        out, err = proc.communicate()
    finally:
        TASK['proc'] = None
    return subprocess.CompletedProcess(args, proc.returncode, out, err)


# ---------------- deeper checks: structure, permissions, ransomware signs, Windows image (DISM)
HEALTH_ACTIONS = ('structure', 'perms', 'ransom', 'dism', 'dismfix', 'selfheal', 'permfix', 'shadow', 'cfa')
HEALTH_AGAIN = {'selfheal': 'structure', 'permfix': 'perms', 'shadow': 'ransom', 'cfa': 'ransom', 'dismfix': 'dism'}
FIX_CODES = {'selfheal', 'permfix', 'shadow', 'cfa', 'dismfix', 'chkdsk', 'sfc'}
LEVELS = ('good', 'watch', 'bad')
SYSTEM_SID, ADMINS_SID = 'S-1-5-18', 'S-1-5-32-544'
BROAD_SIDS = {'S-1-1-0': 'Everyone', 'S-1-5-32-546': 'Guests', 'S-1-5-7': 'Anonymous users'}
USERS_SIDS = {'S-1-5-32-545': 'Users', 'S-1-5-11': 'Authenticated Users'}
WINDOWS_OWNERS = {'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', SYSTEM_SID, ADMINS_SID}   # TrustedInstaller, SYSTEM, Administrators
NORMALLY_LOCKED = {'system volume information', '$recycle.bin', 'config.msi', 'documents and settings', 'recovery', '$winreagent', '$sysreset',
                   '$windows.~bt', '$windows.~ws', 'msocache', 'onedrivetemp'}
RANSOM_EXT = {'.locky', '.zepto', '.odin', '.thor', '.aesir', '.osiris', '.cerber', '.cerber2', '.cerber3', '.wncry', '.wncryt', '.wnry', '.wcry', '.ryk',
              '.ryuk', '.conti', '.lockbit', '.basta', '.akira', '.phobos', '.djvu', '.djvuu', '.uudjvu', '.kraken', '.rdm', '.rrk', '.crinf', '.r5a',
              '.xrnt', '.xtbl', '.crypt1', '.da_vinci_code', '.supercrypt', '.ctbl', '.ctb2', '.lechiffre', '.toxcrypt', '.rokku', '.lesli', '.dharma',
              '.arena', '.combo', '.harma', '.eking', '.zzzzz', '.micro', '.vvv', '.ccc', '.ecc', '.exx', '.ezz', '.encrypted', '.locked', '.crypted',
              '.cryptolocker', '.petya', '.coverton', '.purge', '.sage', '.spora', '.jaff', '.gandcrab', '.krab', '.maze', '.sodinokibi', '.revil',
              '.blackcat', '.rhysida', '.8base', '.babuk', '.avos', '.avoslocker', '.nefilim', '.makop', '.mallox', '.netwalker', '.egregor',
              '.ragnar', '.clop', '.cl0p', '.darkside', '.lockergoga', '.ransomexx', '.qilin', '.blacksuit', '.cactus', '.trigona'}
RANSOM_NOTE = re.compile(r'decrypt|ransom|(restore|recover|unlock|return)[ _-]?(my|your|all)?[ _-]?(files|data)|how[ _-]?to[ _-]?(back|get|restore|recover|unlock)'
                         r'|(files|data)[ _-]?(are|were)?[ _-]?(encrypted|locked)', re.I)
NOTE_EXT = {'.txt', '.html', '.htm', '.hta', '.rtf', '.url'}
DHARMA_NAME = re.compile(r'\.id[-\[][0-9a-f]{8}|\[[^\]\s]+@[^\]\s]+\.[a-z]{2,}\]', re.I)


def finding(level, title, text, fix=''):
    return {'level': level, 'title': title, 'text': text, 'fix': fix}


def worst(found):
    return max((f['level'] for f in found), key=LEVELS.index, default='good')


def clean_findings(items):
    if not isinstance(items, list):
        return None
    return [{'level': f.get('level') if f.get('level') in LEVELS else 'watch', 'title': clean(f.get('title'), 120), 'text': clean(f.get('text'), 1200),
             'fix': f.get('fix') if f.get('fix') in FIX_CODES else ''} for f in items[:20] if isinstance(f, dict)]


def run_health_script(action, p):
    args, env = run_powershell('health.ps1', env_extra={'MD_ACTION': action, 'MD_VOLUME': p['volume']['guid']})
    out = run_job_proc(args, env, 6 * 3600).stdout
    lines = [x for x in out.decode('utf-8', 'replace').splitlines() if x.strip().startswith('{')]
    return json.loads(lines[-1]) if lines else {'ok': False, 'error': 'Windows gave no answer.'}


def layout_findings(d):
    """The partition table: overlaps, partitions past the end, alignment, layout style, the start-up partition."""
    found, parts = [], sorted(d['partitions'], key=lambda x: x['offset'])
    if d['health'] and d['health'] != 'Healthy':
        found.append(finding('bad', f"Windows reports the disk as {d['health']}",
                             'Windows itself thinks the disk is failing or damaged. Back up what is on it now, before checking anything else.'))
    for a, b in zip(parts, parts[1:]):
        if a['offset'] + a['size'] > b['offset']:
            found.append(finding('bad', 'Two partitions overlap', f"Partition {a['number']} runs into partition {b['number']}. Both claim the same space, "
                                 'so writing to one can destroy files in the other. Back up both now, then repair the partition table with a tool such as TestDisk.'))
    for x in parts:
        if d['size'] and x['offset'] + x['size'] > d['size']:
            found.append(finding('bad', f"Partition {x['number']} goes past the end of the disk",
                                 'The partition table says it is bigger than the disk. Files near its end can be lost. Back it up and recreate it.'))
    loose = [x for x in parts if x['offset'] % 4096]
    if loose:
        found.append(finding('watch', 'Not lined up with the disk\'s blocks',
                             f"Partition{'s' if len(loose) > 1 else ''} {', '.join(str(x['number']) for x in loose)} start{'' if len(loose) > 1 else 's'} part-way through the disk's 4 KB blocks, "
                             'so every read and write touches two blocks: slower, and more wear on an SSD. Old tools made partitions like this; '
                             'backing up, deleting and recreating the partition in Windows fixes it.'))
    style = d['style']
    if style == 'RAW':
        found.append(finding('bad', 'The disk has no partition table', 'Windows sees the disk but no layout on it, so it shows no drives. '
                             'If it had files, do not initialise it: a recovery tool may still find them.'))
    if style == 'MBR' and d['size'] > 2 ** 41:
        found.append(finding('bad', 'Space past 2 TB can\'t be used', 'The disk uses the old MBR layout, which can only address the first 2 TB. '
                             'Converting it to GPT (after a backup) makes all of it usable.'))
    if style == 'MBR' and (d['boot'] or d['system']):
        found.append(finding('watch', 'Old start-up layout (MBR)', 'Windows starts from an MBR disk, the older BIOS way. Windows 11 expects GPT with UEFI and Secure Boot. '
                             'Microsoft\'s MBR2GPT tool converts it without losing files; back up first.'))
    if style == 'GPT' and (d['boot'] or d['system']) and not any(x['role'] == 'efi' for x in parts):
        found.append(finding('bad', 'No EFI start-up partition', 'Windows starts from this disk but it has no EFI system partition, which a GPT disk needs to start. '
                             'If the PC still starts, it is using one on another disk; if that disk fails or is removed, Windows will not start.'))
    if d['offline']:
        found.append(finding('watch', 'The disk is offline', f"Windows has switched it off{': ' + d['offlineReason'] if d['offlineReason'] else ''}. Its drives can't be used until it is brought online in Disk Management."))
    if d['readOnly']:
        found.append(finding('watch', 'The disk is read-only', 'Nothing can be saved to it. A write-protect switch, a policy or a failing disk can cause this.'))
    if not found:
        found.append(finding('good', 'The partition table is in order', f"{len(parts)} partition{'' if len(parts) == 1 else 's'} in the {style or 'unknown'} layout: none overlap, "
                             'none go past the end of the disk, and all are lined up with the disk\'s blocks.'))
    return found


def ntfs_findings(o, p):
    """The file system's own records: health, the "needs a repair" flag, known corrupt files, self-healing."""
    if not o.get('ok'):
        return [finding('watch', 'Could not read the file system records', clean(o.get('error'), 300))]
    fs = clean(o.get('fs'))
    found = []
    if o.get('health') and o['health'] != 'Healthy':
        found.append(finding('bad', f"Windows reports the file system as {o['health']}", 'Windows has seen damage on this drive. Check it for errors to find and repair it.', 'chkdsk'))
    if fs != 'NTFS':
        found.append(finding('good', f'{fs or "This file system"} has no repair records',
                             'ReFS repairs itself as it goes.' if fs == 'ReFS' else f'Self-healing and the list of corrupt files are NTFS features. Check for errors still works on {fs}.'))
        return found
    dirty, corrupt, heal = (clean(o.get(k), 4000) for k in ('dirty', 'corrupt', 'heal'))
    if not re.search(r'\bdirty\b', dirty, re.I) or re.search(r'access is denied|^error', dirty + '\n' + heal, re.I | re.M):
        found.append(finding('watch', 'Could not read the file system records', 'Windows did not answer the questions about this drive\'s records '
                             f'({clean(dirty or heal, 100) or "no answer"}). Running My Disk as administrator usually fixes this.'))
        return found
    if re.search(r'\bis dirty', dirty, re.I):
        found.append(finding('bad', 'Marked as needing a repair', 'Windows flagged the drive as possibly damaged (after a crash, a power cut or an unplug mid-save). '
                             'It will check it at the next start; you can check it now.', 'chkdsk'))
    entries = [x for x in corrupt.splitlines() if re.search(r'0x[0-9a-f]{8,}', x, re.I)]
    if entries:
        found.append(finding('bad', f"Windows knows of {len(entries)} damaged file record{'s' if len(entries) > 1 else ''}",
                             'NTFS keeps a list of records it found broken and could not fix on the spot. A check for errors repairs them; files they belong to may be lost or cut short.', 'chkdsk'))
    state = re.search(r'is:\s*0x([0-9a-f]+)', heal, re.I)
    if state and not int(state.group(1), 16) & 1:
        found.append(finding('watch', 'Self-healing is off', 'NTFS normally repairs small damage in the background as it finds it. It is switched off here, '
                             'so damage waits for the next full check.', 'selfheal'))
    if not found:
        found.append(finding('good', 'The file system records are in order', 'Not marked as damaged, no known damaged records, and NTFS self-healing is on.'))
    return found


def access_rights(value):
    r = int(value or 0) & 0xFFFFFFFF
    full = (r & 0x1F01FF) == 0x1F01FF or bool(r & 0x10000000)
    write = full or bool(r & (0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x40000000))
    return full, write


def perm_findings(o, p):
    if not o.get('ok'):
        return [finding('watch', 'Could not read the permissions', clean(o.get('error'), 300))]
    windows, letter = p['volume']['windows'], p['letter'] + ':\\'
    rules = [r for r in (o.get('rules') or []) if isinstance(r, dict)]
    found = []
    for sid, who in ((SYSTEM_SID, 'Windows itself (SYSTEM)'), (ADMINS_SID, 'Administrators')):
        if any(r.get('sid') == sid and not r.get('allow') for r in rules):
            found.append(finding('bad', f'{who} is blocked', f'A "deny" entry stops {who} from using {letter}. Backups, updates and repairs can fail.', 'permfix'))
        elif not any(r.get('sid') == sid and r.get('allow') and access_rights(r.get('rights'))[0] for r in rules):
            found.append(finding('bad' if sid == SYSTEM_SID else 'watch', f'{who} lacks full control',
                                 f'Windows normally gives {who} full control of a drive. Without it, backups, indexing, updates and repairs can fail on {letter}.', 'permfix'))
    broad = sorted({BROAD_SIDS[r['sid']] for r in rules if r.get('sid') in BROAD_SIDS and r.get('allow') and access_rights(r.get('rights'))[1]})
    if broad:
        found.append(finding('bad' if windows else 'watch', f"{' and '.join(broad)} can change files",
                             f"{' and '.join(broad)} may change and delete files on {letter}, including guests and programs without an account. "
                             + ('On the Windows drive that lets anything tamper with Windows.' if windows else 'Fine for a shared USB stick; risky for a drive with your own files.'), 'permfix'))
    users_full = sorted({USERS_SIDS[r['sid']] for r in rules if r.get('sid') in USERS_SIDS and r.get('allow') and not r.get('inheritOnly') and access_rights(r.get('rights'))[0]})
    if windows and users_full:
        found.append(finding('watch', f"{' and '.join(users_full)} have full control of {letter}",
                             'Windows normally lets ordinary users add folders at the top of the Windows drive but not change everything there. '
                             'Something widened it; programs running as you can now change more than they should.'))
    if windows and o.get('ownerSid') and o['ownerSid'] not in WINDOWS_OWNERS:
        found.append(finding('watch', f"{letter} is owned by {clean(o.get('owner'), 80)}", 'The Windows drive is normally owned by TrustedInstaller. An owner can change any permission on it.'))
    blocked = [b for b in (o.get('blocked') or []) if isinstance(b, str) and b.lower() not in NORMALLY_LOCKED and not b.startswith('$')]
    if blocked:
        found.append(finding('watch', f"{len(blocked)} folder{'s' if len(blocked) > 1 else ''} even administrators can't open",
                             f"{', '.join(clean(b, 60) for b in blocked[:8])}{'…' if len(blocked) > 8 else ''}. Usually left by another Windows install or by "
                             'user accounts from another PC. To open one, take ownership in its Properties, Security, Advanced.'))
    if not found:
        found.append(finding('good', 'The permissions look right', f'Windows and administrators have full control of {letter}, no one else can change it wholesale, '
                             'and every top folder can be opened.'))
    return found


def ransom_walk(job, letter, windows):
    """Looks at every file name on the drive (not the contents) for ransom notes and ransomware file endings."""
    files, notes, locked, folders = 0, [], [], set()
    stack, last = [letter + ':\\'], time.time()
    while stack and not TASK['stop']:
        folder = stack.pop()
        try:
            entries = os.scandir(folder)
        except OSError:
            continue
        with entries:
            for e in entries:
                try:
                    if e.stat(follow_symlinks=False).st_file_attributes & 0x400:   # junctions and links: their targets are walked on their own
                        continue
                    if e.is_dir(follow_symlinks=False):
                        low = e.name.lower()
                        if low in ('system volume information', '$recycle.bin') or (windows and folder == letter + ':\\' and low == 'windows'):
                            continue
                        stack.append(e.path)
                        continue
                    files += 1
                    name, ext = e.name, os.path.splitext(e.name)[1].lower()
                    if ext in NOTE_EXT and RANSOM_NOTE.search(name):
                        notes.append(e.path)
                    elif ext in RANSOM_EXT or DHARMA_NAME.search(name):
                        locked.append(e.path)
                        folders.add(folder)
                except OSError:
                    continue
        if time.time() - last > 1:
            job['live'] = f'{files:,} files looked at'
            last = time.time()
    job['live'] = f'{files:,} files looked at'
    found = []
    if notes:
        found.append(finding('bad', f"{len(notes)} possible ransom note{'s' if len(notes) > 1 else ''}",
                             f"Files named like the notes ransomware leaves: {'; '.join(notes[:5])}{'…' if len(notes) > 5 else ''}. If you didn't expect them, "
                             'disconnect the PC from the network, don\'t pay, and get help. Some are harmless (a program\'s own "how to restore files" help page).'))
    if locked:
        heavy = len(locked) >= 20 or len(folders) >= 3
        found.append(finding('bad' if heavy else 'watch', f"{len(locked):,} file{'s' if len(locked) > 1 else ''} with ransomware endings",
                             f"For example {'; '.join(locked[:5])}. " + ('That many, in several folders, looks like files locked by ransomware. Disconnect the PC from the network and get help.'
                                                                        if heavy else 'A few can be normal files that happen to use such an ending; open one to check.')))
    if not found:
        found.append(finding('good', 'No ransom notes or locked files', f'None of the {files:,} files on {letter}: look like ransom notes or ransomware-locked files.'))
    return found, files


def ransom_ps_findings(o, p, av):
    if not o.get('ok'):
        return [finding('watch', 'Could not read the restore copies', clean(o.get('error'), 300))]
    found, letter = [], p['letter'] + ':'
    count = o.get('shadows')
    if type(count) is not int:
        found.append(finding('watch', 'Could not list the restore copies', 'Windows did not say whether it keeps earlier versions of this drive.'))
    elif count:
        newest = time.strftime('%d %b %Y %H:%M', time.localtime(o['newest'])) if type(o.get('newest')) is int else 'unknown'
        found.append(finding('good', f"{count} restore cop{'ies' if count > 1 else 'y'} of {letter}", f'The newest is from {newest}. If files get locked or deleted, '
                             'their Properties, Previous Versions can bring earlier copies back. Ransomware often deletes these, so keep a separate backup too.'))
    else:
        found.append(finding('watch', f'No restore copies of {letter}', 'Windows keeps no earlier versions of this drive, so locked or deleted files can\'t be rolled back '
                             'from here. Ransomware usually deletes them anyway, so a backup on another disk or in the cloud matters most.',
                             'shadow' if p['volume']['fs'] in ('NTFS', 'ReFS') else ''))
    if av.get('defender'):
        cfa = o.get('cfa')
        if cfa == 1:
            found.append(finding('good', 'Ransomware protection is on', 'Microsoft Defender stops unknown apps from changing files in your protected folders.'))
        else:
            found.append(finding('watch', 'Ransomware protection is off' if cfa != 2 else 'Ransomware protection only watches',
                                 'Microsoft Defender\'s Controlled folder access can stop unknown apps from changing Documents, Pictures, Desktop and other folders.', 'cfa'))
    elif av.get('others'):
        found.append(finding('good', f"{' and '.join(av['others'])} handles ransomware", 'Microsoft Defender\'s ransomware protection is off because another antivirus protects this PC.'))
    return found


def run_dism(job, repair):
    """DISM checks (or repairs) the component store: the clean copies System File Checker repairs from."""
    folder = 'Sysnative' if sys.maxsize < 2 ** 32 and os.path.isdir(os.path.join(WINDIR, 'Sysnative')) else 'System32'
    proc = TASK['proc'] = subprocess.Popen([os.path.join(WINDIR, folder, 'Dism.exe'), '/Online', '/Cleanup-Image', '/RestoreHealth' if repair else '/ScanHealth', '/English'],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=0x08000000)
    decoder, text = codecs.getincrementaldecoder('mbcs')('replace'), ''
    while True:
        chunk = proc.stdout.read1(4096)
        if not chunk:
            break
        text += decoder.decode(chunk)
        found = re.findall(r'(\d{1,3})(?:\.\d)?%', text[-300:])
        if found:
            job['progress'] = min(100, int(found[-1]))
    proc.wait()
    low = text.lower()
    lines = [x.strip() for x in re.split(r'[\r\n]+', text) if x.strip() and '%' not in x and not x.startswith('Deployment Image') and not x.startswith('Version')]
    if 'elevated permissions' in low or 'administrator' in low and proc.returncode:
        return {'ok': False, 'error': 'DISM needs administrator rights.'}
    if 'no component store corruption detected' in low:
        return {'ok': True, 'findings': [finding('good', 'The Windows image is healthy', 'The store of clean Windows files has no damage, so System File Checker can repair from it.')]}
    if 'restore operation completed successfully' in low:
        return {'ok': True, 'findings': [finding('good', 'The Windows image is repaired', 'DISM replaced the damaged parts with clean copies from Windows Update. '
                                                 'Now run System File Checker so it repairs Windows\' own files from the fixed store.', 'sfc')]}
    if 'component store is repairable' in low:
        return {'ok': True, 'findings': [finding('bad', 'The Windows image is damaged', 'Parts of the store of clean Windows files are broken, so System File Checker '
                                                 'can\'t repair from them. DISM can fetch fresh copies from Windows Update (10 to 30 minutes, needs the internet).', 'dismfix')]}
    if 'not repairable' in low or 'cannot be repaired' in low:
        return {'ok': True, 'findings': [finding('bad', 'The Windows image can\'t be repaired', 'The damage is too deep for DISM. A repair install keeps your files and apps: '
                                                 'run Windows Setup from the Windows 11 download page and choose to keep everything.')]}
    if 'source files could not be found' in low or '0x800f081f' in low:
        return {'ok': True, 'findings': [finding('bad', 'No clean copies to repair from', 'DISM could not get clean files from Windows Update. Check the internet connection and that '
                                                 'Windows Update works, then try again.', 'dismfix')]}
    return {'ok': False, 'error': ' '.join(lines[-3:]) or f'DISM stopped with code {proc.returncode}.'}


def demo_health(job, action, d, p):
    """Made-up results, so the page can be tried."""
    if action in ('dism', 'dismfix'):
        for pct in range(0, 101, 10):
            if TASK['stop']:
                break
            job['progress'] = pct
            time.sleep(.4)
        if action == 'dism':
            return {'ok': True, 'findings': [finding('bad', 'The Windows image is damaged', 'Parts of the store of clean Windows files are broken (demo). DISM can fetch fresh copies from Windows Update.', 'dismfix')]}
        return {'ok': True, 'findings': [finding('good', 'The Windows image is repaired', 'Now run System File Checker (demo).', 'sfc')]}
    time.sleep(2)
    if action == 'structure':
        found = layout_findings(d)
        found += [finding('watch', 'Self-healing is off', 'NTFS normally repairs small damage in the background (demo).', 'selfheal')] if p['letter'] == 'D' else \
            [finding('good', 'The file system records are in order', 'Not marked as damaged, no known damaged records, and NTFS self-healing is on.')]
        return {'ok': True, 'findings': found}
    if action == 'perms':
        rules = [{'sid': SYSTEM_SID, 'allow': True, 'rights': 0x1F01FF}, {'sid': ADMINS_SID, 'allow': True, 'rights': 0x1F01FF}]
        if p['letter'] == 'E':
            rules.append({'sid': 'S-1-1-0', 'allow': True, 'rights': 0x1F01FF})
        return {'ok': True, 'findings': perm_findings({'ok': True, 'rules': rules, 'blocked': ['Old Windows user'] if p['letter'] == 'D' else []}, p)}
    if action == 'ransom':
        for n in range(0, 200001, 25000):
            if TASK['stop']:
                break
            job['live'] = f'{n:,} files looked at'
            time.sleep(.4)
        found = [finding('watch', '3 files with ransomware endings', f"For example {p['letter']}:\\Games\\save1.locked. A few can be normal files (demo).")] if p['letter'] == 'D' else \
            [finding('good', 'No ransom notes or locked files', f"None of the 200,000 files on {p['letter']}: look like ransom notes or ransomware-locked files.")]
        found += ransom_ps_findings({'ok': True, 'shadows': 0 if p['letter'] == 'E' else 3, 'newest': int(time.time()) - 86400, 'cfa': 0}, p, {'defender': True})
        return {'ok': True, 'findings': found}
    return {'ok': True, 'findings': [finding('good', 'Done', 'The change was made (demo).')]}


def run_health(job, action, d, p, av):
    if action == 'structure':
        return {'ok': True, 'findings': layout_findings(d) + (ntfs_findings(run_health_script('structure', p), p) if p['letter'] else [])}
    if action == 'perms':
        if p['volume']['fs'] not in ('NTFS', 'ReFS'):
            return {'ok': True, 'findings': [finding('good', f"{p['volume']['fs']} has no permissions", 'Anyone who can plug the drive in can read and change everything on it. '
                                                      'That is normal for USB sticks and memory cards; BitLocker To Go can lock it with a password.')]}
        return {'ok': True, 'findings': perm_findings(run_health_script('perms', p), p)}
    if action == 'ransom':
        found, _ = ransom_walk(job, p['letter'], p['volume']['windows'])
        return {'ok': True, 'findings': found + ransom_ps_findings(run_health_script('ransomps', p), p, av)}
    if action in ('dism', 'dismfix'):
        return run_dism(job, action == 'dismfix')
    done = run_health_script(action, p)
    if not done.get('ok'):
        return done
    return {'ok': True, 'findings': [finding('good', *{
        'selfheal': ('Self-healing is on', 'NTFS repairs small damage in the background again.'),
        'permfix': ('Permissions repaired', 'Windows and administrators have full control again, and Everyone, Guests and anonymous users no longer have access to the drive.'),
        'shadow': ('Restore copy made', 'Earlier versions of files on this drive can now be brought back from a file\'s Properties, Previous Versions.'),
        'cfa': ('Ransomware protection is on', 'If an app you trust gets blocked from saving, allow it in Windows Security, Ransomware protection.')}[action])]}


def run_check_script(action, p, **extra):
    args, env = run_powershell('check.ps1', env_extra={'MD_ACTION': action, 'MD_VOLUME': p['volume']['guid'], **extra})
    out = run_job_proc(args, env, 12 * 3600).stdout
    lines = [x for x in out.decode('utf-8', 'replace').splitlines() if x.strip().startswith('{')]
    return json.loads(lines[-1]) if lines else {'ok': False, 'error': 'Windows gave no answer.'}


def run_sfc(job):
    """sfc /scannow, following its progress. It writes UTF-16 text and rewrites its progress line with carriage returns."""
    folder = 'Sysnative' if sys.maxsize < 2 ** 32 and os.path.isdir(os.path.join(WINDIR, 'Sysnative')) else 'System32'
    proc = TASK['proc'] = subprocess.Popen([os.path.join(WINDIR, folder, 'sfc.exe'), '/scannow'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=0x08000000)
    decoder, text = codecs.getincrementaldecoder('utf-16-le')('replace'), ''
    while True:
        chunk = proc.stdout.read1(4096)
        if not chunk:
            break
        text += decoder.decode(chunk)
        found = re.findall(r'(\d{1,3})\s*%', text[-200:])
        if found:
            job['progress'] = min(100, int(found[-1]))
    proc.wait()
    lines = [x.strip() for x in re.split(r'[\r\n]+', text) if x.strip() and not re.search(r'\d+\s*%', x)]
    detail = ' '.join(lines[-3:])
    low = text.lower()
    if 'must be an administrator' in low:
        return {'ok': False, 'error': 'System File Checker needs administrator rights.'}
    result = next((code for words, code in SFC_RESULTS if words in low), 'unknown')
    return {'ok': result != 'failed', 'result': result, 'detail': detail, 'error': detail if result == 'failed' else ''}


def clean_threats(items):
    """Only the fields the page shows, as plain values."""
    if not isinstance(items, list):
        return None
    out = []
    for t in items[:20]:
        if isinstance(t, dict):
            out.append({'name': clean(t.get('name'), 120) or 'Unknown threat', 'severity': t.get('severity') if type(t.get('severity')) is int else 0,
                        'status': t.get('status') if type(t.get('status')) is int else 0, 'active': bool(t.get('active')),
                        'files': [clean(f, 260) for f in (t.get('files') or []) if isinstance(f, str)][:5]})
    return out


def run_defender(p, since):
    """MpCmdRun custom scan of one drive plus its boot sectors, then Defender's own list of what it found.
    MpCmdRun exits with 2 both when it finds threats and when it fails, so the words decide."""
    letter = p['letter']
    exe = os.path.join(os.environ.get('ProgramW6432') or os.environ.get('ProgramFiles') or r'C:\Program Files', 'Windows Defender', 'MpCmdRun.exe')
    if not re.fullmatch(r'[A-Z]', letter or '') or not os.path.isfile(exe):
        return {'ok': False, 'error': 'Microsoft Defender is not on this PC.'}
    proc = run_job_proc([exe, '-Scan', '-ScanType', '3', '-File', letter + ':\\', '-BootSectorScan'], None, 24 * 3600)
    text = (proc.stdout + proc.stderr).decode('mbcs', 'replace')
    low = text.lower()
    found = re.search(r'found (\d+) threat', low)
    if found and int(found.group(1)) or re.search(r'threat\s*:', low):
        listed = run_check_script('threats', p, MD_SINCE=str(since))
        return {'ok': True, 'result': 'threats', 'threats': listed.get('threats') or []}
    if proc.returncode == 0 or 'found no threats' in low:
        return {'ok': True, 'result': 'clean'}
    code = re.search(r'hr = (0x[0-9a-fA-F]+)', text)
    return {'ok': False, 'error': 'Microsoft Defender could not scan, so nothing was checked. If you use another antivirus, scan the drive with it instead.'
            + (f' (error {code.group(1)})' if code else '')}


def run_resize_script(action, d, p, size=0):
    """resize.ps1 with every value in an environment variable. A shrink can take many minutes on a busy hard disk."""
    args, env = run_powershell('resize.ps1', env_extra={'MD_ACTION': action, 'MD_DISK': str(int(d['number'])), 'MD_PART': str(int(p['number'])),
                                                        'MD_OFFSET': str(int(p['offset'])), 'MD_UNIQUE': d['uniqueId'], 'MD_SIZE': str(int(size))})
    out = subprocess.run(args, env=env, capture_output=True, timeout=4 * 3600, creationflags=0x08000000).stdout
    lines = [x for x in out.decode('utf-8', 'replace').splitlines() if x.strip().startswith('{')]
    return json.loads(lines[-1]) if lines else {'ok': False, 'error': 'Windows gave no answer.'}


def run_inventory(disks):
    while not disks.stop.is_set():
        with disks.lock:
            disks.reading = True
        try:
            view = build_view(read_inventory())
            with disks.lock:
                disks.view, disks.read_at, disks.error = view, time.time(), ''
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            with disks.lock:
                disks.error = f"Couldn't read the disks: {clean(e, 200)}"
        with disks.lock:
            disks.reading = False
        disks.wake.wait(INVENTORY_EVERY)
        disks.wake.clear()


def run_live(disks):
    while not disks.stop.is_set():
        args, env = run_powershell('live.ps1', env_extra={'MD_PARENT': str(os.getpid())})
        try:
            proc = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        except OSError:
            return
        for line in proc.stdout:
            if disks.stop.is_set():
                break
            try:
                disks.take_live(json.loads(line.decode('utf-8', 'replace')), time.time())
            except (ValueError, KeyError, TypeError):
                pass
        proc.kill()
        disks.stop.wait(5)


# ---------------------------------------------------------------- made-up disks, for trying the page and for screenshots

def demo_view():
    G, T = 1000 ** 3, 1000 ** 4

    def vol(label, fs, size, free, **more):
        return {'label': label, 'fs': fs, 'size': size, 'free': free, 'cluster': 4096, 'health': 'Healthy', 'status': 'OK', 'dedup': 'NotAvailable', 'indexing': True,
                'dirty': False, 'compressed': False, 'quotas': None, 'serial': 'DEMO0001', 'windows': False, 'boot': False, 'pagefile': False, 'bitlocker': 'Off',
                'bitlockerPercent': None, 'bitlockerMethod': '', 'bitlockerKeys': [], 'guid': '\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\', **more}

    def part(n, role, typ, size, offset, letter='', volume=None, **more):
        return {'number': n, 'letter': letter, 'role': role, 'type': typ, 'gpt': '', 'mbr': None, 'size': size, 'offset': offset, 'hidden': role != 'data',
                'active': False, 'boot': bool(volume and volume.get('windows')), 'system': role == 'efi', 'readOnly': False, 'mounts': [f'{letter}:\\'] if letter else [],
                'volume': volume, **more}

    def disk(n, name, maker, kind, bus, size, parts, external=False, rel=None, **more):
        return {'number': n, 'name': name, 'maker': maker, 'model': name, 'serial': f'DEMO-{n}-7F3A91C2', 'firmware': '1.0.4', 'kind': kind, 'kindSure': True, 'bus': bus,
                'rpm': 5400 if kind == 'HDD' else None, 'external': external, 'size': size, 'health': 'Healthy', 'status': ['OK'], 'logicalSector': 512,
                'physicalSector': 4096, 'usage': 'Auto-Select', 'canPool': False, 'style': 'GPT', 'boot': False, 'system': False, 'offline': False, 'offlineReason': '',
                'readOnly': False, 'location': 'Demo location', 'uniqueId': f'DEMO-UNIQUE-{n}', 'diskId': '{00000000-0000-0000-0000-00000000000%d}' % n, 'largestFree': 0,
                'provisioning': 'Fixed', 'interface': 'SCSI', 'pnp': '', 'driveMedia': 'External hard disk media' if external else 'Fixed hard disk media',
                'partitions': parts, 'reliability': rel, **more}

    c = vol('Windows', 'NTFS', 998 * G, 412 * G, windows=True, pagefile=True, bitlocker='On', bitlockerPercent=100, bitlockerMethod='XtsAes128', bitlockerKeys=['Tpm', 'RecoveryPassword'])
    return {'admin': True, 'trim': True, 'pagefiles': ['C:\\pagefile.sys'], 'windowsDrive': 'C', 'antivirus': {'defender': True, 'mode': 'Normal', 'others': []}, 'other': [{'letter': 'Z', 'type': 'Network drive', 'label': 'Photos', 'fs': 'NTFS',
            'size': 4 * T, 'free': 1300 * G, 'provider': '\\\\nas\\photos'}], 'disks': [
        disk(0, 'Example NVMe 1TB', 'Example Corp', 'SSD', 'NVMe', 1000 * G, [part(1, 'efi', 'EFI system partition', 260 * 1024 ** 2, 1024 ** 2),
             part(2, 'msr', 'Microsoft reserved partition', 16 * 1024 ** 2, 261 * 1024 ** 2), part(3, 'data', 'Basic data partition', 998 * G, 277 * 1024 ** 2, 'C', c),
             part(4, 'recovery', 'Windows recovery partition', 1024 ** 3, 277 * 1024 ** 2 + 998 * G)], boot=True, system=True,
             rel={'Temp': 41, 'TempMax': 70, 'Wear': 3, 'Hours': 4120, 'ReadErrors': 0, 'ReadFixed': 0, 'ReadUnfixed': 0, 'WriteErrors': 0, 'WriteUnfixed': 0, 'Starts': 1310,
                  'LoadCycles': None, 'ReadLatencyMax': 18, 'WriteLatencyMax': 41, 'FlushLatencyMax': 9}),
        disk(1, 'Example SATA SSD 2TB', 'Example Corp', 'SSD', 'SATA', 2 * T, [part(1, 'data', 'Basic data partition', 2 * T - 2 * 1024 ** 2, 1024 ** 2, 'D', vol('Games', 'NTFS', 2 * T - 2 * 1024 ** 2, 186 * G))],
             rel={'Temp': 36, 'TempMax': 70, 'Wear': 22, 'Hours': 15880, 'ReadErrors': 0, 'ReadFixed': 0, 'ReadUnfixed': 0, 'WriteErrors': 0, 'WriteUnfixed': 0, 'Starts': 3022,
                  'LoadCycles': None, 'ReadLatencyMax': 30, 'WriteLatencyMax': 66, 'FlushLatencyMax': 12}),
        disk(2, 'Example Portable 4TB', 'Example Corp', 'HDD', 'USB', 4 * T, [part(1, 'data', 'Basic data partition', 4 * T - 2 * 1024 ** 2, 1024 ** 2, 'E', vol('Backup', 'NTFS', 4 * T - 2 * 1024 ** 2, 210 * G, indexing=False))],
             external=True, rel={'Temp': 44, 'TempMax': 60, 'Wear': None, 'Hours': 9020, 'ReadErrors': 12, 'ReadFixed': 12, 'ReadUnfixed': 0, 'WriteErrors': 0, 'WriteUnfixed': 0,
                                 'Starts': 2400, 'LoadCycles': 18030, 'ReadLatencyMax': 240, 'WriteLatencyMax': 310, 'FlushLatencyMax': 80}),
    ]}


def run_demo(disks):
    import math
    import random
    with disks.lock:
        disks.view, disks.read_at = demo_view(), time.time()
    t0 = time.time()
    while not disks.stop.wait(2):
        now = time.time()
        with disks.lock:
            for n, (r, w) in {0: (90e6, 30e6), 1: (220e6, 4e6), 2: (0, 60e6)}.items():
                s = abs(math.sin((now - t0) / (7 + n * 3))) * random.uniform(.3, 1)
                pts = disks.live.setdefault(str(n), [])
                pts.append({'t': round(now, 1), 'read': round(r * s), 'write': round(w * s * random.uniform(.2, 1)), 'ops': round(300 * s, 1), 'active': round(min(100, 60 * s), 1),
                            'queue': 0, 'ms': round(.2 + s * (8 if n == 2 else .6), 2)})
                del pts[:-HISTORY]
            disks.free = {'C': 412 * 1000 ** 3, 'D': 186 * 1000 ** 3, 'E': 210 * 1000 ** 3}
        if disks.wake.is_set():
            disks.wake.clear()
            with disks.lock:
                disks.read_at = time.time()


# ---------------------------------------------------------------- the local page

CSP = "default-src 'none'; script-src 'nonce-{}'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


def make_handler(disks, page, token, port, launch_key, nonce):
    csp = CSP.format(nonce)
    page_path = f'/?k={launch_key}'.encode()
    origins = (f'http://localhost:{port}', f'http://127.0.0.1:{port}')

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = APP_NAME
        sys_version = ''

        def log_message(self, *args):
            pass

        def send(self, status, ctype, body, extra=None):
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', csp)
            self.send_header('Referrer-Policy', 'no-referrer')
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status, obj, extra=None):
            self.send(status, 'application/json; charset=utf-8', json.dumps(obj).encode('utf-8'), extra)

        def site_headers(self):
            """Lets the Nesiam.com website, and only it, ask whether the app is running."""
            origin = self.headers.get('Origin')
            return {'Access-Control-Allow-Origin': origin, 'Vary': 'Origin'} if origin in SITE_ORIGINS else None

        def do_OPTIONS(self):
            headers = self.site_headers()
            if not self.host_ok() or not headers or self.path not in ('/status', '/site-stop'):
                return self.send_json(403, {'ok': False})
            self.send(204, 'text/plain', b'', {**headers, 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'Content-Type',
                                               'Access-Control-Allow-Private-Network': 'true', 'Access-Control-Max-Age': '600'})

        def host_ok(self):
            return self.headers.get('Host') in (f'localhost:{port}', f'127.0.0.1:{port}')

        def token_ok(self):
            origin = self.headers.get('Origin')
            return secrets.compare_digest(self.headers.get('X-Disk-Token', '').encode('utf-8', 'replace'), token.encode()) and (not origin or origin in origins)

        def do_GET(self):
            if not self.host_ok():
                return self.send_json(403, {'ok': False})
            url = urllib.parse.urlsplit(self.path)
            if url.path == '/':
                if secrets.compare_digest(self.path.encode('utf-8', 'replace'), page_path):
                    return self.send(200, 'text/html; charset=utf-8', page)
                return self.send(403, 'text/plain; charset=utf-8', b'This address has expired. Start My Disk again.')
            if url.path == '/status':   # only "it's running" and the version, and only for the website
                headers = self.site_headers()
                if not headers:
                    return self.send_json(403, {'ok': False})
                answer = {'app': APP_NAME, 'version': APP_VERSION, 'stopping': disks.stop.is_set() or disks.closing}
                hand = disks.handoff
                if hand and time.time() < hand[1]:
                    answer['open'] = hand[0]   # only the website can read this (see site_headers), and only for a few seconds
                return self.send_json(200, answer, headers)
            if url.path == '/open':   # the website's RUN tab, with the one-time code from /status: becomes the view
                hand, code = disks.handoff, urllib.parse.parse_qs(url.query).get('t', [''])[0]
                if not (hand and time.time() < hand[1] and secrets.compare_digest(code.encode(), hand[0].encode())):
                    return self.send(403, 'text/plain; charset=utf-8', b'This link has expired. Click RUN on the website again.')
                disks.handoff = None
                return self.send(302, 'text/plain; charset=utf-8', b'', {'Location': f'/?k={launch_key}'})
            if not self.token_ok():
                return self.send_json(403, {'ok': False})
            disks.last_client = time.time()
            if url.path == '/state':
                return self.send_json(200, disks.state())
            if url.path == '/activity':
                return self.send_json(200, {'ok': True, 'entries': disks.activity()})
            self.send_json(404, {'ok': False})

        def read_numbers(self, names):
            """A small JSON body of whole numbers, nothing else."""
            try:
                length = int(self.headers.get('Content-Length') or 0)
                if not 0 < length <= 1024 or 'application/json' not in (self.headers.get('Content-Type') or ''):
                    return None
                body = json.loads(self.rfile.read(length))
                values = {k: body[k] for k in names}
            except (ValueError, KeyError, TypeError):
                return None
            if not all(type(v) is int and 0 <= v < 2 ** 62 for v in values.values()):
                return None
            return values

        def do_POST(self):
            if self.path == '/site-stop':   # the website's STOP button
                headers = self.site_headers()
                if not self.host_ok() or not headers:
                    return self.send_json(403, {'ok': False})
                self.send_json(200, {'ok': True}, headers)
                disks.quit()
                return
            if not (self.host_ok() and self.token_ok()):
                return self.send_json(403, {'ok': False})
            if self.path == '/quit':
                self.send_json(200, disks.quit())
            elif self.path == '/quit-cancel':
                disks.quit_after = False
                self.send_json(200, {'ok': True})
            elif self.path == '/activity-clear':
                self.send_json(200, disks.clear_activity())
            elif self.path == '/stop':
                self.send_json(200, disks.stop_job())
            elif self.path == '/refresh':
                disks.refresh()
                self.send_json(200, {'ok': True})
            elif self.path in ('/resize-info', '/resize'):
                ask = self.read_numbers(('disk', 'part', 'size') if self.path == '/resize' else ('disk', 'part'))
                if not ask:
                    return self.send_json(400, {'ok': False, 'error': 'Bad request.'})
                if self.path == '/resize-info':
                    return self.send_json(200, disks.resize_info(ask['disk'], ask['part']))
                self.send_json(200, disks.start_resize(ask['disk'], ask['part'], ask['size']))
            elif self.path == '/check':   # action: 0 look for errors, 1 fix now, 2 fix the Windows drive at the next restart
                ask = self.read_numbers(('disk', 'part', 'action'))
                if not ask or ask['action'] > 2:
                    return self.send_json(400, {'ok': False, 'error': 'Bad request.'})
                self.send_json(200, disks.start_check(ask['disk'], ask['part'], ('scan', 'fix', 'atboot')[ask['action']]))
            elif self.path == '/sfc':
                ask = self.read_numbers(('disk', 'part'))
                if not ask:
                    return self.send_json(400, {'ok': False, 'error': 'Bad request.'})
                self.send_json(200, disks.start_sfc(ask['disk'], ask['part']))
            elif self.path == '/health':   # action: an index into HEALTH_ACTIONS
                ask = self.read_numbers(('disk', 'part', 'action'))
                if not ask or ask['action'] >= len(HEALTH_ACTIONS):
                    return self.send_json(400, {'ok': False, 'error': 'Bad request.'})
                self.send_json(200, disks.start_health(ask['disk'], ask['part'], HEALTH_ACTIONS[ask['action']]))
            elif self.path == '/virus':   # action: 0 scan the drive and its boot sectors, 1 restart into Microsoft Defender Offline, 2 remove what it found
                ask = self.read_numbers(('disk', 'part', 'action'))
                if not ask or ask['action'] > 2:
                    return self.send_json(400, {'ok': False, 'error': 'Bad request.'})
                self.send_json(200, disks.start_virus(ask['disk'], ask['part'], ('virus', 'offline', 'remove')[ask['action']]))
            elif self.path == '/elevate' and disks.mode == 'live' and not is_admin():
                ok = restart_as_admin()
                self.send_json(200, {'ok': ok})
                if ok:
                    disks.stop.set()
            else:
                self.send_json(404, {'ok': False})

    return Handler


class LocalServer(http.server.ThreadingHTTPServer):
    """Refuses a port another program holds. Python's default on Windows would share it, and requests would reach the wrong app."""
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self):
        if os.name == 'nt':
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def start_server(disks, first_port):
    with open(os.path.join(RESOURCES, 'my_disk.html'), encoding='utf-8') as f:
        page = f.read()
    token, launch_key, nonce = secrets.token_hex(32), secrets.token_urlsafe(24), secrets.token_urlsafe(18)
    body = page.replace('__DISK_TOKEN__', token).replace('<script>', f'<script nonce="{nonce}">').encode('utf-8')
    for port in range(first_port, first_port + 3):   # the website looks for the app on these three
        try:
            server = LocalServer(('127.0.0.1', port), make_handler(disks, body, token, port, launch_key, nonce))
        except OSError:
            continue
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f'http://localhost:{port}/?k={launch_key}'
    sys.exit(f"Couldn't open a local port for My Disk (tried {first_port} to {first_port + 2}). Close another program using them and try again.")


def is_admin():
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def open_view(url):
    """A browser started from an elevated app would be elevated too, so Explorer opens it as the signed-in user, via a short-lived forwarding page."""
    if not is_admin():
        return webbrowser.open(url)
    try:
        handle, path = tempfile.mkstemp(prefix='my_disk_', suffix='.html')
        with os.fdopen(handle, 'w', encoding='utf-8') as f:
            f.write(f'<!doctype html><meta charset=utf-8><script>location.replace({json.dumps(url)})</script>'
                    f'<meta http-equiv=refresh content="0;url={url}"><a href="{url}">Open My Disk</a>')
        subprocess.Popen([os.path.join(WINDIR, 'explorer.exe'), path])
    except OSError:
        return False

    def remove():
        try:
            os.remove(path)
        except OSError:
            pass
    threading.Timer(20, remove).start()
    return True


def relaunch_as_admin(extra=()):
    """True if Windows started an elevated copy (the person clicked Yes)."""
    target = sys.executable if FROZEN else os.path.abspath(__file__)
    args = [*([] if FROZEN else [target]), *[a for a in sys.argv[1:] if a not in ('--no-elevate',)], *extra]
    program = sys.executable
    return (shell32.ShellExecuteW(None, 'runas', program, subprocess.list2cmdline([*args, '--no-elevate']), None, 1) or 0) > 32


_instance_mutex = None


def another_copy_running():
    global _instance_mutex
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    _instance_mutex = kernel32.CreateMutexW(None, False, 'Local\\MyDisk')
    return ctypes.get_last_error() == 183   # ERROR_ALREADY_EXISTS


def restart_as_admin():
    """The page's 'Restart as administrator' button: let go of the one-copy lock, start an elevated copy, and stop if it started."""
    global _instance_mutex
    held = _instance_mutex
    if held:
        kernel32.CloseHandle(ctypes.c_void_p(held))
        _instance_mutex = None
    if relaunch_as_admin():
        return True
    if held:
        another_copy_running()   # the person said No: keep being the one copy
    return False


def show_error(message):
    ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x10)


def is_redirected(path):
    """True if this folder is a junction or symbolic link, which could send the app's files somewhere else."""
    try:
        return os.lstat(path).st_reparse_tag in (0xA0000003, 0xA000000C)
    except OSError:
        return False


def link_target():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf'Software\Classes\{LINK_SCHEME}\shell\open\command') as k:
            found = re.match(r'^"([^"]+)"', winreg.QueryValueEx(k, '')[0])
            return found.group(1) if found else ''
    except OSError:
        return ''


def register_link(exe):
    """Lets a website's RUN button start this app, for this Windows user."""
    base = rf'Software\Classes\{LINK_SCHEME}'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'URL:{APP_NAME}')
        winreg.SetValueEx(k, 'URL Protocol', 0, winreg.REG_SZ, '')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r'\DefaultIcon') as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'"{exe}",0')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r'\shell\open\command') as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'"{exe}" "%1"')


def unregister_link():
    base = rf'Software\Classes\{LINK_SCHEME}'
    for sub in (r'\shell\open\command', r'\shell\open', r'\shell', r'\DefaultIcon', ''):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + sub)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description='Every disk in this PC and everything Windows knows about it.')
    ap.add_argument('--demo', action='store_true', help='made-up disks, to try the page')
    ap.add_argument('--no-elevate', action='store_true', help="don't ask for Administrator rights (no temperature, wear or running hours without them)")
    ap.add_argument('--no-browser', action='store_true', help="don't open the browser")
    ap.add_argument('--port', type=int, default=8811, help='local port (default 8811; the other Nesiam tools use 8765 to 8803)')
    ap.add_argument('--idle-exit', type=int, default=3, help='minutes without an open page before stopping (0 = never)')
    ap.add_argument('--app', action='store_true', default=FROZEN, help='one copy only (default for the exe)')
    ap.add_argument('link', nargs='?', help=argparse.SUPPRESS)   # mydisk://run, passed by Windows
    args = ap.parse_args()

    exe = sys.executable if FROZEN else os.path.abspath(__file__)
    if args.link and not LINK_PATTERN.match(args.link):
        sys.exit('The app was started from an unsupported link. Links can only start the app or remove the link.')
    if args.link and (LINK_PATTERN.match(args.link).group(2) or '').lower() == 'unregister':
        unregister_link()
        if FROZEN:
            ctypes.windll.user32.MessageBoxW(None, 'The RUN button link was removed. Running MyDisk.exe again sets it up again.', APP_NAME, 0x40)
        return
    # the copy you run takes over the RUN link, so the website starts this exe and not an older or moved one
    if FROZEN and args.app and os.path.normcase(os.path.abspath(link_target() or '')) != os.path.normcase(os.path.abspath(exe)):
        try:
            register_link(exe)
        except OSError:
            pass
    url_file = os.path.join(APP_DIR, 'running.url')
    if args.app:
        os.makedirs(APP_DIR, exist_ok=True)
        if is_admin() and is_redirected(APP_DIR):
            sys.exit(f"The app's folder ({APP_DIR}) points somewhere else, so it won't write there with Administrator rights. Delete that folder and start the app again.")
        if another_copy_running():
            try:
                with open(url_file, encoding='utf-8') as f:
                    saved = f.read().strip()
                if not DASHBOARD_URL.match(saved) or not open_view(saved):
                    show_error('The saved address is not valid. Stop My Disk and start it again.')
            except OSError:
                show_error('My Disk is already running, but its address could not be found. Wait a minute and try again.')
            return

    if not args.demo and not args.no_elevate and not is_admin() and relaunch_as_admin():
        return

    disks = Disks('demo' if args.demo else 'live')
    workers = [run_demo] if args.demo else [run_inventory, run_live]
    for worker in workers:
        threading.Thread(target=worker, args=(disks,), daemon=True, name=worker.__name__).start()

    server, url = start_server(disks, args.port)
    if args.app:
        with open(url_file, 'w', encoding='utf-8') as f:
            f.write(url)
    print(f'{APP_NAME} is running: {url}')
    print('Close with the Exit button on the page, or Ctrl+C here.')
    if args.link and not args.no_browser:
        # started by the website's RUN: its tab, in whichever browser clicked RUN, picks up the view. If that
        # browser can't reach the app (it may block the site from reaching apps on this PC), open it here instead.
        disks.handoff = (secrets.token_urlsafe(18), time.time() + HANDOFF_S)

        def fallback():
            if disks.handoff:
                disks.handoff = None
                open_view(url)
        threading.Timer(HANDOFF_S, fallback).start()
    elif not args.no_browser:
        open_view(url)
    disks.last_client = time.time()
    try:
        while not disks.stop.wait(1):
            if args.idle_exit and time.time() - disks.last_client > args.idle_exit * 60:
                print('The page has been closed for a while, stopping.')
                break
    except KeyboardInterrupt:
        pass
    disks.stop.set()
    server.shutdown()
    if args.app:
        try:   # an elevated copy started from the page may have written its own address here already
            with open(url_file, encoding='utf-8') as f:
                mine = f.read().strip() == url
            if mine:
                os.remove(url_file)
        except OSError:
            pass
    os._exit(0)


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
        with open(os.path.join(APP_DIR, 'error.log'), 'a', encoding='utf-8') as f:
            f.write(f'{time.ctime()}\n{traceback.format_exc()}\n')
        show_error(f'My Disk stopped because of an unexpected problem. Details are in {APP_DIR}\\error.log')
