"""Clean-up: browsing data (everything except saved passwords) and temporary files.

Browsing data is what a thief or a malicious extension takes to get into your accounts without a password (sign-in cookies),
and what tracks you (history, caches). Temporary folders are where downloaded installers and a lot of malware unpack.
"""
import glob
import os
import sqlite3
import subprocess
import sys
import time

import scans_win as S
from scans_win import F, A

LOCAL, ROAMING = os.environ.get('LOCALAPPDATA', ''), os.environ.get('APPDATA', '')
WINDIR = os.environ.get('SystemRoot', r'C:\Windows')

# Chromium browsers: (name, process, where its data lives). Profiles are the folders in it that have a Preferences file.
CHROMIUM = [('Chrome', 'chrome.exe', os.path.join(LOCAL, r'Google\Chrome\User Data')), ('Edge', 'msedge.exe', os.path.join(LOCAL, r'Microsoft\Edge\User Data')),
            ('Brave', 'brave.exe', os.path.join(LOCAL, r'BraveSoftware\Brave-Browser\User Data')), ('Vivaldi', 'vivaldi.exe', os.path.join(LOCAL, r'Vivaldi\User Data')),
            ('Opera', 'opera.exe', os.path.join(ROAMING, r'Opera Software\Opera Stable')), ('Opera GX', 'opera.exe', os.path.join(ROAMING, r'Opera Software\Opera GX Stable'))]
FIREFOX = os.path.join(ROAMING, r'Mozilla\Firefox\Profiles')
FIREFOX_CACHE = os.path.join(LOCAL, r'Mozilla\Firefox\Profiles')

# what goes, per Chromium profile. Kept on purpose: Login Data (passwords), Web Data (payment cards, addresses, search engines),
# Bookmarks, Preferences, Extensions and their storage, Local Storage (extensions such as password managers keep data there), Sessions (open tabs).
C_FILES = ['History', 'History-journal', 'Visited Links', 'Top Sites', 'Top Sites-journal', 'Shortcuts', 'Shortcuts-journal', 'Network Action Predictor',
           'Network Action Predictor-journal', 'Favicons', 'Favicons-journal', 'Media History', 'Media History-journal', 'Cookies', 'Cookies-journal',
           r'Network\Cookies', r'Network\Cookies-journal']
C_DIRS = ['Cache', 'Code Cache', 'GPUCache', 'DawnCache', 'DawnGraphiteCache', 'DawnWebGPUCache', r'Service Worker\CacheStorage', r'Service Worker\ScriptCache',
          'Session Storage', 'blob_storage', 'File System', 'databases']
C_ROOT_DIRS = ['ShaderCache', 'GrShaderCache', 'GraphiteDawnCache']
F_FILES = ['cookies.sqlite', 'cookies.sqlite-wal', 'cookies.sqlite-shm', 'formhistory.sqlite', 'formhistory.sqlite-wal', 'formhistory.sqlite-shm', 'webappsstore.sqlite', 'webappsstore.sqlite-wal']
F_CACHE_DIRS = ['cache2', 'startupCache', 'thumbnails', 'jumpListCache']
SKIP_PREFIX = ('chrome-extension_', 'moz-extension')   # site storage that belongs to extensions stays


def _mb(n):
    return f'{n / 1048576:.0f} MB' if n >= 1048576 else f'{max(1, round(n / 1024))} KB' if n else '0 KB'


def _size(path):
    if os.path.isfile(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _remove(path):
    """Deletes a file or a folder's contents as far as Windows allows. Returns (bytes freed, items that were in use)."""
    if os.path.isfile(path) or os.path.islink(path):
        n = _size(path)
        try:
            os.remove(path)
            return n, 0
        except OSError:
            return 0, 1
    freed = busy = 0
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files:
            p = os.path.join(root, f)
            try:
                n = os.path.getsize(p)
                os.remove(p)
                freed += n
            except OSError:
                busy += 1
        for d in dirs:
            try:
                os.rmdir(os.path.join(root, d))
            except OSError:
                pass
    try:
        os.rmdir(path)
    except OSError:
        pass
    return freed, busy


def _chromium_profiles(root):
    if not os.path.isdir(root):
        return []
    found = [root] if os.path.isfile(os.path.join(root, 'Preferences')) else []
    for d in os.listdir(root):
        p = os.path.join(root, d)
        if os.path.isfile(os.path.join(p, 'Preferences')):
            found.append(p)
    return found


def _mirror(profile):
    """Opera keeps its profile in Roaming and its caches in the same place under Local."""
    if ROAMING and profile.lower().startswith(ROAMING.lower()):
        return LOCAL + profile[len(ROAMING):]
    return ''


def browsing_targets():
    """[(browser, process, [paths to delete])] for every browser with data on this PC."""
    out = []
    for name, proc, root in CHROMIUM:
        paths = []
        for prof in _chromium_profiles(root):
            for base in [prof] + ([_mirror(prof)] if _mirror(prof) else []):
                paths += [os.path.join(base, x) for x in C_FILES + C_DIRS if os.path.exists(os.path.join(base, x))]
                idb = os.path.join(base, 'IndexedDB')
                if os.path.isdir(idb):
                    paths += [os.path.join(idb, x) for x in os.listdir(idb) if not x.startswith(SKIP_PREFIX)]
        if paths:
            paths += [os.path.join(root, x) for x in C_ROOT_DIRS if os.path.exists(os.path.join(root, x))]
            out.append((name, proc, paths))
    paths = []
    for prof in glob.glob(os.path.join(FIREFOX, '*')):
        paths += [os.path.join(prof, x) for x in F_FILES if os.path.exists(os.path.join(prof, x))]
        site = os.path.join(prof, 'storage', 'default')
        if os.path.isdir(site):
            paths += [os.path.join(site, x) for x in os.listdir(site) if not x.startswith(SKIP_PREFIX)]
    for prof in glob.glob(os.path.join(FIREFOX_CACHE, '*')):
        paths += [os.path.join(prof, x) for x in F_CACHE_DIRS if os.path.exists(os.path.join(prof, x))]
    if paths or glob.glob(os.path.join(FIREFOX, '*', 'places.sqlite')):
        out.append(('Firefox', 'firefox.exe', paths))
    return out


def _firefox_history():
    """Firefox keeps history and bookmarks in one database, so history is removed row by row and bookmarks stay."""
    done = failed = 0
    for db in glob.glob(os.path.join(FIREFOX, '*', 'places.sqlite')):
        try:
            con = sqlite3.connect(db, timeout=5)
            with con:
                con.execute('DELETE FROM moz_historyvisits')
                con.execute('DELETE FROM moz_inputhistory')
                con.execute('DELETE FROM moz_places WHERE foreign_count = 0')   # foreign_count counts bookmarks and keywords
                con.execute('DELETE FROM moz_annos WHERE place_id NOT IN (SELECT id FROM moz_places)')   # download history
                con.execute('DELETE FROM moz_origins WHERE id NOT IN (SELECT origin_id FROM moz_places)')
            con.close()
            done += 1
        except sqlite3.Error:
            failed += 1
    return done, failed


def running(procs):
    try:
        r = subprocess.run([os.path.join(S.SYSTEM32, 'tasklist.exe'), '/FO', 'CSV', '/NH'], capture_output=True, timeout=20, creationflags=S.CREATE_NO_WINDOW)
        names = {line.split(b'","')[0].strip(b'"').decode('ascii', 'replace').lower() for line in r.stdout.splitlines() if line}
    except (OSError, subprocess.SubprocessError):
        return []
    return sorted({p for p in procs if p.lower() in names})


def _close(procs):
    """Closes browsers the way the window's X button does, so they save their open tabs; forces only what is still running after that."""
    tk = os.path.join(S.SYSTEM32, 'taskkill.exe')
    for p in procs:
        subprocess.run([tk, '/IM', p], capture_output=True, creationflags=S.CREATE_NO_WINDOW)
    for _ in range(20):
        if not running(procs):
            return
        time.sleep(0.5)
    for p in procs:
        subprocess.run([tk, '/F', '/IM', p], capture_output=True, creationflags=S.CREATE_NO_WINDOW)
    time.sleep(2)


def clear_browsing():
    targets = browsing_targets()
    if not targets:
        return {'ok': True, 'message': 'No browsing data found to clear.'}
    procs = sorted({proc for _n, proc, _p in targets})
    was_open = running(procs)
    if was_open:
        _close(was_open)
    freed = busy = 0
    for _name, _proc, paths in targets:
        for p in paths:
            f, b = _remove(p)
            freed += f
            busy += b
    fx_done, fx_failed = _firefox_history() if any(n == 'Firefox' for n, _p, _x in targets) else (0, 0)
    names = ', '.join(n for n, _p, _x in targets)
    msg = f'Cleared browsing data in {names}: history, download history, cookies and site data, caches and form entries ({_mb(freed)}). Saved passwords, payment cards, addresses and bookmarks were kept. You will need to sign in to websites again.'
    if was_open:
        msg += f" {', '.join(sorted({n for n, p, _x in targets if p in was_open}))} had to be closed first; its open tabs come back when you start it again."
    if busy:
        msg += f' {busy} file{"s were" if busy > 1 else " was"} in use and stayed.'
    if fx_failed:
        msg += ' Firefox history could not be cleared because Firefox was still using it.'
    return {'ok': True, 'message': msg, 'closed': was_open}


# ---- temporary folders

RECENT = 3600   # anything changed in the last hour may belong to something running right now, such as an installer


def temp_folders():
    folders = {os.path.normcase(os.path.abspath(p)): p for p in (os.environ.get('TEMP', ''), os.environ.get('TMP', ''), os.path.join(LOCAL, 'Temp')) if p and os.path.isdir(p)}
    win = os.path.join(WINDIR, 'Temp')
    if S.is_admin() and os.path.isdir(win):
        folders[os.path.normcase(win)] = win
    return list(folders.values())


def _in_use(folder):
    """A folder that a running program has files open in can't be renamed. Such folders are left alone as a whole."""
    probe = folder + '.mysec-check'
    try:
        os.rename(folder, probe)
        os.rename(probe, folder)
        return False
    except OSError:
        return True


def _own():
    """This app's own unpacked files (a one-file exe runs from a folder in Temp)."""
    return {os.path.normcase(os.path.abspath(getattr(sys, '_MEIPASS', '') or '-'))}


def temp_items():
    """[(path, bytes)] that would be deleted: older than an hour, not in use, not this app's own files."""
    now, own, out = time.time(), _own(), []
    for folder in temp_folders():
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for e in entries:
            p = os.path.normcase(os.path.abspath(e.path))
            if p in own:
                continue
            try:
                if now - e.stat(follow_symlinks=False).st_mtime < RECENT:
                    continue
            except OSError:
                continue
            out.append((e.path, _size(e.path)))
    return out


def clear_temp():
    freed = busy = skipped = 0
    for path, _n in temp_items():
        if os.path.isdir(path) and _in_use(path):
            skipped += 1
            continue
        f, b = _remove(path)
        freed += f
        busy += b
    where = ' and '.join(temp_folders())
    msg = f'Cleared {_mb(freed)} of temporary files from {where}.'
    if busy or skipped:
        msg += f' {busy + skipped} item{"s" if busy + skipped > 1 else ""} in use by running programs stayed.'
    msg += ' Files from the last hour were left alone, in case an installer is using them.'
    if not S.is_admin():
        msg += ' Windows\' own Temp folder needs Administrator rights and was skipped.'
    return {'ok': True, 'message': msg}


# ---- the check that offers both

def scan_cleanup(ctx):
    out = []
    targets = browsing_targets()
    if targets:
        size = sum(_size(p) for _n, _proc, paths in targets for p in paths)
        names = ', '.join(n for n, _p, _x in targets)
        cookies = sum(1 for _n, _p, paths in targets for p in paths if os.path.basename(p).lower().startswith('cookies'))
        out.append(F('cleanup', 'browsing', 'medium', f'Browsing data to clear: {_mb(size)} in {names}',
                     'History, download history, cookies and other site data, caches and form entries your browsers keep.',
                     'Sign-in cookies let anyone who copies them into their own browser use your accounts without your password or second factor ("session hijacking"). Malware and malicious extensions steal them, and history shows where you bank and what you do.',
                     f"{names}\n{cookies} cookie store{'s' if cookies != 1 else ''}, {_mb(size)} in all",
                     'Clear it. Saved passwords, payment cards, addresses, bookmarks and extensions are kept. Open browsers are closed first and their tabs come back next time.',
                     A('clear_browsing', 'Clear browsing data', f'Clear browsing data in {names}?\n\nRemoved: history, download history, cookies and site data, caches, form entries.\nKept: saved passwords, payment cards, addresses, bookmarks, extensions.\n\nYou will be signed out of websites. Open browsers are closed first (this dashboard too, and it reopens by itself). Their tabs come back when you start them again.\n\nThis can\'t be undone.')))
    items = temp_items()
    if items:
        size = sum(n for _p, n in items)
        exes = sum(1 for p, _n in items if os.path.splitext(p)[1].lower() in ('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.msi', '.scr'))
        sev = 'medium' if size > 100 * 1048576 or exes else 'low'
        out.append(F('cleanup', 'temp', sev, f'Temporary files to clear: {_mb(size)}' + (f', {exes} of them programs or scripts' if exes else ''),
                     'Files programs left behind in the temporary folders.',
                     'Installers and malware unpack into these folders, and programs or scripts left there can be started again. They also take disk space.',
                     '\n'.join(temp_folders()) + f'\n{len(items)} items older than an hour',
                     'Clear them. Anything changed in the last hour and anything a running program is using is left alone.',
                     A('clear_temp', 'Clear temp files', f'Delete {_mb(size)} of temporary files?\n\n' + '\n'.join(temp_folders()) + '\n\nFiles from the last hour and files in use are left alone. This can\'t be undone.')))
    if not out:
        out.append(F('cleanup', 'clean', 'ok', 'No browsing data or temporary files to clear', 'Nothing to clean up.'))
    return out


S.SCANS.append(('cleanup', 'Browsing data and temp files', scan_cleanup))

import fixes_win as X   # noqa: E402  (registers the two fixes; your own files, so no Administrator rights needed)
X.FIXES.update(clear_browsing=clear_browsing, clear_temp=clear_temp)
X.NO_ADMIN_NEEDED.update({'clear_browsing', 'clear_temp'})
