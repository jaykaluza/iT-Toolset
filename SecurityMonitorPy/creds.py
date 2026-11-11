"""Saved cloud and developer credentials: sign-in files that sit in your account unencrypted.

Anything running as you (including malware) can read these without knowing any password, and use them to reach
your cloud accounts, servers and code. This only notes that a file exists and, for a few, that it holds a secret.
It never reads out, copies or stores the secret itself.
"""
import os

import scans_win as S
from scans_win import F


def _home():
    return os.environ.get('USERPROFILE') or os.path.expanduser('~')


def _appdata():
    return os.environ.get('APPDATA') or os.path.join(_home(), 'AppData', 'Roaming')


def _has(path, *needles, cap=400000):
    """True if the file exists and contains any needle (case-insensitive). Errors count as 'exists, unknown'."""
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read(cap).lower()
        return any(n in text for n in needles) if needles else True
    except OSError:
        return os.path.exists(path)


def scan_creds(ctx):
    out = []
    home, appd = _home(), _appdata()
    local = os.environ.get('LOCALAPPDATA') or os.path.join(home, 'AppData', 'Local')

    # (path, needed?, needles, severity, what it is, who it opens)
    checks = [
        (os.path.join(home, '.aws', 'credentials'), True, ('aws_secret_access_key', 'aws_access_key'), 'high',
         'Amazon Web Services keys', 'full use of your AWS account, where servers and data cost real money'),
        (os.path.join(home, '.azure', 'accessTokens.json'), False, (), 'high', 'Microsoft Azure sign-in tokens', 'your Azure cloud account'),
        (os.path.join(home, '.azure', 'msal_token_cache.json'), False, (), 'high', 'Microsoft Azure sign-in tokens', 'your Azure cloud account'),
        (os.path.join(home, '.azure', 'msal_token_cache.bin'), False, (), 'high', 'Azure PowerShell sign-in tokens', 'your Azure cloud account'),
        (os.path.join(home, '.azure', 'AzureRmContext.json'), True, ('cachedata": "', 'cachedata":"', 'accesstoken', 'refreshtoken'), 'high', 'Azure PowerShell saved sign-in tokens', 'your Azure cloud account and its subscriptions'),
        (os.path.join(home, '.azure', 'TokenCache.dat'), False, (), 'high', 'Azure PowerShell token cache', 'your Azure cloud account'),
        (os.path.join(appd, 'gcloud', 'credentials.db'), False, (), 'high', 'Google Cloud sign-in', 'your Google Cloud account'),
        (os.path.join(appd, 'gcloud', 'legacy_credentials'), False, (), 'high', 'Google Cloud sign-in', 'your Google Cloud account'),
        (os.path.join(home, '.config', 'gcloud', 'credentials.db'), False, (), 'high', 'Google Cloud sign-in', 'your Google Cloud account'),
        (os.path.join(home, '.kube', 'config'), True, ('token:', 'client-key-data', 'password:'), 'high',
         'Kubernetes cluster access', 'control of your Kubernetes clusters'),
        (os.path.join(home, '.docker', 'config.json'), True, ('"auth"', '"identitytoken"'), 'medium',
         'Docker registry sign-in', 'your container registry'),
        (os.path.join(home, '.git-credentials'), True, ('://',), 'high', 'Git sign-in (user name and password in the URL)', 'your source-code accounts'),
        (os.path.join(home, '.npmrc'), True, ('_authtoken', ':_password', '_auth='), 'medium', 'npm package registry token', 'publishing packages as you'),
        (os.path.join(home, '.pypirc'), True, ('password', 'token'), 'medium', 'Python package upload sign-in', 'publishing Python packages as you'),
        (os.path.join(appd, 'FileZilla', 'sitemanager.xml'), True, ('<pass',), 'high', 'FileZilla saved FTP passwords', 'the servers saved in FileZilla'),
        (os.path.join(appd, 'FileZilla', 'recentservers.xml'), True, ('<pass',), 'high', 'FileZilla saved FTP passwords', 'the servers you connected to in FileZilla'),
        (os.path.join(appd, 'WinSCP.ini'), True, ('password=',), 'high', 'WinSCP saved passwords', 'the servers saved in WinSCP'),
        (os.path.join(local, 'WinSCP.ini'), True, ('password=',), 'high', 'WinSCP saved passwords', 'the servers saved in WinSCP'),
    ]
    seen = set()
    for path, need, needles, sev, what, opens in checks:
        key = os.path.normcase(os.path.abspath(path))
        if key in seen or not os.path.exists(path):
            continue
        if need and not _has(path, *needles):
            continue   # file is there but holds no secret (e.g. an empty or SSO-only config)
        seen.add(key)
        out.append(F('creds', 'f:' + key, sev, f'Saved on this PC, unprotected: {what}', f'The file "{os.path.basename(path)}" holds a sign-in that is not protected by a password.',
                     f'Anything running under your account can read it and get {opens}. Attackers grab these the moment they land on a PC.',
                     path, 'Remove it if you no longer use it; otherwise sign in through a tool that stores it securely, and rotate the key so an old copy is useless.',
                     S.A('quarantine', 'Move to quarantine', f'Move this credentials file to quarantine?\n\n{path}\n\nSign-ins that rely on it will stop working until you restore it. You can undo this in the Blocked tab.', path=path),
                     Path=path))

    # WinSCP can also keep passwords in the registry
    try:
        import winreg
        base = r'Software\Martin Prikryl\WinSCP 2\Sessions'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as k:
            i, n = 0, 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base + '\\' + sub) as sk:
                        winreg.QueryValueEx(sk, 'Password')
                        n += 1
                except OSError:
                    pass
            if n:
                out.append(F('creds', 'winscp-reg', 'high', f'WinSCP has {n} saved server password{"s" if n > 1 else ""}',
                             'WinSCP stores these in the registry with weak, reversible scrambling.', 'Anything running as you can unscramble them and sign in to those servers.',
                             base, 'Set a master password in WinSCP, or clear saved sessions you do not use.'))
    except OSError:
        pass

    # PuTTY can keep a plaintext proxy password in each saved session
    try:
        import winreg
        base = r'Software\SimonTatham\PuTTY\Sessions'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as k:
            i, pw = 0, 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base + '\\' + sub) as sk:
                        val, _t = winreg.QueryValueEx(sk, 'ProxyPassword')
                        if val:
                            pw += 1
                except OSError:
                    pass
            if pw:
                out.append(F('creds', 'putty-proxy', 'high', f'PuTTY has {pw} saved proxy password{"s" if pw > 1 else ""} in plain text',
                             'PuTTY stores the proxy password of a saved session unencrypted in the registry.', 'Anything running as you can read it straight out of the registry.',
                             base, 'Clear the proxy password in PuTTY, or remove saved sessions you do not use.'))
    except OSError:
        pass

    # the Windows OpenSSH agent keeps added private keys in the registry, usable with no passphrase
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\OpenSSH\Agent\Keys') as k:
            n = 0
            while True:
                try:
                    winreg.EnumKey(k, n)
                except OSError:
                    break
                n += 1
            if n:
                out.append(F('creds', 'ssh-agent-reg', 'medium', f'{n} SSH key{"s are" if n > 1 else " is"} stored in the Windows SSH agent',
                             'The OpenSSH agent keeps your added private keys in the registry so you do not retype the passphrase.',
                             'Anything running as you can ask the agent to sign in with them, with no passphrase. SSH key files are checked in the Lateral tab.',
                             r'HKCU\Software\OpenSSH\Agent\Keys', 'If you do not use ssh-agent, clear them: in PowerShell run ssh-add -D, and set the ssh-agent service to Manual if you do not need it.'))
    except OSError:
        pass

    if not out:
        out.append(F('creds', 'clean', 'ok', 'No unprotected cloud or tool sign-ins found',
                     'Checked the usual spots for AWS, Azure, Google Cloud, Kubernetes, Docker, Git, npm, PyPI, FileZilla, WinSCP and PuTTY. SSH keys are checked in the Lateral tab.'))
    return out


S.SCANS.append(('creds', 'Saved cloud and tool credentials', scan_creds))
