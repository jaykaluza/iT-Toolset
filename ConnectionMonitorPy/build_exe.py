r"""
Builds MyConnections.exe: a double-click app version of NetMonitor.py.

Needs PyInstaller on the build PC only (pip install pyinstaller); people who run the .exe need nothing.
Run from this folder:  py build_exe.py
Output: dist\MyConnections.exe, plus its SHA-256 fingerprint.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, 'build')
DIST = os.path.join(HERE, 'dist')


# ---------------------------------------------------------------- app icon: the browser tab icon, shared by every Nesiam tool

sys.path.insert(0, os.path.dirname(HERE))
from nesiam_icon import write_icon  # noqa: E402  (nesiam_icon.py in the repo root)


# ---------------------------------------------------------------- version details shown in the file's Properties

EXE = 'MyConnections'   # the app's file name (the source stays NetMonitor.py)


def write_version_file(path, name, version):
    parts = (list(map(int, re.findall(r'\d+', version))) + [0, 0, 0, 0])[:4]
    four = '.'.join(map(str, parts))
    strings = {'CompanyName': 'Nesiam.com', 'FileDescription': name, 'FileVersion': four,
               'InternalName': EXE, 'OriginalFilename': EXE + '.exe', 'ProductName': name,
               'ProductVersion': version, 'LegalCopyright': 'jaykaluza'}
    table = ', '.join(f'StringStruct({k!r}, {v!r})' for k, v in strings.items())
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={tuple(parts)}, prodvers={tuple(parts)}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [{table}])]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])])
""")


def main():
    source = open(os.path.join(HERE, 'NetMonitor.py'), encoding='utf-8').read()
    name = re.search(r'''^APP_NAME = (['"])(.+)\1''', source, re.M).group(2)
    version = re.search(r"^APP_VERSION = '(.+)'", source, re.M).group(1)

    shutil.rmtree(BUILD, ignore_errors=True)
    os.makedirs(BUILD)
    icon, version_file = os.path.join(BUILD, 'NetMonitor.ico'), os.path.join(BUILD, 'version_info.txt')
    write_icon(icon)
    write_version_file(version_file, name, version)

    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--noconsole',
                    '--uac-admin', '--exclude-module', 'multiprocessing', '--name', EXE, '--icon', icon, '--version-file', version_file,
                    '--add-data', f"{os.path.join(HERE, 'dashboard.html')}{os.pathsep}.",
                    '--distpath', DIST, '--workpath', BUILD, '--specpath', BUILD,
                    os.path.join(HERE, 'NetMonitor.py')], check=True)

    exe = os.path.join(DIST, EXE + '.exe')
    digest = hashlib.sha256(open(exe, 'rb').read()).hexdigest().upper()
    print(f'\nBuilt {exe} (version {version}, {os.path.getsize(exe) // 1024} KB)')
    print(f'SHA-256: {digest}')


if __name__ == '__main__':
    main()
