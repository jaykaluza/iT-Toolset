r"""
Builds MySecurity.exe. Needs PyInstaller on the build PC only (pip install pyinstaller).
Run from this folder:  py build_exe.py     Output: dist\MySecurity.exe, plus its SHA-256 fingerprint.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD, DIST = os.path.join(HERE, 'build'), os.path.join(HERE, 'dist')
EXE = 'MySecurity'


# the icon is the same picture as the browser tab icon, shared by every Nesiam tool (nesiam_icon.py in the repo root)
sys.path.insert(0, os.path.dirname(HERE))
from nesiam_icon import write_icon  # noqa: E402


def write_version_file(path, name, version):
    parts = (list(map(int, re.findall(r'\d+', version))) + [0, 0, 0, 0])[:4]
    strings = {'CompanyName': 'Nesiam.com', 'FileDescription': name, 'FileVersion': '.'.join(map(str, parts)), 'InternalName': EXE, 'OriginalFilename': EXE + '.exe', 'ProductName': name, 'ProductVersion': version, 'LegalCopyright': 'jaykaluza'}
    table = ', '.join(f'StringStruct({k!r}, {v!r})' for k, v in strings.items())
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={tuple(parts)}, prodvers={tuple(parts)}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [{table}])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])])
""")


def main():
    source = open(os.path.join(HERE, 'MySecurity.py'), encoding='utf-8').read()
    name = re.search(r"^APP_NAME = '(.+)'", source, re.M).group(1)
    version = re.search(r"^APP_VERSION = '(.+)'", source, re.M).group(1)
    shutil.rmtree(BUILD, ignore_errors=True)
    os.makedirs(BUILD)
    icon, vf = os.path.join(BUILD, 'MySecurity.ico'), os.path.join(BUILD, 'version_info.txt')
    write_icon(icon)
    write_version_file(vf, name, version)
    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--noconsole', '--uac-admin', '--exclude-module', 'multiprocessing', '--name', EXE, '--icon', icon, '--version-file', vf,
                    '--add-data', f"{os.path.join(HERE, 'dashboard.html')}{os.pathsep}.", '--paths', HERE, '--distpath', DIST, '--workpath', BUILD, '--specpath', BUILD, os.path.join(HERE, 'MySecurity.py')], check=True)
    exe = os.path.join(DIST, EXE + '.exe')
    print(f'\nBuilt {exe} (version {version}, {os.path.getsize(exe) // 1024} KB)')
    print('SHA-256:', hashlib.sha256(open(exe, 'rb').read()).hexdigest().upper())


if __name__ == '__main__':
    main()
