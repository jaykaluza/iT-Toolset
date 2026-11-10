r"""
Builds MySecurity.exe. Needs PyInstaller on the build PC only (pip install pyinstaller).
Run from this folder:  py build_exe.py     Output: dist\MySecurity.exe, plus its SHA-256 fingerprint.
"""

import hashlib
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD, DIST = os.path.join(HERE, 'build'), os.path.join(HERE, 'dist')
EXE = 'MySecurity'
BG = (22, 22, 23)


def _icon_png(size):
    """A white shield with a green tick on a black rounded square, as PNG bytes."""
    s = float(size)

    def seg(px, py, a, b):
        ax, ay, bx, by = a[0] * s, a[1] * s, b[0] * s, b[1] * s
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
        return math.hypot(px - ax - t * dx, py - ay - t * dy)

    outline = [(.5, .12), (.82, .24), (.82, .5), (.74, .7), (.5, .89), (.26, .7), (.18, .5), (.18, .24), (.5, .12)]
    tick = [(.36, .49), (.46, .59), (.65, .38)]
    rows, radius = bytearray(), 0.2 * s
    for y in range(size):
        rows.append(0)
        for x in range(size):
            px, py = x + .5, y + .5
            qx, qy = abs(px - s / 2) - (s / 2 - radius), abs(py - s / 2) - (s / 2 - radius)
            bg = max(0.0, min(1.0, .5 - (math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - radius)))
            white = max(0.0, min(1.0, .5 - (min(seg(px, py, a, b) for a, b in zip(outline, outline[1:])) - .035 * s))) * bg
            green = max(0.0, min(1.0, .5 - (min(seg(px, py, a, b) for a, b in zip(tick, tick[1:])) - .045 * s))) * bg
            c = [round(v * (1 - white) + 255 * white) for v in BG]
            c = [round(v * (1 - green) + t * green) for v, t in zip(c, (0, 224, 74))]
            rows += bytes((*c, round(255 * bg)))

    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)

    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(bytes(rows), 9)) + chunk(b'IEND', b'')


def write_icon(path, sizes=(256, 64, 48, 32, 16)):
    images = [_icon_png(n) for n in sizes]
    offset = 6 + 16 * len(images)
    entries = b''
    for n, img in zip(sizes, images):
        entries += struct.pack('<BBBBHHII', n % 256, n % 256, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
    with open(path, 'wb') as f:
        f.write(struct.pack('<HHH', 0, 1, len(images)) + entries + b''.join(images))


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
