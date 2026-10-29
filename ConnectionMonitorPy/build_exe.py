r"""
Builds NetMonitor.exe: a double-click app version of NetMonitor.py.

Needs PyInstaller on the build PC only (pip install pyinstaller); people who run the .exe need nothing.
Run from this folder:  py build_exe.py
Output: dist\NetMonitor.exe, plus its SHA-256 fingerprint.
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
BUILD = os.path.join(HERE, 'build')
DIST = os.path.join(HERE, 'dist')


# ---------------------------------------------------------------- app icon (drawn in code, no image files)

CARDINAL = (140, 21, 21)


def _icon_png(size):
    """A white network symbol on a Cardinal Red rounded square, as PNG bytes."""
    s = float(size)
    centre, outer = (0.5, 0.52), [(0.25, 0.27), (0.75, 0.27), (0.25, 0.77), (0.75, 0.77)]

    def seg_dist(px, py, a, b):
        ax, ay, bx, by = a[0] * s, a[1] * s, b[0] * s, b[1] * s
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
        return math.hypot(px - ax - t * dx, py - ay - t * dy)

    rows = bytearray()
    radius, line = 0.2 * s, 0.045 * s
    for y in range(size):
        rows.append(0)   # PNG filter: none
        for x in range(size):
            px, py = x + 0.5, y + 0.5
            # rounded square background (signed distance, 1px anti-aliasing)
            qx, qy = abs(px - s / 2) - (s / 2 - radius), abs(py - s / 2) - (s / 2 - radius)
            sd = math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - radius
            bg = max(0.0, min(1.0, 0.5 - sd))
            # white symbol: lines from the centre node to four outer nodes
            d = min(seg_dist(px, py, centre, o) - line / 2 for o in outer)
            d = min(d, math.hypot(px - centre[0] * s, py - centre[1] * s) - 0.11 * s)
            for o in outer:
                d = min(d, math.hypot(px - o[0] * s, py - o[1] * s) - 0.085 * s)
            fg = max(0.0, min(1.0, 0.5 - d)) * bg
            r, g, b = (round(c * (1 - fg) + 255 * fg) for c in CARDINAL)
            rows += bytes((r, g, b, round(255 * bg)))

    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(bytes(rows), 9)) + chunk(b'IEND', b''))


def write_icon(path, sizes=(256, 64, 48, 32, 16)):
    images = [_icon_png(n) for n in sizes]
    header = struct.pack('<HHH', 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b''
    for n, img in zip(sizes, images):
        entries += struct.pack('<BBBBHHII', n % 256, n % 256, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
    with open(path, 'wb') as f:
        f.write(header + entries + b''.join(images))


# ---------------------------------------------------------------- version details shown in the file's Properties

def write_version_file(path, name, version):
    parts = (list(map(int, re.findall(r'\d+', version))) + [0, 0, 0, 0])[:4]
    four = '.'.join(map(str, parts))
    strings = {'CompanyName': 'iT-Toolset', 'FileDescription': name, 'FileVersion': four,
               'InternalName': 'NetMonitor', 'OriginalFilename': 'NetMonitor.exe', 'ProductName': name,
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
    name = re.search(r"^APP_NAME = '(.+)'", source, re.M).group(1)
    version = re.search(r"^APP_VERSION = '(.+)'", source, re.M).group(1)

    shutil.rmtree(BUILD, ignore_errors=True)
    os.makedirs(BUILD)
    icon, version_file = os.path.join(BUILD, 'NetMonitor.ico'), os.path.join(BUILD, 'version_info.txt')
    write_icon(icon)
    write_version_file(version_file, name, version)

    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--noconsole',
                    '--uac-admin', '--name', 'NetMonitor', '--icon', icon, '--version-file', version_file,
                    '--add-data', f"{os.path.join(HERE, 'dashboard.html')}{os.pathsep}.",
                    '--distpath', DIST, '--workpath', BUILD, '--specpath', BUILD,
                    os.path.join(HERE, 'NetMonitor.py')], check=True)

    exe = os.path.join(DIST, 'NetMonitor.exe')
    digest = hashlib.sha256(open(exe, 'rb').read()).hexdigest().upper()
    print(f'\nBuilt {exe} (version {version}, {os.path.getsize(exe) // 1024} KB)')
    print(f'SHA-256: {digest}')


if __name__ == '__main__':
    main()
