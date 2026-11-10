"""
The Nesiam app icon, shared by every tool's build_exe.py: the same picture as the browser tab icon
(a white "n" with a red, a blue and a green ball on a dark rounded square), drawn in code at each size.

    python nesiam_icon.py preview.png    writes a 256-pixel PNG to look at
"""

import math
import struct
import sys
import zlib

# all shapes in the tab icon's 32 x 32 grid
BACKGROUND, CORNER = (0x16, 0x16, 0x17), 7.0
RED = [(0, 'ffffff'), (.1, 'ff8a80'), (.42, 'ff1400'), (1, 'f00000')]
BLUE = [(0, 'ffffff'), (.1, '6fc3ff'), (.42, '0090ff'), (1, '0060ff')]
GREEN = [(0, 'ffffff'), (.1, '7dffa8'), (.42, '00ff55'), (1, '00d13f')]
BALLS_UNDER = [((19.5, 24.0), 4.0, RED)]                       # drawn before the "n", as in the tab icon
BALLS_OVER = [((19.0, 6.5), 4.0, BLUE), ((27.0, 24.0), 3.6, GREEN)]
STROKE = 2.0                                                   # half of the "n"'s 4-unit line


def _cubic(p0, p1, p2, p3, steps=16):
    out = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        out.append((u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
                    u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]))
    return out


# the arch and right leg of the "n": M7.5 18 c0-4 2.6-6.2 6-6.2 s6 2.2 6 6.2 V27
ARCH = _cubic((7.5, 18), (7.5, 14), (10.1, 11.8), (13.5, 11.8)) + _cubic((13.5, 11.8), (16.9, 11.8), (19.5, 14), (19.5, 18))[1:] + [(19.5, 27)]
SEGMENTS = list(zip(ARCH, ARCH[1:]))


def _segment_distance(x, y, a, b):
    dx, dy = b[0] - a[0], b[1] - a[1]
    t = max(0.0, min(1.0, ((x - a[0]) * dx + (y - a[1]) * dy) / (dx * dx + dy * dy)))
    return math.hypot(x - a[0] - t * dx, y - a[1] - t * dy)


def _n_distance(x, y):
    """Signed distance to the white "n" (negative inside)."""
    qx, qy = abs(x - 7.5) - STROKE, abs(y - 19.75) - 7.25        # left leg: M7.5 27V12.5, flat ends
    left = math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0)
    if 3 < x < 24 and 7 < y < 30:
        arch = max(min(_segment_distance(x, y, a, b) for a, b in SEGMENTS) - STROKE, y - 27)   # flat bottom end
    else:
        arch = 9.0
    return min(left, arch)


def _gradient(stops, t):
    t = max(0.0, min(1.0, t))
    for (t0, c0), (t1, c1) in zip(stops, stops[1:]):
        if t <= t1:
            k = (t - t0) / (t1 - t0) if t1 > t0 else 0
            a, b = bytes.fromhex(c0), bytes.fromhex(c1)
            return tuple(a[i] + (b[i] - a[i]) * k for i in range(3))
    return tuple(bytes.fromhex(stops[-1][1]))


def _ball(x, y, centre, radius, stops):
    """(colour, signed distance) of a shaded ball, lit from the upper left like the tab icon's gradient."""
    lx, ly = centre[0] - radius + .64 * radius, centre[1] - radius + .56 * radius
    colour = _gradient(stops, math.hypot(x - lx, y - ly) / (1.7 * radius))
    return colour, math.hypot(x - centre[0], y - centre[1]) - radius


def render(size):
    """RGBA rows for a size x size icon."""
    unit = 32.0 / size            # one pixel, in grid units: used to smooth every edge by one pixel
    rows = bytearray()
    for py in range(size):
        rows.append(0)            # PNG filter: none
        for px in range(size):
            x, y = (px + .5) * unit, (py + .5) * unit
            qx, qy = abs(x - 16) - (16 - CORNER), abs(y - 16) - (16 - CORNER)
            edge = math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - CORNER
            alpha = max(0.0, min(1.0, .5 - edge / unit))
            if alpha == 0:
                rows += b'\0\0\0\0'
                continue
            c = list(BACKGROUND)

            def paint(colour, distance):
                cover = max(0.0, min(1.0, .5 - distance / unit))
                if cover:
                    for i in range(3):
                        c[i] = c[i] * (1 - cover) + colour[i] * cover

            for centre, radius, stops in BALLS_UNDER:
                paint(*_ball(x, y, centre, radius, stops))
            paint((255, 255, 255), _n_distance(x, y))
            for centre, radius, stops in BALLS_OVER:
                paint(*_ball(x, y, centre, radius, stops))
            rows += bytes((*(round(v) for v in c), round(255 * alpha)))
    return rows


def png(size):
    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(bytes(render(size)), 9)) + chunk(b'IEND', b''))


def write_icon(path, sizes=(256, 64, 48, 32, 24, 16)):
    """A Windows .ico holding the icon at each size."""
    images = [png(n) for n in sizes]
    offset, entries = 6 + 16 * len(images), b''
    for n, image in zip(sizes, images):
        entries += struct.pack('<BBBBHHII', n % 256, n % 256, 0, 0, 1, 32, len(image), offset)
        offset += len(image)
    with open(path, 'wb') as f:
        f.write(struct.pack('<HHH', 0, 1, len(images)) + entries + b''.join(images))


if __name__ == '__main__':
    with open(sys.argv[1] if len(sys.argv) > 1 else 'nesiam-icon.png', 'wb') as f:
        f.write(png(int(sys.argv[2]) if len(sys.argv) > 2 else 256))
