#!/usr/bin/env python3
"""Give the default (male) viking a blonde beard on every display frame.

The web portrait is blonde; the on-device frames were drawn with a brown beard.
This recolours the beard in resources/images/status/*/*<n>.bmp and
static/ragnar1.bmp, and nothing else.

How it stays off the props (shield, laptop, bottle, pet, sword, hood):
every frame is the same body with things drawn over it, so a pixel is beard
only if it matches the plain frame (IDLE/IDLE1.bmp) at the same position.
The beard colours are found once on that plain frame, by hue, and the same
colour shift is then applied to the matching pixels of every other frame.

The originals are read from git (SOURCE_REF), never from the working tree, so
the script can be re-run to re-tune the colour without stacking recolours.

Usage: python3 scripts/recolor_male_blonde.py
Needs Pillow and git.
"""
import colorsys
import glob
import io
import os
import subprocess
import sys

from PIL import Image, ImageChops, ImageFilter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE_REF = 'c2a0fa28'          # last commit with the brown-bearded frames
PLAIN = 'resources/images/status/IDLE/IDLE1.bmp'
SIZE = (78, 78)

BEARD_TOP = 38       # rows above this are helmet, horns and eyes
SHADE_TOP = 46       # the purple-shaded lower beard starts below the eyes
MATCH_TOL = 28       # how close a pixel must be to the plain frame to be body
MOUSTACHE_BOX = (26, 44, 52, 56)


def _sstep(a, b, x):
    t = max(0.0, min(1.0, (x - a) / (b - a)))
    return t * t * (3 - 2 * t)


def _hue_dist(h, target):
    d = abs(h - target)
    return min(d, 360 - d)


def _brown_weight(h, s, v):
    """Lit beard: desaturated brown."""
    return ((1 - _sstep(22, 40, _hue_dist(h, 12)))
            * _sstep(0.10, 0.17, s) * (1 - _sstep(0.36, 0.46, s))
            * _sstep(0.36, 0.46, v) * (1 - _sstep(0.80, 0.90, v)))


def _mauve_weight(h, s, v):
    """Shaded beard: dark purple-mauve."""
    return ((1 - _sstep(38, 58, _hue_dist(h, 295)))
            * _sstep(0.16, 0.26, s) * (1 - _sstep(0.62, 0.72, s))
            * _sstep(0.25, 0.30, v) * (1 - _sstep(0.56, 0.64, v)))


def _blonde(v):
    t = max(0.0, min(1.0, (v - 0.42) / 0.30))
    return colorsys.hsv_to_rgb((36 + 10 * t) / 360, 0.72 - 0.22 * t, 0.80 + 0.20 * t)


def _amber(v):
    t = max(0.0, min(1.0, (v - 0.27) / 0.31))
    return colorsys.hsv_to_rgb((28 + 8 * t) / 360, 0.80 - 0.08 * t, 0.52 + 0.28 * t)


def recolor_plain(plain):
    """The plain frame with its beard recoloured."""
    out = plain.copy()
    px = out.load()
    for y in range(BEARD_TOP, SIZE[1]):
        for x in range(SIZE[0]):
            r, g, b = px[x, y]
            h, s, v = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
            h *= 360
            w = _brown_weight(h, s, v)
            target = _blonde(v)
            if w <= 0.02 and y >= SHADE_TOP:
                w = _mauve_weight(h, s, v)
                target = _amber(v)
            if w <= 0.02:
                continue
            px[x, y] = tuple(int(round(o + (t * 255 - o) * w)) for o, t in zip((r, g, b), target))
    return out


def recolor_frame(frame, plain, plain_blonde):
    """Apply the plain frame's beard recolour to the pixels of `frame` that
    are still plain body (not covered by a prop)."""
    diff = ImageChops.difference(frame, plain).convert('L')
    # Props, grown by a pixel so their soft edges are left alone too.
    props = diff.point(lambda p: 255 if p > MATCH_TOL else 0).filter(ImageFilter.MaxFilter(3))
    shifted = ImageChops.add(ImageChops.subtract(plain_blonde, plain), frame)
    shifted = ImageChops.subtract(shifted, ImageChops.subtract(plain, plain_blonde))
    out = shifted.copy()
    out.paste(frame, mask=props)
    # The tongue-out frames redraw the moustache, so it differs from the plain
    # frame and was just protected as a "prop". Recolour it by hue alone,
    # inside the moustache box only (the tongue itself is far too red and
    # bright to match).
    px, mask = out.load(), props.load()
    x0, y0, x1, y1 = MOUSTACHE_BOX
    for y in range(y0, y1):
        for x in range(x0, x1):
            if not mask[x, y]:
                continue
            r, g, b = px[x, y]
            h, s_, v = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
            w = _brown_weight(h * 360, s_, v)
            if w > 0.02:
                t = _blonde(v)
                px[x, y] = tuple(int(round(o + (c * 255 - o) * w)) for o, c in zip((r, g, b), t))
    return out


def _from_git(path):
    data = subprocess.run(['git', '-C', REPO, 'show', f'{SOURCE_REF}:{path}'],
                          capture_output=True, check=True).stdout
    return Image.open(io.BytesIO(data)).convert('RGB')


def main():
    plain = _from_git(PLAIN)
    plain_blonde = recolor_plain(plain)
    paths = sorted(glob.glob(os.path.join(REPO, 'resources/images/status/*/*[0-9].bmp')))
    paths.append(os.path.join(REPO, 'resources/images/static/ragnar1.bmp'))
    done = 0
    for full in paths:
        rel = os.path.relpath(full, REPO)
        try:
            frame = _from_git(rel)
        except subprocess.CalledProcessError:
            print(f'  skip {rel} (not in {SOURCE_REF})', file=sys.stderr)
            continue
        if frame.size != SIZE:
            continue                     # the 28 px status icons
        recolor_frame(frame, plain, plain_blonde).save(full)
        done += 1
    print(f'recoloured {done} frames')


if __name__ == '__main__':
    main()
