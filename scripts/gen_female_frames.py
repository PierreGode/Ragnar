#!/usr/bin/env python3
"""Build the shieldmaiden display frames in resources/images/status/woman/.

The on-device character is a 78x78 1-bit sprite. The female art is a set of
detailed full-colour, full-body illustrations, which turn into noise if they
are simply shrunk to that size. This script does what makes them legible:

  1. crop each illustration to a head-and-shoulders portrait, so the face
     fills the frame the way the default viking's does;
  2. brighten and add contrast so the pale hair and skin go white instead of
     speckled grey, then dither;
  3. force the ink outlines to solid black so they are not broken up by the
     dither.

Two stages, so the frames can be re-tuned without the 17 MB of original art:

  gen_female_frames.py --from-originals DIR
      DIR holds the original illustrations (axe.png, bluuetooth.png, ...).
      Writes the portrait crops to woman/src/<name>.png (greyscale, 296 px).

  gen_female_frames.py
      Renders woman/<name>.png (78x78, 1-bit) from woman/src/.

Tuning knobs are the constants below. Needs Pillow.
"""
import argparse
import os
import sys

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageOps

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WOMAN_DIR = os.path.join(REPO, 'resources', 'images', 'status', 'woman')
SRC_DIR = os.path.join(WOMAN_DIR, 'src')

FRAME = 78           # sprite size, same as the default frames
ART = 74             # portrait size inside the frame (2 px side margin, 4 px top)
SRC_SIZE = ART * 4   # stored portrait crop

GAMMA = 0.7          # < 1 brightens: hair and skin go white
CONTRAST = 1.5
LINE_DARK = 80       # source pixels darker than this are outline ink
LINE_COVER = 90      # share (0-255) of a sprite pixel that must be ink to force it black

# Portrait crop per original, in fractions of the character's bounding box:
# (centre x / width, top / height, side / width) -> output name.
PORTRAITS = {
    'axe':         (0.58, 0.00, 0.72, 'axe'),
    'bluuetooth':  (0.50, 0.00, 0.82, 'bluetooth'),
    'bowandarrow': (0.48, 0.00, 0.73, 'bow'),
    'ftp':         (0.46, 0.00, 0.74, 'ftp'),
    'laptop':      (0.50, 0.00, 0.80, 'laptop'),
    'raspbery':    (0.53, 0.02, 0.66, 'raspberry'),
    'swords':      (0.49, 0.00, 0.73, 'swords'),
    'wifi':        (0.51, 0.00, 0.77, 'wifi'),
}

# Props that end up as black blobs at the edge of a portrait, painted out
# before cropping. Polygons in bounding-box coordinates scaled to width 500.
PAINT_OUT = {
    'raspbery': [   # the two antenna panels and their masts
        [(0, 0), (121, 0), (108, 70), (113, 160), (102, 215), (0, 215)],
        [(396, 0), (500, 0), (500, 344), (376, 344), (376, 190), (394, 185),
         (406, 172), (423, 110), (400, 45)],
    ],
}


def _character(path):
    """The illustration flattened on white and cropped to the character."""
    im = Image.open(path).convert('RGBA')
    flat = Image.new('RGB', im.size, 'white')
    flat.paste(im, mask=im.split()[-1])
    ink = ImageOps.invert(flat.convert('L')).point(lambda p: 255 if p > 12 else 0)
    return flat.crop(ink.getbbox())


def build_sources(originals_dir):
    os.makedirs(SRC_DIR, exist_ok=True)
    for name, (cx, top, side, out) in PORTRAITS.items():
        path = os.path.join(originals_dir, name + '.png')
        if not os.path.exists(path):
            print(f'  missing {path}', file=sys.stderr)
            continue
        char = _character(path)
        k = char.width / 500.0
        draw = ImageDraw.Draw(char)
        for poly in PAINT_OUT.get(name, ()):
            draw.polygon([(x * k, y * k) for x, y in poly], fill='white')
        px = int(char.width * side)
        x0 = int(char.width * cx - px / 2)
        y0 = int(char.height * top)
        square = Image.new('RGB', (px, px), 'white')
        square.paste(char, (-x0, -y0))
        square.convert('L').resize((SRC_SIZE, SRC_SIZE), Image.LANCZOS) \
              .save(os.path.join(SRC_DIR, out + '.png'), optimize=True)
        print(f'  src/{out}.png')


def render_frame(src):
    """A greyscale portrait crop -> the 78x78 1-bit display frame."""
    grey = src.convert('L')
    lines = grey.point(lambda p: 255 if p < LINE_DARK else 0).resize((ART, ART), Image.BOX)
    small = grey.resize((ART, ART), Image.LANCZOS)
    small = small.filter(ImageFilter.UnsharpMask(radius=1, percent=120, threshold=2))
    small = small.point(lambda p: int(255 * ((p / 255.0) ** GAMMA)))
    small = ImageEnhance.Contrast(small).enhance(CONTRAST)
    art = small.convert('1').convert('L')          # Floyd-Steinberg dither
    art.paste(0, mask=lines.point(lambda p: 255 if p > LINE_COVER else 0))
    frame = Image.new('1', (FRAME, FRAME), 255)
    frame.paste(art.convert('1'), ((FRAME - ART) // 2, FRAME - ART))
    return frame


def build_frames():
    names = sorted(n for n in os.listdir(SRC_DIR) if n.endswith('.png'))
    if not names:
        sys.exit(f'no portrait crops in {SRC_DIR} — run with --from-originals first')
    for name in names:
        render_frame(Image.open(os.path.join(SRC_DIR, name))) \
            .save(os.path.join(WOMAN_DIR, name), optimize=True)
        print(f'  {name}')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--from-originals', metavar='DIR',
                    help='rebuild woman/src/ from the original illustrations first')
    args = ap.parse_args()
    if args.from_originals:
        print('Portrait crops:')
        build_sources(args.from_originals)
    print('Display frames:')
    build_frames()


if __name__ == '__main__':
    main()
