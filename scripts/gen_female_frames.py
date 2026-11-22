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
      Writes the portrait crops to woman/src/<name>.png (colour on a
      transparent background, 296 px).

  gen_female_frames.py
      Renders woman/<name>.png (78x78, 1-bit) from woman/src/, plus the
      idle-only expression variants woman/idle_<name>_<kind>.png (closed
      smiling eyes, a blink, a wink) drawn onto the calm portraits. Every
      frame also gets a full-colour twin in woman/color/ (156x156, RGBA) for
      colour displays.

Tuning knobs are the constants below. Needs Pillow.
"""
import argparse
import os
import sys

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageOps

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WOMAN_DIR = os.path.join(REPO, 'resources', 'images', 'status', 'woman')
SRC_DIR = os.path.join(WOMAN_DIR, 'src')
COLOR_DIR = os.path.join(WOMAN_DIR, 'color')

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


# Extra frames shown only while the unit is idle: the calm, front-facing
# portraits with a different expression drawn on. Named idle_<portrait>_<kind>.
#   happy = both eyes closed in a smile, blink = eyes shut with lashes,
#   wink_l / wink_r = one eye closed (left / right as seen on screen).
IDLE_VARIANTS = {
    'laptop':    ('happy', 'blink', 'wink_r'),
    'wifi':      ('happy', 'wink_r'),
    'bluetooth': ('happy', 'blink'),
    'swords':    ('happy', 'blink', 'wink_l'),
}

# Where the eyes are in each woman/src/ portrait: (left edge, top, right edge)
# of the dark part of the left and the right eye, in the 296 px crop.
EYES = {
    'laptop':    ((68, 171, 113), (147, 165, 194)),
    'swords':    ((73, 160, 124), (167, 164, 220)),
    'wifi':      ((55, 170, 108), (156, 171, 209)),
    'bluetooth': ((63, 158, 113), (157, 160, 212)),
}
EYE_LINE = 8         # stroke width in the 296 px crop (about 2 px on the sprite)


def _eye_box(eye):
    x0, y0, x1 = eye
    return (x0 - 7, y0 - 9, x1 + 7, y0 + 50)


EYE_INK = (52, 32, 30, 255)      # closed-eye stroke on the colour portrait


def _close_eye(im, eye, skin, kind):
    """Paint one open eye out with the skin tone and draw it closed."""
    x0, y0, x1, y1 = _eye_box(eye)
    mask = Image.new('L', im.size, 0)
    ImageDraw.Draw(mask).ellipse((x0, y0, x1, y1), fill=255)
    im.paste(skin, mask=mask.filter(ImageFilter.GaussianBlur(3)))
    draw = ImageDraw.Draw(im)
    cx, cy, rx = (x0 + x1) // 2, (y0 + y1) // 2 + 6, (x1 - x0) // 2 - 6
    if kind == 'blink':     # lower-lid curve with lashes
        draw.arc((cx - rx, cy - 22, cx + rx, cy + 12), 25, 155, fill=EYE_INK, width=EYE_LINE)
        for dx in (-rx + 4, 0, rx - 4):
            draw.line((cx + dx, cy + 8, cx + dx * 1.25, cy + 19), fill=EYE_INK, width=5)
    else:                   # smiling upward arc
        draw.arc((cx - rx, cy - 14, cx + rx, cy + 26), 200, 340, fill=EYE_INK, width=EYE_LINE)


def _eyes_for(name, kind):
    left, right = EYES[name]
    return {'happy': (left, right), 'blink': (left, right),
            'wink_l': (left,), 'wink_r': (right,)}[kind]


def idle_variant(src, name, kind):
    """A portrait crop with the expression `kind` drawn on (see IDLE_VARIANTS)."""
    im = src.convert('RGBA').copy()
    left, right = EYES[name]
    skin = im.getpixel(((left[2] + right[0]) // 2, left[1] + 30))   # between the eyes
    skin = skin[:3] + (255,)
    for eye in _eyes_for(name, kind):
        _close_eye(im, eye, skin, 'blink' if kind == 'blink' else 'smile')
    return im


def render_idle_frame(src, name, kind):
    """The display frame for an idle variant.

    Rendering the edited crop on its own would re-dither the whole portrait
    (the contrast step and the error diffusion both spread a local change), so
    helmet and hair would flicker between frames. Instead only the eye regions
    are taken from the edited render and laid over the plain frame: everything
    but the eyes stays pixel-identical to the base portrait."""
    frame = render_frame(src)
    edited = render_frame(idle_variant(src, name, kind))
    scale = SRC_SIZE // ART
    ox, oy = (FRAME - ART) // 2, FRAME - ART
    for eye in _eyes_for(name, kind):
        x0, y0, x1, y1 = _eye_box(eye)
        box = (ox + x0 // scale - 1, oy + y0 // scale - 1,
               ox + -(-x1 // scale) + 1, oy + -(-y1 // scale) + 1)
        frame.paste(edited.crop(box), box[:2])
    return frame


def _character(path):
    """The illustration (RGBA) cropped to the character."""
    im = Image.open(path).convert('RGBA')
    flat = Image.new('RGB', im.size, 'white')
    flat.paste(im, mask=im.split()[-1])
    ink = ImageOps.invert(flat.convert('L')).point(lambda p: 255 if p > 12 else 0)
    return im.crop(ink.getbbox())


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
            draw.polygon([(x * k, y * k) for x, y in poly], fill=(255, 255, 255, 0))
        px = int(char.width * side)
        x0 = int(char.width * cx - px / 2)
        y0 = int(char.height * top)
        square = Image.new('RGBA', (px, px), (255, 255, 255, 0))
        square.paste(char, (-x0, -y0))
        square.resize((SRC_SIZE, SRC_SIZE), Image.LANCZOS) \
              .save(os.path.join(SRC_DIR, out + '.png'), optimize=True)
        print(f'  src/{out}.png')


def _grey(src):
    """A portrait crop (colour, transparent background) as greyscale on white."""
    if src.mode in ('RGBA', 'LA', 'P'):
        src = src.convert('RGBA')
        flat = Image.new('RGB', src.size, 'white')
        flat.paste(src, mask=src.split()[-1])
        src = flat
    return src.convert('L')


def render_frame(src):
    """A greyscale portrait crop -> the 78x78 1-bit display frame."""
    grey = _grey(src)
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


COLOR_SCALE = 2      # colour frames are 2x the 1-bit ones (156 px), same geometry


def render_color_frame(src):
    """A portrait crop -> the full-colour frame for colour displays: RGBA,
    COLOR_SCALE times the 1-bit frame with the portrait in the same place, so
    the two can stand in for each other in a layout."""
    art = ART * COLOR_SCALE
    frame = Image.new('RGBA', (FRAME * COLOR_SCALE,) * 2, (0, 0, 0, 0))
    frame.paste(src.convert('RGBA').resize((art, art), Image.LANCZOS),
                ((FRAME - ART) // 2 * COLOR_SCALE, (FRAME - ART) * COLOR_SCALE))
    return frame


def build_frames():
    names = sorted(n for n in os.listdir(SRC_DIR) if n.endswith('.png'))
    if not names:
        sys.exit(f'no portrait crops in {SRC_DIR} — run with --from-originals first')
    os.makedirs(COLOR_DIR, exist_ok=True)
    for folder in (WOMAN_DIR, COLOR_DIR):
        for stale in os.listdir(folder):
            if stale.startswith('idle_') and stale.endswith('.png'):
                os.remove(os.path.join(folder, stale))
    for name in names:
        src = Image.open(os.path.join(SRC_DIR, name))
        render_frame(src).save(os.path.join(WOMAN_DIR, name), optimize=True)
        render_color_frame(src).save(os.path.join(COLOR_DIR, name), optimize=True)
        print(f'  {name}')
        base = name[:-4]
        for kind in IDLE_VARIANTS.get(base, ()):
            out = f'idle_{base}_{kind}.png'
            render_idle_frame(src, base, kind) \
                .save(os.path.join(WOMAN_DIR, out), optimize=True)
            render_color_frame(idle_variant(src, base, kind)) \
                .save(os.path.join(COLOR_DIR, out), optimize=True)
            print(f'  {out}')


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
