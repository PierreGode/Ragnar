# Female (shieldmaiden) status frames — e-paper + LCD

These PNGs are the on-device character for a unit with a woman's Viking name on
the mesh, or with `mesh_viking_gender = female`. Such a unit draws these instead
of the default viking — see `SharedData.load_female_images` /
`update_image_randomizer` in `shared.py`.

## What is here

- `*.png` — the display frames: **78×78, 1-bit**, the same footprint as the
  default frames. They are loaded as-is (scaled with NEAREST on large displays).
- `src/*.png` — the head-and-shoulders portrait crops (greyscale, 296 px) the
  frames are rendered from.

- `idle_<portrait>_<kind>.png` — idle-only expression variants of the calm,
  front-facing portraits: `happy` (both eyes closed in a smile), `blink` (eyes
  shut with lashes) and `wink_l` / `wink_r`. The generator draws them; only the
  eyes differ from the base portrait, pixel for pixel.

Every scan status draws a random frame from the eight plain portraits. **IDLE**
draws from those plus the `idle_*` variants, so a unit doing nothing has the
most variety.

## How the frames are made

The art is a set of detailed full-colour, full-body illustrations. Shrunk whole
to 78 px on a 1-bit panel they turn into noise, so `scripts/gen_female_frames.py`:

1. crops each illustration to a head-and-shoulders portrait, so the face fills
   the frame the way the default viking's does;
2. brightens and adds contrast so pale hair and skin go white, then dithers;
3. forces the ink outlines to solid black so the dither does not break them up.

Re-tune and rebuild the frames from the committed crops:

```bash
python3 scripts/gen_female_frames.py
```

The knobs (`GAMMA`, `CONTRAST`, `LINE_DARK`, `LINE_COVER`) are at the top of the
script. To add an idle expression, add it to `IDLE_VARIANTS` (the portrait needs
its eye positions in `EYES`). To add or re-crop a pose from an original illustration, add it to
`PORTRAITS` and run with `--from-originals <dir>`.

## Adding a frame by hand

Drop a 78×78 black-and-white `.png` in this folder; it joins the pool
automatically (name it `idle_…` to show it only while idle). Note that
re-running the generator deletes and rebuilds every `idle_*.png`. To pin specific frames to a specific status, add an entry to
`SharedData.WOMAN_STATUS_IMAGES` (`shared.py`), e.g.
`'SSHBruteforce': ('axe', 'swords')`.
