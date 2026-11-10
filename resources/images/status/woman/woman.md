# Female (shieldmaiden) status frames — e-paper + LCD

These PNGs are the on-device character for a **mesh unit named after a woman**
(or one with `mesh_viking_gender = female`). When such a unit is active the
e-paper / LCD draws these instead of the default frames — see
`SharedData.load_female_images` / `update_image_randomizer` in `shared.py`.

All of these images belong to the **IDLE pool**, and IDLE is the fallback for
every scan status, so **every status draws a random frame from the whole set**
(per-status selection, but one shared art pool — a random shieldmaiden frame
regardless of activity).

Notes for adding/replacing art:
## Art spec — READ THIS before adding images

The **entire Ragnar UI is 1-bit black/white** (e-paper *and* LCD/TFT), and each
frame is shown as a tiny ~52×78 sprite. So the art here must be drawn for that:

- **Simple black-on-white line art.** Bold outlines, few interior lines, lots of
  white space — the same style as the built-in male frames in the sibling
  status folders (`../IDLE/`, etc.). Think icon, not illustration.
- **High contrast, no shading/gradients.** Grayscale shading, photographic
  detail and painted rendering all collapse into noise or a black blob when
  reduced to 1-bit at sprite size. (This is why the original detailed uploads
  looked like "random pixels" — no conversion can fix over-detailed source art.)
- Square-ish or portrait, any resolution — it's scaled down to the frame height.

Processing on load (`_prepare_female_image`): flatten onto white → scale to the
standard frame height → threshold to 1-bit, **no dithering**. Tune the cut point
with `SharedData.WOMAN_BW_THRESHOLD` in `shared.py` (higher = heavier lines;
default 200 keeps thin lines from breaking up when downscaled).
- Add a new frame by dropping a `.png` in this folder — it joins the shared
  pool automatically.
- To pin a specific image to a specific status instead of the shared pool, add
  an entry to `SharedData.WOMAN_STATUS_IMAGES` (`shared.py`) keyed by status
  name, e.g. `'SSHBruteforce': ('axe', 'swords')`.
