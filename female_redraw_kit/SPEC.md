# Female Viking Redraw Kit

Goal: for each of the 89 chibi-viking sprites in `resources/images/status/**`, produce a
**female** counterpart where the **beard is replaced by long blonde hair** and the face is
feminine — everything else (helmet/hood, horns, props, pose, expression, background) stays
identical. Finished files land next to each original as `female_<name>.bmp` (78×78 RGB BMP).

This needs a real image-generation / image-edit model (the beard→hair change is a redraw, not a
recolor). This kit gives you clean high-res references, one reusable instruction, and a script
that snaps the results back into the sprite format and folders.

## Folders
- `references/` — each male sprite upscaled 8× (624×624) as PNG, named for its **target**
  (`female_<name>.png`). Use these as the img2img / edit **source** so pose + props + helmet are
  preserved automatically per frame.
- `generated/` — drop the model's output here, **keeping the same filename** as the reference
  (`female_<name>.png`). Any pixel size is fine; the integrate script rescales.
- `mapping.csv` — `result_png, source_bmp, target_female_bmp` for all 89 (used by integrate).

## Character style (for the prompt)
- Kawaii **chibi pixel-art** viking: big round body, tiny arms/legs, front-facing, thick dark
  outline, on a **plain white background**, single character, centered.
- **Blonde** palette — hair main `#E6C56C`, hair shadow `#BC9446`, outline `#30244A`,
  skin `#FFEBD0`.
- Head is one of two kinds, already present in each reference — **keep whichever it is**:
  - silver **horned viking helmet** (rivets + noseguard, cream curved horns), or
  - black **hood/cowl**.
- Some frames show **round goggles with cyan eyes** (scanner poses) or hold **props**
  (shield, sword, potion bottle, laptop, envelope, unicorn). Keep them exactly.

## The edit instruction (use per reference, img2img / "edit this image")
> Redraw this chibi pixel-art viking as **female**. **Remove the beard** and give her **long
> blonde flowing hair** that frames her face and falls down the sides past the shoulders, same
> blonde tones as the original (`#E6C56C` / `#BC9446`). Feminine face with soft cheeks, large
> friendly eyes, small mouth, pale skin `#FFEBD0`. **Keep everything else identical**: the same
> helmet/hood, horns, any goggles/props she holds, the same pose, expression, thick dark
> outline, pixel-art style, and plain white background. Single character, centered, 1:1.

Low denoise / high image-fidelity setting so only the beard→hair + face changes.

## Workflow
1. Run each `references/female_<name>.png` through your image tool with the instruction above.
2. Save each result into `generated/` under the **same filename**.
3. From the repo root run: `python female_redraw_kit/integrate.py`
   - rescales each generated PNG to 78×78, writes it as `female_<name>.bmp` next to its original,
     and reports anything in `generated/` it couldn't match or that's still missing.
4. Re-run step 3 anytime you add more; it's incremental and idempotent.

You don't have to describe frames individually — the reference image carries each frame's pose and
props, so the one instruction works for all 89.
