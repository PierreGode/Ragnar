"""Snap generated female PNGs back into the sprite folders as 78x78 RGB BMP.

Usage (from repo root):  python female_redraw_kit/integrate.py
Reads mapping.csv, takes each generated/<result_png>, resizes to 78x78 and writes it
as the target female_<name>.bmp next to its original. Incremental and idempotent.
"""
import csv
import os
import sys

from PIL import Image

KIT = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(KIT, "generated")
MAP = os.path.join(KIT, "mapping.csv")
SIZE = (78, 78)


def main():
    if not os.path.exists(MAP):
        sys.exit(f"mapping.csv not found at {MAP}")
    with open(MAP, newline="") as fh:
        rows = list(csv.DictReader(fh))

    done, missing, extra = [], [], []
    wanted = set()
    for r in rows:
        result = r["result_png"]
        wanted.add(result)
        src = os.path.join(GEN, result)
        if not os.path.exists(src):
            missing.append(result)
            continue
        im = Image.open(src).convert("RGB")
        if im.size != SIZE:
            im = im.resize(SIZE, Image.LANCZOS)
        target = r["target_female_bmp"]
        os.makedirs(os.path.dirname(target), exist_ok=True)
        im.save(target, format="BMP")
        done.append(target)

    for fn in sorted(os.listdir(GEN)) if os.path.isdir(GEN) else []:
        if fn.lower().endswith(".png") and fn not in wanted:
            extra.append(fn)

    print(f"integrated : {len(done)} / {len(rows)}")
    if missing:
        print(f"still missing in generated/ : {len(missing)}")
        for m in missing[:12]:
            print("   -", m)
        if len(missing) > 12:
            print(f"   ... and {len(missing) - 12} more")
    if extra:
        print(f"unrecognized files in generated/ (name must match a reference): {len(extra)}")
        for e in extra[:12]:
            print("   -", e)


if __name__ == "__main__":
    main()
