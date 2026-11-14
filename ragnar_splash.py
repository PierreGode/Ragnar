#!/usr/bin/env python3
# ragnar_splash.py
"""
A picture on the M5Stack CardputerZero's LCD while Ragnar is not drawing yet:
during boot, while the service starts, and during the first install.

Ragnar needs most of a minute to start on this board, and the first install
takes much longer. Without this the LCD is blank (or white) all that time and
looks broken.

It draws straight to the panel through the same driver Ragnar uses
(resources/waveshare_epd/st7789v2.py: the kernel framebuffer when the image
has one, the panel over SPI otherwise), and imports nothing else from Ragnar,
so it runs before Ragnar's dependencies are installed. It needs python3-pil,
and for the SPI path python3-spidev, python3-gpiozero and python3-smbus2.

    ragnar_splash.py --boot                     early in boot (ragnar-splash.service)
    ragnar_splash.py --start                    the Ragnar service is starting
    ragnar_splash.py --install "Step" --progress 40
    ragnar_splash.py --message "Text" [--detail "smaller text"]
    ragnar_splash.py ... --png out.png          render to a file, touch no hardware

It only ever draws on a CardputerZero, and never while Ragnar itself is
running (two writers on one panel flicker), so it is safe to call anywhere.
"""

import argparse
import fcntl
import importlib.util
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.abspath(__file__))
WIDTH, HEIGHT = 320, 170

BG = (0, 0, 0)
TITLE = (255, 200, 90)
INK = (236, 236, 228)
DIM = (140, 146, 156)
BAR = (90, 235, 130)
FRAME = (70, 78, 90)

M5IOE1_ADDR = 0x4F            # the board's own I/O expander: only this board has it
I2C_SLAVE = 0x0703

MESSAGES = {
    "boot": ("Starting up", "Ragnar is loading. This takes about a minute."),
    "start": ("Starting Ragnar", "Almost there."),
    "install": ("Installing Ragnar", "This takes a while. Follow the progress in your terminal."),
}


def saved_config(root=""):
    try:
        with open(root + os.path.join(REPO, "config", "shared_config.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def expander_answers(bus="/dev/i2c-1", addr=M5IOE1_ADDR):
    """True when the CardputerZero's I/O expander answers on I2C. Plain file
    I/O, so it needs no Python packages."""
    try:
        fd = os.open(bus, os.O_RDWR)
    except OSError:
        return False
    try:
        fcntl.ioctl(fd, I2C_SLAVE, addr)
        os.read(fd, 1)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def is_cardputer_zero(config=None, root=""):
    """Ragnar's saved display setting says so, or (before the first install
    has written one) the hardware does: a Compute Module 0 with the expander."""
    if os.environ.get("RAGNAR_SPLASH_BOARD") == "1":
        return True                # the installer already knows (menu choice)
    config = saved_config(root) if config is None else config
    if config.get("epd_type"):
        return config.get("epd_type") == "st7789v2"
    try:
        with open(root + "/proc/device-tree/model") as f:
            model = f.read()
    except OSError:
        return False
    return "Compute Module 0" in model and expander_answers()


def ragnar_is_running(runner=None):
    """True when the Ragnar service owns the display."""
    run = runner or subprocess.run
    try:
        done = run(["systemctl", "is-active", "ragnar.service"], capture_output=True,
                   text=True, timeout=5)
        return (done.stdout or "").strip() == "active"
    except Exception:
        return False


def rotation(config):
    """0 or 180, as Ragnar will draw: the saved screen_reversed, and 180 when
    nothing is saved yet (this panel is mounted upside down, so that is the
    default Ragnar picks on a first start)."""
    value = (config or {}).get("screen_reversed")
    if value is None or value is True:
        return 180
    try:
        return 180 if int(value) % 360 == 180 else 0
    except (TypeError, ValueError):
        return 0


def _font(name, size):
    from PIL import ImageFont
    try:
        return ImageFont.truetype(os.path.join(REPO, "resources", "fonts", name), size)
    except Exception:
        return ImageFont.load_default()


def _character(config, height):
    """The viking (or the shieldmaiden, by the saved setting) with the
    backdrop cut away, `height` pixels tall. None when the art is missing."""
    from PIL import Image
    status = os.path.join(REPO, "resources", "images", "status")
    female = str(config.get("mesh_viking_gender") or "").strip().lower() == "female"
    candidates = []
    if female:
        candidates.append(os.path.join(status, "woman", "color", "idle_swords_happy.png"))
    candidates.append(os.path.join(status, "IDLE", "IDLE1.bmp"))
    for path in candidates:
        try:
            art = Image.open(path).convert("RGBA")
        except Exception:
            continue
        if path.endswith(".bmp"):
            # The viking frames sit on a white backdrop.
            pixels = art.load()
            for y in range(art.height):
                for x in range(art.width):
                    r, g, b, _ = pixels[x, y]
                    if r > 240 and g > 240 and b > 240:
                        pixels[x, y] = (0, 0, 0, 0)
        box = art.getbbox()
        if box:
            art = art.crop(box)
        ratio = height / art.height
        return art.resize((max(1, int(art.width * ratio)), height),
                          Image.LANCZOS if ratio < 1 else Image.NEAREST)
    return None


def _wrap(draw, text, font, width):
    lines, line = [], ""
    for word in str(text).split():
        trial = (line + " " + word).strip()
        if line and draw.textlength(trial, font=font) > width:
            lines.append(line)
            line = word
        else:
            line = trial
    if line:
        lines.append(line)
    return lines


def render(message, detail="", progress=None, config=None, size=(WIDTH, HEIGHT)):
    """The splash as an RGB image."""
    from PIL import Image, ImageDraw
    config = config or {}
    W, H = size
    image = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(image)
    art = _character(config, H - 34)
    text_w = W - 16
    if art is not None:
        x = W - art.width - 8
        image.paste(art, (x, 6), art)
        text_w = x - 14
    draw.text((8, 10), "RAGNAR", font=_font("Viking.TTF", 30), fill=TITLE)
    y = 54
    head = _font("ArialB.TTF", 14)
    for line in _wrap(draw, message, head, text_w)[:2]:
        draw.text((8, y), line, font=head, fill=INK)
        y += 18
    small = _font("Arial.ttf", 11)
    y += 2
    for line in _wrap(draw, detail, small, text_w)[:4]:
        draw.text((8, y), line, font=small, fill=DIM)
        y += 13
    if progress is not None:
        progress = max(0, min(100, int(progress)))
        x0, x1, by = 8, W - 8, H - 16
        draw.rectangle((x0, by, x1, by + 8), outline=FRAME)
        fill = x0 + 2 + int((x1 - x0 - 4) * progress / 100)
        if fill > x0 + 2:
            draw.rectangle((x0 + 2, by + 2, fill, by + 6), fill=BAR)
    if rotation(config) == 180:
        image = image.rotate(180)
    return image


def _driver():
    path = os.path.join(REPO, "resources", "waveshare_epd", "st7789v2.py")
    if REPO not in sys.path:
        sys.path.insert(0, REPO)          # the driver imports m5ioe1 from here
    spec = importlib.util.spec_from_file_location("ragnar_st7789v2", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def show(image, wait=0.0, driver=None):
    """Put `image` on the LCD. `wait` is how long to keep trying while the
    kernel is still creating the devices (early boot). True when shown."""
    deadline = time.monotonic() + max(0.0, wait)
    while True:
        try:
            epd = (driver or _driver()).EPD()
            epd.boot_screen = False       # we are the boot screen
            epd.init()
            epd.display(epd.getbuffer(image))
            return True
        except Exception as e:
            if time.monotonic() >= deadline:
                print(f"ragnar_splash: no display ({e})", file=sys.stderr)
                return False
            time.sleep(0.5)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Splash screen for the CardputerZero LCD")
    ap.add_argument("--boot", action="store_true")
    ap.add_argument("--start", action="store_true")
    ap.add_argument("--install", nargs="?", const="", metavar="STEP")
    ap.add_argument("--message")
    ap.add_argument("--detail")
    ap.add_argument("--progress", type=int)
    ap.add_argument("--wait", type=float, default=0.0)
    ap.add_argument("--png")
    ap.add_argument("--force", action="store_true", help="draw even while Ragnar runs")
    args = ap.parse_args(argv)

    kind = "install" if args.install is not None else "start" if args.start else "boot"
    message, detail = MESSAGES[kind]
    if args.install:
        detail = args.install + "... " + detail
    message = args.message or message
    detail = args.detail if args.detail is not None else detail
    config = saved_config()
    image = render(message, detail, args.progress, config)
    if args.png:
        image.save(args.png)
        return 0
    if not is_cardputer_zero(config):
        return 0
    if not args.force and kind != "start" and ragnar_is_running():
        return 0
    return 0 if show(image, args.wait) else 1


if __name__ == "__main__":
    sys.exit(main())
