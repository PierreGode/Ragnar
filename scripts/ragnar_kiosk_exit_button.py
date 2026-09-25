#!/usr/bin/env python3
# ragnar_kiosk_exit_button.py — a small always-on-top touch button that closes
# the Ragnar kiosk. The Hackberry Pi CM5 has a BlackBerry keyboard with no
# obvious Ctrl key, so a keyboard chord (Ctrl+Alt+Q) is awkward to hit. This
# gives a tap target instead: one touch runs ragnar_kiosk_exit.sh, which closes
# the full-screen kiosk browser (autostart mode) or stops the kiosk service.
# Launched by ragnar_kiosk_run.sh when the escape hatch is enabled.
#
# It floats over the full-screen Chromium (override-redirect + periodic raise),
# and self-exits if the kiosk browser goes away, so it never lingers as a stray
# button on the desktop.
#
# Config (env, all optional):
#   KIOSK_EXIT_SCRIPT   path to ragnar_kiosk_exit.sh (default: sibling file)
#   KIOSK_EXIT_CORNER   ne | nw | se | sw   (default: se — bottom-right)
#   KIOSK_EXIT_SIZE     button size in px    (default: 66)
#   KIOSK_EXIT_ALPHA    0.0-1.0 opacity      (default: 0.72)
#   KIOSK_PROFILE       kiosk Chromium profile dir (used by the watchdog)
import os
import subprocess
import sys
import tkinter as tk

HERE = os.path.dirname(os.path.abspath(__file__))
EXIT_SCRIPT = os.environ.get("KIOSK_EXIT_SCRIPT", os.path.join(HERE, "ragnar_kiosk_exit.sh"))
CORNER = os.environ.get("KIOSK_EXIT_CORNER", "se").lower()
SIZE = max(40, int(os.environ.get("KIOSK_EXIT_SIZE", "66") or 66))
ALPHA = float(os.environ.get("KIOSK_EXIT_ALPHA", "0.72") or 0.72)
MARGIN = 8
PROFILE = os.environ.get("KIOSK_PROFILE", "")


def run_exit(_event=None):
    """Fire the close script and quit. Detach it so we can tear down cleanly."""
    try:
        subprocess.Popen(["/bin/sh", EXIT_SCRIPT],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    root.after(150, root.destroy)


root = tk.Tk()
root.title("ragnar-exit")
root.overrideredirect(True)          # no titlebar; float free of the WM
root.attributes("-topmost", True)
try:
    root.attributes("-alpha", ALPHA)
except tk.TclError:
    pass

sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
x = sw - SIZE - MARGIN if CORNER in ("ne", "se") else MARGIN
y = sh - SIZE - MARGIN if CORNER in ("sw", "se") else MARGIN
root.geometry(f"{SIZE}x{SIZE}+{x}+{y}")

btn = tk.Button(
    root, text="✕", command=run_exit,
    bg="#b71c1c", fg="white", activebackground="#e53935", activeforeground="white",
    relief="flat", bd=0, highlightthickness=0,
    font=("DejaVu Sans", int(SIZE * 0.42), "bold"),
)
btn.pack(fill="both", expand=True)
# Touch panels report a press; treat a tap anywhere on the button as a click.
btn.bind("<ButtonRelease-1>", run_exit)


def keep_on_top():
    try:
        root.lift()
        root.attributes("-topmost", True)
    except tk.TclError:
        return
    root.after(1500, keep_on_top)


# Watchdog: once the kiosk browser has had time to appear, exit if it's gone,
# so tapping X (or any other close path) never leaves this button orphaned.
_grace = {"ticks": 0}


def watchdog():
    if not PROFILE:
        return
    _grace["ticks"] += 1
    if _grace["ticks"] >= 6:  # ~12s grace before we start policing
        try:
            alive = subprocess.run(
                ["pgrep", "-f", "--user-data-dir=" + PROFILE],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ).returncode == 0
        except Exception:
            alive = True
        if not alive:
            root.destroy()
            return
    root.after(2000, watchdog)


root.after(500, keep_on_top)
root.after(2000, watchdog)
try:
    root.mainloop()
except KeyboardInterrupt:
    sys.exit(0)
