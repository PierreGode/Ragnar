#!/usr/bin/env python3
# pi_camera.py
"""
Raspberry Pi CSI camera for Ragnar: still photos and a live MJPEG view.

Built for the M5Stack CardputerZero's IMX219, but nothing here is specific to
it: any camera `rpicam-hello --list-cameras` reports works.

Everything goes through the rpicam-apps command-line tools (rpicam-still /
rpicam-vid, or their older libcamera-* names), so there is no Python camera
dependency and the camera is only open while something is using it:

  * A photo runs rpicam-still once and returns the JPEG.
  * The live view runs ONE rpicam-vid for all viewers and stops it a few
    seconds after the last viewer leaves, which matters on a 512 MB board.
  * The camera can be opened by one process at a time, so a photo taken
    while the live view runs pauses the view for the shot.

CLI:  python3 pi_camera.py photo.jpg     take one photo
"""

import logging
import os
import shutil
import subprocess
import sys
import threading
import time

try:
    from logger import Logger
    logger = Logger(name="pi_camera.py", level=logging.INFO)
except Exception:  # standalone / CLI use
    logger = logging.getLogger("pi_camera")

SOI = b"\xff\xd8"
EOI = b"\xff\xd9"

STREAM_SIZE = (640, 480)
STREAM_FPS = 10
STREAM_IDLE_SECONDS = 8          # stop rpicam-vid this long after the last viewer
STILL_SIZE = (1640, 1232)        # 2x2 binned full field of view on an IMX219
STILL_TIMEOUT = 25
MAX_FRAME_BYTES = 4 * 1024 * 1024
DETECT_TTL = 60


def _tool(*names):
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def split_jpegs(buffer):
    """Split complete JPEG images off the front of an MJPEG byte buffer.
    Returns (frames, remainder). Bytes before the first start marker are
    dropped; an unfinished image stays in the remainder."""
    frames = []
    while True:
        start = buffer.find(SOI)
        if start < 0:
            return frames, b""
        end = buffer.find(EOI, start + 2)
        if end < 0:
            return frames, buffer[start:]
        frames.append(buffer[start:end + 2])
        buffer = buffer[end + 2:]


class PiCamera:
    """One camera, shared by every web client."""

    def __init__(self, popen=None, run=None, detector=None):
        self._popen = popen or subprocess.Popen
        self._run = run or subprocess.run
        self._detector = detector
        self._lock = threading.RLock()          # serialises camera ownership
        self._frame_cond = threading.Condition()
        self._frame = None
        self._frame_id = 0
        self._proc = None
        self._reader = None
        self._viewers = 0
        self._last_viewer = 0.0
        self._detected = None
        self._detected_at = 0.0
        self.last_error = None

    # ── detection ──────────────────────────────────────────────────────

    def info(self, refresh=False):
        """{'present': bool, 'model': ..., 'modes': ...}, cached for a minute.
        Not refreshed while the live view owns the camera."""
        now = time.monotonic()
        with self._lock:
            fresh = self._detected is not None and now - self._detected_at < DETECT_TTL
            if (fresh and not refresh) or (self._proc is not None and self._detected):
                return dict(self._detected)
            try:
                if self._detector:
                    found = self._detector()
                else:
                    import cardputer_caps
                    found = cardputer_caps.detect_camera()
            except Exception as e:
                found = {"present": False, "reason": str(e)}
            self._detected, self._detected_at = found, now
            return dict(found)

    def status(self):
        info = self.info()
        info.update({"streaming": self._proc is not None, "viewers": self._viewers,
                     "error": self.last_error})
        return info

    # ── still photo ────────────────────────────────────────────────────

    def photo(self, width=None, height=None):
        """Take one photo. Returns JPEG bytes; raises RuntimeError with a
        message fit for the UI when it cannot."""
        tool = _tool("rpicam-still", "libcamera-still")
        if not tool:
            raise RuntimeError("rpicam-apps is not installed (sudo apt install rpicam-apps)")
        width, height = int(width or STILL_SIZE[0]), int(height or STILL_SIZE[1])
        cmd = [tool, "-n", "--immediate", "-t", "1", "--width", str(width),
               "--height", str(height), "-e", "jpg", "-o", "-"]
        with self._lock:
            resume = self._proc is not None
            if resume:
                self._stop_stream()
            try:
                result = self._run(cmd, capture_output=True, timeout=STILL_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.last_error = "camera timed out"
                raise RuntimeError(self.last_error)
            except OSError as e:
                self.last_error = f"cannot run {os.path.basename(tool)}: {e}"
                raise RuntimeError(self.last_error)
            finally:
                if resume and self._viewers > 0:
                    self._start_stream()
        data = result.stdout or b""
        if result.returncode != 0 or not data.startswith(SOI):
            detail = (result.stderr or b"").decode("utf-8", "replace").strip().splitlines()
            self.last_error = detail[-1] if detail else "camera returned no image"
            raise RuntimeError(self.last_error)
        self.last_error = None
        return data

    # ── live view ──────────────────────────────────────────────────────

    def _start_stream(self):
        tool = _tool("rpicam-vid", "libcamera-vid")
        if not tool:
            self.last_error = "rpicam-apps is not installed (sudo apt install rpicam-apps)"
            return False
        cmd = [tool, "-n", "-t", "0", "--codec", "mjpeg", "--width", str(STREAM_SIZE[0]),
               "--height", str(STREAM_SIZE[1]), "--framerate", str(STREAM_FPS),
               "--flush", "-o", "-"]
        try:
            self._proc = self._popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError as e:
            self.last_error = f"cannot start the live view: {e}"
            self._proc = None
            return False
        self.last_error = None
        self._reader = threading.Thread(target=self._read_frames, args=(self._proc,),
                                        name="pi-camera", daemon=True)
        self._reader.start()
        logger.info("Camera live view started")
        return True

    def _stop_stream(self):
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        logger.info("Camera live view stopped")

    def _read_frames(self, proc):
        buffer = b""
        while True:
            try:
                chunk = proc.stdout.read(65536)
            except Exception:
                chunk = b""
            if not chunk:
                break
            buffer += chunk
            frames, buffer = split_jpegs(buffer)
            if len(buffer) > MAX_FRAME_BYTES:
                buffer = b""                      # not MJPEG: do not grow forever
            if frames:
                with self._frame_cond:
                    self._frame = frames[-1]
                    self._frame_id += 1
                    self._frame_cond.notify_all()
            with self._lock:
                idle = (self._proc is proc and self._viewers == 0
                        and time.monotonic() - self._last_viewer > STREAM_IDLE_SECONDS)
                if idle:
                    self._stop_stream()
                    break
        with self._lock:
            if self._proc is proc:               # ended on its own (camera lost)
                self._proc = None
                self.last_error = self.last_error or "the live view stopped"
        with self._frame_cond:
            self._frame_cond.notify_all()

    def frames(self, timeout=5.0):
        """Generator of JPEG frames for one viewer. Starts the live view when
        the first viewer arrives; ends when the camera stops."""
        with self._lock:
            self._viewers += 1
            if self._proc is None and not self._start_stream():
                self._viewers -= 1
                return
        last = self._frame_id
        try:
            while True:
                with self._frame_cond:
                    if self._frame_id == last:
                        self._frame_cond.wait(timeout)
                    if self._frame_id == last:
                        if self._proc is None:
                            return                # camera gone
                        continue
                    last = self._frame_id
                    frame = self._frame
                yield frame
        finally:
            with self._lock:
                self._viewers = max(0, self._viewers - 1)
                self._last_viewer = time.monotonic()

    def mjpeg(self):
        """multipart/x-mixed-replace body for a Flask Response."""
        for frame in self.frames():
            yield (b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                   + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n")

    def stop(self):
        with self._lock:
            self._viewers = 0
            self._stop_stream()


_camera = None
_camera_lock = threading.Lock()


def get_camera():
    """The process-wide camera."""
    global _camera
    with _camera_lock:
        if _camera is None:
            _camera = PiCamera()
        return _camera


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "photo.jpg"
    cam = PiCamera()
    info = cam.info()
    if not info.get("present"):
        print(f"No camera found ({info.get('reason', 'unknown')})")
        return 1
    try:
        data = cam.photo()
    except RuntimeError as e:
        print(f"Photo failed: {e}")
        return 1
    with open(out, "wb") as f:
        f.write(data)
    print(f"{info.get('model')}: saved {len(data)} bytes to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
