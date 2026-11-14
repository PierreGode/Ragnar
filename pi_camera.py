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
  * A video is the live view written to disk: the frames rpicam-vid already
    delivers go into a Motion-JPEG AVI, so the view keeps running for the web
    page and the device's own screen while it records. When ffmpeg is
    installed the finished file is turned into an MP4 a browser can play.

CLI:  python3 pi_camera.py photo.jpg     take one photo
"""

import logging
import os
import re
import shutil
import struct
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

MAX_RECORD_SECONDS = 600         # a video stops by itself after this long
MIN_FREE_BYTES = 200 * 1024 * 1024   # ... or when the disk gets this full
FREE_CHECK_FRAMES = 50
CONVERT_TIMEOUT = 1800

PHOTO_RE = re.compile(r'^ragnar_\d{8}_\d{6}(_\d+)?\.jpg$')
VIDEO_RE = re.compile(r'^ragnar_\d{8}_\d{6}(_\d+)?\.(mp4|avi)$')


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


def new_name(folder, ext):
    """A file name of Ragnar's own pattern that is free in `folder`
    (whatever the extension: a video keeps its name when it becomes an MP4)."""
    base = time.strftime('ragnar_%Y%m%d_%H%M%S')
    stem, n = base, 1
    while any(os.path.exists(os.path.join(folder, stem + e)) for e in ('.jpg', '.avi', '.mp4')):
        n += 1
        stem = f'{base}_{n}'
    return stem + ext


def save_photo(folder, data):
    """Write a JPEG into `folder` under a new name. Returns the name."""
    os.makedirs(folder, exist_ok=True)
    name = new_name(folder, '.jpg')
    with open(os.path.join(folder, name), 'wb') as f:
        f.write(data)
    return name


def list_media(folder, pattern, limit=24):
    """Ragnar's own files in `folder`, newest first: [{name, size, time}]."""
    try:
        names = sorted((n for n in os.listdir(folder) if pattern.match(n)), reverse=True)
    except OSError:
        return []
    out = []
    for name in names[:limit]:
        try:
            st = os.stat(os.path.join(folder, name))
            out.append({'name': name, 'size': st.st_size, 'time': int(st.st_mtime)})
        except OSError:
            continue
    return out


def rotation_for(config):
    """Degrees to turn the picture: the `camera_rotation` setting (0 or 180),
    or by board when it is 'auto'. The CardputerZero's sensor is mounted
    upside down, so there it is 180."""
    value = (config or {}).get('camera_rotation', 'auto')
    try:
        return 180 if int(value) % 360 == 180 else 0
    except (TypeError, ValueError):
        pass
    try:
        import cardputer_caps
        return 180 if cardputer_caps.is_cardputer_zero(config) else 0
    except Exception:
        return 0


class AviWriter:
    """Motion-JPEG AVI: every JPEG frame is stored as it came from the camera.
    The frame rate is only known at the end, so the header is written twice."""

    HEADER_BYTES = 224           # everything before the first frame

    def __init__(self, path, width, height):
        self.path = path
        self.width, self.height = int(width), int(height)
        self.frames = 0
        self.bytes = 0
        self._index = []
        self._file = open(path, 'wb')
        self._file.write(self._header(10.0))
        self._pos = self.HEADER_BYTES

    def _header(self, fps):
        rate = max(1, int(round(fps * 1000)))
        biggest = max([size for _, size in self._index] or [0])
        movi_size = 4 + sum(8 + size + (size & 1) for _, size in self._index)
        idx_size = 16 * len(self._index)
        avih = struct.pack('<14I', int(1000000 / max(fps, 0.001)), 0, 0, 0x10, self.frames,
                           0, 1, biggest, self.width, self.height, 0, 0, 0, 0)
        strh = struct.pack('<4s4sIHHIIIIIIII4H', b'vids', b'MJPG', 0, 0, 0, 0, 1000, rate,
                           0, self.frames, biggest, 0xFFFFFFFF, 0, 0, 0, self.width, self.height)
        strf = struct.pack('<IiiHH4sIiiII', 40, self.width, self.height, 1, 24, b'MJPG',
                           self.width * self.height * 3, 0, 0, 0, 0)
        strl = b'strl' + b'strh' + struct.pack('<I', len(strh)) + strh \
            + b'strf' + struct.pack('<I', len(strf)) + strf
        hdrl = b'hdrl' + b'avih' + struct.pack('<I', len(avih)) + avih \
            + b'LIST' + struct.pack('<I', len(strl)) + strl
        head = b'AVI ' + b'LIST' + struct.pack('<I', len(hdrl)) + hdrl \
            + b'LIST' + struct.pack('<I', movi_size) + b'movi'
        riff = len(head) + (movi_size - 4) + ((8 + idx_size) if self._index else 0)
        out = b'RIFF' + struct.pack('<I', riff) + head
        assert len(out) == self.HEADER_BYTES
        return out

    def write(self, frame):
        size = len(frame)
        self._file.write(b'00dc' + struct.pack('<I', size) + frame + (b'\0' if size & 1 else b''))
        # Index offsets count from the 'movi' tag, 4 bytes before the first chunk.
        self._index.append((self._pos - self.HEADER_BYTES + 4, size))
        self._pos += 8 + size + (size & 1)
        self.frames += 1
        self.bytes = self._pos

    def close(self, fps):
        """Write the index and the final header. `fps` is the measured rate."""
        if self._file is None:
            return
        try:
            if self._index:
                self._file.write(b'idx1' + struct.pack('<I', 16 * len(self._index)))
                self._file.write(b''.join(struct.pack('<4sIII', b'00dc', 0x10, off, size)
                                          for off, size in self._index))
            self.bytes = self._file.tell()
            self._file.seek(0)
            self._file.write(self._header(fps))
        finally:
            self._file.close()
            self._file = None


class PiCamera:
    """One camera, shared by every web client and the device's own screen."""

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
        self.rotation = 0                       # 0 or 180 (see rotation_for)
        self._rec_lock = threading.Lock()
        self._rec = None                        # the video being recorded
        self._converting = set()                # names being turned into MP4
        self.last_video = None

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
                     "error": self.last_error, "rotation": self.rotation,
                     "recording": self.recording(), "converting": sorted(self._converting)})
        return info

    def _turn(self):
        return ["--rotation", "180"] if self.rotation == 180 else []

    def set_rotation(self, degrees):
        """Turn the picture 0 or 180 degrees; a running live view restarts."""
        degrees = 180 if int(degrees) % 360 == 180 else 0
        with self._lock:
            if degrees == self.rotation:
                return degrees
            self.rotation = degrees
            if self._proc is not None:
                self._stop_stream()
                self._start_stream()
        return degrees

    # ── still photo ────────────────────────────────────────────────────

    def photo(self, width=None, height=None):
        """Take one photo. Returns JPEG bytes; raises RuntimeError with a
        message fit for the UI when it cannot."""
        tool = _tool("rpicam-still", "libcamera-still")
        if not tool:
            raise RuntimeError("rpicam-apps is not installed (sudo apt install rpicam-apps)")
        width, height = int(width or STILL_SIZE[0]), int(height or STILL_SIZE[1])
        cmd = [tool, "-n", "--immediate", "-t", "1", "--width", str(width),
               "--height", str(height)] + self._turn() + ["-e", "jpg", "-o", "-"]
        if self._rec is not None:
            # The camera is busy recording: hand back the frame it just took
            # instead of interrupting the video.
            with self._frame_cond:
                frame = self._frame
            if frame:
                return frame
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
               "--height", str(STREAM_SIZE[1]), "--framerate", str(STREAM_FPS)] \
            + self._turn() + ["--flush", "-o", "-"]
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
                self._record(frames)
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
            ended = self._proc is None
        if ended and self._rec is not None:      # nothing left to record from
            self._finish_recording("the camera stopped")
        with self._frame_cond:
            self._frame_cond.notify_all()

    @property
    def streaming(self):
        return self._proc is not None

    def acquire(self):
        """Become a viewer: starts the live view if it is not running. False
        (and last_error set) when it cannot start. Pair with release()."""
        with self._lock:
            self._viewers += 1
            if self._proc is None and not self._start_stream():
                self._viewers -= 1
                return False
        return True

    def release(self):
        with self._lock:
            self._viewers = max(0, self._viewers - 1)
            self._last_viewer = time.monotonic()

    def ensure_stream(self):
        """Restart the live view for the current viewers if it has stopped."""
        with self._lock:
            if self._proc is None and self._viewers > 0:
                return self._start_stream()
            return self._proc is not None

    def wait_frame(self, last=0, timeout=1.0):
        """(id, jpeg) of the newest frame once it differs from `last`;
        (last, None) when nothing new arrived within `timeout`."""
        with self._frame_cond:
            if self._frame_id == last:
                self._frame_cond.wait(timeout)
            if self._frame_id == last:
                return last, None
            return self._frame_id, self._frame

    def frames(self, timeout=5.0):
        """Generator of JPEG frames for one viewer. Starts the live view when
        the first viewer arrives; ends when the camera stops."""
        if not self.acquire():
            return
        last = self._frame_id
        try:
            while True:
                last, frame = self.wait_frame(last, timeout)
                if frame is None:
                    if self._proc is None:
                        return                    # camera gone
                    continue
                yield frame
        finally:
            self.release()

    def mjpeg(self):
        """multipart/x-mixed-replace body for a Flask Response."""
        for frame in self.frames():
            yield (b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                   + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n")

    # ── video ──────────────────────────────────────────────────────────

    def recording(self):
        """{'name', 'seconds', 'frames', 'size'} while a video records, else None."""
        rec = self._rec
        if rec is None:
            return None
        return {"name": rec["name"], "seconds": int(time.monotonic() - rec["started"]),
                "frames": rec["writer"].frames, "size": rec["writer"].bytes}

    def start_recording(self, folder):
        """Start a video in `folder`. Returns recording(); raises RuntimeError
        with a message fit for the UI when it cannot."""
        with self._rec_lock:
            if self._rec is not None:
                return self.recording()
            os.makedirs(folder, exist_ok=True)
            try:
                if shutil.disk_usage(folder).free < MIN_FREE_BYTES:
                    raise RuntimeError("not enough free space for a video")
            except OSError:
                pass
            if not self.acquire():
                raise RuntimeError(self.last_error or "the camera did not start")
            name = new_name(folder, ".avi")
            try:
                writer = AviWriter(os.path.join(folder, name), *STREAM_SIZE)
            except OSError as e:
                self.release()
                raise RuntimeError(f"cannot write the video: {e}")
            self._rec = {"name": name, "folder": folder, "writer": writer,
                         "started": time.monotonic(), "first": None, "last": None}
            logger.info(f"Camera recording started: {name}")
            return self.recording()

    def _record(self, frames):
        """Reader thread: add the new frames to the video being recorded."""
        stop = None
        with self._rec_lock:
            rec = self._rec
            if rec is None:
                return
            writer, now = rec["writer"], time.monotonic()
            try:
                for frame in frames:
                    writer.write(frame)
                rec["first"] = rec["first"] or now
                rec["last"] = now
                if now - rec["started"] >= MAX_RECORD_SECONDS:
                    stop = "stopped at the %d minute limit" % (MAX_RECORD_SECONDS // 60)
                elif (writer.frames % FREE_CHECK_FRAMES < len(frames)
                      and shutil.disk_usage(rec["folder"]).free < MIN_FREE_BYTES):
                    stop = "stopped: the disk is nearly full"
            except OSError as e:
                stop = f"stopped: {e}"
        if stop:
            self._finish_recording(stop)

    def stop_recording(self):
        """Finish the video. Returns {'name', 'seconds', 'frames', 'size',
        'note'} or None when nothing was recording."""
        return self._finish_recording(None)

    def _finish_recording(self, note):
        with self._rec_lock:
            rec, self._rec = self._rec, None
        if rec is None:
            return None
        writer = rec["writer"]
        span = (rec["last"] or 0) - (rec["first"] or 0)
        fps = (writer.frames - 1) / span if writer.frames > 1 and span > 0 else STREAM_FPS
        try:
            writer.close(fps)
        except OSError as e:
            note = note or f"could not finish the video: {e}"
        self.release()
        path = os.path.join(rec["folder"], rec["name"])
        done = {"name": rec["name"], "frames": writer.frames, "size": writer.bytes,
                "seconds": int(round(span)), "note": note}
        if writer.frames == 0:
            try:
                os.remove(path)
            except OSError:
                pass
            done.update(name=None, note=note or "no frames arrived from the camera")
        else:
            self._convert_async(path)
        self.last_video = done
        if note:
            self.last_error = note
        logger.info(f"Camera recording finished: {done}")
        return done

    def _convert_async(self, avi_path):
        """Turn a finished AVI into an MP4 (plays in a browser and on a
        phone) when ffmpeg is installed; the AVI is kept if that fails."""
        ffmpeg = _tool("ffmpeg")
        if not ffmpeg:
            return
        name = os.path.basename(avi_path)
        mp4, part = avi_path[:-4] + ".mp4", avi_path[:-4] + ".part"

        def work():
            cmd = ["nice", "-n", "15", ffmpeg, "-y", "-loglevel", "error", "-i", avi_path,
                   "-c:v", "libx264", "-preset", "veryfast", "-crf", "24",
                   "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-f", "mp4", part]
            try:
                result = self._run(cmd, capture_output=True, timeout=CONVERT_TIMEOUT)
                if result.returncode == 0 and os.path.getsize(part) > 0:
                    os.replace(part, mp4)
                    os.remove(avi_path)
                else:
                    logger.warning(f"Camera: {name} stays an AVI (ffmpeg failed)")
            except Exception as e:
                logger.warning(f"Camera: {name} stays an AVI ({e})")
            finally:
                try:
                    os.remove(part)
                except OSError:
                    pass
                self._converting.discard(name)

        self._converting.add(name)
        threading.Thread(target=work, name="pi-camera-mp4", daemon=True).start()

    def stop(self):
        with self._lock:
            self._viewers = 0
            self._stop_stream()
        if self._rec is not None:
            self._finish_recording("the camera was stopped")


_camera = None
_camera_lock = threading.Lock()


def get_camera(config=None):
    """The process-wide camera. With Ragnar's config, the picture is turned
    the way that config asks (see rotation_for)."""
    global _camera
    with _camera_lock:
        if _camera is None:
            _camera = PiCamera()
        camera = _camera
    if config is not None:
        try:
            camera.set_rotation(rotation_for(config))
        except Exception as e:
            logger.debug(f"camera rotation not applied: {e}")
    return camera


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
