"""Fixed terminal display used by the interactive installer."""

from collections import deque
import atexit
import ctypes
import os
import shutil
import sys
import threading
import time
import unicodedata


def _width(text):
    return sum(0 if unicodedata.combining(char) else
               2 if unicodedata.east_asian_width(char) in "WF" else 1
               for char in text)


def _clip(text, width):
    if _width(text) <= width:
        return text
    result = ""
    used = 0
    for char in text:
        size = _width(char)
        if used + size > width - 1:
            break
        result += char
        used += size
    return result + "…"


def _wrap(text, width):
    rows = []
    for source in str(text).split("\n"):
        current = ""
        used = 0
        for char in source:
            size = _width(char)
            if used + size > width and current:
                split = current.rfind(" ")
                if split > 0:
                    rows.append(current[:split])
                    current = current[split + 1:]
                    used = _width(current)
                else:
                    rows.append(current)
                    current = ""
                    used = 0
            current += char
            used += size
        rows.append(current)
    return rows


class Panel:
    def __init__(self, platform):
        self.platform = platform
        self.stream = sys.stdout
        self.active = False
        self.suspended = False
        self.language = ""
        self.camera = "—"
        self.features = "—"
        self.step = "—"
        self.done = 0
        self.total = 0
        self.status = ""
        self.prompt = ""
        self.events = deque(maxlen=12)
        self.running_since = None
        self.heartbeat = False
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.thread = None
        self.windows_mode = None

    def open(self):
        if not (sys.stdin.isatty() and self.stream.isatty()):
            return False
        size = shutil.get_terminal_size((80, 24))
        if size.columns < 70 or size.lines < 20:
            return False
        if os.name == "nt":
            kernel = ctypes.windll.kernel32
            kernel.GetStdHandle.argtypes = [ctypes.c_uint32]
            kernel.GetStdHandle.restype = ctypes.c_void_p
            kernel.GetConsoleMode.argtypes = [ctypes.c_void_p,
                                              ctypes.POINTER(ctypes.c_uint32)]
            kernel.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            handle = kernel.GetStdHandle(ctypes.c_uint32(-11).value)
            mode = ctypes.c_uint32()
            if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            self.windows_mode = (handle, mode.value)
            if not kernel.SetConsoleMode(handle, mode.value | 0x0004):
                return False
        self.stream.write("\x1b[?1049h\x1b[?25l")
        self.stream.flush()
        self.active = True
        self.thread = threading.Thread(target=self._pulse, daemon=True)
        self.thread.start()
        atexit.register(self.close)
        self.render()
        return True

    def close(self):
        if not self.active:
            return
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=1)
        with self.lock:
            if not self.suspended:
                self.stream.write("\x1b[?25h\x1b[?1049l")
                self.stream.flush()
            self.active = False
        if self.windows_mode is not None:
            handle, mode = self.windows_mode
            ctypes.windll.kernel32.SetConsoleMode(handle, mode)

    def _pulse(self):
        while not self.stop.wait(1):
            if not self.suspended and self.heartbeat and self.running_since is not None:
                self.render()

    def pause(self):
        if self.active and not self.suspended:
            with self.lock:
                self.suspended = True
                self.stream.write("\x1b[?25h\x1b[?1049l")
                self.stream.flush()

    def resume(self):
        if self.active and self.suspended:
            with self.lock:
                self.stream.write("\x1b[?1049h\x1b[?25l")
                self.stream.flush()
                self.suspended = False
            self.render()

    def set_language(self, value):
        with self.lock:
            self.language = value
        self.render()

    def set_camera(self, value):
        with self.lock:
            self.camera = value
        self.render()

    def set_features(self, value):
        with self.lock:
            self.features = value
        self.render()

    def set_progress(self, done, total, step):
        with self.lock:
            self.done, self.total, self.step = done, total, step
        self.render()

    def set_status(self, value):
        with self.lock:
            self.status = str(value)
        self.render()

    def set_prompt(self, value):
        with self.lock:
            self.prompt = str(value)
        self.render()

    def event(self, value):
        with self.lock:
            for line in str(value).splitlines():
                if line.strip():
                    self.events.append(line.strip())
        self.render()

    def start_task(self, value, heartbeat=True):
        with self.lock:
            self.running_since = time.monotonic()
            self.heartbeat = heartbeat
            self.status = str(value)
        self.event(value)

    def end_task(self):
        with self.lock:
            self.heartbeat = False
            self.running_since = None
        self.render()

    def render(self):
        if not self.active or self.suspended:
            return
        with self.lock:
            size = shutil.get_terminal_size((80, 24))
            columns = max(20, size.columns - 1)
            height = max(12, size.lines - 1)
            bar_width = min(36, max(12, columns - 30))
            filled = (bar_width * self.done // self.total) if self.total else 0
            bar = "█" * filled + "·" * (bar_width - filled)
            elapsed = (f"  {int(time.monotonic() - self.running_since)}s"
                       if self.running_since is not None else "")
            heading = f"A7C II  |  {self.platform}  |  {self.language}"
            fixed = [heading, "─" * columns,
                     f"Camera: {self.camera}    Features: {self.features}",
                     f"Progress: {self.done}/{self.total}  [{bar}]",
                     f"Current: {self.step}",
                     f"Status: {self.status}{elapsed}", "─" * columns,
                     "Recent events:"]
            prompt_rows = _wrap(self.prompt, columns) if self.prompt else []
            prompt_rows = prompt_rows[:max(3, height // 3)]
            event_space = max(2, height - len(fixed) - len(prompt_rows) - 2)
            recent = list(self.events)[-event_space:]
            lines = fixed + ["  " + line for line in recent]
            lines += [""] * (event_space - len(recent))
            lines += ["─" * columns] + prompt_rows
            frame = "\x1b[H" + "\n".join("\x1b[2K" + _clip(line, columns)
                                            for line in lines[:height]) + "\x1b[J"
            self.stream.write(frame)
            self.stream.flush()
