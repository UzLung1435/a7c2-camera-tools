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


class _Coord(ctypes.Structure):
    _fields_ = (("X", ctypes.c_short), ("Y", ctypes.c_short))


class _SmallRect(ctypes.Structure):
    _fields_ = (("Left", ctypes.c_short), ("Top", ctypes.c_short),
                ("Right", ctypes.c_short), ("Bottom", ctypes.c_short))


class _BufferInfo(ctypes.Structure):
    _fields_ = (("dwSize", _Coord), ("dwCursorPosition", _Coord),
                ("wAttributes", ctypes.c_ushort), ("srWindow", _SmallRect),
                ("dwMaximumWindowSize", _Coord))


class _CursorInfo(ctypes.Structure):
    _fields_ = (("dwSize", ctypes.c_uint32), ("bVisible", ctypes.c_int))


class _WindowsViewport:
    def __init__(self):
        kernel = ctypes.windll.kernel32
        kernel.GetStdHandle.argtypes = [ctypes.c_uint32]
        kernel.GetStdHandle.restype = ctypes.c_void_p
        kernel.GetConsoleMode.argtypes = [ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_uint32)]
        kernel.GetConsoleScreenBufferInfo.argtypes = [ctypes.c_void_p,
                                                      ctypes.POINTER(_BufferInfo)]
        kernel.GetConsoleCursorInfo.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(_CursorInfo)]
        kernel.SetConsoleCursorInfo.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(_CursorInfo)]
        kernel.SetConsoleCursorPosition.argtypes = [ctypes.c_void_p, _Coord]
        kernel.FillConsoleOutputCharacterW.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar, ctypes.c_uint32, _Coord,
            ctypes.POINTER(ctypes.c_uint32)]
        kernel.FillConsoleOutputAttribute.argtypes = [
            ctypes.c_void_p, ctypes.c_ushort, ctypes.c_uint32, _Coord,
            ctypes.POINTER(ctypes.c_uint32)]
        kernel.WriteConsoleW.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        self.kernel = kernel
        self.handle = kernel.GetStdHandle(ctypes.c_uint32(-11).value)
        mode = ctypes.c_uint32()
        if not self.handle or not kernel.GetConsoleMode(self.handle, ctypes.byref(mode)):
            raise OSError("Windows console output is unavailable")
        self.cursor = _CursorInfo()
        if not kernel.GetConsoleCursorInfo(self.handle, ctypes.byref(self.cursor)):
            raise OSError("Windows console cursor is unavailable")
        self.previous = None
        self.frame = []

    def info(self):
        value = _BufferInfo()
        if not self.kernel.GetConsoleScreenBufferInfo(self.handle,
                                                       ctypes.byref(value)):
            raise OSError("Windows console viewport is unavailable")
        rect = value.srWindow
        return value, rect.Left, rect.Top, rect.Right - rect.Left + 1, rect.Bottom - rect.Top + 1

    def hide_cursor(self):
        hidden = _CursorInfo(self.cursor.dwSize, 0)
        self.kernel.SetConsoleCursorInfo(self.handle, ctypes.byref(hidden))

    def show_cursor(self):
        self.kernel.SetConsoleCursorInfo(self.handle, ctypes.byref(self.cursor))

    def paint(self, lines):
        info, left, top, width, height = self.info()
        geometry = left, top, width, height
        if geometry != self.previous:
            self.previous = geometry
            self.frame = []
        written = ctypes.c_uint32()
        for row in range(height):
            line = _clip(lines[row], width - 1) if row < len(lines) else ""
            if row < len(self.frame) and self.frame[row] == line:
                continue
            position = _Coord(left, top + row)
            self.kernel.FillConsoleOutputCharacterW(
                self.handle, " ", width, position, ctypes.byref(written))
            self.kernel.FillConsoleOutputAttribute(
                self.handle, info.wAttributes, width, position, ctypes.byref(written))
            if line:
                self.kernel.SetConsoleCursorPosition(self.handle, position)
                self.kernel.WriteConsoleW(self.handle, line, len(line),
                                          ctypes.byref(written), None)
            if row >= len(self.frame):
                self.frame.append(line)
            else:
                self.frame[row] = line
        self.kernel.SetConsoleCursorPosition(self.handle, _Coord(left, top + height - 1))

    def clear(self):
        self.previous = None
        self.frame = []
        self.paint([])


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
        self.windows_viewport = None

    def open(self):
        if not (sys.stdin.isatty() and self.stream.isatty()):
            return False
        if os.name == "nt":
            try:
                self.windows_viewport = _WindowsViewport()
                _, _, _, width, height = self.windows_viewport.info()
            except OSError:
                return False
            if width < 70 or height < 20:
                return False
            self.windows_viewport.hide_cursor()
        else:
            size = shutil.get_terminal_size((80, 24))
            if size.columns < 70 or size.lines < 20:
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
            if self.windows_viewport is not None:
                self.windows_viewport.clear()
                self.windows_viewport.show_cursor()
            elif not self.suspended:
                self.stream.write("\x1b[?25h\x1b[?1049l")
                self.stream.flush()
            self.active = False

    def _pulse(self):
        while not self.stop.wait(1):
            if not self.suspended and self.heartbeat and self.running_since is not None:
                self.render()

    def pause(self):
        if self.active and not self.suspended:
            with self.lock:
                self.suspended = True
                if self.windows_viewport is not None:
                    self.windows_viewport.show_cursor()
                else:
                    self.stream.write("\x1b[?25h\x1b[?1049l")
                    self.stream.flush()

    def resume(self):
        if self.active and self.suspended:
            with self.lock:
                if self.windows_viewport is not None:
                    self.windows_viewport.hide_cursor()
                    self.windows_viewport.previous = None
                else:
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
            if self.windows_viewport is not None:
                _, _, _, width, rows = self.windows_viewport.info()
            else:
                size = shutil.get_terminal_size((80, 24))
                width, rows = size.columns, size.lines
            columns = max(20, width - 1)
            height = max(12, rows - 1)
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
            if self.windows_viewport is not None:
                self.windows_viewport.paint(lines[:height])
            else:
                frame = "\x1b[H" + "\n".join("\x1b[2K" + _clip(line, columns)
                                                for line in lines[:height]) + "\x1b[J"
                self.stream.write(frame)
                self.stream.flush()
