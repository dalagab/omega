#!/usr/bin/env python3
"""Native DeltaScope desktop window hosted by pywebview.

This process is presentation-only. Go owns the loopback front door and Python
DeltaScope owns application/security semantics; no JS API is exposed here.
"""
from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path
import struct
import sys

APP_USER_MODEL_ID = "Dalagab.Omega.DeltaScope"

WM_SETICON = 0x0080
ICON_SMALL = 0
ICON_BIG = 1
IMAGE_ICON = 1
LR_LOADFROMFILE = 0x0010
SM_CXICON = 11
SM_CYICON = 12
SM_CXSMICON = 49
SM_CYSMICON = 50


def _png_size(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:24])
    if not (1 <= width <= 256 and 1 <= height <= 256):
        return None
    return width, height


def png_to_ico(source: Path, destination: Path) -> Path | None:
    """Wrap one <=256px PNG in an ICO container without changing artwork."""
    try:
        data = source.read_bytes()
        size = _png_size(data)
        if size is None:
            return None
        width, height = size
        destination.parent.mkdir(parents=True, exist_ok=True)
        entry = struct.pack(
            "<BBBBHHII",
            0 if width == 256 else width,
            0 if height == 256 else height,
            0,
            0,
            1,
            32,
            len(data),
            6 + 16,
        )
        destination.write_bytes(struct.pack("<HHH", 0, 1, 1) + entry + data)
        return destination
    except OSError:
        return None


def resolve_icon(raw: str, cache_dir: Path) -> str | None:
    if not raw:
        return None
    source = Path(raw).expanduser().resolve()
    if not source.is_file():
        return None
    if sys.platform == "win32" and source.suffix.lower() == ".png":
        converted = png_to_ico(source, cache_dir / "deltascope.ico")
        return str(converted) if converted else None
    return str(source)


def set_windows_identity() -> None:
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass


def _native_window_handle(window: object) -> int:
    native = getattr(window, "native", None)
    handle = getattr(native, "Handle", None)
    if handle is None:
        return 0
    for method_name in ("ToInt64", "ToInt32"):
        method = getattr(handle, method_name, None)
        if callable(method):
            try:
                return int(method())
            except (TypeError, ValueError, OverflowError):
                pass
    try:
        return int(handle)
    except (TypeError, ValueError, OverflowError):
        return 0


def apply_windows_window_icon(window: object, icon: str | None) -> bool:
    """Force the DeltaScope ICO onto the native WinForms HWND/taskbar button.

    pywebview 6.2 supports WinForms icons, but the top-level process is still python.exe.
    Explicit WM_SETICON messages prevent Windows from falling back to Python's executable
    icon when the Edge/WebView2 host creates the taskbar entry.
    """
    if sys.platform != "win32" or not icon:
        return False
    path = Path(icon)
    if path.suffix.lower() != ".ico" or not path.is_file():
        return False
    hwnd = _native_window_handle(window)
    if not hwnd:
        return False

    try:
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.LoadImageW.argtypes = [
            wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
            ctypes.c_int, ctypes.c_int, wintypes.UINT,
        ]
        user32.LoadImageW.restype = wintypes.HANDLE
        user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.SendMessageW.restype = wintypes.LRESULT

        def load_icon(width_metric: int, height_metric: int):
            width = int(user32.GetSystemMetrics(width_metric))
            height = int(user32.GetSystemMetrics(height_metric))
            return user32.LoadImageW(None, str(path), IMAGE_ICON, width, height, LR_LOADFROMFILE)

        big = load_icon(SM_CXICON, SM_CYICON)
        small = load_icon(SM_CXSMICON, SM_CYSMICON)
        if not big and not small:
            return False
        if big:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, int(big))
        if small:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, int(small))
        return True
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--url")
    parser.add_argument("--title", default="DeltaScope")
    parser.add_argument("--width", type=int, default=1600)
    parser.add_argument("--height", type=int, default=1000)
    parser.add_argument("--storage-path", default="")
    parser.add_argument("--icon", default="")
    args = parser.parse_args()

    try:
        import webview
    except Exception as exc:
        print(f"pywebview unavailable: {exc}", file=sys.stderr)
        return 2

    if args.probe:
        print(getattr(webview, "__version__", "pywebview"))
        return 0
    if not args.url:
        parser.error("--url is required")

    set_windows_identity()
    storage = Path(args.storage_path).expanduser().resolve() if args.storage_path else Path.home() / ".deltascope-webview"
    storage.mkdir(parents=True, exist_ok=True)
    icon = resolve_icon(args.icon, storage)

    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
    window = webview.create_window(
        args.title,
        args.url,
        width=max(args.width, 960),
        height=max(args.height, 680),
        min_size=(900, 620),
        background_color="#f4f4f4",
        text_select=True,
    )
    if sys.platform == "win32" and icon:
        window.events.before_show += lambda current_window: apply_windows_window_icon(current_window, icon)
    start_kwargs = {
        "private_mode": False,
        "storage_path": str(storage),
        "debug": False,
    }
    if sys.platform == "win32":
        start_kwargs["gui"] = "edgechromium"
    if icon:
        start_kwargs["icon"] = icon
    webview.start(**start_kwargs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
