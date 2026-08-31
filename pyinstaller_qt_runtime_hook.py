"""Prioritize GibVPN's bundled Qt DLLs in one-file Windows builds."""

import ctypes
import os
import sys


if getattr(sys, "frozen", False):
    qt_bin = os.path.join(sys._MEIPASS, "PyQt6", "Qt6", "bin")
    if os.path.isdir(qt_bin):
        os.environ["PATH"] = qt_bin + os.pathsep + os.environ.get("PATH", "")
        os.add_dll_directory(qt_bin)
        ctypes.windll.kernel32.SetDllDirectoryW(qt_bin)
