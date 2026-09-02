# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec — build a single-file Aetheris Quantum Core executable.

    pyinstaller aetheris.spec            # -> dist/AetherisQuantumCore.exe

Design notes:
  * Entry point is run.py (keeps the UAC self-elevation bootstrap).
  * The optional native engines (comtypes/pywin32/capstone/keystone/memprocfs)
    are collected best-effort: if a package isn't installed in the build env it
    is simply skipped, and the app degrades gracefully at runtime.
  * uac_admin is False so the exe self-elevates via UAC at runtime (works from a
    normal double-click). Set it True to bake an always-elevated manifest.
"""
from PyInstaller.utils.hooks import collect_submodules, collect_dynamic_libs

# Optional modules to pull in fully when present in the build environment.
_OPTIONAL = [
    "pyqtgraph", "OpenGL", "comtypes", "win32com", "win32api", "win32con",
    "win32security", "win32file", "capstone", "keystone", "memprocfs", "yara",
]

hiddenimports = ["aetheris.cli", "aetheris.ui.schedule_dialog",
                 "aetheris.core.autoruns", "aetheris.core.updater"]
binaries = []
for mod in _OPTIONAL:
    try:
        hiddenimports += collect_submodules(mod)
    except Exception:
        pass
    try:
        binaries += collect_dynamic_libs(mod)   # native DLLs (e.g. memprocfs)
    except Exception:
        pass

# Built-in plugins are imported dynamically (importlib), so PyInstaller can't
# see them by static analysis — collect the whole package explicitly.
try:
    hiddenimports += collect_submodules("aetheris.plugins")
except Exception:
    pass

import os

datas = [("aetheris/ui/assets/aetheris.ico", "aetheris/ui/assets")]

# Bundle the native API-monitor agent DLL at the exe root if it's been built
# (agent/build.ps1 → dist/aetheris_agent.dll). apimonitor.agent_dll_path() looks
# for it next to sys._MEIPASS. Absent → the API Monitor tab reports it's unbuilt.
if os.path.exists("dist/aetheris_agent.dll"):
    datas.append(("dist/aetheris_agent.dll", "."))

a = Analysis(
    ["run.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "PySide6", "PyQt5", "pytest"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="AetherisQuantumCore",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,                 # GUI app: no console window
    disable_windowed_traceback=False,
    icon="aetheris/ui/assets/aetheris.ico",
    uac_admin=False,               # self-elevates at runtime; True = always admin
)
