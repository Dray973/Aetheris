# Aetheris Quantum Core — Installer

## ⭐ Install on ANY computer (no Python, no internet, no setup)

Use the **standalone frozen exe**. It bundles Python and every dependency
inside a single file — copy it to any Windows 10/11 machine and double-click.
Nothing else is required on that machine.

**Step 1 — build the exe once (on a machine that has this project + Python):**

```powershell
powershell -ExecutionPolicy Bypass -File installer\build_exe.ps1
# -> dist\AetherisQuantumCore.exe   (~66 MB, self-contained)
```

**Then, either:**

- **Just share the exe.** Give anyone `dist\AetherisQuantumCore.exe`. They
  double-click it. Done. (Windows SmartScreen may warn about an unknown
  publisher until the exe is code-signed — see [`../docs/SIGNING.md`](../docs/SIGNING.md).)

- **Or wrap it in a real setup.exe** (Start-menu entry, uninstall):

  ```powershell
  # 1) install Inno Setup 6:  https://jrsoftware.org/isdl.php
  # 2) compile the self-contained installer:
  & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\aetheris_exe.iss
  # -> installer\Output\AetherisQuantumCoreSetup.exe   (hand this to anyone)
  ```

  `aetheris_exe.iss` packages the frozen exe only — the target machine needs
  **nothing** (no Python, no pip, no internet).

> Do **not** use `Install.bat` / `install.ps1` for other people's machines —
> those download Python + dependencies at install time and need the whole
> project folder present. They're the developer / online-install path (below).

---

## Developer / online-install routes (need Python or internet on the target)

These install a Python-based copy instead of the frozen exe.

## 1. One-click (no build tools needed)

Ship the whole project folder (or a zip of it). The user:

1. Opens the `installer\` folder.
2. Double-clicks **`Install.bat`**.

That runs `install.ps1`, which:

- ensures **Python 3.10+** is present (installs Python 3.12 via `winget`, or
  downloads the official python.org installer if `winget` is unavailable),
- copies the app to `%LOCALAPPDATA%\Aetheris Quantum Core`,
- creates a private virtual environment and **downloads every dependency**
  (PyQt6, psutil, pyqtgraph, pywin32, comtypes, and best-effort capstone /
  keystone / memprocfs),

## 1. One-click (no build tools needed)

Ship the whole project folder (or a zip of it). The user:

1. Opens the `installer\` folder.
2. Double-clicks **`Install.bat`**.

That runs `install.ps1`, which:

- ensures **Python 3.10+** is present (installs Python 3.12 via `winget`, or
  downloads the official python.org installer if `winget` is unavailable),
- copies the app to `%LOCALAPPDATA%\Aetheris Quantum Core`,
- creates a private virtual environment and **downloads every dependency**
  (PyQt6, psutil, pyqtgraph, pywin32, comtypes, and best-effort capstone /
  keystone / memprocfs),
- creates **Start-menu + Desktop shortcuts** (flagged run-as-administrator; the
  app also self-elevates via UAC),
- registers an **Add/Remove Programs** entry.

Uninstall from *Apps & features*, or run `uninstall.ps1`.

> Per-user install — no admin needed for the app itself. Installing Python may
> prompt for elevation.

## 2. Single `AetherisSetup.exe` (Inno Setup)

For a classic one-file Windows installer:

1. Install **Inno Setup 6** — https://jrsoftware.org/isdl.php
2. Compile the script:
   ```powershell
   & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\aetheris.iss
   ```
3. Distribute the produced **`installer\Output\AetherisSetup.exe`**.

Running it installs to `Program Files`, then bootstraps the venv + dependencies
(the download step) and offers to launch on finish.

## 3. pip (developers)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .[full]      # or .[recommended] to skip the heavy forensics wheels
aetheris                 # GUI launcher entry point
```

## Files

| File | Role |
|---|---|
| `Install.bat`   | double-click entry point (wraps `install.ps1`) |
| `install.ps1`   | standalone installer: copy app, bootstrap, shortcuts, ARP entry |
| `bootstrap.ps1` | shared: ensure Python, create venv, download+install dependency tiers |
| `uninstall.ps1` | remove shortcuts, ARP entry, install dir |
| `aetheris_exe.iss` | **self-contained** installer → `AetherisQuantumCoreSetup.exe` (wraps the frozen exe; no Python needed on the target) |
| `aetheris.iss`  | online installer → `AetherisSetup.exe` (installs a Python venv at setup time) |
| `build_exe.ps1` | build the standalone one-file `AetherisQuantumCore.exe` (PyInstaller) |
| `build_all.ps1` | rebuild the exe (run after any code change) |
| `make_icon.py`  | regenerates the app icon `aetheris/ui/assets/aetheris.ico` |

(`../aetheris.spec` is the PyInstaller build spec used by `build_exe.ps1`.)

### App icon

The multi-resolution icon (`aetheris/ui/assets/aetheris.ico`, 16–256 px) is
committed and used by the window, taskbar, both shortcuts, the Inno Setup
wizard, and the Add/Remove Programs entry. To regenerate it (e.g. after a design
change), run `python installer/make_icon.py`.

## Notes

- **capstone / keystone / memprocfs** are best-effort: if a wheel isn't yet
  published for the installed Python version, the installer logs a skip and the
  app still runs (those features show an "install …" hint instead of crashing).
- The dependency download is the network step; the core install itself is local.
