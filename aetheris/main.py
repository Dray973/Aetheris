"""
Application bootstrap: build the QApplication and show the main window.

Kept import-light at module top so ``python -c "import aetheris.main"`` works
for smoke tests even where PyQt6 isn't installed; the heavy imports happen
inside run_app().
"""
from __future__ import annotations

import sys


def run_app() -> int:
    try:
        from PyQt6.QtWidgets import QApplication
    except Exception as exc:  # pragma: no cover
        print("PyQt6 is required to launch the GUI. Install with: pip install PyQt6")
        print(f"(import error: {exc})")
        return 2

    from PyQt6.QtGui import QIcon

    from .core import crashreport
    from .ui.mainwindow import ICON_PATH, MainWindow

    crashreport.install()          # scrubbed crash file on any unhandled exception

    app = QApplication(sys.argv)
    app.setApplicationName("Aetheris Quantum Core")
    app.setOrganizationName("Aetheris")
    if ICON_PATH.exists():
        app.setWindowIcon(QIcon(str(ICON_PATH)))

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(run_app())
