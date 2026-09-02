"""Dark 'quantum core' stylesheet + level→colour map for the log drawer."""
from __future__ import annotations

from ..core.logbus import Level

QSS = """
* { font-family: 'Segoe UI', 'Cascadia Code', sans-serif; font-size: 12px; }
QMainWindow, QWidget { background: #0b0e14; color: #c8d3f5; }
QTabWidget::pane { border: none; border-top: 1px solid #223049; background: #0b0e14; }
QTabBar { qproperty-drawBase: 0; background: #090c12; }
QTabBar::tab {
    background: transparent; color: #6f7d9c;
    padding: 9px 20px; margin: 0;
    border: none; border-top: 2px solid transparent;
    border-top-left-radius: 4px; border-top-right-radius: 4px;
}
QTabBar::tab:hover:!selected { color: #b7c3e8; background: #0e1522; }
QTabBar::tab:selected {
    color: #eaf0ff; background: #121a2b; border-top: 2px solid #7dd3fc;
}
QPushButton {
    background: #16203a; color: #c8d3f5; border: 1px solid #274060;
    padding: 6px 14px; border-radius: 4px;
}
QPushButton:hover { background: #1d2b4d; border-color: #3b6ea5; }
QPushButton:pressed { background: #24365f; }
QPushButton#panic {
    background: #4a0f16; color: #ffb3ba; border: 1px solid #a4222f;
    font-weight: bold; padding: 6px 18px;
}
QPushButton#panic:hover { background: #6b1622; border-color: #ff4d5e; }
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox {
    background: #0d111a; color: #e6ecff; border: 1px solid #24304a;
    selection-background-color: #274060; padding: 4px;
}
QTableWidget, QTreeWidget {
    background: #0d111a; alternate-background-color: #10151f;
    gridline-color: #1c2333; border: 1px solid #1c2333;
}
QHeaderView::section {
    background: #131a28; color: #7dd3fc; border: none;
    border-right: 1px solid #1c2333; padding: 5px;
}
QTableWidget::item:selected, QTreeWidget::item:selected { background: #274060; }
QLabel#title { color: #7dd3fc; font-size: 16px; font-weight: bold; }
QLabel#subtle { color: #6b7699; }
QDockWidget { titlebar-close-icon: none; color: #7dd3fc; }
QScrollBar:vertical { background: #0b0e14; width: 12px; }
QScrollBar::handle:vertical { background: #24304a; border-radius: 5px; min-height: 24px; }
QStatusBar { background: #080a10; color: #6b7699; }
"""

LEVEL_COLORS = {
    Level.TRACE: "#5f6b8f",
    Level.INFO: "#9fb0e0",
    Level.WARN: "#e0b341",
    Level.ERROR: "#ff5d6c",
    Level.ACTION: "#7dd3fc",
    Level.SUCCESS: "#5ee0a0",
}
