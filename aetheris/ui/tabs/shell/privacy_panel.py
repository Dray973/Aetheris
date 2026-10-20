"""Privacy Exterminator: reversible telemetry toggles + DiagTrack shutdown."""
from __future__ import annotations

from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from ....core import registry
from ._base import PanelBase


class PrivacyPanel(PanelBase):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        v = QVBoxLayout(self)
        v.addWidget(QLabel("Each toggle is reversible via PANIC or the rollback ledger.",
                           objectName="subtle"))
        for key, (_r, _s, _n, _d, label) in registry.PRIVACY_TOGGLES.items():
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, k=key, lbl=label: self._apply_toggle(k, lbl))
            v.addWidget(b)
        dt = QPushButton("Stop + disable DiagTrack (Connected User Experiences) service")
        dt.clicked.connect(self._disable_diagtrack)
        v.addWidget(dt)
        v.addStretch(1)

    def _apply_toggle(self, key: str, label: str = "") -> None:
        # Registry writes are confirm-gated like every other write in the app.
        if not self._confirm("Privacy toggle",
                             f"{label or key}?\n\n(Reversible via PANIC.)"):
            return
        self._run(registry.apply_privacy_toggle, self._show_result, key)

    def _disable_diagtrack(self) -> None:
        if not self._confirm("DiagTrack", "Stop and disable the DiagTrack service?"):
            return
        self._run(registry.disable_diagtrack_service, self._show_result)

    def _show_result(self, res) -> None:
        ok, msg = res
        self._toast(ok, msg)
