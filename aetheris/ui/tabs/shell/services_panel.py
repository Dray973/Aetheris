"""Services & drivers: state, start type, signature, unquoted-path privesc."""
from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ._base import PanelBase


class ServicesPanel(PanelBase):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._services: list = []
        self._filtered_services: list = []
        v = QVBoxLayout(self)
        v.addWidget(QLabel(
            "Windows services + loaded kernel drivers: state, start type, "
            "Authenticode status, and unquoted-path privilege-escalation "
            "candidates (red). Start / Stop / Start-type are reversible (PANIC "
            "restores).", objectName="subtle"))
        bar = QHBoxLayout()
        self.svc_filter = QLineEdit(placeholderText="filter by name…")
        self.svc_filter.textChanged.connect(self._apply_svc_filter)
        bar.addWidget(self.svc_filter)
        self.svc_scope = QComboBox()
        self.svc_scope.addItems(["All", "Services", "Drivers",
                                 "Unquoted-path only", "Unsigned only"])
        self.svc_scope.currentIndexChanged.connect(self._apply_svc_filter)
        bar.addWidget(self.svc_scope)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_services)
        bar.addWidget(refresh)
        v.addLayout(bar)

        self.svc_table = QTableWidget(0, 7)
        self.svc_table.setHorizontalHeaderLabels(
            ["Name", "Kind", "State", "Start", "Signed", "Account", "Binary"])
        self.svc_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.svc_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.svc_table.horizontalHeader().setSectionResizeMode(
            6, QHeaderView.ResizeMode.Stretch)
        v.addWidget(self.svc_table)

        ctl = QHBoxLayout()
        for label, op in (("Start", "start"), ("Stop", "stop")):
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, o=op: self._svc_control(o))
            ctl.addWidget(b)
        ctl.addWidget(QLabel("Start type:"))
        self.svc_start_combo = QComboBox()
        self.svc_start_combo.addItems(["auto", "manual", "disabled"])
        ctl.addWidget(self.svc_start_combo)
        apply_b = QPushButton("Apply start type")
        apply_b.clicked.connect(lambda: self._svc_control("config"))
        ctl.addWidget(apply_b)
        ctl.addStretch(1)
        self.svc_count = QLabel("Click Refresh to enumerate services & drivers.",
                                objectName="subtle")
        self._status = self.svc_count
        ctl.addWidget(self.svc_count)
        v.addLayout(ctl)

    def _refresh_services(self) -> None:
        from ....core import services
        if self._run(lambda: services.enumerate_services() + services.enumerate_drivers(),
                     self._show_services):
            self.svc_count.setText("enumerating…")

    def _show_services(self, rows) -> None:
        self._services = rows
        self._apply_svc_filter()

    def _apply_svc_filter(self) -> None:
        needle = self.svc_filter.text().lower().strip()
        scope = self.svc_scope.currentText()
        rows = self._services
        if scope == "Services":
            rows = [r for r in rows if r.kind == "service"]
        elif scope == "Drivers":
            rows = [r for r in rows if r.kind == "driver"]
        elif scope == "Unquoted-path only":
            rows = [r for r in rows if r.unquoted_path]
        elif scope == "Unsigned only":
            rows = [r for r in rows if r.signed == "unsigned"]
        if needle:
            rows = [r for r in rows
                    if needle in r.name.lower() or needle in r.display_name.lower()]
        self._filtered_services = rows
        t = self.svc_table
        t.setRowCount(len(rows))
        for i, r in enumerate(rows):
            vals = [r.name, r.kind, r.state, r.start_type, r.signed, r.account, r.binary]
            for c, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                if r.unquoted_path:
                    item.setForeground(QColor("#ff5d6c"))
                elif r.signed == "unsigned":
                    item.setForeground(QColor("#e0b341"))
                t.setItem(i, c, item)
        n_vuln = sum(1 for r in self._services if r.unquoted_path)
        n_unsigned = sum(1 for r in self._services if r.signed == "unsigned")
        self.svc_count.setText(
            f"{len(rows)} shown / {len(self._services)} total  ·  "
            f"{n_vuln} unquoted-path  ·  {n_unsigned} unsigned")

    def _selected_service(self):
        row = self.svc_table.currentRow()
        if 0 <= row < len(self._filtered_services):
            return self._filtered_services[row]
        return None

    def _svc_control(self, op: str) -> None:
        from ....core import services
        svc = self._selected_service()
        if svc is None:
            self._toast(False, "select a service or driver first")
            return
        if svc.kind != "service":
            self._toast(False, "start/stop/start-type apply to services, not drivers")
            return
        newtype = self.svc_start_combo.currentText()
        action = ({"start": f"start {svc.name}", "stop": f"stop {svc.name}"}
                  .get(op, f"set {svc.name} start type to {newtype}"))
        if not self._confirm("Service control", f"{action}?\n\n(Reversible via PANIC.)"):
            return

        def call():
            if op == "start":
                return services.start_service(svc.name)
            if op == "stop":
                return services.stop_service(svc.name)
            return services.set_start_type(svc.name, newtype)

        self._run(call, self._show_result_then(self._refresh_services))
