"""Sub-panels of the Shell Engineer tab (one module per panel)."""
from .autoruns_panel import AutorunsPanel
from .contextmenu_panel import ContextMenuPanel
from .persistence_panel import PersistencePanel
from .privacy_panel import PrivacyPanel
from .regdiff_panel import RegistryDiffPanel
from .services_panel import ServicesPanel
from .tasks_panel import TasksPanel

__all__ = [
    "AutorunsPanel",
    "ContextMenuPanel",
    "PersistencePanel",
    "PrivacyPanel",
    "RegistryDiffPanel",
    "ServicesPanel",
    "TasksPanel",
]
