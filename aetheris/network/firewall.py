"""
Live firewall isolation via the Windows Advanced Firewall COM interface
(INetFwPolicy2 / HNetCfg.FwPolicy2).

``isolate(app_path)`` injects paired inbound+outbound BLOCK rules scoped to a
specific executable image, instantly dropping that app's traffic across all
profiles. Every rule added is registered with the Omega Rollback ledger so the
PANIC button removes it, and ``deisolate`` removes it on demand.

Uses win32com if present, else comtypes. Both talk to the same COM objects.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core import dryrun, logbus, safety

SRC = "network.firewall"

NET_FW_RULE_DIR_IN = 1
NET_FW_RULE_DIR_OUT = 2
NET_FW_ACTION_BLOCK = 0
NET_FW_PROFILE2_ALL = 0x7FFFFFFF
RULE_PREFIX = "Aetheris Isolation"


def _dispatch(progid: str):
    try:
        import win32com.client  # type: ignore
        return win32com.client.Dispatch(progid)
    except Exception:
        import comtypes.client  # type: ignore
        return comtypes.client.CreateObject(progid)


def _policy():
    return _dispatch("HNetCfg.FwPolicy2")


@dataclass
class IsolationResult:
    ok: bool
    message: str
    rule_names: list[str]


def isolate(app_path: str, label: str | None = None) -> IsolationResult:
    """Add BLOCK rules (in + out) for ``app_path``. Registers rollback."""
    label = label or app_path.rsplit("\\", 1)[-1]
    names: list[str] = []
    if dryrun.skip(SRC, f"isolate {label} (block in+out)", app_path):
        return IsolationResult(True, f"[dry-run] would isolate {label}", [])
    try:
        policy = _policy()
        rules = policy.Rules
        for direction, dname in ((NET_FW_RULE_DIR_OUT, "out"), (NET_FW_RULE_DIR_IN, "in")):
            rule = _dispatch("HNetCfg.FWRule")
            rule.Name = f"{RULE_PREFIX}: {label} ({dname})"
            rule.Description = "Injected by Aetheris Quantum Core socket isolation"
            rule.ApplicationName = app_path
            rule.Direction = direction
            rule.Action = NET_FW_ACTION_BLOCK
            rule.Enabled = True
            rule.Profiles = NET_FW_PROFILE2_ALL
            rules.Add(rule)
            names.append(rule.Name)
            logbus.action(SRC, f"BLOCK rule added: {rule.Name}", app_path)

        safety.ledger.register(
            f"firewall isolation: {label}",
            lambda p=app_path, ns=list(names): _remove_rules(ns),
        )
        return IsolationResult(True, f"isolated {label} (in+out blocked)", names)
    except Exception as exc:  # noqa: BLE001
        logbus.error(SRC, f"isolation failed for {app_path}", str(exc))
        return IsolationResult(False, str(exc), names)


def _remove_rules(names: list[str]) -> None:
    policy = _policy()
    rules = policy.Rules
    for n in names:
        try:
            rules.Remove(n)
            logbus.success(SRC, f"removed rule: {n}")
        except Exception as exc:  # noqa: BLE001
            logbus.warn(SRC, f"could not remove rule {n}", str(exc))


def deisolate(app_label: str) -> tuple[bool, str]:
    """Remove both isolation rules for a label."""
    names = [f"{RULE_PREFIX}: {app_label} (out)", f"{RULE_PREFIX}: {app_label} (in)"]
    try:
        _remove_rules(names)
        return True, f"removed isolation for {app_label}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def list_isolation_rules() -> list[str]:
    """Return the names of currently active Aetheris isolation rules."""
    out: list[str] = []
    try:
        policy = _policy()
        for rule in policy.Rules:
            try:
                if str(rule.Name).startswith(RULE_PREFIX):
                    out.append(rule.Name)
            except Exception:
                continue
    except Exception as exc:  # noqa: BLE001
        logbus.warn(SRC, "could not enumerate firewall rules", str(exc))
    return out
