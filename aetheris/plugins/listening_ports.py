"""Built-in plugin: processes listening on TCP/UDP ports."""
from aetheris.core.plugins import plugin, PluginContext


@plugin("listening-ports", "List sockets in the LISTEN state and their owners")
def run(ctx: PluginContext) -> str:
    listening = [c for c in ctx.connections(resolve_geo=False)
                 if c.status == "LISTEN"]
    if not listening:
        return "No listening sockets found."
    lines = ["# Listening ports", "",
             f"{'PROTO':<7}  {'LOCAL':<24}  {'PID':>7}  PROCESS"]
    for c in sorted(listening, key=lambda c: c.lport):
        lines.append(f"{c.kind + '/' + c.family[-1]:<7}  "
                     f"{c.laddr + ':' + str(c.lport):<24}  "
                     f"{(c.pid or 0):>7}  {c.proc_name}")
    lines.append("")
    lines.append(f"({len(listening)} listening socket(s))")
    return "\n".join(lines)


PLUGIN = run
