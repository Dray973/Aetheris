"""Built-in plugin: active connections to public IP addresses."""
from aetheris.core.plugins import PluginContext, plugin

PERMISSIONS = ["reads-connections", "network"]


@plugin("public-connections", "List established connections to public IPs (with geo)")
def run(ctx: PluginContext) -> str:
    conns = [c for c in ctx.connections()
             if c.remote_class == "public" and c.raddr]
    if not conns:
        return "No established connections to public IP addresses."
    lines = ["# Public connections", "",
             f"{'PID':>7}  {'PROCESS':<20}  {'REMOTE':<22}  {'PORT':>5}  GEO"]
    for c in sorted(conns, key=lambda c: (c.proc_name, c.raddr)):
        lines.append(f"{(c.pid or 0):>7}  {c.proc_name[:20]:<20}  "
                     f"{c.raddr:<22}  {c.rport:>5}  {c.geo}")
    lines.append("")
    lines.append(f"({len(conns)} public connection(s))")
    return "\n".join(lines)


PLUGIN = run
