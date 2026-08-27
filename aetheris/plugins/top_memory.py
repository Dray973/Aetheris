"""Built-in plugin: the top memory-consuming processes."""
from aetheris.core.plugins import plugin, PluginContext


@plugin("top-memory", "List the 15 processes using the most memory")
def run(ctx: PluginContext) -> str:
    procs = sorted(ctx.processes(), key=lambda p: p.mem_rss, reverse=True)[:15]
    lines = ["# Top processes by memory", "",
             f"{'PID':>8}  {'MEM (MB)':>10}  {'CPU%':>6}  NAME"]
    for p in procs:
        lines.append(f"{p.pid:>8}  {p.mem_rss / 1048576:>10,.1f}  "
                     f"{p.cpu_percent:>6.1f}  {p.name}")
    total = sum(p.mem_rss for p in procs) / 1048576
    lines.append("")
    lines.append(f"(top 15 total: {total:,.1f} MB)")
    return "\n".join(lines)


PLUGIN = run
