"""
PathTravScan — Terminal UI (Rich)
All display logic: banner, panels, tables, progress bars.
"""
from typing import Dict, List
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table

console = Console()

BANNER = r"""
 ██████╗  █████╗ ████████╗██╗  ██╗    ████████╗██████╗  █████╗ ██╗   ██╗
 ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║    ╚══██╔══╝██╔══██╗██╔══██╗██║   ██║
 ██████╔╝███████║   ██║   ███████║       ██║   ██████╔╝███████║██║   ██║
 ██╔═══╝ ██╔══██║   ██║   ██╔══██║       ██║   ██╔══██╗██╔══██║╚██╗ ██╔╝
 ██║     ██║  ██║   ██║   ██║  ██║       ██║   ██║  ██║██║  ██║ ╚████╔╝
 ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝
"""

SEV_COLOR = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "INFO": "cyan"}


def print_banner():
    console.print(Panel(
        f"[bold cyan]{BANNER}[/bold cyan]"
        "[yellow]  Advanced Path Traversal Scanner  |  Burp-Style Repeater[/yellow]\n"
        "[dim]  v1.0.0  •  github.com/YourName/PathTravScan[/dim]\n"
        "[bold red]  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠[/bold red]",
        border_style="cyan", padding=(0, 2),
    ))


def print_disclaimer():
    console.print(Panel(
        "[bold red]LEGAL DISCLAIMER[/bold red]\n\n"
        "This tool is for [bold]authorized[/bold] penetration testing, security research,\n"
        "and bug bounty programs only. Unauthorized use is [bold red]ILLEGAL[/bold red] and\n"
        "may result in criminal prosecution. The authors accept NO liability for misuse.",
        border_style="red", padding=(0, 2),
    ))


def print_request(url: str, method: str, headers: Dict):
    lines = [f"[bold green]{method}[/bold green] {url} HTTP/1.1"]
    for k, v in list(headers.items())[:12]:
        lines.append(f"[cyan]{k}:[/cyan] {v}")
    console.print(Panel("\n".join(lines), title="[bold]REQUEST[/bold]", border_style="blue"))


def print_response(resp: Dict):
    st = resp.get("status_code", "N/A")
    c  = "green" if st == 200 else ("yellow" if str(st).startswith("3") else "red")
    hlines = [f"[{c}]HTTP/1.1 {st}[/{c}]"]
    for k, v in list(resp.get("response_headers", {}).items())[:12]:
        hlines.append(f"[cyan]{k}:[/cyan] {v}")
    console.print(Panel("\n".join(hlines), title="[bold]RESPONSE HEADERS[/bold]", border_style=c))
    body = (resp.get("body") or "")[:3000]
    if body:
        console.print(Panel(
            Syntax(body, "text", theme="monokai", line_numbers=True),
            title=f"[bold]RESPONSE BODY[/bold] ({resp.get('length',0)} bytes)",
            border_style=c,
        ))


def print_finding(r: Dict):
    sev = r.get("severity", "INFO")
    c   = SEV_COLOR.get(sev, "white")
    console.print(Rule(f"[bold {c}]🔥  {sev} — Confidence {r['confidence']}%[/bold {c}]"))
    console.print(f"  [bold]URL[/bold]      : {r['url']}")
    console.print(f"  [bold]Type[/bold]     : {r['type']}  |  Encoding: {r['encoding']}")
    console.print(f"  [bold]Status[/bold]   : {r['status']}  |  Length: {r['length']}B  |  {r['time_ms']}ms")
    console.print(f"  [bold]Evidence[/bold] : [green]{', '.join(r.get('evidence', []))}[/green]\n")
    preview = (r.get("body") or "")[:1800]
    if preview:
        console.print(Panel(
            Syntax(preview, "text", theme="monokai", line_numbers=True),
            title="File Content Preview", border_style=c,
        ))


def print_table(results: List[Dict], show_all: bool = False):
    t = Table(title="Scan Results", box=box.ROUNDED,
              show_header=True, header_style="bold cyan")
    t.add_column("#",        width=4,  style="dim")
    t.add_column("Status",   width=7)
    t.add_column("Length",   width=8)
    t.add_column("ms",       width=7)
    t.add_column("Depth",    width=5)
    t.add_column("Type",     width=14)
    t.add_column("Encoding", width=16)
    t.add_column("Sev",      width=9)
    t.add_column("Conf",     width=6)
    t.add_column("Payload",  min_width=40)

    for r in results:
        if not show_all and not r.get("vulnerable"):
            continue
        st  = str(r.get("status") or "ERR")
        sc  = ("green" if r.get("status") == 200
               else "yellow" if str(r.get("status","")).startswith("3")
               else "red")
        sev = r.get("severity", "")
        sc2 = SEV_COLOR.get(sev, "dim")
        pl  = r["payload"][:65] + "..." if len(r["payload"]) > 65 else r["payload"]
        t.add_row(
            str(r["index"]),
            f"[{sc}]{st}[/{sc}]",
            str(r.get("length", 0)),
            str(r.get("time_ms", 0)),
            str(r.get("depth", 0)),
            r.get("type", "-"),
            (r.get("encoding") or "-")[:15],
            f"[bold {sc2}]{sev}[/bold {sc2}]" if sev else "-",
            f"{r['confidence']}%" if r.get("vulnerable") else "-",
            pl,
        )
    console.print(t)


def print_summary(total: int, findings: int, elapsed: float):
    g = Table.grid(padding=(0, 3))
    g.add_column(); g.add_column()
    g.add_row("[bold]Total payloads tested[/bold]", str(total))
    g.add_row("[bold]Vulnerabilities found[/bold]",
              f"[bold {'green' if findings else 'yellow'}]{findings}[/]")
    g.add_row("[bold]Time taken[/bold]", f"{elapsed:.1f}s")
    console.print(Panel(g, title="[bold]SCAN SUMMARY[/bold]", border_style="cyan"))


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        TimeElapsedColumn(),
        console=console,
    )
