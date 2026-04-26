#!/usr/bin/env python3
"""
PathTravScan v1.0.0 — Advanced Path Traversal & LFI Scanner
github.com/rastthack/PathTravScan
"""

import argparse
import re
import sys
import time

from rich import box
from rich.panel  import Panel
from rich.prompt import Confirm, Prompt
from rich.rule   import Rule
from rich.table  import Table

from scanner import PayloadEngine, RequestEngine, VulnDetector, ScanEngine, Reporter
from scanner.ui import (console, print_banner, print_disclaimer,
                        print_finding, print_table, print_summary,
                        print_request, print_response, make_progress)

VERSION = "1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
#  VALIDATION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _valid_url(url: str) -> bool:
    return bool(re.match(r'^https?://.+', url.strip()))

def _valid_path(path: str) -> bool:
    return path.strip().startswith("/")

def _valid_file(f: str) -> bool:
    s = f.strip()
    return s.startswith("/") or bool(re.match(r'^[A-Za-z]:[/\\]', s))

def _ask_url(label: str) -> str:
    while True:
        v = Prompt.ask(f"  {label}").strip()
        if not v:
            console.print("[red]  ✗  Cannot be empty. Example: https://target.com[/red]")
        elif not _valid_url(v):
            console.print("[red]  ✗  Must start with http:// or https://[/red]")
        else:
            return v

def _ask_path(label: str) -> str:
    while True:
        v = Prompt.ask(f"  {label}").strip()
        if not v:
            console.print("[red]  ✗  Cannot be empty. Example: /SiteScope/htdocs/artwork[/red]")
        elif not _valid_path(v):
            console.print("[red]  ✗  Must start with /   Example: /app/images[/red]")
        else:
            return v

def _ask_int(label: str, default: int, lo: int, hi: int) -> int:
    while True:
        raw = Prompt.ask(f"  {label}", default=str(default)).strip()
        try:
            v = int(raw)
            if lo <= v <= hi:
                return v
            console.print(f"[red]  ✗  Enter a number between {lo} and {hi}[/red]")
        except ValueError:
            console.print("[red]  ✗  Enter a whole number[/red]")

def _ask_float(label: str, default: float, lo: float, hi: float) -> float:
    while True:
        raw = Prompt.ask(f"  {label}", default=str(default)).strip()
        try:
            v = float(raw)
            if lo <= v <= hi:
                return v
            console.print(f"[red]  ✗  Enter a value between {lo} and {hi}[/red]")
        except ValueError:
            console.print("[red]  ✗  Enter a number e.g. 0.5[/red]")

# ─────────────────────────────────────────────────────────────────────────────
#  TARGET FILE MENU
# ─────────────────────────────────────────────────────────────────────────────

FILE_MENU = [
    ("/etc/passwd",                 "Linux — user list (confirms traversal)"),
    ("/etc/shadow",                 "Linux — password hashes  ★ HIGH value"),
    ("/etc/hosts",                  "Linux — host mappings"),
    ("/proc/version",               "Linux — kernel + gcc version"),
    ("/proc/self/environ",          "Linux — live environment variables / secrets"),
    ("/root/.ssh/id_rsa",           "Linux — root private SSH key  ★ CRITICAL"),
    ("/var/log/auth.log",           "Linux — SSH login history"),
    ("/var/www/html/.env",          "Web app — secrets, DB passwords, API keys"),
    ("/var/www/html/wp-config.php", "WordPress — database credentials"),
    ("C:/Windows/win.ini",          "Windows — confirms traversal on IIS"),
    ("C:/inetpub/wwwroot/web.config","Windows — connection strings, app secrets"),
]

def _ask_file() -> str:
    console.print("\n  [bold cyan]Target File[/bold cyan]\n")
    for i, (path, desc) in enumerate(FILE_MENU, 1):
        star = "[bold yellow]★[/bold yellow] " if "★" in desc else "  "
        console.print(f"   {star}[dim]{i:>2}.[/dim]  [green]{path:<40}[/green] {desc.split('★')[0].strip()}")
    console.print(f"   [dim] 0.[/dim]  Enter a custom file path\n")

    while True:
        raw = Prompt.ask("  Select number or type path directly", default="1").strip()

        # direct path typed
        if raw.startswith("/") or re.match(r'^[A-Za-z]:[/\\]', raw):
            if _valid_file(raw):
                return raw
            console.print("[red]  ✗  Invalid path[/red]")
            continue

        # numeric choice
        if raw.isdigit():
            n = int(raw)
            if n == 0:
                while True:
                    custom = Prompt.ask("  Custom file path").strip()
                    if _valid_file(custom):
                        return custom
                    console.print("[red]  ✗  Must start with / or C:/[/red]")
            if 1 <= n <= len(FILE_MENU):
                return FILE_MENU[n - 1][0]

        console.print(f"[red]  ✗  Enter a number 0–{len(FILE_MENU)} or a file path[/red]")

# ─────────────────────────────────────────────────────────────────────────────
#  PARAM SUMMARY TABLE
# ─────────────────────────────────────────────────────────────────────────────

def _summary(params: dict):
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan",
              title="[bold]Scan Configuration — Confirm[/bold]")
    t.add_column("Parameter", style="bold", width=22)
    t.add_column("Value",     style="green")
    for k, v in params.items():
        t.add_row(k, str(v))
    console.print(t)

# ─────────────────────────────────────────────────────────────────────────────
#  REPEATER MODE
# ─────────────────────────────────────────────────────────────────────────────

def run_repeater(req: RequestEngine):
    det     = VulnDetector()
    history = []
    console.print(Rule("[bold cyan]REPEATER MODE[/bold cyan]"))
    console.print("[dim]Commands: exit | history | clear[/dim]\n")

    while True:
        try:
            url = Prompt.ask("[bold cyan]URL[/bold cyan]").strip()
            if not url or url.lower() == "exit":
                break
            if url.lower() == "history":
                if not history:
                    console.print("[dim]No history yet.[/dim]")
                else:
                    for i, h in enumerate(history, 1):
                        sc = "green" if h["status"] == 200 else "red"
                        console.print(f"  [{i}] [{sc}]{h['status']}[/{sc}] {h['method']}  {h['url'][:80]}")
                continue
            if url.lower() == "clear":
                history.clear(); console.print("[dim]Cleared.[/dim]"); continue

            if not _valid_url(url):
                console.print("[red]  ✗  URL must start with http:// or https://[/red]")
                continue

            method   = Prompt.ask("[bold cyan]Method[/bold cyan]",
                                  choices=["GET","POST","PUT","HEAD","DELETE"], default="GET")
            hdr_raw  = Prompt.ask("[bold cyan]Extra Headers[/bold cyan] (Key:Val,Key2:Val2)", default="")
            extra    = {}
            for pair in hdr_raw.split(","):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    extra[k.strip()] = v.strip()
            body = None
            if method in ("POST", "PUT"):
                body = Prompt.ask("[bold cyan]Body[/bold cyan]", default="") or None

            print_request(url, method, extra)
            resp     = req.send(url, method=method, headers=extra, body=body)
            print_response(resp)
            analysis = det.analyse(resp, url.split("/")[-1] or "default")
            if analysis["vulnerable"]:
                console.print(f"\n[bold green]🔥 TRAVERSAL DETECTED!  "
                              f"Confidence: {analysis['confidence']}%  "
                              f"Evidence: {analysis['evidence']}[/bold green]\n")
            history.append({"url": url, "method": method,
                            "status": resp.get("status_code", "ERR")})
        except KeyboardInterrupt:
            console.print("\n[dim]Repeater stopped.[/dim]"); break

# ─────────────────────────────────────────────────────────────────────────────
#  GENERATE MODE
# ─────────────────────────────────────────────────────────────────────────────

def run_generate(base_path: str, target_file: str, output: str, mode: str):
    engine   = PayloadEngine()
    payloads = engine.quick(base_path, target_file) if mode == "quick" \
               else engine.full(base_path, target_file)
    console.print(f"\n[bold cyan]Generated {len(payloads)} payloads[/bold cyan]\n")
    for p in payloads[:25]:
        console.print(f"  [green]{p['type']:<16}[/green] {p['payload']}")
    if len(payloads) > 25:
        console.print(f"  [dim]... and {len(payloads)-25} more[/dim]")
    engine.save_wordlist(payloads, output)
    console.print(f"\n[green]✓ Saved {len(payloads)} payloads → {output}[/green]")

# ─────────────────────────────────────────────────────────────────────────────
#  SCAN MODE
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(args):
    engine   = PayloadEngine()
    req      = RequestEngine(timeout=args.timeout,
                             legacy_tls=args.legacy_tls,
                             proxy=args.proxy)
    scan_eng = ScanEngine(req, VulnDetector(),
                          threads=args.threads,
                          delay=args.delay,
                          stop_on_first=args.stop_on_first)
    reporter = Reporter()

    if args.wordlist:
        payloads = engine.from_wordlist(args.path, args.wordlist)
    elif args.mode == "quick":
        payloads = engine.quick(args.path, args.file)
    else:
        payloads = engine.full(args.path, args.file)

    # ── pre-scan info ─────────────────────────────────────────────────
    info = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    info.add_column(style="bold cyan", width=14)
    info.add_column(style="white")
    info.add_row("Target",   args.url)
    info.add_row("Path",     args.path)
    info.add_row("File",     args.file)
    info.add_row("Payloads", str(len(payloads)))
    info.add_row("Mode",     args.mode + (" [wordlist]" if args.wordlist else ""))
    info.add_row("Threads",  str(args.threads))
    info.add_row("Delay",    f"{args.delay}s")
    info.add_row("TLS 1.0",  "enabled" if args.legacy_tls else "disabled")
    info.add_row("Proxy",    args.proxy or "none")
    console.print(Panel(info, title="[bold]Scan Configuration[/bold]",
                        border_style="cyan", padding=(0, 1)))
    console.print()

    all_results, t0 = [], time.time()

    with make_progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(payloads))
        def on_result(r):
            all_results.append(r)
            if r["vulnerable"]:
                progress.console.print(
                    f"  [bold green]🔥 FOUND[/bold green]  "
                    f"[{r['status']}] {r['severity']} {r['confidence']}%  "
                    f"{r['payload'][:70]}")
            elif r.get("error"):
                progress.console.print(f"  [red]ERR[/red] {r['error'][:80]}")
            progress.advance(task)
        scan_eng.run(args.url, payloads, args.file, on_result=on_result)

    elapsed  = time.time() - t0
    findings = [r for r in all_results if r["vulnerable"]]

    console.print()
    if findings:
        console.print(Rule("[bold green]VULNERABILITIES FOUND[/bold green]"))
        for f in findings:
            print_finding(f)

    print_table(all_results, show_all=getattr(args, "show_all", False))
    print_summary(len(all_results), len(findings), elapsed)

    if args.output:
        jp = reporter.save_json(all_results, args.url, args.file, args.output)
        tp = reporter.save_txt (all_results, args.url, args.file,
                                args.output.replace(".json", ".txt"))
        console.print(f"[green]✓ JSON → {jp}[/green]")
        console.print(f"[green]✓ TXT  → {tp}[/green]")

# ─────────────────────────────────────────────────────────────────────────────
#  INTERACTIVE WIZARD  (fully validated, 4-step flow)
# ─────────────────────────────────────────────────────────────────────────────

def interactive_wizard():
    print_banner()
    print_disclaimer()
    console.print()

    if not Confirm.ask("[yellow]I confirm I have written authorization to test the target[/yellow]"):
        console.print("[red]Exiting. No targets were tested.[/red]")
        sys.exit(0)

    console.print()

    # ── Mode ──────────────────────────────────────────────────────────
    console.print(Panel(
        "  [bold cyan]scan[/bold cyan]      Automated path traversal scanner\n"
        "  [bold cyan]repeater[/bold cyan]  Burp-style manual request tool\n"
        "  [bold cyan]generate[/bold cyan]  Export payload wordlist to file",
        title="[bold]Select Mode[/bold]", border_style="cyan", padding=(0, 2)))
    mode = Prompt.ask("\n  Mode", choices=["scan","repeater","generate"], default="scan")
    console.print()

    # ══════════════════════════════════════════════════════════════════
    #  REPEATER
    # ══════════════════════════════════════════════════════════════════
    if mode == "repeater":
        console.print(Rule("[bold cyan]Repeater — Network[/bold cyan]"))
        timeout    = _ask_int("Timeout (seconds)", 10, 1, 120)
        legacy_tls = Confirm.ask("  Enable legacy TLS 1.0?", default=True)
        proxy      = Prompt.ask("  Proxy URL (blank = none)", default="").strip() or None
        run_repeater(RequestEngine(timeout=timeout, legacy_tls=legacy_tls, proxy=proxy))
        return

    # ══════════════════════════════════════════════════════════════════
    #  GENERATE
    # ══════════════════════════════════════════════════════════════════
    if mode == "generate":
        console.print(Rule("[bold cyan]Generate — Payload Config[/bold cyan]"))
        base_path   = _ask_path("Base path  (e.g. /app/images)")
        target_file = _ask_file()
        gen_mode    = Prompt.ask("  Payload mode", choices=["quick","full"], default="full")
        out         = Prompt.ask("  Output file", default="wordlists/custom_payloads.txt").strip()
        run_generate(base_path, target_file, out or "wordlists/custom_payloads.txt", gen_mode)
        return

    # ══════════════════════════════════════════════════════════════════
    #  SCAN — 4 validated steps, confirm before firing
    # ══════════════════════════════════════════════════════════════════

    # Step 1 — Target ─────────────────────────────────────────────────
    console.print(Rule("[bold cyan]Step 1 / 4 — Target[/bold cyan]"))
    target_url  = _ask_url("Target URL       e.g. https://target.com")
    base_path   = _ask_path("Vulnerable path  e.g. /SiteScope/htdocs/artwork")
    target_file = _ask_file()

    # Step 2 — Payloads ───────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan]Step 2 / 4 — Payload Settings[/bold cyan]"))
    console.print("  [dim]quick[/dim] = 15 top payloads (fast first pass)")
    console.print("  [dim]full[/dim]  = 300+ payloads across all 14 encodings × 10 depths\n")
    scan_mode = Prompt.ask("  Payload mode", choices=["quick","full"], default="quick")
    wordlist  = Prompt.ask("  Custom wordlist (blank = built-in)", default="").strip() or None

    # Step 3 — Network ────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan]Step 3 / 4 — Network Settings[/bold cyan]"))
    timeout    = _ask_int ("Timeout (seconds)                  [default 10]", 10, 1, 120)
    threads    = _ask_int ("Threads  1=stealth  5=balanced  10=fast", 1, 1, 50)
    delay      = _ask_float("Delay between requests (s)   0=none  0.5=stealthy", 0.0, 0.0, 60.0)
    legacy_tls = Confirm.ask("  Enable legacy TLS 1.0 support?", default=True)
    proxy      = Prompt.ask("  Proxy URL (blank=none  Burp: http://127.0.0.1:8080)",
                            default="").strip() or None

    # Step 4 — Output ─────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan]Step 4 / 4 — Output & Behaviour[/bold cyan]"))
    stop_first = Confirm.ask("  Stop on first confirmed finding?", default=False)
    show_all   = Confirm.ask("  Show ALL results in table (not just findings)?", default=False)
    output     = Prompt.ask("  Save report to (blank = skip)",
                            default="reports/report.json").strip() or None

    # Confirm ─────────────────────────────────────────────────────────
    console.print()
    _summary({
        "Target URL":    target_url,
        "Vuln Path":     base_path,
        "Target File":   target_file,
        "Payload Mode":  scan_mode + (" + wordlist" if wordlist else ""),
        "Threads":       threads,
        "Delay":         f"{delay}s",
        "Timeout":       f"{timeout}s",
        "Legacy TLS":    "Yes" if legacy_tls else "No",
        "Proxy":         proxy or "none",
        "Stop on First": "Yes" if stop_first else "No",
        "Report":        output or "not saved",
    })
    console.print()
    if not Confirm.ask("[bold yellow]Everything correct? Start scan?[/bold yellow]", default=True):
        console.print("[yellow]Cancelled. Re-run to start over.[/yellow]")
        sys.exit(0)

    class _Args: pass
    a = _Args()
    a.url = target_url; a.path = base_path; a.file = target_file
    a.mode = scan_mode; a.wordlist = wordlist; a.threads = threads
    a.delay = delay; a.timeout = timeout; a.legacy_tls = legacy_tls
    a.proxy = proxy; a.stop_on_first = stop_first
    a.show_all = show_all; a.output = output
    run_scan(a)

# ─────────────────────────────────────────────────────────────────────────────
#  --help  (custom rich formatter)
# ─────────────────────────────────────────────────────────────────────────────

HELP_TEXT = """
[bold cyan]PathTravScan v{ver}[/bold cyan]  —  Advanced Path Traversal & LFI Scanner
[dim]github.com/rastthack/PathTravScan[/dim]

[bold yellow]USAGE[/bold yellow]
  python pathtravscan.py                        Interactive wizard (recommended)
  python pathtravscan.py [OPTIONS]              CLI mode
  python pathtravscan.py repeater               Manual Burp-style repeater
  python pathtravscan.py generate [OPTIONS]     Generate payload wordlist

[bold yellow]TARGET FLAGS[/bold yellow]
  [bold]-u[/bold], [bold]--url[/bold]      URL    Target base URL
                       [dim]Example: https://target.com[/dim]
  [bold]-p[/bold], [bold]--path[/bold]     PATH   Vulnerable endpoint path
                       [dim]Example: /SiteScope/htdocs/artwork[/dim]
  [bold]-f[/bold], [bold]--file[/bold]     FILE   File to read (default: /etc/passwd)
                       [dim]Linux:   /etc/shadow  /root/.ssh/id_rsa  /proc/self/environ[/dim]
                       [dim]Windows: C:/Windows/win.ini  C:/inetpub/wwwroot/web.config[/dim]

[bold yellow]PAYLOAD FLAGS[/bold yellow]
  [bold]--mode[/bold]          quick | full
                       [dim]quick = 15 high-confidence payloads (fast first pass)[/dim]
                       [dim]full  = 300+ payloads × 14 encodings × 10 depths[/dim]
  [bold]--wordlist[/bold] FILE  Use a custom payload wordlist (one path per line)
                       [dim]Compatible with SecLists LFI wordlists[/dim]

[bold yellow]NETWORK FLAGS[/bold yellow]
  [bold]--threads[/bold]   N    Concurrent threads (default: 1, max: 50)
                       [dim]1=stealth  5=balanced  10=fast  (high values may trigger WAF)[/dim]
  [bold]--delay[/bold]     S    Delay between requests in seconds (default: 0)
                       [dim]0.5 = stealthy  2.0 = very slow / WAF evasion[/dim]
  [bold]--timeout[/bold]   S    Request timeout in seconds (default: 10)
  [bold]--proxy[/bold]     URL  Route all traffic through a proxy
                       [dim]Burp Suite:  http://127.0.0.1:8080[/dim]
                       [dim]OWASP ZAP:   http://127.0.0.1:8090[/dim]
  [bold]--no-legacy-tls[/bold]  Disable TLS 1.0 support (on by default)
                       [dim]Leave ON for old backend servers (SiteScope, Pulse Secure, etc.)[/dim]

[bold yellow]BEHAVIOUR FLAGS[/bold yellow]
  [bold]--stop-on-first[/bold]  Stop scanning after first confirmed finding
  [bold]--show-all[/bold]       Show every request in the results table (not just findings)

[bold yellow]OUTPUT FLAGS[/bold yellow]
  [bold]-o[/bold], [bold]--output[/bold]   FILE  Save JSON + TXT report
                       [dim]Auto-generates both report.json AND report.txt[/dim]

[bold yellow]INFO FLAGS[/bold yellow]
  [bold]--help[/bold]           Show this help message
  [bold]--version[/bold]        Show version number

[bold yellow]EXAMPLES[/bold yellow]
  [dim]# Interactive wizard — best for beginners[/dim]
  python pathtravscan.py

  [dim]# Quick scan — 15 payloads, fast first pass[/dim]
  python pathtravscan.py -u https://target.com -p /app/images -f /etc/passwd --mode quick

  [dim]# Full scan — 300+ payloads via Burp Suite[/dim]
  python pathtravscan.py -u https://target.com -p /app/images \\
    --mode full --proxy http://127.0.0.1:8080 --threads 5 -o reports/out.json

  [dim]# Legacy TLS bypass (old backend server found via Shodan)[/dim]
  python pathtravscan.py -u https://192.168.1.100 -p /SiteScope/htdocs/artwork \\
    --mode full -f /etc/shadow

  [dim]# Stealth scan — slow, randomised delay, single thread[/dim]
  python pathtravscan.py -u https://target.com -p /app --mode full \\
    --threads 1 --delay 2.0

  [dim]# Use SecLists wordlist[/dim]
  python pathtravscan.py -u https://target.com -p /app \\
    --wordlist ~/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt

  [dim]# Manual repeater — inspect raw request/response[/dim]
  python pathtravscan.py repeater

  [dim]# Export payload wordlist[/dim]
  python pathtravscan.py generate -p /app -f /etc/passwd --mode full -o wordlists/out.txt
""".format(ver=VERSION)

# ─────────────────────────────────────────────────────────────────────────────
#  CLI PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pathtravscan",
        add_help=False,   # we handle --help ourselves for Rich output
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-u","--url")
    p.add_argument("-p","--path")
    p.add_argument("-f","--file", default="/etc/passwd")
    p.add_argument("--mode",     choices=["quick","full"], default="quick")
    p.add_argument("--wordlist")
    p.add_argument("--threads",  type=int,   default=1)
    p.add_argument("--delay",    type=float, default=0.0)
    p.add_argument("--timeout",  type=int,   default=10)
    p.add_argument("--proxy")
    p.add_argument("--no-legacy-tls", dest="legacy_tls", action="store_false")
    p.add_argument("--stop-on-first", dest="stop_on_first", action="store_true")
    p.add_argument("--show-all",      dest="show_all",      action="store_true")
    p.add_argument("-o","--output")
    p.add_argument("--help",    "-h", action="store_true")
    p.add_argument("--version", "-V", action="store_true")
    p.set_defaults(legacy_tls=True, stop_on_first=False, show_all=False)

    sub = p.add_subparsers(dest="subcommand")

    sub.add_parser("repeater", add_help=False)

    gen = sub.add_parser("generate", add_help=False)
    gen.add_argument("-p","--path",  required=True)
    gen.add_argument("-f","--file",  default="/etc/passwd")
    gen.add_argument("--mode",       choices=["quick","full"], default="full")
    gen.add_argument("-o","--output",default="wordlists/generated.txt")

    return p

# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # no args → wizard
    if len(sys.argv) == 1:
        interactive_wizard()
        return

    parser = build_parser()
    args   = parser.parse_args()

    # --version
    if getattr(args, "version", False):
        console.print(f"PathTravScan v{VERSION}")
        sys.exit(0)

    # --help
    if getattr(args, "help", False):
        print_banner()
        console.print(HELP_TEXT)
        sys.exit(0)

    print_banner()

    # subcommands
    if args.subcommand == "repeater":
        req = RequestEngine(legacy_tls=args.legacy_tls, proxy=args.proxy)
        run_repeater(req)
        return

    if args.subcommand == "generate":
        run_generate(args.path, args.file, args.output, args.mode)
        return

    # ── CLI scan — strict validation ──────────────────────────────────
    errors = []
    if not args.url:
        errors.append("  [red]✗[/red]  -u / --url is required        e.g.  -u https://target.com")
    elif not _valid_url(args.url):
        errors.append("  [red]✗[/red]  --url must start with http:// or https://")

    if not args.path:
        errors.append("  [red]✗[/red]  -p / --path is required       e.g.  -p /app/images")
    elif not _valid_path(args.path):
        errors.append("  [red]✗[/red]  --path must start with /")

    if args.file and not _valid_file(args.file):
        errors.append("  [red]✗[/red]  --file must start with / or C:/")

    if args.threads < 1 or args.threads > 50:
        errors.append("  [red]✗[/red]  --threads must be 1–50")

    if args.delay < 0:
        errors.append("  [red]✗[/red]  --delay cannot be negative")

    if errors:
        console.print()
        console.print(Panel(
            "\n".join(errors) + "\n\n"
            "  Run [bold cyan]python pathtravscan.py --help[/bold cyan] for full flag reference.\n"
            "  Run [bold cyan]python pathtravscan.py[/bold cyan]        for the interactive wizard.",
            title="[bold red]Parameter Error[/bold red]",
            border_style="red", padding=(1, 2)
        ))
        sys.exit(1)

    args.output = args.output or "reports/report.json"
    run_scan(args)


if __name__ == "__main__":
    main()
