#!/usr/bin/env python3
"""
PathTravScan — Main CLI Entry Point
Usage: python pathtravscan.py [options]
       python pathtravscan.py          (interactive wizard)
"""
import argparse
import sys
import time

from rich.prompt import Confirm, Prompt
from rich.rule   import Rule

from scanner           import PayloadEngine, RequestEngine, VulnDetector, ScanEngine, Reporter
from scanner.ui        import (console, print_banner, print_disclaimer,
                               print_finding, print_table, print_summary,
                               print_request, print_response, make_progress)

# ──────────────────────────────────────────────────────────────────────────────
#  REPEATER MODE
# ──────────────────────────────────────────────────────────────────────────────

def run_repeater(req: RequestEngine):
    """Burp Suite-style manual request repeater."""
    det = VulnDetector()
    history = []

    console.print(Rule("[bold cyan]REPEATER MODE[/bold cyan]"))
    console.print("[dim]Send individual requests manually. Commands: exit | history | clear[/dim]\n")

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
                        console.print(f"  [{i}] [{h['status']}] {h['method']} {h['url'][:80]}")
                continue
            if url.lower() == "clear":
                history.clear()
                console.print("[dim]History cleared.[/dim]")
                continue

            method = Prompt.ask("[bold cyan]Method[/bold cyan]",
                                choices=["GET","POST","PUT","HEAD","DELETE"],
                                default="GET")

            raw_hdrs = Prompt.ask("[bold cyan]Extra Headers[/bold cyan] (Key:Val,Key2:Val2)",
                                  default="")
            extra = {}
            for pair in raw_hdrs.split(","):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    extra[k.strip()] = v.strip()

            body_data = None
            if method in ("POST", "PUT"):
                body_data = Prompt.ask("[bold cyan]Body[/bold cyan]", default="") or None

            print_request(url, method, extra)
            resp = req.send(url, method=method, headers=extra, body=body_data)
            print_response(resp)

            target_guess = url.split("/")[-1] or "default"
            analysis = det.analyse(resp, target_guess)
            if analysis["vulnerable"]:
                console.print(f"\n[bold green]🔥 TRAVERSAL DETECTED!  "
                              f"Evidence: {analysis['evidence']}  "
                              f"Confidence: {analysis['confidence']}%[/bold green]\n")

            history.append({
                "url": url, "method": method,
                "status": resp.get("status_code","ERR"),
            })

        except KeyboardInterrupt:
            console.print("\n[dim]Repeater stopped.[/dim]")
            break


# ──────────────────────────────────────────────────────────────────────────────
#  GENERATE MODE
# ──────────────────────────────────────────────────────────────────────────────

def run_generate(base_path: str, target_file: str, output: str, mode: str):
    engine = PayloadEngine()
    if mode == "quick":
        payloads = engine.quick(base_path, target_file)
    else:
        payloads = engine.full(base_path, target_file)

    console.print(f"\n[bold cyan]Generated {len(payloads)} payloads[/bold cyan]\n")
    for p in payloads[:20]:
        console.print(f"  [green]{p['type']:<14}[/green]  {p['payload']}")
    if len(payloads) > 20:
        console.print(f"  [dim]...and {len(payloads)-20} more[/dim]")

    engine.save_wordlist(payloads, output)
    console.print(f"\n[green]✓ Saved {len(payloads)} payloads → {output}[/green]")


# ──────────────────────────────────────────────────────────────────────────────
#  SCAN MODE
# ──────────────────────────────────────────────────────────────────────────────

def run_scan(args):
    engine   = PayloadEngine()
    req      = RequestEngine(
                   timeout=args.timeout,
                   legacy_tls=args.legacy_tls,
                   proxy=args.proxy)
    det      = VulnDetector()
    scan_eng = ScanEngine(req, det,
                          threads=args.threads,
                          delay=args.delay,
                          stop_on_first=args.stop_on_first)
    reporter = Reporter()

    # Build payload list
    if args.wordlist:
        payloads = engine.from_wordlist(args.path, args.wordlist)
    elif args.mode == "quick":
        payloads = engine.quick(args.path, args.file)
    else:
        payloads = engine.full(args.path, args.file)

    console.print(f"\n[bold cyan]Scanning[/bold cyan] {args.url}")
    console.print(f"  Path     : {args.path}")
    console.print(f"  File     : {args.file}")
    console.print(f"  Payloads : {len(payloads)}")
    console.print(f"  Threads  : {args.threads}")
    console.print(f"  Delay    : {args.delay}s")
    console.print(f"  Proxy    : {args.proxy or 'none'}\n")

    all_results = []
    t0 = time.time()

    with make_progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(payloads))

        def on_result(r):
            all_results.append(r)
            if r["vulnerable"]:
                progress.console.print(
                    f"  [bold green]🔥 FOUND[/bold green]  "
                    f"[{r['status']}] {r['severity']} {r['confidence']}%  "
                    f"{r['payload'][:70]}"
                )
            elif r.get("error"):
                progress.console.print(f"  [red]ERR[/red]  {r['error'][:80]}")
            progress.advance(task)

        scan_eng.run(args.url, payloads, args.file, on_result=on_result)

    elapsed  = time.time() - t0
    findings = [r for r in all_results if r["vulnerable"]]

    console.print()
    if findings:
        console.print(Rule("[bold green]VULNERABILITIES FOUND[/bold green]"))
        for f in findings:
            print_finding(f)

    # Table
    show_all = getattr(args, "show_all", False)
    print_table(all_results, show_all=show_all)
    print_summary(len(all_results), len(findings), elapsed)

    # Save reports
    if args.output:
        json_path = reporter.save_json(all_results, args.url, args.file, args.output)
        txt_path  = reporter.save_txt(all_results, args.url, args.file,
                                      args.output.replace(".json", ".txt"))
        console.print(f"[green]✓ JSON report → {json_path}[/green]")
        console.print(f"[green]✓ TXT  report → {txt_path}[/green]")


# ──────────────────────────────────────────────────────────────────────────────
#  INTERACTIVE WIZARD
# ──────────────────────────────────────────────────────────────────────────────

def interactive_wizard():
    print_banner()
    print_disclaimer()
    console.print()

    if not Confirm.ask("[yellow]I confirm I have written authorization to test the target[/yellow]"):
        console.print("[red]Exiting. No targets were tested.[/red]")
        sys.exit(0)

    console.print()
    mode = Prompt.ask("Select mode",
                      choices=["scan","repeater","generate"],
                      default="scan")

    timeout    = int(Prompt.ask("Request timeout (seconds)", default="10"))
    legacy_tls = Confirm.ask("Enable legacy TLS 1.0 support?", default=True)
    proxy_raw  = Prompt.ask("Proxy URL (blank = none)", default="")
    proxy      = proxy_raw.strip() or None

    req = RequestEngine(timeout=timeout, legacy_tls=legacy_tls, proxy=proxy)

    # ── Repeater ──────────────────────────────────────────────────────
    if mode == "repeater":
        run_repeater(req)
        return

    base_path = Prompt.ask("Vulnerable base path", default="/SiteScope/htdocs/artwork")
    target_file = Prompt.ask("Target file", default="/etc/passwd")

    # ── Generate ──────────────────────────────────────────────────────
    if mode == "generate":
        gen_mode = Prompt.ask("Payload mode", choices=["quick","full"], default="full")
        out      = Prompt.ask("Output file", default="wordlists/custom_payloads.txt")
        run_generate(base_path, target_file, out, gen_mode)
        return

    # ── Scan ──────────────────────────────────────────────────────────
    target_url = Prompt.ask("Target base URL", default="https://target.com")
    scan_mode  = Prompt.ask("Payload mode", choices=["quick","full"], default="quick")
    threads    = int(Prompt.ask("Threads", default="1"))
    delay      = float(Prompt.ask("Delay between requests (s)", default="0"))
    stop_first = Confirm.ask("Stop on first finding?", default=False)
    out        = Prompt.ask("Output file (blank = skip)", default="reports/report.json")
    show_all   = Confirm.ask("Show all results in final table?", default=False)

    class Args:
        pass

    a = Args()
    a.url           = target_url
    a.path          = base_path
    a.file          = target_file
    a.mode          = scan_mode
    a.threads       = threads
    a.delay         = delay
    a.stop_on_first = stop_first
    a.output        = out or None
    a.timeout       = timeout
    a.legacy_tls    = legacy_tls
    a.proxy         = proxy
    a.wordlist      = None
    a.show_all      = show_all

    run_scan(a)


# ──────────────────────────────────────────────────────────────────────────────
#  CLI ARGUMENT PARSER
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pathtravscan",
        description="PathTravScan — Advanced Path Traversal Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  # Interactive wizard (recommended first run)
  python pathtravscan.py

  # Quick scan — top 15 payloads
  python pathtravscan.py -u https://target.com -p /app/images -f /etc/passwd --mode quick

  # Full scan — 300+ payloads, route through Burp Suite
  python pathtravscan.py -u https://target.com -p /app/images -f /etc/passwd \\
    --mode full --proxy http://127.0.0.1:8080 --threads 5 -o reports/output.json

  # Repeater mode (manual requests)
  python pathtravscan.py --repeater

  # Generate payload wordlist only
  python pathtravscan.py --generate -p /app/images -f /etc/shadow \\
    --mode full -o wordlists/shadow_payloads.txt

  # Use custom wordlist
  python pathtravscan.py -u https://target.com -p /app \\
    --wordlist wordlists/lfi_payloads.txt
"""
    )

    p.add_argument("-u",  "--url",      help="Target base URL")
    p.add_argument("-p",  "--path",     help="Vulnerable endpoint base path")
    p.add_argument("-f",  "--file",     default="/etc/passwd", help="File to read (default: /etc/passwd)")
    p.add_argument("--mode",            choices=["quick","full"], default="quick", help="Payload mode")
    p.add_argument("--wordlist",        help="Path to custom payload wordlist")
    p.add_argument("--threads",    type=int,   default=1,   help="Concurrent threads (default: 1)")
    p.add_argument("--delay",      type=float, default=0.0, help="Delay between requests in seconds")
    p.add_argument("--timeout",    type=int,   default=10,  help="Request timeout in seconds")
    p.add_argument("--proxy",      help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--no-legacy-tls", dest="legacy_tls", action="store_false",
                   help="Disable legacy TLS 1.0 support")
    p.add_argument("--stop-on-first", dest="stop_on_first", action="store_true",
                   help="Stop after first confirmed finding")
    p.add_argument("--show-all",    dest="show_all", action="store_true",
                   help="Show all results in table, not just findings")
    p.add_argument("-o", "--output", help="Output JSON report path (default: reports/report.json)")
    p.set_defaults(legacy_tls=True, stop_on_first=False, show_all=False)

    sub = p.add_subparsers(dest="subcommand")

    # repeater sub-command
    sub.add_parser("repeater", help="Launch manual repeater mode")

    # generate sub-command
    gen = sub.add_parser("generate", help="Generate payload wordlist")
    gen.add_argument("-p","--path",  required=True, help="Base path")
    gen.add_argument("-f","--file",  default="/etc/passwd", help="Target file")
    gen.add_argument("--mode",       choices=["quick","full"], default="full")
    gen.add_argument("-o","--output",default="wordlists/generated.txt")

    return p


# ──────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) == 1:
        interactive_wizard()
        return

    parser = build_parser()
    args   = parser.parse_args()

    print_banner()

    if args.subcommand == "repeater":
        req = RequestEngine(legacy_tls=args.legacy_tls, proxy=args.proxy)
        run_repeater(req)
        return

    if args.subcommand == "generate":
        run_generate(args.path, args.file, args.output, args.mode)
        return

    if not args.url or not args.path:
        console.print("[red]Error: -u/--url and -p/--path are required for scanning.[/red]")
        parser.print_help()
        sys.exit(1)

    args.output = args.output or "reports/report.json"
    run_scan(args)


if __name__ == "__main__":
    main()
