#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║              BBHunter - Bug Bounty CLI               ║
║   Recon · Scanning · Payloads · Report Writing       ║
╚══════════════════════════════════════════════════════╝
"""

import argparse
import os
import sys
import uuid

from modules.utils import BANNER, BOLD, RST
from modules.recon import run_recon
from modules.scan import run_scan
from modules.dirb import run_dirb
from modules.payloads import PAYLOADS, run_payloads
from modules.ai_analyze import run_ai_analyze
from modules.report import run_report
from modules.utils import section, err, G, DIM


def _print_banner():
    """Print unicode banner with a safe fallback on non-UTF terminals."""
    try:
        print(BANNER)
    except UnicodeEncodeError:
        print("BBHunter - Bug Bounty Hunter CLI")


def _run_interactive_agent():
    """Start interactive AI agent session in terminal."""
    from agent.loop import run_agent

    _print_banner()
    session_id = str(uuid.uuid4())[:8]
    print(f"BBHunter AI v2.0 | Session: {session_id}")
    print("Type a target or task. Commands: exit, new")

    while True:
        try:
            user_input = input("\nYou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not user_input:
            continue
        if user_input.lower() == "exit":
            print("Bye.")
            break
        if user_input.lower() == "new":
            session_id = str(uuid.uuid4())[:8]
            print(f"New session: {session_id}")
            continue

        try:
            response = run_agent(user_input, session_id, verbose=True)
            print(f"\nBBHunter AI>\n{response}")
        except Exception as ex:
            err(f"Agent error: {ex}")


def _run_telegram_mode():
    """Run Telegram bot mode if optional channel module is installed."""
    try:
        from config.config import load_config as load_agent_config
        from channels.telegram import run_telegram_bot
    except Exception as ex:
        err(f"Telegram mode unavailable: {ex}")
        raise SystemExit(1)

    cfg = load_agent_config()
    token = cfg.get("telegram", {}).get("token") or os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        err("No Telegram token found. Set ~/.bbhunter/config.json or TELEGRAM_BOT_TOKEN.")
        raise SystemExit(1)
    run_telegram_bot(token)
#  CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────
def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--telegram":
        _run_telegram_mode()
        return
    if not argv or argv[0] in ("-i", "--interactive", "agent"):
        _run_interactive_agent()
        return

    _print_banner()

    parser = argparse.ArgumentParser(
        prog="bbhunter",
        description="Bug Bounty Hunter CLI — Recon · Scan · Payloads · Reports",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
{BOLD}Examples:{RST}
  Recon a domain:
    python bbhunter.py recon -d example.com

  Recon with custom wordlist:
    python bbhunter.py recon -d example.com -w subs.txt

  Scan a URL for vulnerabilities:
    python bbhunter.py scan -u https://example.com

  Scan with Nuclei-Lite:
    python bbhunter.py scan -u https://example.com --nuclei

  Directory brute-force:
    python bbhunter.py dirb -u https://example.com
    python bbhunter.py dirb -u https://example.com -w dirs.txt -t 60

  Generate XSS payloads:
    python bbhunter.py payloads -t xss -c bypass

  List all payload types:
    python bbhunter.py payloads --list

  Write a bug bounty report:
    python bbhunter.py report

  Analyze scan output with AI:
    python bbhunter.py ai-analyze -f ./results/scan_example.com.json

  Analyze with specific AI provider:
    python bbhunter.py ai-analyze --auto --provider grok

  Save all output to a folder:
    python bbhunter.py recon -d example.com -o ./results
"""
    )
    parser.add_argument("-o", "--output", default="./bbhunter_output",
                        help="Output directory (default: ./bbhunter_output)")

    sub = parser.add_subparsers(dest="command", required=True)

    # recon
    p_recon = sub.add_parser("recon", help="Subdomain enumeration + DNS recon")
    p_recon.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    p_recon.add_argument("-t", "--threads", type=int, default=50, help="Threads (default: 50)")
    p_recon.add_argument("-w", "--wordlist", help="Custom wordlist file (one subdomain per line, supports # comments)")

    # scan
    p_scan = sub.add_parser("scan", help="Vulnerability scanning of a URL")
    p_scan.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    p_scan.add_argument("--nuclei", "--nuclei-lite", action="store_true", dest="nuclei",
                        help="Run Nuclei-Lite scan with popular templates")

    # payloads
    p_pay = sub.add_parser("payloads", help="Generate attack payloads")
    p_pay.add_argument("-t", "--type", dest="vuln_type",
                       help="Vuln type: xss / sqli / ssrf / lfi / open_redirect / ssti / xxe")
    p_pay.add_argument("-c", "--category", default="all",
                       help="Category: basic / bypass / blind / all (default: all)")
    p_pay.add_argument("--list", action="store_true", help="List all available payload types")

    # ai-analyze
    p_ai = sub.add_parser("ai-analyze", help="Analyze scan findings with AI (Claude/GPT/Grok)")
    p_ai.add_argument("-f", "--file", help="Path to scan JSON results")
    p_ai.add_argument("-u", "--url", help="Target URL to scan first (use with --auto)")
    p_ai.add_argument("--auto", action="store_true", help="Auto use latest scan JSON or scan URL first")
    p_ai.add_argument("--provider", choices=["auto", "openai", "anthropic", "grok"],
                      default="auto", help="AI provider (default: auto)")

    # dirb
    p_dirb = sub.add_parser("dirb", help="Directory brute-force")
    p_dirb.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    p_dirb.add_argument("-w", "--wordlist", help="Custom wordlist file (one path per line)")
    p_dirb.add_argument("-t", "--threads", type=int, default=40, help="Threads (default: 40)")
    p_dirb.add_argument("--status", default="200,204,301,302,307,401,403,500",
                        help="Comma-separated status codes to show (default: 200,204,301,302,307,401,403,500)")

    # report
    sub.add_parser("report", help="Interactive bug bounty report writer")

    args = parser.parse_args(argv)
    out  = args.output

    if args.command == "recon":
        run_recon(args.domain, out, args.threads, wordlist_path=args.wordlist)

    elif args.command == "scan":
        run_scan(args.url, out, nuclei=args.nuclei)

    elif args.command == "dirb":
        run_dirb(args.url, out, wordlist_path=args.wordlist, threads=args.threads,
                 status_filter=args.status)

    elif args.command == "payloads":
        if args.list or not args.vuln_type:
            section("AVAILABLE PAYLOAD TYPES")
            for vt, cats in PAYLOADS.items():
                total = sum(len(v) for v in cats.values())
                cats_str = " / ".join(cats.keys())
                print(f"  {G}{vt:20s}{RST}  {DIM}[{cats_str}]{RST}  {total} payloads")
        else:
            run_payloads(args.vuln_type, args.category, out)

    elif args.command == "ai-analyze":
        run_ai_analyze(args.file, args.url, args.auto, out, provider=args.provider)

    elif args.command == "report":
        run_report(out)


if __name__ == "__main__":
    main()
