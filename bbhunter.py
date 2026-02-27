#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║              BBHunter - Bug Bounty CLI               ║
║   Recon · Scanning · Payloads · Report Writing       ║
╚══════════════════════════════════════════════════════╝
"""

import argparse

from modules.utils import BANNER, BOLD, RST
from modules.recon import run_recon
from modules.scan import run_scan
from modules.dirb import run_dirb
from modules.payloads import PAYLOADS, run_payloads
from modules.ai_analyze import run_ai_analyze
from modules.report import run_report
from modules.utils import section, G, DIM


# ─────────────────────────────────────────────────────────────────────────
#  CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

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

    args = parser.parse_args()
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
