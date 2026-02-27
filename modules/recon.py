"""
Module 1 — Subdomain enumeration & DNS recon.
"""

import concurrent.futures
import datetime
import socket
import ssl
import subprocess
import urllib.parse
import urllib.request

from .utils import (
    http_get, save_json,
    info, ok, warn, section,
    G, DIM, RST,
)

# ── Built-in subdomain wordlist ───────────────────────────────────────────
WORDLIST = [
    "www","mail","ftp","admin","api","dev","staging","test","beta","blog",
    "shop","store","app","mobile","m","cdn","static","assets","img","images",
    "portal","dashboard","login","auth","sso","vpn","remote","git","gitlab",
    "jenkins","jira","confluence","docs","help","support","status","monitoring",
    "grafana","kibana","elastic","s3","backup","old","legacy","v1","v2","v3",
    "internal","corp","intranet","extranet","partner","client","customer",
    "api-v1","api-v2","api-dev","api-staging","api-prod",
]


def load_wordlist(path):
    """Load subdomain wordlist from file, one per line, supports # comments."""
    words = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    return words


def crtsh_enum(domain):
    """Passive subdomain enumeration via crt.sh."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    info(f"Querying crt.sh for *.{domain} ...")
    try:
        import json
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "BBHunter/1.0"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            if r.status != 200:
                warn(f"crt.sh returned HTTP {r.status}")
                return []
            body = r.read().decode("utf-8", errors="ignore")
        entries = json.loads(body) if body else []
        subs = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for part in name.split("\n"):
                part = part.strip().lower()
                if part.endswith(f".{domain}") or part == domain:
                    part = part.lstrip("*.")
                    if part:
                        subs.add(part)
        ok(f"crt.sh returned {len(subs)} unique names")
        return list(subs)
    except Exception as ex:
        warn(f"crt.sh enumeration error: {ex}")
        return []


def resolve(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except Exception:
        return None


def resolve_fqdn(fqdn):
    """Resolve an already-qualified domain name."""
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except Exception:
        return None


def run_recon(domain, output_dir, threads=50, wordlist_path=None):
    section(f"RECON  →  {domain}")
    results = {"domain": domain, "timestamp": str(datetime.datetime.now()), "subdomains": []}
    found_set = set()
    found = []

    # ── Passive enumeration via crt.sh ──────────────────────────────────
    crt_names = crtsh_enum(domain)
    if crt_names:
        info(f"Resolving {len(crt_names)} crt.sh results with {threads} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for res in ex.map(resolve_fqdn, crt_names):
                if res:
                    fqdn, ip = res
                    if fqdn not in found_set:
                        found_set.add(fqdn)
                        ok(f"  {G}{fqdn}{RST}  →  {DIM}{ip}{RST}  {DIM}(crt.sh){RST}")
                        found.append({"subdomain": fqdn, "ip": ip, "source": "crt.sh"})

    # ── Wordlist brute-force ────────────────────────────────────────────
    wl = WORDLIST
    if wordlist_path:
        info(f"Loading custom wordlist: {wordlist_path}")
        wl = load_wordlist(wordlist_path)
    info(f"Brute-forcing {len(wl)} subdomains with {threads} threads...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve, sub, domain): sub for sub in wl}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                fqdn, ip = res
                if fqdn not in found_set:
                    found_set.add(fqdn)
                    ok(f"  {G}{fqdn}{RST}  →  {DIM}{ip}{RST}")
                    found.append({"subdomain": fqdn, "ip": ip, "source": "brute"})

    results["subdomains"] = found

    # HTTP probe on found subdomains
    info(f"\nProbing {len(found)} subdomains for HTTP/S...")
    for entry in found:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{entry['subdomain']}"
            r = http_get(url)
            if r:
                code, headers, _ = r
                server = headers.get("Server", "?")
                ok(f"  {scheme.upper()} {code}  {entry['subdomain']}  [{DIM}{server}{RST}]")
                entry["http"] = {"url": url, "status": code, "server": server}
                break

    # WHOIS-style TXT / MX records
    info("\nChecking DNS TXT records (SPF / DMARC)...")
    for rec in ["_dmarc", "_domainkey", "default._domainkey"]:
        try:
            out = subprocess.check_output(
                ["nslookup", "-type=TXT", f"{rec}.{domain}"],
                stderr=subprocess.DEVNULL, timeout=4
            ).decode()
            for line in out.splitlines():
                if "text" in line.lower() or '"' in line:
                    ok(f"  {rec}: {line.strip()}")
        except Exception:
            pass

    ok(f"\nFound {len(found)} subdomains for {domain}")
    if output_dir:
        save_json(f"{output_dir}/{domain}_recon.json", results)
    return results
