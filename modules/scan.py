"""
Module 2 — Vulnerability scanning of a URL.
Includes HTTP header checks, TLS inspection, sensitive path probing,
CORS testing, cookie flag checks, optional Nuclei-Lite, and
auto-generation of Burp/Repeater .http request files.
"""

import concurrent.futures
import datetime
import json
import os
import re
import socket
import ssl
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

from .utils import (
    http_get, save_json,
    info, ok, warn, err, section,
    R, Y, B, G, M, C, DIM, RST, BOLD,
)

# ── Header lists ──────────────────────────────────────────────────────────
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

# ── Sensitive paths ───────────────────────────────────────────────────────
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
            if acao.rstrip("/") in ("https://evil.com", "http://evil.com") and acac.lower() == "true":
                warn(f"  CORS: Reflected origin + credentials=true  {R}HIGH{RST}")
                return {"issue": "reflected+credentials", "acao": acao, "acac": acac}
    except Exception:
        pass
    return None


def generate_burp_requests(output_dir, results):
    """Generate .http files for HIGH/CRITICAL findings and 200 responses."""
    burp_dir = os.path.join(output_dir, "burp_requests")
    Path(burp_dir).mkdir(parents=True, exist_ok=True)
    count = 0
    target_url = results.get("url", "")
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.netloc or "unknown"

    for i, f in enumerate(results.get("findings", [])):
        sev = f.get("severity", "")
        title = f.get("title", "")
        detail = f.get("detail", "")
        status_code = f.get("status_code")

        is_high_crit = sev in ("HIGH", "CRITICAL")
        is_interesting_200 = (status_code == 200) or ("HTTP 200" in detail and sev == "HIGH")
        if not (is_high_crit or is_interesting_200):
            continue

        path = "/"
        if f.get("path"):
            path = f["path"]
        elif detail and detail.startswith("/"):
            path = detail.split()[0]
        elif ":" in title:
            candidate = title.split(":")[-1].strip().split()[0]
            if candidate.startswith("/"):
                path = candidate

        safe_title = re.sub(r"[^a-zA-Z0-9._-]+", "_", title)[:60]
        fname = os.path.join(burp_dir, f"{i:03d}_{safe_title}.http")
        with open(fname, "w") as fp:
            fp.write(f"GET {path} HTTP/1.1\r\n")
            fp.write(f"Host: {host}\r\n")
            fp.write("User-Agent: BBHunter/1.0\r\n")
            fp.write("Accept: */*\r\n")
            fp.write("Connection: close\r\n")
            fp.write("\r\n")
        count += 1

    if count:
        ok(f"Generated {count} Burp/Repeater .http files → {burp_dir}")


def run_scan(url, output_dir, nuclei=False):
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
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
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

    # ── Nuclei-Lite ──────────────────────────────────────────────────────
    if nuclei:
        section("NUCLEI-LITE SCAN")
        if subprocess.call(["which", "nuclei"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            err("nuclei is not installed. Install from https://github.com/projectdiscovery/nuclei")
        else:
            templates = "exposed-panels,misconfiguration,vulnerabilities,default-logins,cves,takeovers"
            info(f"Running nuclei with templates: {templates}")
            try:
                proc = subprocess.run(
                    ["nuclei", "-u", url, "-t", templates, "-jsonl", "-silent"],
                    capture_output=True, text=True, timeout=300,
                )
                nuclei_findings = []
                for line in proc.stdout.strip().splitlines():
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        nuclei_findings.append(item)
                    except json.JSONDecodeError:
                        pass
                if nuclei_findings:
                    for nf in nuclei_findings:
                        sev = (nf.get("info", {}).get("severity", "info")).upper()
                        name = nf.get("info", {}).get("name", nf.get("template-id", "?"))
                        matched = nf.get("matched-at", "")
                        tag = {
                            "CRITICAL": f"{R}[CRITICAL]{RST}",
                            "HIGH":     f"{R}[HIGH]{RST}",
                            "MEDIUM":   f"{Y}[MEDIUM]{RST}",
                            "LOW":      f"{B}[LOW]{RST}",
                        }.get(sev, f"{DIM}[{sev}]{RST}")
                        print(f"  {tag} {name}  {DIM}{matched}{RST}")
                        results["findings"].append({"severity": sev, "title": f"[nuclei] {name}", "detail": matched})
                    ok(f"Nuclei found {len(nuclei_findings)} issue(s)")
                else:
                    ok("Nuclei found no issues")
            except subprocess.TimeoutExpired:
                warn("Nuclei scan timed out (300s)")
            except Exception as ex:
                err(f"Nuclei error: {ex}")

    # ── Auto-generate Burp / Repeater .http files ────────────────────────
    if output_dir:
        generate_burp_requests(output_dir, results)

    return results
