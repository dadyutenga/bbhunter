"""
Module 2b — Directory brute-force (dirb).
"""

import concurrent.futures
import datetime
import urllib.parse

from .utils import (
    http_get, save_json,
    info, ok, section,
    G, Y, M, R, DIM, RST,
)
from .scan import generate_burp_requests

# ── Built-in directory wordlist ───────────────────────────────────────────
DIRB_WORDLIST = [
    "admin", "administrator", "api", "app", "assets", "auth", "backup",
    "bin", "blog", "cache", "cgi-bin", "cms", "config", "console",
    "css", "dashboard", "data", "db", "debug", "dev", "docs", "download",
    "downloads", "editor", "email", "error", "export", "files", "fonts",
    "forum", "graphql", "help", "home", "html", "images", "img", "import",
    "includes", "index", "info", "install", "internal", "js", "json",
    "lib", "log", "login", "logout", "logs", "mail", "main", "manage",
    "media", "metrics", "mobile", "modules", "monitor", "new", "node",
    "old", "panel", "phpinfo", "phpmyadmin", "plugins", "portal",
    "private", "profile", "public", "reports", "rest", "robots.txt",
    "scripts", "search", "server-status", "settings", "setup", "sitemap",
    "sitemap.xml", "static", "status", "storage", "swagger", "system",
    "temp", "test", "tmp", "tools", "upload", "uploads", "user", "users",
    "vendor", "version", "web", "webmail", "wp-admin", "wp-content",
    "wp-login.php", "xmlrpc.php",
]


def load_wordlist(path):
    """Load wordlist from file, one entry per line, supports # comments."""
    words = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    return words


def run_dirb(url, output_dir, wordlist_path=None, threads=40, status_filter="200,204,301,302,307,401,403,500"):
    section(f"DIRB  →  {url}")
    allowed = set(int(s.strip()) for s in status_filter.split(",") if s.strip())

    wl = DIRB_WORDLIST
    if wordlist_path:
        info(f"Loading custom wordlist: {wordlist_path}")
        wl = load_wordlist(wordlist_path)

    base = url.rstrip("/")
    info(f"Brute-forcing {len(wl)} paths with {threads} threads  (status: {status_filter})")

    results = {
        "url": url,
        "timestamp": str(datetime.datetime.now()),
        "findings": [],
    }

    def dirb_probe(word):
        path = f"/{word}" if not word.startswith("/") else word
        target = f"{base}{path}"
        try:
            r = http_get(target, timeout=5)
            if r:
                code, hdrs, body = r
                if code in allowed:
                    return {"path": path, "url": target, "status": code, "size": len(body),
                            "server": hdrs.get("Server", "")}
        except Exception:
            pass
        return None

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(dirb_probe, wl):
            if res:
                code = res["status"]
                color = G if code == 200 else (Y if code in (301, 302, 307) else (M if code in (401, 403) else R))
                print(f"  {color}[{code}]{RST}  {res['path']:30s}  {DIM}size={res['size']}b{RST}")
                found.append(res)

    results["findings"] = found

    section("DIRB SUMMARY")
    ok(f"Found {len(found)} paths matching status filter")
    for code in sorted(set(f["status"] for f in found)):
        cnt = sum(1 for f in found if f["status"] == code)
        print(f"  HTTP {code}: {cnt}")

    if output_dir:
        netloc = urllib.parse.urlparse(url).netloc
        save_json(f"{output_dir}/dirb_{netloc}.json", results)
        sensitive_prefixes = ("/admin", "/config", "/backup", "/db", "/debug",
                              "/install", "/internal", "/manage", "/monitor",
                              "/panel", "/private", "/setup", "/phpmyadmin",
                              "/graphql", "/rest", "/swagger", "/phpinfo")
        burp_results = {"url": url, "findings": []}
        for f in found:
            if f["status"] == 200:
                is_sensitive = any(f["path"].startswith(p) for p in sensitive_prefixes)
                sev = "HIGH" if is_sensitive else "LOW"
                burp_results["findings"].append({
                    "severity": sev, "title": f"Dir found: {f['path']}",
                    "detail": f"HTTP 200  size={f['size']}b",
                })
        if burp_results["findings"]:
            generate_burp_requests(output_dir, burp_results)

    return results
