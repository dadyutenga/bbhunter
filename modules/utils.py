"""
Shared utilities: colour constants, logging helpers, HTTP helper, JSON saver,
and AI-provider callers.
"""

import json
import os
import ssl
import urllib.request
import urllib.error
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

# ── Logging helpers ───────────────────────────────────────────────────────
def info(msg):  print(f"{B}[*]{RST} {msg}")
def ok(msg):    print(f"{G}[+]{RST} {msg}")
def warn(msg):  print(f"{Y}[!]{RST} {msg}")
def err(msg):   print(f"{R}[-]{RST} {msg}")
def section(title):
    print(f"\n{BOLD}{C}{'─'*55}{RST}")
    print(f"{BOLD}{C}  {title}{RST}")
    print(f"{BOLD}{C}{'─'*55}{RST}")

# ── HTTP helper ───────────────────────────────────────────────────────────
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

# ── JSON persistence ──────────────────────────────────────────────────────
def save_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    ok(f"Saved → {path}")

# ── AI provider callers ───────────────────────────────────────────────────
def call_openai(api_key, prompt):
    try:
        max_tokens = int(os.getenv("BBHUNTER_AI_MAX_TOKENS", "1200"))
    except ValueError:
        max_tokens = 1200
    payload = {
        "model": "gpt-4o-mini",
        "max_tokens": max_tokens,
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


def call_grok(api_key, prompt):
    try:
        max_tokens = int(os.getenv("BBHUNTER_AI_MAX_TOKENS", "1200"))
    except ValueError:
        max_tokens = 1200
    payload = {
        "model": "grok-2-1212",
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        "https://api.x.ai/v1/chat/completions",
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
        raise RuntimeError(f"Grok API HTTP {ex.code}: {body[:300]}") from ex
    return data["choices"][0]["message"]["content"].strip()
