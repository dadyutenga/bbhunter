"""
Module — Interactive bug bounty report writer.
"""

import datetime
from pathlib import Path

from .utils import (
    ok, section,
    C, DIM, RST,
)
from .payloads import PAYLOADS

# ── Report template ───────────────────────────────────────────────────────
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

    steps       = "\n".join(steps_list)
    impact      = SEVERITY_IMPACT.get(severity.lower(), "Impact to be assessed.")
    remediation = REMEDIATION_ADVICE.get(vuln_type.lower(), "Follow OWASP best practices for this vulnerability type.")
    cvss, cvss_vector = CVSS_MAP.get(severity.lower(), ("?", "N/A"))
    date        = datetime.date.today().isoformat()

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
