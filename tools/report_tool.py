"""Report writer tool for agent mode."""

import os
import re
from datetime import datetime
from pathlib import Path

from config.config import load_config
from memory.db import save_finding


def _resolve_output_dir() -> str:
    cfg = load_config()
    out = (
        cfg.get("output_dir")
        or cfg.get("defaults", {}).get("output_dir")
        or "./bbhunter_output"
    )
    return os.path.expanduser(out)


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_")[:80] or "target"


def _fmt_finding(item) -> str:
    if not isinstance(item, dict):
        return f"- {item}"
    severity = str(item.get("severity", "")).upper()
    title = str(item.get("title", "Finding"))
    detail = str(item.get("detail", "")).strip()
    if detail:
        return f"- **{severity}** {title}: {detail}"
    return f"- **{severity}** {title}"


def run_report(
    target: str,
    vuln_type: str,
    severity: str,
    summary: str,
    findings=None,
):
    findings = findings or []
    output_dir = _resolve_output_dir()
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    file_name = f"agent_report_{_safe_name(target)}_{stamp}.md"
    report_path = os.path.join(output_dir, file_name)

    lines = [
        f"# BBHunter Agent Report - {target}",
        "",
        f"- Generated: {datetime.utcnow().isoformat()}Z",
        f"- Vulnerability Type: `{vuln_type}`",
        f"- Severity: `{severity}`",
        "",
        "## Summary",
        summary,
        "",
        "## Findings",
    ]
    if findings:
        lines.extend(_fmt_finding(item) for item in findings)
    else:
        lines.append("- No structured findings were provided.")

    lines.extend(
        [
            "",
            "## Remediation Guidance",
            "- Validate and sanitize untrusted input.",
            "- Enforce least privilege and secure defaults.",
            "- Add monitoring and alerting for exploit indicators.",
        ]
    )

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    save_finding(
        session_id="agent_report",
        target=target,
        severity=str(severity).upper(),
        vuln_type=vuln_type,
        description=summary,
    )

    return {
        "report_path": report_path,
        "target": target,
        "severity": severity,
        "vuln_type": vuln_type,
        "summary": summary,
    }

