"""Payload generation tool wrapper for agent mode."""

import os

from config.config import load_config
from modules.payloads import run_payloads as module_run_payloads


def _resolve_output_dir() -> str:
    cfg = load_config()
    out = (
        cfg.get("output_dir")
        or cfg.get("defaults", {}).get("output_dir")
        or "./bbhunter_output"
    )
    return os.path.expanduser(out)


def run_payloads(vuln_type: str, category: str = "all"):
    return {
        "vuln_type": vuln_type,
        "category": category,
        "payloads": module_run_payloads(
            vuln_type=vuln_type,
            category=category,
            output_dir=_resolve_output_dir(),
        ),
    }

