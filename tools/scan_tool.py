"""Scan tool wrapper for agent mode."""

import os

from config.config import load_config
from modules.scan import run_scan as module_run_scan


def _resolve_output_dir() -> str:
    cfg = load_config()
    out = (
        cfg.get("output_dir")
        or cfg.get("defaults", {}).get("output_dir")
        or "./bbhunter_output"
    )
    return os.path.expanduser(out)


def run_scan(url: str):
    return module_run_scan(
        url=url,
        output_dir=_resolve_output_dir(),
    )

