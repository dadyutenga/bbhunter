"""Recon tool wrapper for agent mode."""

import os

from config.config import load_config
from modules.recon import run_recon as module_run_recon


def _resolve_output_dir() -> str:
    cfg = load_config()
    out = (
        cfg.get("output_dir")
        or cfg.get("defaults", {}).get("output_dir")
        or "./bbhunter_output"
    )
    return os.path.expanduser(out)


def run_recon(domain: str, threads: int = 50):
    threads = max(1, min(int(threads), 200))
    return module_run_recon(
        domain=domain,
        output_dir=_resolve_output_dir(),
        threads=threads,
    )

