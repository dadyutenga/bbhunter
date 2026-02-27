"""
Module — AI-powered vulnerability analyzer.
Feeds scan JSON into Claude / GPT / Grok and prints a prioritized report.
"""

import json
import os
import re
import urllib.parse
from pathlib import Path

from .utils import (
    info, ok, err, section, M, RST,
    call_openai, call_anthropic, call_grok,
)
from .scan import run_scan


def run_ai_analyze(file_path, url, auto, output_dir, provider="auto"):
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
    try:
        max_chars = int(os.getenv("BBHUNTER_AI_MAX_PROMPT_CHARS", "12000"))
    except ValueError:
        max_chars = 12000
    scan_json = json.dumps(results, indent=2)
    if len(scan_json) > max_chars:
        scan_json = scan_json[:max_chars] + "\n... [truncated]"
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
        grok_key = os.getenv("GROK_API_KEY") or os.getenv("XAI_API_KEY")

        provider_used = None
        if provider == "anthropic":
            if not anthropic_key:
                err("ANTHROPIC_API_KEY not set"); return
            analysis = call_anthropic(anthropic_key, prompt)
            provider_used = "Anthropic (claude-3-5-haiku)"
        elif provider == "openai":
            if not openai_key:
                err("OPENAI_API_KEY not set"); return
            analysis = call_openai(openai_key, prompt)
            provider_used = "OpenAI (gpt-4o-mini)"
        elif provider == "grok":
            if not grok_key:
                err("GROK_API_KEY or XAI_API_KEY not set"); return
            analysis = call_grok(grok_key, prompt)
            provider_used = "Grok (grok-2-1212)"
        else:  # auto
            if anthropic_key:
                analysis = call_anthropic(anthropic_key, prompt)
                provider_used = "Anthropic (claude-3-5-haiku)"
            elif openai_key:
                analysis = call_openai(openai_key, prompt)
                provider_used = "OpenAI (gpt-4o-mini)"
            elif grok_key:
                analysis = call_grok(grok_key, prompt)
                provider_used = "Grok (grok-2-1212)"
            else:
                err("Missing API key. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GROK_API_KEY / XAI_API_KEY")
                return
        info(f"Provider: {provider_used}")
    except Exception as ex:
        err(f"AI analysis failed: {ex}")
        return

    print(f"\n{analysis}\n")
    if output_dir:
        target = results.get("url", results.get("domain", "unknown_target"))
        safe_target = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(target))
        out_path = f"{output_dir}/ai_analysis_{safe_target}.txt"
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            f.write(analysis + "\n")
        ok(f"Saved → {out_path}")
