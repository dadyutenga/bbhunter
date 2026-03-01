"""Anthropic API adapter with tool-use support for BBHunter agent."""

import json
import urllib.error
import urllib.request

from config.config import get_api_key, load_config


def _provider_settings():
    cfg = load_config()
    provider_cfg = cfg.get("providers", {}).get("anthropic", {})
    model = provider_cfg.get("model", "claude-3-5-haiku-latest")
    max_tokens = int(provider_cfg.get("max_tokens", 4096))
    return model, max_tokens


def call_claude(system: str, messages: list, tools: list) -> dict:
    """
    Call Anthropic messages API with tool definitions.
    Returns API JSON response as dict.
    """
    api_key = get_api_key("anthropic")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not configured.")

    model, max_tokens = _provider_settings()
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": messages,
        "tools": tools,
    }

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as ex:
        body = ex.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Anthropic API HTTP {ex.code}: {body[:400]}") from ex

