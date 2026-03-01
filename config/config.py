"""Config loader for BBHunter AI mode."""

import json
import os

CONFIG_PATH = os.path.expanduser("~/.bbhunter/config.json")


def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except Exception:
        return {}
    return {}


def get_api_key(provider: str) -> str:
    cfg = load_config()
    key = cfg.get("providers", {}).get(provider, {}).get("api_key")
    if key:
        return str(key)

    env_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "grok": "GROK_API_KEY",
    }
    return os.getenv(env_map.get(provider, ""), "")

