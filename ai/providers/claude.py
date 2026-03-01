"""Anthropic Claude AI provider for BBHunter."""

import json
import os
import urllib.error
import urllib.request
from typing import Any

from ai.base_provider import BaseProvider


_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"

_CLAUDE_MODELS = [
    {"id": "claude-3-5-haiku-latest", "name": "Claude 3.5 Haiku"},
    {"id": "claude-3-5-sonnet-latest", "name": "Claude 3.5 Sonnet"},
    {"id": "claude-3-opus-latest", "name": "Claude 3 Opus"},
    {"id": "claude-sonnet-4-0", "name": "Claude Sonnet 4"},
    {"id": "claude-opus-4", "name": "Claude Opus 4"},
]


class ClaudeProvider(BaseProvider):
    """Anthropic Claude provider — uses the Messages API with tool-use."""

    name = "claude"
    requires_auth = True

    def __init__(self) -> None:
        self._api_key: str | None = None
        self._model: str = "claude-3-5-haiku-latest"
        self._max_tokens: int = 4096

    # ── auth ──────────────────────────────────────────────────────
    def authenticate(self, **kwargs) -> bool:
        key = kwargs.get("api_key") or ""
        if not key:
            # Try environment
            key = os.getenv("ANTHROPIC_API_KEY", "")
        if not key:
            # Try bbhunter config
            try:
                from config.config import get_api_key
                key = get_api_key("anthropic")
            except Exception:
                pass
        if key:
            self._api_key = key
            return True
        print("[!] No Anthropic API key found. Set ANTHROPIC_API_KEY or add to config.")
        return False

    def is_connected(self) -> bool:
        return bool(self._api_key)

    # ── models ────────────────────────────────────────────────────
    def list_models(self) -> list[dict]:
        return list(_CLAUDE_MODELS)

    # ── chat ──────────────────────────────────────────────────────
    def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        system: str | None = None,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        if not self._api_key:
            raise RuntimeError("Claude is not authenticated. Provide an API key.")

        use_model = model or self._model
        payload: dict[str, Any] = {
            "model": use_model,
            "max_tokens": self._max_tokens,
            "messages": messages,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = tools

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            _API_URL,
            data=data,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as ex:
            body = ex.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Anthropic API HTTP {ex.code}: {body[:400]}") from ex
