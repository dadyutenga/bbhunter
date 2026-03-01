"""OpenAI / Codex AI provider for BBHunter."""

import json
import os
import urllib.error
import urllib.request
from typing import Any

from ai.base_provider import BaseProvider


_API_URL = "https://api.openai.com/v1/chat/completions"

_OPENAI_MODELS = [
    {"id": "gpt-4o", "name": "GPT-4o"},
    {"id": "gpt-4o-mini", "name": "GPT-4o Mini"},
    {"id": "gpt-4-turbo", "name": "GPT-4 Turbo"},
    {"id": "o1-mini", "name": "o1-mini"},
    {"id": "o1-preview", "name": "o1-preview"},
]


class OpenAIProvider(BaseProvider):
    """OpenAI provider — uses the Chat Completions API with function-calling."""

    name = "openai"
    requires_auth = True

    def __init__(self) -> None:
        self._api_key: str | None = None
        self._model: str = "gpt-4o"
        self._max_tokens: int = 4096

    # ── auth ──────────────────────────────────────────────────────
    def authenticate(self, **kwargs) -> bool:
        key = kwargs.get("api_key") or ""
        if not key:
            key = os.getenv("OPENAI_API_KEY", "")
        if not key:
            try:
                from config.config import get_api_key
                key = get_api_key("openai")
            except Exception:
                pass
        if key:
            self._api_key = key
            return True
        print("[!] No OpenAI API key found. Set OPENAI_API_KEY or add to config.")
        return False

    def is_connected(self) -> bool:
        return bool(self._api_key)

    # ── models ────────────────────────────────────────────────────
    def list_models(self) -> list[dict]:
        return list(_OPENAI_MODELS)

    # ── chat ──────────────────────────────────────────────────────
    def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        system: str | None = None,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        if not self._api_key:
            raise RuntimeError("OpenAI is not authenticated. Provide an API key.")

        use_model = model or self._model

        oai_messages: list[dict] = []
        if system:
            oai_messages.append({"role": "system", "content": system})

        for msg in messages:
            oai_messages.append(self._normalise_message(msg))

        payload: dict[str, Any] = {
            "model": use_model,
            "messages": oai_messages,
            "max_tokens": self._max_tokens,
        }

        if tools:
            payload["tools"] = self._convert_tools(tools)

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            _API_URL,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                result = json.loads(resp.read().decode())
        except urllib.error.HTTPError as ex:
            body = ex.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"OpenAI API HTTP {ex.code}: {body[:400]}") from ex

        return self._normalise_response(result)

    # ── internal helpers ──────────────────────────────────────────
    @staticmethod
    def _normalise_message(msg: dict) -> dict:
        """Convert Anthropic-style messages to OpenAI-style if needed."""
        role = msg.get("role", "user")
        content = msg.get("content", "")

        if isinstance(content, str):
            return {"role": role, "content": content}

        if isinstance(content, list):
            parts: list[str] = []
            tool_calls: list[dict] = []
            tool_results: list[dict] = []

            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type", "")
                if btype == "text":
                    parts.append(block.get("text", ""))
                elif btype == "tool_use":
                    tool_calls.append({
                        "id": block.get("id", ""),
                        "type": "function",
                        "function": {
                            "name": block.get("name", ""),
                            "arguments": json.dumps(block.get("input", {})),
                        },
                    })
                elif btype == "tool_result":
                    tool_results.append({
                        "role": "tool",
                        "tool_call_id": block.get("tool_use_id", ""),
                        "content": block.get("content", ""),
                    })

            if tool_results:
                return tool_results[0]

            out: dict[str, Any] = {"role": role}
            if parts:
                out["content"] = "\n".join(parts)
            if tool_calls:
                out["tool_calls"] = tool_calls
                out.setdefault("content", None)
            return out

        return {"role": role, "content": str(content)}

    @staticmethod
    def _convert_tools(anthropic_tools: list[dict]) -> list[dict]:
        """Convert Anthropic tool defs to OpenAI function-calling format."""
        oai_tools: list[dict] = []
        for t in anthropic_tools:
            oai_tools.append({
                "type": "function",
                "function": {
                    "name": t.get("name", ""),
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {}),
                },
            })
        return oai_tools

    @staticmethod
    def _normalise_response(oai_resp: dict) -> dict[str, Any]:
        """Convert OpenAI response to Anthropic-style for the agent loop."""
        choice = oai_resp.get("choices", [{}])[0]
        message = choice.get("message", {})

        content_blocks: list[dict] = []
        if message.get("content"):
            content_blocks.append({"type": "text", "text": message["content"]})

        tool_calls = message.get("tool_calls", [])
        if tool_calls:
            for tc in tool_calls:
                fn = tc.get("function", {})
                try:
                    args = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    args = {}
                content_blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id", ""),
                    "name": fn.get("name", ""),
                    "input": args,
                })

        stop_reason = "tool_use" if tool_calls else "end_turn"
        return {"content": content_blocks, "stop_reason": stop_reason}
