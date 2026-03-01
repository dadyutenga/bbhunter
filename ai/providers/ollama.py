"""Ollama (local) AI provider for BBHunter."""

import json
import urllib.error
import urllib.request
from typing import Any

from ai.base_provider import BaseProvider


_DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaProvider(BaseProvider):
    """Local Ollama provider — no API key required, just a running Ollama server."""

    name = "ollama"
    requires_auth = False

    def __init__(self) -> None:
        self._base_url: str = _DEFAULT_BASE_URL
        self._connected: bool = False
        self._model: str = "llama3"

    # ── auth ──────────────────────────────────────────────────────
    def authenticate(self, **kwargs) -> bool:
        self._base_url = kwargs.get("base_url", _DEFAULT_BASE_URL)
        # Just verify the server is reachable
        try:
            req = urllib.request.Request(f"{self._base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5):
                self._connected = True
                print(f"[+] Connected to Ollama at {self._base_url}")
                return True
        except Exception as ex:
            print(f"[!] Cannot reach Ollama at {self._base_url}: {ex}")
            self._connected = False
            return False

    def is_connected(self) -> bool:
        return self._connected

    # ── models ────────────────────────────────────────────────────
    def list_models(self) -> list[dict]:
        """Query Ollama for locally-available models."""
        try:
            req = urllib.request.Request(f"{self._base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            models = []
            for m in data.get("models", []):
                name = m.get("name", "unknown")
                models.append({"id": name, "name": name})
            return models
        except Exception:
            return []

    # ── chat ──────────────────────────────────────────────────────
    def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        system: str | None = None,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        if not self._connected:
            raise RuntimeError("Ollama is not connected. Run /connectors to connect.")

        use_model = model or self._model

        oai_messages: list[dict] = []
        if system:
            oai_messages.append({"role": "system", "content": system})

        for msg in messages:
            oai_messages.append(self._normalise_message(msg))

        payload: dict[str, Any] = {
            "model": use_model,
            "messages": oai_messages,
            "stream": False,
        }

        if tools:
            payload["tools"] = self._convert_tools(tools)

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self._base_url}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode())
        except urllib.error.HTTPError as ex:
            body = ex.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Ollama API HTTP {ex.code}: {body[:400]}") from ex
        except Exception as ex:
            raise RuntimeError(f"Ollama request failed: {ex}") from ex

        return self._normalise_response(result)

    # ── internal helpers ──────────────────────────────────────────
    @staticmethod
    def _normalise_message(msg: dict) -> dict:
        """Convert Anthropic-style messages to simple role/content."""
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
        """Convert Anthropic tool defs to Ollama/OpenAI function-calling format."""
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
    def _normalise_response(ollama_resp: dict) -> dict[str, Any]:
        """Convert Ollama response to Anthropic-style for the agent loop."""
        message = ollama_resp.get("message", {})

        content_blocks: list[dict] = []
        if message.get("content"):
            content_blocks.append({"type": "text", "text": message["content"]})

        tool_calls = message.get("tool_calls", [])
        if tool_calls:
            for tc in tool_calls:
                fn = tc.get("function", {})
                content_blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id", f"tool_{fn.get('name', 'unknown')}"),
                    "name": fn.get("name", ""),
                    "input": fn.get("arguments", {}),
                })

        stop_reason = "tool_use" if tool_calls else "end_turn"
        return {"content": content_blocks, "stop_reason": stop_reason}
