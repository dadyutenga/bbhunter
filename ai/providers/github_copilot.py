"""GitHub Copilot AI provider for BBHunter."""

import json
import subprocess
import urllib.error
import urllib.request
from typing import Any

from ai.base_provider import BaseProvider


# Copilot-available models (as of early 2026)
_COPILOT_MODELS = [
    {"id": "gpt-4o", "name": "GPT-4o (Copilot)"},
    {"id": "gpt-4o-mini", "name": "GPT-4o Mini (Copilot)"},
    {"id": "claude-3.5-sonnet", "name": "Claude 3.5 Sonnet (Copilot)"},
    {"id": "o1-mini", "name": "o1-mini (Copilot)"},
]

_API_URL = "https://api.githubcopilot.com/chat/completions"


class GitHubCopilotProvider(BaseProvider):
    """Connects to GitHub Copilot via the `gh` CLI OAuth token."""

    name = "github_copilot"
    requires_auth = True

    def __init__(self) -> None:
        self._token: str | None = None

    # ── auth ──────────────────────────────────────────────────────
    def authenticate(self, **kwargs) -> bool:
        """
        Authenticate via the GitHub CLI.
        1. Check `gh auth status`
        2. If not logged in, prompt user to run `gh auth login`
        3. Grab a Copilot chat token from `gh copilot` API endpoint
        """
        token = kwargs.get("token")
        if token:
            self._token = token
            return True

        # Check gh CLI is available
        if not self._gh_installed():
            print("[!] GitHub CLI (`gh`) is not installed. Install from https://cli.github.com")
            return False

        # Check logged in
        if not self._gh_authenticated():
            print("[*] Not logged in to GitHub CLI. Running `gh auth login`...")
            try:
                subprocess.run(["gh", "auth", "login"], check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("[!] `gh auth login` failed.")
                return False

        # Fetch a Copilot token
        self._token = self._fetch_copilot_token()
        return self._token is not None

    def is_connected(self) -> bool:
        return self._token is not None

    # ── models ────────────────────────────────────────────────────
    def list_models(self) -> list[dict]:
        return list(_COPILOT_MODELS)

    # ── chat ──────────────────────────────────────────────────────
    def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        system: str | None = None,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        if not self._token:
            raise RuntimeError("GitHub Copilot is not authenticated. Run /connectors to connect.")

        model = model or "gpt-4o"

        # Build OpenAI-compatible payload
        oai_messages: list[dict] = []
        if system:
            oai_messages.append({"role": "system", "content": system})

        for msg in messages:
            oai_messages.append(self._normalise_message(msg))

        payload: dict[str, Any] = {
            "model": model,
            "messages": oai_messages,
            "max_tokens": 4096,
            "stream": False,
        }

        if tools:
            payload["tools"] = self._convert_tools(tools)

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            _API_URL,
            data=data,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Editor-Version": "vscode/1.85.0",
                "Copilot-Integration-Id": "vscode-chat",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                result = json.loads(resp.read().decode())
        except urllib.error.HTTPError as ex:
            body = ex.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Copilot API HTTP {ex.code}: {body[:400]}") from ex

        return self._normalise_response(result)

    # ── internal helpers ──────────────────────────────────────────
    @staticmethod
    def _gh_installed() -> bool:
        try:
            subprocess.run(["gh", "--version"], capture_output=True, check=True)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    @staticmethod
    def _gh_authenticated() -> bool:
        try:
            r = subprocess.run(["gh", "auth", "status"], capture_output=True)
            return r.returncode == 0
        except FileNotFoundError:
            return False

    @staticmethod
    def _fetch_copilot_token() -> str | None:
        """Use the gh CLI to get a Copilot token via internal API."""
        try:
            r = subprocess.run(
                ["gh", "api", "-X", "GET",
                 "https://api.github.com/copilot_internal/v2/token",
                 "-H", "Accept: application/json"],
                capture_output=True, text=True, check=True,
            )
            data = json.loads(r.stdout)
            token = data.get("token")
            if token:
                print(f"[+] Copilot token acquired (expires {data.get('expires_at', 'unknown')})")
                return token
            print("[!] Token response did not contain a token field.")
            return None
        except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError) as ex:
            print(f"[!] Failed to fetch Copilot token: {ex}")
            return None

    @staticmethod
    def _normalise_message(msg: dict) -> dict:
        """Convert Anthropic-style messages to OpenAI-style if needed."""
        role = msg.get("role", "user")
        content = msg.get("content", "")

        # If content is already a string, passthrough
        if isinstance(content, str):
            return {"role": role, "content": content}

        # Anthropic list-of-blocks → single string (text blocks)
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
                # Return only the first tool result; caller loops for others
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
        """
        Convert an OpenAI chat-completion response to the Anthropic-style
        format that the BBHunter agent loop expects.
        """
        choice = oai_resp.get("choices", [{}])[0]
        message = choice.get("message", {})
        finish = choice.get("finish_reason", "stop")

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
