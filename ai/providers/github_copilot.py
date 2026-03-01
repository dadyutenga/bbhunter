"""GitHub Copilot AI provider for BBHunter.

Auth flow:
1. Read OAuth token from Windows Credential Manager (copilot-cli or git cred)
2. Call /copilot_internal/user to get the user's API endpoint + validate token
3. Use the returned API endpoint for chat completions

The OAuth token from the Copilot CLI works directly as a Bearer token.
"""

import ctypes
import ctypes.wintypes
import json
import os
import subprocess
import urllib.error
import urllib.request
from typing import Any

from ai.base_provider import BaseProvider


_GITHUB_API = "https://api.github.com"

# Models dynamically fetched from the API; these are fallback defaults
_DEFAULT_MODELS = [
    {"id": "gpt-4o", "name": "GPT-4o"},
    {"id": "gpt-4o-mini", "name": "GPT-4o Mini"},
    {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo"},
]

# Dated / snapshot IDs to hide (users should use the stable alias)
# Matches -YYYY-MM-DD or -MMDD suffixes
_DATED_MODEL_RE = __import__("re").compile(r"-\d{4}(-\d{2}){0,2}$")

# Preferred display order (first = best)
_MODEL_RANK = {"gpt-4o": 0, "gpt-4o-mini": 1, "gpt-3.5-turbo": 2}


class GitHubCopilotProvider(BaseProvider):
    """Connects to GitHub Copilot using OAuth credentials from the Copilot CLI."""

    name = "github_copilot"
    requires_auth = True

    def __init__(self) -> None:
        self._oauth_token: str | None = None     # GitHub OAuth token (long-lived)
        self._api_url: str = ""                   # e.g. https://api.individual.githubcopilot.com
        self._copilot_plan: str = ""
        self._cached_models: list[dict] | None = None

    # ── auth ──────────────────────────────────────────────────────
    def authenticate(self, **kwargs) -> bool:
        """
        Try multiple auth sources:
        1. Explicit token kwarg
        2. Copilot CLI cred from Windows Credential Manager
        3. Git cred from Windows Credential Manager
        4. GITHUB_TOKEN / GH_TOKEN env vars
        5. gh CLI (gh auth token)
        """
        tok = kwargs.get("token") or kwargs.get("oauth_token")
        if tok:
            self._oauth_token = tok
            return self._validate_copilot_access()

        # 1. Copilot CLI credential
        print("[*] Checking Copilot CLI credentials...")
        cred = _read_windows_credential("copilot-cli/https://github.com")
        if cred:
            self._oauth_token = cred
            if self._validate_copilot_access():
                return True

        # 2. Git credential
        print("[*] Checking Git credentials...")
        cred = _read_windows_credential("git:https://github.com")
        if cred:
            self._oauth_token = cred
            if self._validate_copilot_access():
                return True

        # 3. Environment variables
        for env in ("GITHUB_TOKEN", "GH_TOKEN"):
            tok = os.getenv(env, "")
            if tok:
                print(f"[*] Trying {env}...")
                self._oauth_token = tok
                if self._validate_copilot_access():
                    return True

        # 4. gh CLI
        gh_tok = self._try_gh_cli_token()
        if gh_tok:
            self._oauth_token = gh_tok
            if self._validate_copilot_access():
                return True

        print("[!] Could not authenticate with GitHub Copilot.")
        self._oauth_token = None
        return False

    def is_connected(self) -> bool:
        return bool(self._oauth_token and self._api_url)

    # ── models ────────────────────────────────────────────────────
    def list_models(self) -> list[dict]:
        if self._cached_models is not None:
            return self._cached_models

        if not self.is_connected():
            return list(_DEFAULT_MODELS)

        # Fetch from API and filter out dated snapshot IDs
        try:
            req = urllib.request.Request(
                f"{self._api_url}/models",
                headers={
                    "Authorization": f"Bearer {self._oauth_token}",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            models = []
            for m in data.get("data", []):
                mid = m.get("id", "")
                # Skip dated snapshot variants (e.g. gpt-4o-2024-11-20)
                if _DATED_MODEL_RE.search(mid):
                    continue
                nice = mid.replace("gpt-", "GPT-").replace("-turbo", " Turbo").replace("-mini", " Mini")
                models.append({"id": mid, "name": nice})
            # Sort: known models first by rank, unknowns alphabetically at the end
            models.sort(key=lambda m: (_MODEL_RANK.get(m["id"], 999), m["id"]))
            if models:
                self._cached_models = models
                return models
        except Exception:
            pass

        return list(_DEFAULT_MODELS)

    # ── chat ──────────────────────────────────────────────────────
    def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        system: str | None = None,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        if not self.is_connected():
            raise RuntimeError("GitHub Copilot is not authenticated. Run /connectors to connect.")

        model = model or "gpt-4o"

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
            f"{self._api_url}/chat/completions",
            data=data,
            headers={
                "Authorization": f"Bearer {self._oauth_token}",
                "Content-Type": "application/json",
                "Editor-Version": "vscode/1.96.0",
                "Copilot-Integration-Id": "vscode-chat",
                "Editor-Plugin-Version": "copilot-chat/0.24.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode())
        except urllib.error.HTTPError as ex:
            body = ex.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Copilot API HTTP {ex.code}: {body[:400]}") from ex

        return self._normalise_response(result)

    # ── validate Copilot access ───────────────────────────────────
    def _validate_copilot_access(self) -> bool:
        """
        Call /copilot_internal/user to:
        1. Validate the token has Copilot access
        2. Get the per-user API endpoint (e.g. api.individual.githubcopilot.com)
        """
        if not self._oauth_token:
            return False
        try:
            req = urllib.request.Request(
                f"{_GITHUB_API}/copilot_internal/user",
                headers={
                    "Authorization": f"Bearer {self._oauth_token}",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            endpoints = data.get("endpoints", {})
            api_url = endpoints.get("api", "")
            if not api_url:
                print("[!] Copilot user endpoint returned no API URL.")
                return False

            self._api_url = api_url.rstrip("/")
            self._copilot_plan = data.get("copilot_plan", "unknown")
            chat_ok = data.get("chat_enabled", False)

            print(f"[+] Copilot connected! Plan: {self._copilot_plan} | Chat: {chat_ok}")
            print(f"    API: {self._api_url}")
            return True

        except urllib.error.HTTPError as ex:
            body = ex.read().decode("utf-8", errors="ignore")[:200]
            if ex.code == 401:
                print("[!] Token not valid for Copilot.")
            elif ex.code == 404:
                print("[!] No Copilot subscription found for this account.")
            else:
                print(f"[!] Copilot validation failed (HTTP {ex.code}): {body}")
            return False
        except Exception as ex:
            print(f"[!] Copilot validation error: {ex}")
            return False

    # ── CLI helpers ───────────────────────────────────────────────
    @staticmethod
    def _try_gh_cli_token() -> str | None:
        try:
            r = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True, text=True, check=True,
            )
            tok = r.stdout.strip()
            if tok:
                print("[+] Got token from gh CLI")
                return tok
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        return None

    # ── message/tool normalisation (Anthropic ↔ OpenAI) ──────────
    @staticmethod
    def _normalise_message(msg: dict) -> dict:
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


# ── Windows Credential Manager reader ────────────────────────────────
def _read_windows_credential(target_name: str) -> str | None:
    """
    Read a credential from Windows Credential Manager by target name.
    Searches for partial matches (the Copilot CLI stores creds with
    the GitHub username appended).
    """
    if os.name != "nt":
        return None

    try:
        advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", ctypes.wintypes.DWORD),
                ("Type", ctypes.wintypes.DWORD),
                ("TargetName", ctypes.wintypes.LPWSTR),
                ("Comment", ctypes.wintypes.LPWSTR),
                ("LastWritten", ctypes.wintypes.FILETIME),
                ("CredentialBlobSize", ctypes.wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
                ("Persist", ctypes.wintypes.DWORD),
                ("AttributeCount", ctypes.wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", ctypes.wintypes.LPWSTR),
                ("UserName", ctypes.wintypes.LPWSTR),
            ]

        PCREDENTIAL = ctypes.POINTER(CREDENTIAL)

        # Try exact match first
        cred_ptr = PCREDENTIAL()
        ok = advapi32.CredReadW(target_name, 1, 0, ctypes.byref(cred_ptr))
        if ok:
            cred = cred_ptr.contents
            blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
            advapi32.CredFree(cred_ptr)
            return blob.decode("utf-8", errors="ignore").strip()

        # Enumerate and find partial match
        pcreds = ctypes.POINTER(PCREDENTIAL)()
        count = ctypes.wintypes.DWORD()
        ok = advapi32.CredEnumerateW(
            None, 0, ctypes.byref(count), ctypes.byref(pcreds)
        )
        if not ok:
            return None

        result = None
        for i in range(count.value):
            c = pcreds[i].contents
            cred_target = c.TargetName or ""
            if target_name.lower() in cred_target.lower():
                blob = ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize)
                result = blob.decode("utf-8", errors="ignore").strip()
                break

        advapi32.CredFree(pcreds)
        return result

    except Exception as ex:
        print(f"[!] Could not read Windows credentials: {ex}")
        return None
