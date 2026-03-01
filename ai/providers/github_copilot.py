"""GitHub Copilot AI provider for BBHunter.

Two authentication tiers:
─────────────────────────
Tier 1 — "Basic" (copilot-cli credential, no `copilot` OAuth scope)
  •  Reads token from Windows Credential Manager / env / gh cli
  •  GPT models only: gpt-4o, gpt-4o-mini, gpt-3.5-turbo

Tier 2 — "Full" (device-flow token with `copilot` OAuth scope)
  •  User runs /copilot auth → GitHub Device Flow via VS Code OAuth app
  •  Token saved to ~/.bbhunter/copilot_token.json
  •  All models: GPT + Claude Sonnet 4 + Gemini 2.5 Pro + GPT-4.1

Both tiers use the same endpoint:
  api.individual.githubcopilot.com/chat/completions  (Bearer token)
"""

import ctypes
import ctypes.wintypes
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ai.base_provider import BaseProvider

_GITHUB_API = "https://api.github.com"
_GITHUB_BASE = "https://github.com"
# VS Code's OAuth app — needed for device flow with `copilot` scope
_VSCODE_CLIENT_ID = "01ab8ac9400c4e429b23"

# ── model metadata ────────────────────────────────────────────────────
# Tier-2 models (copilot scope required for non-GPT models)
_TIER2_MODELS = [
    # OpenAI GPT
    {"id": "gpt-4o",           "name": "GPT-4o",           "vendor": "OpenAI"},
    {"id": "gpt-4o-mini",      "name": "GPT-4o Mini",      "vendor": "OpenAI"},
    {"id": "gpt-4.1",          "name": "GPT-4.1",          "vendor": "OpenAI"},
    {"id": "gpt-4",            "name": "GPT-4",            "vendor": "OpenAI"},
    {"id": "gpt-3.5-turbo",    "name": "GPT-3.5 Turbo",    "vendor": "OpenAI"},
    # Anthropic Claude
    {"id": "claude-sonnet-4",  "name": "Claude Sonnet 4",   "vendor": "Anthropic"},
    # Google Gemini
    {"id": "gemini-2.5-pro",   "name": "Gemini 2.5 Pro",    "vendor": "Google"},
]

# Tier-1 models (basic copilot-cli token)
_TIER1_MODELS = [
    {"id": "gpt-4o",         "name": "GPT-4o",         "vendor": "OpenAI"},
    {"id": "gpt-4o-mini",    "name": "GPT-4o Mini",    "vendor": "OpenAI"},
    {"id": "gpt-3.5-turbo",  "name": "GPT-3.5 Turbo",  "vendor": "OpenAI"},
]

_MODEL_RANK = {m["id"]: i for i, m in enumerate(_TIER2_MODELS)}

# Token cache path
_TOKEN_FILE = os.path.join(os.path.expanduser("~"), ".bbhunter", "copilot_token.json")


class GitHubCopilotProvider(BaseProvider):
    """Connects to GitHub Copilot via CLI credentials or Device Flow."""

    name = "github_copilot"
    requires_auth = True

    def __init__(self) -> None:
        self._oauth_token: str | None = None
        self._api_url: str = ""
        self._copilot_plan: str = ""
        self._tier: int = 0                        # 1 = basic, 2 = full
        self._cached_models: list[dict] | None = None

    # ── auth ──────────────────────────────────────────────────────
    def authenticate(self, **kwargs) -> bool:
        """
        Try auth sources in order.  If 'device_flow' kwarg is True,
        run the interactive GitHub Device Flow to get the copilot scope.
        """
        if kwargs.get("device_flow"):
            return self._device_flow_login()

        tok = kwargs.get("token") or kwargs.get("oauth_token")
        if tok:
            self._oauth_token = tok
            return self._try_connect()

        # 1. Saved full-scope token from ~/.bbhunter/copilot_token.json
        saved = self._load_saved_token()
        if saved:
            self._oauth_token = saved
            if self._try_connect():
                return True

        # 2. Copilot CLI credential (Windows Credential Manager)
        cred = _read_windows_credential("copilot-cli/https://github.com")
        if cred:
            self._oauth_token = cred
            if self._try_connect():
                return True

        # 3. Git credential
        cred = _read_windows_credential("git:https://github.com")
        if cred:
            self._oauth_token = cred
            if self._try_connect():
                return True

        # 4. Environment variables
        for env in ("GITHUB_TOKEN", "GH_TOKEN"):
            tok = os.getenv(env, "")
            if tok:
                self._oauth_token = tok
                if self._try_connect():
                    return True

        # 5. gh CLI
        gh_tok = self._try_gh_cli_token()
        if gh_tok:
            self._oauth_token = gh_tok
            if self._try_connect():
                return True

        self._oauth_token = None
        return False

    def is_connected(self) -> bool:
        return self._tier > 0

    # ── models ────────────────────────────────────────────────────
    def list_models(self) -> list[dict]:
        if self._cached_models is not None:
            return self._cached_models
        if self._tier == 2:
            self._cached_models = list(_TIER2_MODELS)
        else:
            self._cached_models = list(_TIER1_MODELS)
        return self._cached_models

    # ── chat ──────────────────────────────────────────────────────
    def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        system: str | None = None,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        if not self.is_connected():
            raise RuntimeError("GitHub Copilot is not authenticated. Run /connect github_copilot.")

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

        url = f"{self._api_url}/chat/completions"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
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

    # ── connection + tier detection ───────────────────────────────
    def _try_connect(self) -> bool:
        """Validate token and detect tier."""
        if not self._oauth_token:
            return False
        if not self._validate_copilot_user():
            return False
        tier = self._detect_tier()
        self._tier = tier
        self._cached_models = None
        if tier == 2:
            print(f"    Tier 2 (full) — Claude, Gemini & all GPT models available!")
        else:
            print(f"    Tier 1 (basic) — GPT models only. Run /copilot auth to unlock Claude & Gemini.")
        return True

    def _detect_tier(self) -> int:
        """Check if the token has the `copilot` OAuth scope."""
        if not self._oauth_token:
            return 1
        try:
            req = urllib.request.Request(
                f"{_GITHUB_API}/user",
                headers={"Authorization": f"token {self._oauth_token}"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                scopes = resp.headers.get("X-OAuth-Scopes", "")
            if "copilot" in scopes.lower():
                return 2
        except Exception:
            pass
        return 1

    # ── validate /copilot_internal/user ───────────────────────────
    def _validate_copilot_user(self) -> bool:
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
            if api_url:
                self._api_url = api_url.rstrip("/")
            self._copilot_plan = data.get("copilot_plan", "unknown")
            chat_ok = data.get("chat_enabled", False)
            print(f"[+] Copilot connected! Plan: {self._copilot_plan} | Chat: {chat_ok}")
            return True
        except urllib.error.HTTPError:
            return False
        except Exception:
            return False

    # ── GitHub Device Flow (interactive) ──────────────────────────
    def _device_flow_login(self) -> bool:
        """
        Run GitHub Device Flow with VS Code's OAuth app requesting `copilot` scope.
        Unlocks Claude Sonnet 4, Gemini 2.5 Pro, and additional GPT models.
        """
        print()
        print("[*] Starting GitHub Device Flow to unlock full Copilot access...")
        print("    This gives access to Claude Sonnet 4, Gemini 2.5 Pro & more.")
        print()

        # Step 1: Request device code
        try:
            body = urllib.parse.urlencode({
                "client_id": _VSCODE_CLIENT_ID,
                "scope": "user:email copilot",
            }).encode()
            req = urllib.request.Request(
                f"{_GITHUB_BASE}/login/device/code",
                data=body,
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                dc = json.loads(resp.read().decode())
        except Exception as ex:
            print(f"[!] Device code request failed: {ex}")
            return False

        user_code = dc.get("user_code", "")
        verify_url = dc.get("verification_uri", "")
        device_code = dc.get("device_code", "")
        interval = dc.get("interval", 5)
        expires_in = dc.get("expires_in", 900)

        print(f"  1. Open this URL in your browser:")
        print(f"     \033[1;96m{verify_url}\033[0m")
        print()
        print(f"  2. Enter this code:  \033[1;93m{user_code}\033[0m")
        print()
        print(f"  Waiting for authorization (expires in {expires_in // 60} min)...")
        print(f"  Press Ctrl+C to cancel.")

        # Step 2: Poll for token
        deadline = time.time() + expires_in
        try:
            while time.time() < deadline:
                time.sleep(interval)
                try:
                    body = urllib.parse.urlencode({
                        "client_id": _VSCODE_CLIENT_ID,
                        "device_code": device_code,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    }).encode()
                    req = urllib.request.Request(
                        f"{_GITHUB_BASE}/login/oauth/access_token",
                        data=body,
                        headers={"Accept": "application/json"},
                    )
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        result = json.loads(resp.read().decode())

                    error = result.get("error", "")
                    if error == "authorization_pending":
                        continue
                    elif error == "slow_down":
                        interval = result.get("interval", interval + 5)
                        continue
                    elif error == "expired_token":
                        print("\n[!] Authorization expired. Try again.")
                        return False
                    elif error == "access_denied":
                        print("\n[!] Authorization denied.")
                        return False
                    elif error:
                        print(f"\n[!] OAuth error: {error}")
                        return False

                    access_token = result.get("access_token", "")
                    if access_token:
                        print(f"\n[+] Authorization successful!")
                        self._oauth_token = access_token
                        self._save_token(access_token)
                        return self._try_connect()

                except Exception as ex:
                    print(f"\n[!] Polling error: {ex}")
                    return False
        except KeyboardInterrupt:
            print("\n[*] Authorization cancelled.")
            return False

        print("\n[!] Timed out waiting for authorization.")
        return False

    # ── token persistence ─────────────────────────────────────────
    @staticmethod
    def _save_token(token: str) -> None:
        os.makedirs(os.path.dirname(_TOKEN_FILE), exist_ok=True)
        try:
            with open(_TOKEN_FILE, "w", encoding="utf-8") as f:
                json.dump({"oauth_token": token}, f)
        except Exception:
            pass

    @staticmethod
    def _load_saved_token() -> str | None:
        try:
            with open(_TOKEN_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("oauth_token") or None
        except Exception:
            return None

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

    except Exception:
        return None
