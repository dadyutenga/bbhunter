"""GitHub Copilot AI provider for BBHunter.

Two authentication tiers:
─────────────────────────
Tier 1 — "Basic" (copilot-cli / env token, scopes: read:user, repo …)
  •  Uses  /copilot_internal/user  →  api.individual.githubcopilot.com
  •  Only GPT models work (gpt-4o, gpt-4o-mini, gpt-3.5-turbo)

Tier 2 — "Full" (device-flow token WITH `copilot` scope)
  •  Exchanges token via  /copilot_internal/v2/token  →  short-lived JWT
  •  Calls  api.githubcopilot.com  →  ALL models (Claude, Gemini, o-series, GPT)

On first /connect the provider tries Tier 1 automatically.
If the user runs  `/copilot auth`  we do a GitHub Device Flow requesting the
`copilot` scope, unlock Tier 2, and save the token for next time.
"""

import ctypes
import ctypes.wintypes
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ai.base_provider import BaseProvider

_GITHUB_API = "https://api.github.com"
_GITHUB_BASE = "https://github.com"
_CLIENT_ID = "Ov23ctDVkRmgkPke0Mmm"          # Copilot CLI OAuth app
_FULL_CHAT_URL = "https://api.githubcopilot.com/chat/completions"

# ── model metadata ────────────────────────────────────────────────────
# Tier-2 (full-scope) model catalogue — updated March 2026
_FULL_MODELS = [
    # OpenAI GPT
    {"id": "gpt-4o",                "name": "GPT-4o",                  "vendor": "OpenAI"},
    {"id": "gpt-4o-mini",           "name": "GPT-4o Mini",             "vendor": "OpenAI"},
    {"id": "gpt-4.1",              "name": "GPT-4.1",                 "vendor": "OpenAI"},
    {"id": "gpt-4.1-mini",        "name": "GPT-4.1 Mini",            "vendor": "OpenAI"},
    {"id": "gpt-4.1-nano",        "name": "GPT-4.1 Nano",            "vendor": "OpenAI"},
    # OpenAI o-series
    {"id": "o3-mini",              "name": "o3-mini",                  "vendor": "OpenAI"},
    {"id": "o4-mini",              "name": "o4-mini",                  "vendor": "OpenAI"},
    # Anthropic Claude
    {"id": "claude-3.5-sonnet",    "name": "Claude 3.5 Sonnet",       "vendor": "Anthropic"},
    {"id": "claude-3.7-sonnet",    "name": "Claude 3.7 Sonnet",       "vendor": "Anthropic"},
    {"id": "claude-3.7-sonnet-thought", "name": "Claude 3.7 Sonnet (Thinking)", "vendor": "Anthropic"},
    {"id": "claude-sonnet-4",      "name": "Claude Sonnet 4",         "vendor": "Anthropic"},
    # Google Gemini
    {"id": "gemini-2.0-flash-001", "name": "Gemini 2.0 Flash",        "vendor": "Google"},
    {"id": "gemini-2.5-pro",       "name": "Gemini 2.5 Pro",          "vendor": "Google"},
]

# Tier-1 (basic-scope) fallback models
_BASIC_MODELS = [
    {"id": "gpt-4o",         "name": "GPT-4o",         "vendor": "OpenAI"},
    {"id": "gpt-4o-mini",    "name": "GPT-4o Mini",    "vendor": "OpenAI"},
    {"id": "gpt-3.5-turbo",  "name": "GPT-3.5 Turbo",  "vendor": "OpenAI"},
]

_DATED_RE = re.compile(r"-\d{4}(-\d{2}){0,2}$")

# Preferred display order
_MODEL_RANK = {m["id"]: i for i, m in enumerate(_FULL_MODELS)}

# Token cache path
_TOKEN_FILE = os.path.join(os.path.expanduser("~"), ".bbhunter", "copilot_token.json")


class GitHubCopilotProvider(BaseProvider):
    """Connects to GitHub Copilot via CLI credentials or Device Flow."""

    name = "github_copilot"
    requires_auth = True

    def __init__(self) -> None:
        self._oauth_token: str | None = None      # long-lived GitHub OAuth token
        self._copilot_token: str | None = None     # short-lived Copilot API JWT (Tier 2)
        self._copilot_token_exp: float = 0.0
        self._api_url: str = ""                    # Tier 1 endpoint
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
            return self._try_all_tiers()

        # 1. Saved full-scope token from ~/.bbhunter/copilot_token.json
        saved = self._load_saved_token()
        if saved:
            self._oauth_token = saved
            if self._try_all_tiers():
                return True

        # 2. Copilot CLI credential (Windows Credential Manager)
        print("[*] Checking Copilot CLI credentials...")
        cred = _read_windows_credential("copilot-cli/https://github.com")
        if cred:
            self._oauth_token = cred
            if self._try_all_tiers():
                return True

        # 3. Git credential
        cred = _read_windows_credential("git:https://github.com")
        if cred:
            self._oauth_token = cred
            if self._try_all_tiers():
                return True

        # 4. Environment variables
        for env in ("GITHUB_TOKEN", "GH_TOKEN"):
            tok = os.getenv(env, "")
            if tok:
                self._oauth_token = tok
                if self._try_all_tiers():
                    return True

        # 5. gh CLI
        gh_tok = self._try_gh_cli_token()
        if gh_tok:
            self._oauth_token = gh_tok
            if self._try_all_tiers():
                return True

        print("[!] Could not authenticate with GitHub Copilot.")
        self._oauth_token = None
        return False

    def is_connected(self) -> bool:
        return self._tier > 0

    # ── models ────────────────────────────────────────────────────
    def list_models(self) -> list[dict]:
        if self._cached_models is not None:
            return self._cached_models

        if self._tier == 2:
            # Full-scope: return catalogue + anything extra from API
            models = list(_FULL_MODELS)
            self._cached_models = models
            return models

        if self._tier == 1:
            # Basic-scope: try /models endpoint, filter dated IDs
            models = self._fetch_api_models()
            if models:
                self._cached_models = models
                return models
            return list(_BASIC_MODELS)

        return list(_BASIC_MODELS)

    def _fetch_api_models(self) -> list[dict]:
        """Fetch model list from Tier-1 API and filter dated variants."""
        if not self._api_url or not self._oauth_token:
            return []
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
                if _DATED_RE.search(mid):
                    continue
                nice = mid.replace("gpt-", "GPT-").replace("-turbo", " Turbo").replace("-mini", " Mini")
                models.append({"id": mid, "name": nice, "vendor": "OpenAI"})
            models.sort(key=lambda m: (_MODEL_RANK.get(m["id"], 999), m["id"]))
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

        # Pick the right auth + endpoint for the tier
        if self._tier == 2:
            self._ensure_copilot_jwt()
            url = _FULL_CHAT_URL
            auth = f"Bearer {self._copilot_token}"
        else:
            url = f"{self._api_url}/chat/completions"
            auth = f"Bearer {self._oauth_token}"

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={
                "Authorization": auth,
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
            # If tier-2 401, refresh JWT once
            if ex.code == 401 and self._tier == 2:
                print("[*] Copilot token expired, refreshing...")
                if self._exchange_copilot_token():
                    return self.chat(messages, model, system, tools)
            raise RuntimeError(f"Copilot API HTTP {ex.code}: {body[:400]}") from ex

        return self._normalise_response(result)

    # ── tier detection ────────────────────────────────────────────
    def _try_all_tiers(self) -> bool:
        """Try Tier 2 first (full), fall back to Tier 1 (basic)."""
        if self._try_tier2():
            return True
        return self._try_tier1()

    def _try_tier2(self) -> bool:
        """Try token exchange → if it works, we have the copilot scope."""
        if not self._oauth_token:
            return False
        if self._exchange_copilot_token():
            self._tier = 2
            self._cached_models = None
            # Also grab the user endpoint info
            self._validate_copilot_user()
            print(f"[+] Copilot Tier 2 (full) — all models unlocked!")
            return True
        return False

    def _try_tier1(self) -> bool:
        """Validate via /copilot_internal/user for basic GPT access."""
        if not self._oauth_token:
            return False
        if self._validate_copilot_user():
            self._tier = 1
            self._cached_models = None
            print(f"    Tier 1 (basic) — GPT models only. Run /copilot auth to unlock all models.")
            return True
        return False

    # ── token exchange (Tier 2) ───────────────────────────────────
    def _exchange_copilot_token(self) -> bool:
        """Exchange GitHub OAuth token for short-lived Copilot API JWT."""
        if not self._oauth_token:
            return False
        try:
            req = urllib.request.Request(
                f"{_GITHUB_API}/copilot_internal/v2/token",
                headers={
                    "Authorization": f"token {self._oauth_token}",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            token = data.get("token")
            if token:
                exp = data.get("expires_at", 0)
                self._copilot_token = token
                self._copilot_token_exp = exp if isinstance(exp, (int, float)) else 0
                return True
        except Exception:
            pass
        return False

    def _ensure_copilot_jwt(self) -> None:
        """Refresh the short-lived JWT if it's expired or missing."""
        if self._copilot_token and self._copilot_token_exp > time.time() + 60:
            return
        if not self._exchange_copilot_token():
            raise RuntimeError("Failed to refresh Copilot API token.")

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
        except urllib.error.HTTPError as ex:
            if ex.code == 401:
                print("[!] Token not valid for Copilot.")
            elif ex.code == 404:
                print("[!] No Copilot subscription for this account.")
            return False
        except Exception:
            return False

    # ── GitHub Device Flow (interactive) ──────────────────────────
    def _device_flow_login(self) -> bool:
        """
        Run GitHub Device Flow with `copilot` scope.
        The user opens a URL, enters a code, and we get a token
        that can access ALL Copilot models (Claude, Gemini, etc.).
        """
        print()
        print("[*] Starting GitHub Device Flow to unlock full Copilot access...")
        print("    (This gives access to Claude, Gemini, o-series and all GPT models)")
        print()

        # Step 1: Request device code
        try:
            body = urllib.parse.urlencode({
                "client_id": _CLIENT_ID,
                "scope": "read:user copilot",
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
                        "client_id": _CLIENT_ID,
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
                        print("[!] Authorization expired. Try again.")
                        return False
                    elif error == "access_denied":
                        print("[!] Authorization denied.")
                        return False
                    elif error:
                        print(f"[!] OAuth error: {error}")
                        return False

                    access_token = result.get("access_token", "")
                    if access_token:
                        print(f"\n[+] Authorization successful!")
                        self._oauth_token = access_token
                        self._save_token(access_token)
                        return self._try_all_tiers()

                except Exception as ex:
                    print(f"[!] Polling error: {ex}")
                    return False
        except KeyboardInterrupt:
            print("\n[*] Authorization cancelled.")
            return False

        print("[!] Timed out waiting for authorization.")
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
