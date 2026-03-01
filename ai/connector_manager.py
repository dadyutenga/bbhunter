"""
Connector manager — manages all AI providers, authentication, and switching.
This is the central orchestrator for the multi-provider system.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ai.base_provider import BaseProvider
from ai.providers.github_copilot import GitHubCopilotProvider
from ai.providers.claude import ClaudeProvider
from ai.providers.openai import OpenAIProvider
from ai.providers.ollama import OllamaProvider


_CONFIG_DIR = os.path.expanduser("~/.bbhunter")
_PROVIDERS_JSON = os.path.join(_CONFIG_DIR, "providers.json")


class ConnectorManager:
    """
    Manages all available AI providers, handles connect/disconnect,
    persists provider config, and tracks the active provider+model.
    """

    def __init__(self) -> None:
        self.providers: dict[str, BaseProvider] = {
            "github_copilot": GitHubCopilotProvider(),
            "claude": ClaudeProvider(),
            "openai": OpenAIProvider(),
            "ollama": OllamaProvider(),
        }
        self.active_provider_name: str = ""
        self.active_model: str = ""
        self._load_config()

    # ── public API ────────────────────────────────────────────────

    def list_connectors(self) -> list[dict]:
        """Return provider status list for display."""
        result: list[dict] = []
        for name, provider in self.providers.items():
            result.append({
                "name": name,
                "connected": provider.is_connected(),
                "active": name == self.active_provider_name,
            })
        return result

    def connect(self, provider_name: str, **kwargs) -> bool:
        """Trigger authentication for a provider."""
        provider = self.providers.get(provider_name)
        if not provider:
            print(f"[!] Unknown provider: {provider_name}")
            return False
        success = provider.authenticate(**kwargs)
        if success:
            self._save_config()
        return success

    def disconnect(self, provider_name: str) -> None:
        """Remove saved credentials & mark provider as disconnected."""
        provider = self.providers.get(provider_name)
        if not provider:
            return
        # Reset internal state
        if hasattr(provider, "_api_key"):
            provider._api_key = None
        if hasattr(provider, "_token"):
            provider._token = None
        if hasattr(provider, "_connected"):
            provider._connected = False

        if provider_name == self.active_provider_name:
            self.active_provider_name = ""
            self.active_model = ""
        self._save_config()
        print(f"[*] Disconnected from {provider_name}")

    def get_active(self) -> BaseProvider | None:
        """Return the currently active provider, or None."""
        if not self.active_provider_name:
            return None
        provider = self.providers.get(self.active_provider_name)
        if provider and provider.is_connected():
            return provider
        return None

    def set_active(self, provider_name: str, model: str = "") -> bool:
        """Switch the active provider and model."""
        provider = self.providers.get(provider_name)
        if not provider:
            print(f"[!] Unknown provider: {provider_name}")
            return False
        if not provider.is_connected():
            print(f"[!] {provider_name} is not connected. Use /connectors to connect first.")
            return False
        self.active_provider_name = provider_name
        self.active_model = model or self._default_model(provider_name)
        self._save_config()
        print(f"[+] Active: {provider_name} / {self.active_model}")
        return True

    def chat(
        self,
        messages: list[dict],
        system: str | None = None,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        """Send a chat request through the active provider."""
        provider = self.get_active()
        if not provider:
            raise RuntimeError(
                "No active AI provider. Use /connectors to connect, then /use <provider> <model>."
            )
        return provider.chat(
            messages=messages,
            model=self.active_model or None,
            system=system,
            tools=tools,
        )

    # ── auto-connect at startup ───────────────────────────────────

    def auto_connect(self) -> bool:
        """
        Try to auto-connect providers from saved config / env vars.
        Returns True if at least one provider connected.
        """
        connected_any = False

        # 1. Try Claude (most common for existing users)
        if self.connect("claude"):
            connected_any = True

        # 2. Try OpenAI
        if self.connect("openai"):
            connected_any = True

        # 3. Try Ollama (always worth a shot, no key needed)
        if self.connect("ollama"):
            connected_any = True

        # 4. Try GitHub Copilot (reads from Windows Credential Manager / env)
        if self.connect("github_copilot"):
            connected_any = True

        # Restore active provider from config
        if self.active_provider_name:
            provider = self.providers.get(self.active_provider_name)
            if provider and provider.is_connected():
                return connected_any
            # Saved active provider isn't connected — pick first connected
            self.active_provider_name = ""
            self.active_model = ""

        if not self.active_provider_name:
            for name, prov in self.providers.items():
                if prov.is_connected():
                    self.active_provider_name = name
                    self.active_model = self._default_model(name)
                    break

        return connected_any

    # ── startup provider selection UI ─────────────────────────────

    def run_startup_selection(self) -> bool:
        """
        Interactive startup flow when no provider is configured.
        Returns True if a provider was successfully connected.
        """
        print()
        print("┌─────────────────────────────────┐")
        print("│  No AI provider configured.     │")
        print("│  Select a provider to continue: │")
        print("│                                 │")
        print("│  1. GitHub Copilot (recommended) │")
        print("│  2. Claude (API key required)   │")
        print("│  3. OpenAI (API key required)   │")
        print("│  4. Ollama (local, free)        │")
        print("│  5. Skip (limited mode)         │")
        print("└─────────────────────────────────┘")

        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            return False

        if choice == "1":
            return self._setup_copilot()
        elif choice == "2":
            return self._setup_api_key("claude")
        elif choice == "3":
            return self._setup_api_key("openai")
        elif choice == "4":
            return self._setup_ollama()
        elif choice == "5":
            print("[*] Running in limited mode (no AI analysis).")
            return False
        else:
            print("[!] Invalid choice.")
            return False

    # ── CLI command: /connectors ──────────────────────────────────

    def print_connectors(self) -> None:
        """Pretty-print the /connectors table."""
        from modules.utils import BOLD, RST, G, R

        print()
        print(f"{BOLD}┌─────────────────────────────────────────────────┐{RST}")
        print(f"{BOLD}│  CONNECTORS                                     │{RST}")
        print(f"{BOLD}├──────────────────┬────────────┬─────────────────┤{RST}")
        print(f"{BOLD}│  Provider        │  Status    │  Action         │{RST}")
        print(f"{BOLD}├──────────────────┼────────────┼─────────────────┤{RST}")

        for name, provider in self.providers.items():
            nice = _nice_name(name)
            if provider.is_connected():
                if name == self.active_provider_name:
                    status = f"{G}✅ Active{RST} "
                    action = "[disconnect]"
                else:
                    status = f"{G}✅ Ready{RST}  "
                    action = "[use]       "
            else:
                status = f"{R}❌ No key{RST} "
                action = "[connect]   "
            print(f"│  {nice:<16s}│  {status}│  {action}    │")

        print(f"└──────────────────┴────────────┴─────────────────┘")
        print()

    # ── private helpers ───────────────────────────────────────────

    def _setup_copilot(self) -> bool:
        print("[*] Connecting to GitHub Copilot...")
        if self.connect("github_copilot"):
            self.set_active("github_copilot", "gpt-4o")
            return True
        return False

    def _setup_api_key(self, provider_name: str) -> bool:
        try:
            key = input(f"Enter {provider_name} API key: ").strip()
        except (EOFError, KeyboardInterrupt):
            return False
        if not key:
            print("[!] No key provided.")
            return False
        if self.connect(provider_name, api_key=key):
            default_model = self._default_model(provider_name)
            self.set_active(provider_name, default_model)
            return True
        return False

    def _setup_ollama(self) -> bool:
        url = input("Ollama URL [http://localhost:11434]: ").strip()
        if not url:
            url = "http://localhost:11434"
        if self.connect("ollama", base_url=url):
            models = self.providers["ollama"].list_models()
            model = models[0]["id"] if models else "llama3"
            self.set_active("ollama", model)
            return True
        return False

    @staticmethod
    def _default_model(provider_name: str) -> str:
        return {
            "github_copilot": "gpt-4o",
            "claude": "claude-3-5-haiku-latest",
            "openai": "gpt-4o",
            "ollama": "llama3",
        }.get(provider_name, "")

    # ── persistence ───────────────────────────────────────────────

    def _load_config(self) -> None:
        """Load saved provider config from ~/.bbhunter/providers.json."""
        saved = self._load_saved_providers()
        self.active_provider_name = saved.get("active_provider", "")
        self.active_model = saved.get("active_model", "")

    @staticmethod
    def _load_saved_providers() -> dict:
        if not os.path.exists(_PROVIDERS_JSON):
            return {}
        try:
            with open(_PROVIDERS_JSON, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_config(self) -> None:
        """Persist current provider state to disk."""
        os.makedirs(_CONFIG_DIR, exist_ok=True)

        data: dict[str, Any] = {
            "active_provider": self.active_provider_name,
            "active_model": self.active_model,
            "providers": {},
        }

        # Save provider-specific info
        for name, provider in self.providers.items():
            pdata: dict[str, Any] = {"connected": provider.is_connected()}
            if name == "ollama" and hasattr(provider, "_base_url"):
                pdata["base_url"] = provider._base_url
            # Note: Copilot tokens come from Windows Credential Manager
            # API keys come from env vars / main config — not saved here
            data["providers"][name] = pdata

        try:
            with open(_PROVIDERS_JSON, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception as ex:
            print(f"[!] Could not save provider config: {ex}")


def _nice_name(name: str) -> str:
    return {
        "github_copilot": "GitHub Copilot",
        "claude": "Claude",
        "openai": "OpenAI",
        "ollama": "Ollama (local)",
    }.get(name, name)
