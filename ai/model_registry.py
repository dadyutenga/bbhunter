"""Model registry — lists available models across all connected providers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai.connector_manager import ConnectorManager


def list_all_models(manager: ConnectorManager) -> list[dict]:
    """
    Gather models from every *connected* provider.
    Returns a flat list of dicts:
      [{"provider": "claude", "id": "claude-3-5-haiku-latest", "name": "..."}, ...]
    """
    results: list[dict] = []
    for name, provider in manager.providers.items():
        if provider.is_connected():
            for m in provider.list_models():
                results.append({**m, "provider": name})
    return results


def print_models_table(manager: ConnectorManager) -> None:
    """Pretty-print the /models table to stdout."""
    from modules.utils import BOLD, RST, G, R, DIM, Y

    active_provider = manager.active_provider_name
    active_model = manager.active_model

    print()
    print(f"{BOLD}  AVAILABLE MODELS{RST}")
    print(f"  {'─' * 50}")

    idx = 1
    for name, provider in manager.providers.items():
        nice = _nice_name(name)
        if provider.is_connected():
            models = provider.list_models()
            print(f"\n  {G}■{RST} {BOLD}{nice}{RST}  {DIM}(connected){RST}")
            for m in models:
                mid = m["id"]
                mname = m.get("name", mid)
                marker = ""
                if name == active_provider and mid == active_model:
                    marker = f"  {Y}◀ active{RST}"
                elif mid == _recommend(name):
                    marker = f"  {DIM}(recommended){RST}"
                print(f"    {DIM}{idx}.{RST} {mid:<28s} {mname}{marker}")
                idx += 1
        else:
            print(f"\n  {R}■{RST} {BOLD}{nice}{RST}  {DIM}(not connected — /connect {name}){RST}")

    print(f"\n  {'─' * 50}")
    print(f"  {DIM}Switch:{RST} /use <provider> <model>")
    print()


def _recommend(provider_name: str) -> str:
    """Return the recommended model id per provider."""
    return {
        "github_copilot": "gpt-4o",
        "claude": "claude-3-5-haiku-latest",
        "openai": "gpt-4o",
        "ollama": "llama3",
    }.get(provider_name, "")


def _nice_name(name: str) -> str:
    return {
        "github_copilot": "GitHub Copilot",
        "claude": "Claude",
        "openai": "OpenAI",
        "ollama": "Ollama (local)",
    }.get(name, name)
