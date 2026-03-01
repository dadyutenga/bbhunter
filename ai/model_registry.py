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
    from modules.utils import BOLD, RST, G, R, DIM

    print()
    print(f"{BOLD}┌──────────────────────────────────────────────────┐{RST}")
    print(f"{BOLD}│  AVAILABLE MODELS                                │{RST}")
    print(f"{BOLD}├──────────────────────┬───────────────────────────┤{RST}")
    print(f"{BOLD}│  Provider            │  Models                   │{RST}")
    print(f"{BOLD}├──────────────────────┼───────────────────────────┤{RST}")

    for name, provider in manager.providers.items():
        if provider.is_connected():
            models = provider.list_models()
            model_ids = ", ".join(m["id"] for m in models[:4])
            if len(models) > 4:
                model_ids += f" +{len(models)-4} more"
            status = f"{G}✅{RST}"
            nice_name = _nice_name(name)
            print(f"│  {nice_name:<16s} {status} │  {model_ids:<25s} │")
        else:
            status = f"{R}❌{RST}"
            nice_name = _nice_name(name)
            print(f"│  {nice_name:<16s} {status} │  {DIM}(connect first){RST}           │")

    print(f"└──────────────────────┴───────────────────────────┘")

    # Show active
    active = manager.get_active()
    if active:
        print(f"\n  {DIM}Active:{RST} {_nice_name(manager.active_provider_name)} / {manager.active_model}")
    print()


def _nice_name(name: str) -> str:
    return {
        "github_copilot": "GitHub Copilot",
        "claude": "Claude",
        "openai": "OpenAI",
        "ollama": "Ollama (local)",
    }.get(name, name)
