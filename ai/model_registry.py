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


def _build_numbered_list(manager: ConnectorManager) -> list[dict]:
    """Build a flat numbered list of all models across connected providers."""
    items: list[dict] = []
    for name, provider in manager.providers.items():
        if provider.is_connected():
            for m in provider.list_models():
                items.append({**m, "provider": name})
    return items


def print_models_table(manager: ConnectorManager) -> None:
    """Pretty-print the /models table to stdout."""
    from modules.utils import BOLD, RST, G, R, DIM, Y, C

    active_provider = manager.active_provider_name
    active_model = manager.active_model

    # Check copilot tier
    copilot = manager.providers.get("github_copilot")
    copilot_basic = copilot and hasattr(copilot, "_tier") and copilot._tier == 1

    print()
    print(f"{BOLD}  AVAILABLE MODELS{RST}")
    print(f"  {'─' * 60}")

    idx = 1
    for name, provider in manager.providers.items():
        nice = _nice_name(name)
        if provider.is_connected():
            models = provider.list_models()
            tier_info = ""
            if name == "github_copilot" and hasattr(provider, "_tier"):
                if provider._tier == 2:
                    tier_info = f"  {G}full access{RST}"
                else:
                    tier_info = f"  {Y}GPT only{RST}"
            print(f"\n  {G}■{RST} {BOLD}{nice}{RST}  {DIM}(connected){RST}{tier_info}")

            # Group by vendor
            cur_vendor = ""
            for m in models:
                mid = m["id"]
                mname = m.get("name", mid)
                vendor = m.get("vendor", "")
                if vendor and vendor != cur_vendor:
                    cur_vendor = vendor
                    print(f"    {DIM}── {vendor} ──{RST}")

                marker = ""
                if name == active_provider and mid == active_model:
                    marker = f"  {C}◀ active{RST}"
                print(f"    {DIM}{idx:>2}.{RST} {mid:<32s} {mname}{marker}")
                idx += 1
        else:
            print(f"\n  {R}■{RST} {BOLD}{nice}{RST}  {DIM}(not connected — /connect {name}){RST}")

    print(f"\n  {'─' * 60}")
    if copilot_basic:
        print(f"  {Y}Unlock Claude & Gemini: /copilot auth{RST}")
    print()


def interactive_model_select(manager: ConnectorManager) -> None:
    """Show models and let user pick by number."""
    from modules.utils import RST, G, DIM

    print_models_table(manager)
    items = _build_numbered_list(manager)
    if not items:
        print("[!] No models available. Connect a provider first.")
        return

    try:
        choice = input(f"  Select model # (Enter to keep current): ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if not choice:
        return

    try:
        num = int(choice)
        if 1 <= num <= len(items):
            picked = items[num - 1]
            manager.set_active(picked["provider"], picked["id"])
        else:
            print(f"[!] Invalid number. Choose 1-{len(items)}.")
    except ValueError:
        # Maybe they typed a model name directly
        for it in items:
            if choice == it["id"]:
                manager.set_active(it["provider"], it["id"])
                return
        print(f"[!] Unknown selection: {choice}. Enter a number or model ID.")


def _nice_name(name: str) -> str:
    return {
        "github_copilot": "GitHub Copilot",
        "claude": "Claude",
        "openai": "OpenAI",
        "ollama": "Ollama (local)",
    }.get(name, name)
