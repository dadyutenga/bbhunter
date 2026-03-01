"""LLM tool-calling loop for BBHunter agent mode."""

import json
from typing import TYPE_CHECKING

from agent.context import build_system_prompt
from memory.db import load_history, save_message
from tools.executor import execute_tool
from tools.registry import TOOLS

if TYPE_CHECKING:
    from ai.connector_manager import ConnectorManager

# Module-level reference to the ConnectorManager singleton.
# Set by bbhunter.py at startup via `set_connector_manager()`.
_connector_manager: "ConnectorManager | None" = None


def set_connector_manager(manager: "ConnectorManager") -> None:
    """Inject the ConnectorManager so the agent loop can call any provider."""
    global _connector_manager
    _connector_manager = manager


def _get_manager() -> "ConnectorManager":
    if _connector_manager is None:
        raise RuntimeError(
            "No ConnectorManager configured. "
            "Run BBHunter with provider selection first."
        )
    return _connector_manager


def _extract_text(content_blocks):
    if isinstance(content_blocks, str):
        return content_blocks
    text_parts = []
    if isinstance(content_blocks, list):
        for block in content_blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))
    return "".join(text_parts).strip()


def run_agent(user_message: str, session_id: str, verbose: bool = True) -> str:
    """
    Run the BBHunter tool-use loop.
    Iterates until the model returns a final text response.
    Uses whichever AI provider is currently active via the ConnectorManager.
    """
    manager = _get_manager()

    history = load_history(session_id)
    history.append({"role": "user", "content": user_message})
    save_message(session_id, "user", user_message)

    max_iterations = 20
    iteration = 0

    while iteration < max_iterations:
        iteration += 1
        response = manager.chat(
            system=build_system_prompt(),
            messages=history,
            tools=TOOLS,
        )
        content = response.get("content", [])
        stop_reason = response.get("stop_reason")

        if stop_reason == "tool_use":
            history.append({"role": "assistant", "content": content})
            tool_results = []

            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue

                tool_name = block.get("name", "")
                tool_input = block.get("input", {}) or {}
                tool_use_id = block.get("id", "")

                if verbose:
                    print(f"[tool] {tool_name} {json.dumps(tool_input)}")

                result = execute_tool(tool_name, tool_input)

                if verbose:
                    preview = result[:240] + "..." if len(result) > 240 else result
                    print(f"[tool-result] {preview}")

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": result,
                    }
                )

            if not tool_results:
                final = _extract_text(content) or "No response content returned."
                save_message(session_id, "assistant", final)
                return final

            history.append({"role": "user", "content": tool_results})
            continue

        final = _extract_text(content) or "No response content returned."
        save_message(session_id, "assistant", final)
        return final

    return "Max iterations reached. Please try a more specific request."

