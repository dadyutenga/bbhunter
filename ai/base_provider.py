"""Abstract base class for all AI providers in BBHunter."""

from abc import ABC, abstractmethod
from typing import Any


class BaseProvider(ABC):
    """
    Every AI provider must subclass this and implement all abstract methods.
    The connector_manager uses these methods to authenticate, list models,
    and send chat completions.
    """

    name: str = "base"
    requires_auth: bool = True

    # ── authentication ────────────────────────────────────────────
    @abstractmethod
    def authenticate(self, **kwargs) -> bool:
        """
        Handle login / token setup for this provider.
        Return True on success.
        """

    @abstractmethod
    def is_connected(self) -> bool:
        """Return True if the provider is authenticated and ready."""

    # ── model discovery ───────────────────────────────────────────
    @abstractmethod
    def list_models(self) -> list[dict]:
        """
        Return a list of dicts, each with at least:
          { "id": "model-id", "name": "Human Name" }
        """

    # ── chat / completion ─────────────────────────────────────────
    @abstractmethod
    def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        system: str | None = None,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        """
        Send *messages* (OpenAI-style list) to the provider.
        Return a normalised dict:
          {
            "content": [{"type": "text", "text": "..."}],
            "stop_reason": "end_turn" | "tool_use",
          }
        If *tools* are supplied the provider must support tool-use / function-calling.
        """

    # ── helpers ───────────────────────────────────────────────────
    def __repr__(self) -> str:
        status = "connected" if self.is_connected() else "disconnected"
        return f"<{self.__class__.__name__} [{status}]>"
