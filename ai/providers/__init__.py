"""AI provider sub-package — registers all available providers."""

from ai.providers.github_copilot import GitHubCopilotProvider
from ai.providers.claude import ClaudeProvider
from ai.providers.openai import OpenAIProvider
from ai.providers.ollama import OllamaProvider

__all__ = [
    "GitHubCopilotProvider",
    "ClaudeProvider",
    "OpenAIProvider",
    "OllamaProvider",
]
