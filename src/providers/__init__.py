"""
Provider abstraction package.

Import the factory function to get the right LLM provider:

    from .providers import get_provider
    provider = get_provider(config)
"""
from .base import BaseLLMProvider
from .claude_provider import ClaudeProvider
from .gemini_provider import GeminiProvider


def get_provider(config: dict) -> BaseLLMProvider:
    """
    Instantiate and return the LLM provider specified in config.

    Reads ``config["llm"]["provider"]`` (default: ``"claude"``).
    Supported values: ``"claude"``, ``"gemini"``.
    """
    provider_name = config.get("llm", {}).get("provider", "claude").lower()

    if provider_name == "claude":
        return ClaudeProvider(config)
    elif provider_name == "gemini":
        return GeminiProvider(config)
    else:
        raise ValueError(
            f"Unknown LLM provider: '{provider_name}'. "
            "Supported providers: 'claude', 'gemini'."
        )


__all__ = ["BaseLLMProvider", "ClaudeProvider", "GeminiProvider", "get_provider"]
