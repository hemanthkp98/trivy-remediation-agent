"""
Abstract base class for LLM providers.

All providers must implement the ``complete`` method, which takes a
system prompt and a user prompt and returns the raw text response.
The structured parsing (JSON → RemediationPlan) is handled centrally
in LLMAnalyzer so the prompt and schema logic stays in one place.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    """Common interface every LLM provider must implement."""

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int) -> str:
        """
        Send *system_prompt* and *user_prompt* to the model and return
        the raw text response.

        Args:
            system_prompt: The system / instruction prompt.
            user_prompt:   The user turn containing vulnerability data.
            max_tokens:    Maximum tokens to generate.

        Returns:
            The model's text response (may be raw JSON or prose).
        """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable name, e.g. ``'claude'`` or ``'gemini'``."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """The specific model identifier being used."""
