"""
Anthropic Claude provider.

Uses the Anthropic Python SDK with extended thinking enabled (adaptive mode).
Requires the ``ANTHROPIC_API_KEY`` environment variable to be set.

Supported models (as of 2025):
  - claude-opus-4-6      (default — most capable)
  - claude-sonnet-4-6
  - claude-haiku-3-5
"""
from __future__ import annotations

import anthropic

from .base import BaseLLMProvider

DEFAULT_MODEL = "claude-opus-4-6"


class ClaudeProvider(BaseLLMProvider):
    """LLM provider backed by Anthropic Claude."""

    def __init__(self, config: dict) -> None:
        llm_cfg = config.get("llm", {})
        self._model = llm_cfg.get("model", DEFAULT_MODEL)
        # anthropic.Anthropic() automatically reads ANTHROPIC_API_KEY from env
        self._client = anthropic.Anthropic()

    # ------------------------------------------------------------------
    # BaseLLMProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "claude"

    @property
    def model_name(self) -> str:
        return self._model

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int) -> str:
        """
        Call the Claude Messages API with adaptive thinking and return
        the plain-text content of the first text block.
        """
        response = self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            thinking={"type": "enabled", "budget_tokens": 5000},
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        # Extract text blocks (skip thinking blocks)
        text_parts = [
            block.text
            for block in response.content
            if block.type == "text"
        ]
        if not text_parts:
            raise RuntimeError("Claude returned no text content in its response.")
        return "\n".join(text_parts)
