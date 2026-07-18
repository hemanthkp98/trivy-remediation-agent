"""
Google Gemini provider.

Uses the ``google-genai`` Python SDK.
Requires the ``GEMINI_API_KEY`` environment variable to be set.

Supported models (as of 2025):
  - gemini-2.5-pro       (default — most capable, with thinking)
  - gemini-2.5-flash     (faster, cost-efficient)
  - gemini-2.0-flash
"""
from __future__ import annotations

import json
import os

from .base import BaseLLMProvider

DEFAULT_MODEL = "gemini-2.5-flash"


class GeminiProvider(BaseLLMProvider):
    """LLM provider backed by Google Gemini via the google-genai SDK."""

    def __init__(self, config: dict) -> None:
        try:
            from google import genai
            from google.genai import types as genai_types
        except ImportError as exc:
            raise ImportError(
                "The 'google-genai' package is required for the Gemini provider. "
                "Install it with: pip install google-genai"
            ) from exc

        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            raise EnvironmentError(
                "GEMINI_API_KEY environment variable is not set. "
                "Get a key at https://aistudio.google.com/apikey"
            )

        llm_cfg = config.get("llm", {})
        model = llm_cfg.get("model", DEFAULT_MODEL)
        # The google-genai SDK requires the "models/" prefix
        self._model = model if model.startswith("models/") else f"models/{model}"
        self._client = genai.Client(api_key=api_key)
        self._genai_types = genai_types

    # ------------------------------------------------------------------
    # BaseLLMProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str:
        return self._model

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int) -> str:
        """
        Call the Gemini GenerateContent API requesting JSON output and
        return the raw text of the response.
        """
        response = self._client.models.generate_content(
            model=self._model,
            contents=user_prompt,
            config=self._genai_types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",
                max_output_tokens=max_tokens,
                thinking_config=self._genai_types.ThinkingConfig(
                    thinking_budget=5000,
                ),
            ),
        )

        text = response.text
        if not text:
            raise RuntimeError("Gemini returned an empty response.")
        return text
