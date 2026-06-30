from __future__ import annotations

import os
from targets.base import BaseLLMTarget, LLMResponse, TargetConfig


class OpenAITarget(BaseLLMTarget):
    """Target adapter for OpenAI models (GPT-4o, GPT-4, GPT-3.5-turbo)."""

    SUPPORTED_MODELS = [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "gpt-4",
        "gpt-3.5-turbo",
    ]

    def __init__(self, config: TargetConfig, api_key: str | None = None):
        super().__init__(config)
        self._api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self._api_key:
            raise ValueError(
                "OpenAI API key required. Set OPENAI_API_KEY env var "
                "or pass api_key= to OpenAITarget()."
            )
        self._client = None  # lazy init

    def _get_client(self):
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError:
                raise ImportError("Run: pip install openai")
            self._client = OpenAI(api_key=self._api_key)
        return self._client

    def _call_api(self, prompt: str) -> LLMResponse:
        client = self._get_client()

        response = client.chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "system", "content": self.config.system_prompt},
                {"role": "user", "content": prompt},
            ],
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            timeout=self.config.timeout,
        )

        choice = response.choices[0]
        usage = response.usage or {}

        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            prompt_tokens=getattr(usage, "prompt_tokens", 0),
            completion_tokens=getattr(usage, "completion_tokens", 0),
            finish_reason=choice.finish_reason or "stop",
            raw=response.model_dump() if hasattr(response, "model_dump") else {},
        )
