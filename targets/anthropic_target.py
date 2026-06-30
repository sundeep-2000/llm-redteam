from __future__ import annotations

import os
from targets.base import BaseLLMTarget, LLMResponse, TargetConfig


class AnthropicTarget(BaseLLMTarget):
    """Target adapter for Anthropic Claude models."""

    SUPPORTED_MODELS = [
        "claude-opus-4-6",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
        "claude-3-5-sonnet-20241022",
        "claude-3-haiku-20240307",
    ]

    def __init__(self, config: TargetConfig, api_key: str | None = None):
        super().__init__(config)
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY env var "
                "or pass api_key= to AnthropicTarget()."
            )
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError:
                raise ImportError("Run: pip install anthropic")
            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def _call_api(self, prompt: str) -> LLMResponse:
        client = self._get_client()

        response = client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            system=self.config.system_prompt,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.config.temperature,
        )

        content = ""
        for block in response.content:
            if hasattr(block, "text"):
                content += block.text

        usage = response.usage

        return LLMResponse(
            content=content,
            model=response.model,
            prompt_tokens=getattr(usage, "input_tokens", 0),
            completion_tokens=getattr(usage, "output_tokens", 0),
            finish_reason=response.stop_reason or "stop",
            raw={"id": response.id, "type": response.type},
        )
