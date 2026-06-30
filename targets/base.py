from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LLMResponse:
    """Standardized response from any LLM target."""
    content: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    finish_reason: str = "stop"
    error: Optional[str] = None
    raw: dict = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.error is None

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def content_lower(self) -> str:
        return self.content.lower()

    def __repr__(self) -> str:
        preview = self.content[:80].replace("\n", " ")
        return (
            f"LLMResponse(model={self.model!r}, tokens={self.total_tokens}, "
            f"latency={self.latency_ms:.0f}ms, preview={preview!r})"
        )


@dataclass
class TargetConfig:
    """Configuration for an LLM target."""
    model: str
    system_prompt: str = "You are a helpful assistant."
    temperature: float = 0.7
    max_tokens: int = 1024
    timeout: int = 30
    extra: dict = field(default_factory=dict)


class BaseLLMTarget(ABC):
    """Abstract base for all LLM targets."""

    def __init__(self, config: TargetConfig):
        self.config = config

    @property
    def name(self) -> str:
        return f"{self.__class__.__name__}({self.config.model})"

    @abstractmethod
    def _call_api(self, prompt: str) -> LLMResponse:
        """Make the actual API call. Subclasses implement this."""
        ...

    def send(self, prompt: str, retries: int = 2) -> LLMResponse:
        """Send a prompt with retry logic and timing."""
        last_error: Optional[Exception] = None

        for attempt in range(retries + 1):
            try:
                start = time.perf_counter()
                response = self._call_api(prompt)
                elapsed = (time.perf_counter() - start) * 1000
                response.latency_ms = elapsed
                return response
            except Exception as exc:
                last_error = exc
                if attempt < retries:
                    wait = 2 ** attempt
                    print(f"    [RETRY {attempt+1}/{retries}] {exc} — waiting {wait}s")
                    time.sleep(wait)

        return LLMResponse(
            content="",
            model=self.config.model,
            error=str(last_error),
        )

    def health_check(self) -> bool:
        """Send a minimal probe to verify connectivity."""
        resp = self.send("Say 'OK' and nothing else.")
        return resp.success and len(resp.content) > 0
