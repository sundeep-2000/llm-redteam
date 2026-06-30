from __future__ import annotations

import json
import urllib.request
import urllib.error
from targets.base import BaseLLMTarget, LLMResponse, TargetConfig


class OllamaTarget(BaseLLMTarget):
    """
    Target adapter for Ollama (local models: llama3, mistral, phi3, etc.)
    Requires Ollama running at http://localhost:11434 by default.
    """

    def __init__(self, config: TargetConfig, base_url: str = "http://localhost:11434"):
        super().__init__(config)
        self.base_url = base_url.rstrip("/")

    def _call_api(self, prompt: str) -> LLMResponse:
        url = f"{self.base_url}/api/chat"

        payload = json.dumps({
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": self.config.system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.base_url}. "
                f"Is it running? Error: {e}"
            )

        message = data.get("message", {})
        content = message.get("content", "")

        return LLMResponse(
            content=content,
            model=data.get("model", self.config.model),
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
            finish_reason=data.get("done_reason", "stop"),
            raw=data,
        )

    def list_models(self) -> list[str]:
        """List available local Ollama models."""
        url = f"{self.base_url}/api/tags"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []
