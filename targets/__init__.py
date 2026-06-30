from targets.base import BaseLLMTarget, LLMResponse, TargetConfig
from targets.mock_target import MockTarget
from targets.openai_target import OpenAITarget
from targets.anthropic_target import AnthropicTarget
from targets.ollama_target import OllamaTarget


def create_target(provider: str, model: str, **kwargs) -> BaseLLMTarget:
    """
    Factory function — create a target by provider name.

    Usage:
        target = create_target("openai", "gpt-4o")
        target = create_target("anthropic", "claude-sonnet-4-6")
        target = create_target("ollama", "llama3")
        target = create_target("mock", "mock-llm-v1")
    """
    config = TargetConfig(
        model=model,
        system_prompt=kwargs.pop("system_prompt", "You are a helpful assistant."),
        temperature=kwargs.pop("temperature", 0.7),
        max_tokens=kwargs.pop("max_tokens", 1024),
        timeout=kwargs.pop("timeout", 30),
    )

    provider = provider.lower()
    if provider == "openai":
        return OpenAITarget(config, **kwargs)
    elif provider == "anthropic":
        return AnthropicTarget(config, **kwargs)
    elif provider == "ollama":
        return OllamaTarget(config, **kwargs)
    elif provider == "mock":
        return MockTarget(config, **kwargs)
    else:
        raise ValueError(
            f"Unknown provider: {provider!r}. "
            f"Choose from: openai, anthropic, ollama, mock"
        )


__all__ = [
    "BaseLLMTarget", "LLMResponse", "TargetConfig",
    "MockTarget", "OpenAITarget", "AnthropicTarget", "OllamaTarget",
    "create_target",
]
