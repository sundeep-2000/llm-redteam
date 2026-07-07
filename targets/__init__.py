from targets.base import BaseLLMTarget, LLMResponse, TargetConfig
from targets.mock_target import MockTarget, MockJudge
from targets.openai_target import OpenAITarget
from targets.anthropic_target import AnthropicTarget
from targets.ollama_target import OllamaTarget


def create_target(provider: str, model: str, *, judge: bool = False, **kwargs) -> BaseLLMTarget:
    """
    Factory function — create a target by provider name.

    Pass judge=True when the target will be used as the LLM-as-judge rather
    than the attack target. Only affects the mock provider, which uses a
    separate judge-aware mock (MockJudge) so `--provider mock` exercises real
    verdict parsing instead of always hitting the fallback path.

    Usage:
        target = create_target("openai", "gpt-4o")
        target = create_target("anthropic", "claude-sonnet-4-6")
        target = create_target("ollama", "llama3")
        target = create_target("mock", "mock-llm-v1")
        judge_target = create_target("mock", "mock-judge-v1", judge=True)
    """
    provider = provider.lower()

    if provider == "mock" and judge:
        return MockJudge(TargetConfig(model=model))

    config = TargetConfig(
        model=model,
        system_prompt=kwargs.pop("system_prompt", "You are a helpful assistant."),
        temperature=kwargs.pop("temperature", 0.7),
        max_tokens=kwargs.pop("max_tokens", 1024),
        timeout=kwargs.pop("timeout", 30),
    )

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
    "MockTarget", "MockJudge", "OpenAITarget", "AnthropicTarget", "OllamaTarget",
    "create_target",
]
