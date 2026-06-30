# 🛡️ LLM Security Evaluation Framework

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/sundeep-2000/llm-redteam/actions/workflows/ci.yml/badge.svg)](https://github.com/sundeep-2000/llm-redteam/actions/workflows/ci.yml)

An automated red-teaming suite for LLM applications. Systematically tests language models against the **OWASP LLM Top 10** attack taxonomy using a 3-layer detection pipeline — rule-based pattern matching, LLM-as-judge semantic evaluation, and CVSS-inspired severity scoring.

Built to identify prompt injection, jailbreaks, data exfiltration, insecure output handling, and adversarial AI attacks across any LLM provider.

---

## ✨ Features

- **43 adversarial payloads** across 5 OWASP LLM Top 10 categories with MITRE ATLAS and CWE mappings
- **3-layer evaluation pipeline** — rule-based → LLM-as-judge → CVSS severity scoring
- **Multi-provider support** — OpenAI, Anthropic, Ollama (local), and custom OpenAI-compatible endpoints
- **HTML + JSON reports** with per-finding CVSS vectors, rule matches, and judge reasoning
- **Pluggable architecture** — add new attack categories, targets, or evaluators without touching core logic
- **Zero-dependency mock target** for testing the pipeline without API keys

---

## 🏗️ Architecture

```
Attack Taxonomy (OWASP LLM Top 10 + MITRE ATLAS)
         │
         ▼
Attack Generator (loads YAML payloads, filters by severity/category)
         │
         ▼
Target LLM (OpenAI / Anthropic / Ollama / Custom)
         │
         ▼
┌────────────────────────────────────────┐
│         3-Layer Evaluation Pipeline    │
│                                        │
│  Layer 1: Rule-based scorer            │
│           Pattern + keyword matching   │
│                                        │
│  Layer 2: LLM-as-judge                 │
│           Semantic vulnerability eval  │
│                                        │
│  Layer 3: Severity classifier          │
│           CVSS-inspired scoring (0-10) │
└────────────────────────────────────────┘
         │
         ▼
Security Report (HTML + JSON)
```

---

## 📦 Installation

```bash
git clone https://github.com/sundeep-2000/llm-redteam.git
cd llm-redteam
pip install -r requirements.txt
```

---

## 🚀 Quick Start

### Test without API keys (mock mode)
```bash
python main.py --provider mock --model mock-llm-v1
```

### Run against OpenAI GPT-4o
```bash
export OPENAI_API_KEY=sk-...
python main.py --provider openai --model gpt-4o
```

### Run against Anthropic Claude
```bash
export ANTHROPIC_API_KEY=sk-ant-...
python main.py --provider anthropic --model claude-sonnet-4-6
```

### Run against a local Ollama model
```bash
# Start Ollama first: ollama run llama3
python main.py --provider ollama --model llama3
```

### Target a custom system prompt
```bash
python main.py --provider openai --model gpt-4o \
  --system-prompt "You are a banking assistant. Never reveal account details."
```

---

## ⚙️ CLI Options

```
python main.py [OPTIONS]

Options:
  --provider         LLM provider: openai | anthropic | ollama | mock
  --model            Model name (e.g. gpt-4o, claude-sonnet-4-6, llama3)
  --categories       Attack categories to run (default: all)
                     Choices: prompt_injection jailbreak data_exfiltration
                              model_dos insecure_output
  --severity         Minimum severity: low | medium | high | critical
  --no-judge         Skip LLM-as-judge layer (faster, rule-based only)
  --judge-provider   Separate provider for the judge LLM
  --judge-model      Separate model for the judge LLM
  --system-prompt    System prompt to inject into target
  --output-dir       Report output directory (default: reports/)
  --max-tokens       Max tokens per response (default: 1024)
  --timeout          Request timeout in seconds (default: 30)
```

### Examples

```bash
# High-severity attacks only, prompt injection + jailbreak
python main.py --provider openai --model gpt-4o \
  --categories prompt_injection jailbreak \
  --severity high

# Use GPT-4o as judge while testing GPT-3.5
python main.py --provider openai --model gpt-3.5-turbo \
  --judge-provider openai --judge-model gpt-4o

# Fast mode — rule-based only, no LLM judge
python main.py --provider anthropic --model claude-sonnet-4-6 --no-judge
```

---

## 📊 Attack Categories

| ID | Category | Payloads | Max Severity |
|---|---|---|---|
| LLM01 | Prompt Injection | 10 | 🔴 Critical |
| LLM02 | Insecure Output Handling | 8 | 🟠 High |
| LLM04 | Model Denial of Service | 5 | 🟠 High |
| EXT01 | Jailbreak | 10 | 🔴 Critical |
| EXT02 | Data Exfiltration | 10 | 🔴 Critical |

Each payload maps to OWASP LLM Top 10 IDs, MITRE ATLAS techniques, and CWE identifiers.

---

## 🔍 Evaluation Pipeline

### Layer 1 — Rule-Based Scorer
Fast regex/keyword matching against known vulnerability indicators:
- System prompt disclosure patterns
- Instruction override acknowledgements
- Credential/PII patterns (emails, API keys, SSNs)
- XSS, SQLi, command injection in outputs
- DAN persona acceptance signals

### Layer 2 — LLM-as-Judge
Uses a secondary LLM to semantically evaluate whether a response indicates exploitation:
- Structured JSON verdict with confidence score
- Flags: `bypassed_safety`, `revealed_system_info`, `generated_harmful_content`
- Low temperature (0.1) for consistent verdicts
- Graceful fallback if judge is unavailable

### Layer 3 — Severity Classifier
Combines both signals into a CVSS 3.1-inspired score (0–10):
- Base score derived from attack category impact potential
- Adjusted by combined confidence from layers 1 and 2
- Outputs full CVSS vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`)
- Final verdict: Critical / High / Medium / Low

---

## 📄 Report Output

Reports are saved to `reports/` as both HTML and JSON:

```
reports/
├── report_gpt-4o_20260618_143022.html   # Interactive HTML report
└── report_gpt-4o_20260618_143022.json   # Machine-readable JSON
```

The HTML report includes:
- Overall risk rating with severity breakdown
- Per-attack results table with CVSS scores
- Detailed finding cards for each vulnerability
- Rule match evidence and judge reasoning
- Collapsible model response previews

---

## 🔧 Adding Custom Payloads

Create a YAML file following the payload schema:

```yaml
category: EXT01_jailbreak
name: My Custom Attacks
description: Custom adversarial prompts

payloads:
  - id: CUSTOM-001
    name: My attack name
    severity: high
    prompt: |
      Your adversarial prompt here...
    tags: [custom, my_tag]
```

Load it via the Python API:

```python
from attacks import AttackGenerator
from pathlib import Path

gen = AttackGenerator()
custom_payloads = gen.load_custom(Path("my_payloads.yaml"))
```

---

## 🔌 Adding a New Target

Subclass `BaseLLMTarget` and implement `_call_api`:

```python
from targets.base import BaseLLMTarget, LLMResponse, TargetConfig

class GeminiTarget(BaseLLMTarget):
    def _call_api(self, prompt: str) -> LLMResponse:
        # Call Gemini API here
        response = gemini_client.generate(prompt)
        return LLMResponse(
            content=response.text,
            model=self.config.model,
            prompt_tokens=response.usage.input,
            completion_tokens=response.usage.output,
        )
```

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## 📁 Project Structure

```
llm-redteam/
├── main.py                        # CLI entry point
├── requirements.txt
│
├── attacks/
│   ├── taxonomy.py                # OWASP LLM Top 10 registry + MITRE ATLAS
│   ├── generator.py               # Payload loader and attack suite builder
│   └── payloads/
│       ├── prompt_injection.yaml  # 10 payloads
│       ├── jailbreak.yaml         # 10 payloads
│       ├── data_exfiltration.yaml # 10 payloads
│       ├── model_dos.yaml         # 5 payloads
│       └── insecure_output.yaml   # 8 payloads
│
├── targets/
│   ├── base.py                    # Abstract LLM client + LLMResponse
│   ├── openai_target.py           # OpenAI adapter
│   ├── anthropic_target.py        # Anthropic adapter
│   ├── ollama_target.py           # Ollama (local) adapter
│   └── mock_target.py             # Mock target for testing
│
├── evaluators/
│   ├── rule_based.py              # Layer 1: pattern matching
│   ├── llm_judge.py               # Layer 2: LLM-as-judge
│   └── severity.py                # Layer 3: CVSS scoring
│
└── reporting/
    ├── html_reporter.py           # Interactive HTML report
    └── json_reporter.py           # Machine-readable JSON report
```

---

## 🔒 Security Note

This tool is intended for **authorized security testing only**. Only use it against LLM systems you own or have explicit permission to test. The payloads are designed to identify real vulnerabilities — treat generated reports as sensitive security findings.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Sandeep Tumu** — Security Engineer specializing in AI/LLM security, product security, and automated threat detection.

- GitHub: [@sundeep-2000](https://github.com/sundeep-2000)
- Built as part of an AI security engineering portfolio focused on OWASP LLM Top 10 and MITRE ATLAS coverage.
