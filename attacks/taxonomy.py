from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AttackCategory(str, Enum):
    # OWASP LLM Top 10 (2025)
    PROMPT_INJECTION = "LLM01_prompt_injection"
    INSECURE_OUTPUT = "LLM02_insecure_output_handling"
    TRAINING_DATA_POISONING = "LLM03_training_data_poisoning"
    MODEL_DOS = "LLM04_model_denial_of_service"
    SUPPLY_CHAIN = "LLM05_supply_chain_vulnerabilities"
    SENSITIVE_INFO_DISCLOSURE = "LLM06_sensitive_information_disclosure"
    INSECURE_PLUGIN = "LLM07_insecure_plugin_design"
    EXCESSIVE_AGENCY = "LLM08_excessive_agency"
    OVERRELIANCE = "LLM09_overreliance"
    MODEL_THEFT = "LLM10_model_theft"
    # Extended
    JAILBREAK = "EXT01_jailbreak"
    DATA_EXFILTRATION = "EXT02_data_exfiltration"
    ADVERSARIAL_ROLEPLAY = "EXT03_adversarial_roleplay"


@dataclass
class AttackMeta:
    category: AttackCategory
    owasp_id: str
    name: str
    description: str
    max_severity: Severity
    mitre_atlas: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)


# Full taxonomy registry
TAXONOMY: dict[AttackCategory, AttackMeta] = {
    AttackCategory.PROMPT_INJECTION: AttackMeta(
        category=AttackCategory.PROMPT_INJECTION,
        owasp_id="LLM01",
        name="Prompt Injection",
        description=(
            "Attacker crafts malicious inputs that override system prompt instructions, "
            "hijack the model's behavior, or exfiltrate context. Includes direct injection "
            "via user input and indirect injection via external data sources."
        ),
        max_severity=Severity.CRITICAL,
        mitre_atlas=["AML.T0051", "AML.T0054"],
        cwe=["CWE-77", "CWE-94"],
    ),
    AttackCategory.INSECURE_OUTPUT: AttackMeta(
        category=AttackCategory.INSECURE_OUTPUT,
        owasp_id="LLM02",
        name="Insecure Output Handling",
        description=(
            "LLM output is passed downstream without sanitization, enabling XSS, SSRF, "
            "CSRF, command injection, or privilege escalation in consuming systems."
        ),
        max_severity=Severity.HIGH,
        mitre_atlas=["AML.T0048"],
        cwe=["CWE-79", "CWE-116"],
    ),
    AttackCategory.MODEL_DOS: AttackMeta(
        category=AttackCategory.MODEL_DOS,
        owasp_id="LLM04",
        name="Model Denial of Service",
        description=(
            "Crafted inputs that cause excessive resource consumption — infinite loops, "
            "max-token responses, recursive context expansion, or compute exhaustion."
        ),
        max_severity=Severity.HIGH,
        mitre_atlas=["AML.T0029"],
        cwe=["CWE-400", "CWE-770"],
    ),
    AttackCategory.SENSITIVE_INFO_DISCLOSURE: AttackMeta(
        category=AttackCategory.SENSITIVE_INFO_DISCLOSURE,
        owasp_id="LLM06",
        name="Sensitive Information Disclosure",
        description=(
            "Model reveals system prompts, training data, PII, credentials, internal "
            "architecture details, or other confidential information through clever prompting."
        ),
        max_severity=Severity.CRITICAL,
        mitre_atlas=["AML.T0044", "AML.T0025"],
        cwe=["CWE-200", "CWE-312"],
    ),
    AttackCategory.EXCESSIVE_AGENCY: AttackMeta(
        category=AttackCategory.EXCESSIVE_AGENCY,
        owasp_id="LLM08",
        name="Excessive Agency",
        description=(
            "Model is manipulated into taking unauthorized actions via connected tools, "
            "APIs, or plugins beyond its intended scope. Critical for agentic systems."
        ),
        max_severity=Severity.CRITICAL,
        mitre_atlas=["AML.T0051"],
        cwe=["CWE-269", "CWE-732"],
    ),
    AttackCategory.JAILBREAK: AttackMeta(
        category=AttackCategory.JAILBREAK,
        owasp_id="EXT01",
        name="Jailbreak",
        description=(
            "Bypasses model safety training through roleplay, persona switching, "
            "hypothetical framing, base64 encoding, token smuggling, or other "
            "safety-alignment circumvention techniques."
        ),
        max_severity=Severity.CRITICAL,
        mitre_atlas=["AML.T0054", "AML.T0043"],
        cwe=["CWE-284"],
    ),
    AttackCategory.DATA_EXFILTRATION: AttackMeta(
        category=AttackCategory.DATA_EXFILTRATION,
        owasp_id="EXT02",
        name="Data Exfiltration",
        description=(
            "Tricks model into revealing sensitive context, conversation history, "
            "other users' data, or system configuration through indirect extraction."
        ),
        max_severity=Severity.HIGH,
        mitre_atlas=["AML.T0025", "AML.T0044"],
        cwe=["CWE-200", "CWE-359"],
    ),
    AttackCategory.ADVERSARIAL_ROLEPLAY: AttackMeta(
        category=AttackCategory.ADVERSARIAL_ROLEPLAY,
        owasp_id="EXT03",
        name="Adversarial Roleplay",
        description=(
            "Uses fictional framing, character personas, or creative writing contexts "
            "to extract harmful content, bypass guardrails, or manipulate model behavior."
        ),
        max_severity=Severity.HIGH,
        mitre_atlas=["AML.T0043"],
        cwe=["CWE-284"],
    ),
}


def get_all_categories() -> list[AttackCategory]:
    return list(TAXONOMY.keys())


def get_meta(category: AttackCategory) -> AttackMeta:
    return TAXONOMY[category]


def get_high_severity_categories() -> list[AttackCategory]:
    return [
        cat for cat, meta in TAXONOMY.items()
        if meta.max_severity in (Severity.CRITICAL, Severity.HIGH)
    ]
