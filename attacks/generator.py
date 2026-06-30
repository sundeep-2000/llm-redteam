from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from attacks.taxonomy import AttackCategory, Severity, get_meta


PAYLOAD_DIR = Path(__file__).parent / "payloads"

# Map categories to payload files
CATEGORY_FILES: dict[AttackCategory, str] = {
    AttackCategory.PROMPT_INJECTION: "prompt_injection.yaml",
    AttackCategory.JAILBREAK: "jailbreak.yaml",
    AttackCategory.DATA_EXFILTRATION: "data_exfiltration.yaml",
    AttackCategory.MODEL_DOS: "model_dos.yaml",
    AttackCategory.INSECURE_OUTPUT: "insecure_output.yaml",
}


@dataclass
class AttackPayload:
    id: str
    name: str
    category: AttackCategory
    severity: Severity
    prompt: str
    tags: list[str] = field(default_factory=list)

    @property
    def owasp_id(self) -> str:
        return get_meta(self.category).owasp_id

    @property
    def display_name(self) -> str:
        return f"[{self.owasp_id}] {self.name} ({self.id})"


@dataclass
class AttackSuite:
    """Collection of attack payloads to run against a target."""
    payloads: list[AttackPayload] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.payloads)

    def __iter__(self) -> Iterator[AttackPayload]:
        return iter(self.payloads)

    def filter_by_severity(self, min_severity: Severity) -> "AttackSuite":
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        min_idx = order.index(min_severity)
        filtered = [p for p in self.payloads if order.index(p.severity) >= min_idx]
        return AttackSuite(payloads=filtered)

    def filter_by_category(self, categories: list[AttackCategory]) -> "AttackSuite":
        filtered = [p for p in self.payloads if p.category in categories]
        return AttackSuite(payloads=filtered)

    def summary(self) -> dict:
        by_cat: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for p in self.payloads:
            by_cat[p.category.value] = by_cat.get(p.category.value, 0) + 1
            by_sev[p.severity.value] = by_sev.get(p.severity.value, 0) + 1
        return {
            "total": len(self.payloads),
            "by_category": by_cat,
            "by_severity": by_sev,
        }


class AttackGenerator:
    """Loads attack payloads from YAML files and builds attack suites."""

    def __init__(self, payload_dir: Path = PAYLOAD_DIR):
        self.payload_dir = payload_dir
        self._cache: dict[AttackCategory, list[AttackPayload]] = {}

    def load_category(self, category: AttackCategory) -> list[AttackPayload]:
        if category in self._cache:
            return self._cache[category]

        filename = CATEGORY_FILES.get(category)
        if not filename:
            return []

        filepath = self.payload_dir / filename
        if not filepath.exists():
            print(f"  [WARN] Payload file not found: {filepath}")
            return []

        with open(filepath) as f:
            data = yaml.safe_load(f)

        payloads = []
        for item in data.get("payloads", []):
            try:
                sev = Severity(item["severity"])
            except (KeyError, ValueError):
                sev = Severity.MEDIUM

            payloads.append(AttackPayload(
                id=item["id"],
                name=item["name"],
                category=category,
                severity=sev,
                prompt=item["prompt"].strip(),
                tags=item.get("tags", []),
            ))

        self._cache[category] = payloads
        return payloads

    def load_all(self) -> AttackSuite:
        """Load every available payload across all categories."""
        all_payloads: list[AttackPayload] = []
        for category in CATEGORY_FILES:
            loaded = self.load_category(category)
            all_payloads.extend(loaded)
            print(f"  Loaded {len(loaded):>3} payloads  [{category.value}]")
        return AttackSuite(payloads=all_payloads)

    def load_categories(self, categories: list[AttackCategory]) -> AttackSuite:
        """Load payloads for specific categories only."""
        all_payloads: list[AttackPayload] = []
        for category in categories:
            loaded = self.load_category(category)
            all_payloads.extend(loaded)
        return AttackSuite(payloads=all_payloads)

    def load_custom(self, yaml_path: Path) -> list[AttackPayload]:
        """Load user-supplied custom payload file."""
        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        category_str = data.get("category", "EXT01_jailbreak")
        try:
            category = AttackCategory(category_str)
        except ValueError:
            category = AttackCategory.JAILBREAK

        payloads = []
        for item in data.get("payloads", []):
            payloads.append(AttackPayload(
                id=item.get("id", "CUSTOM-001"),
                name=item.get("name", "Custom payload"),
                category=category,
                severity=Severity(item.get("severity", "medium")),
                prompt=item["prompt"].strip(),
                tags=item.get("tags", ["custom"]),
            ))
        return payloads
