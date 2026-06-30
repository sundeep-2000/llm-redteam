from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from evaluators.severity import AttackFinding
from attacks.taxonomy import Severity


def generate_json_report(
    findings: list[AttackFinding],
    target_name: str,
    output_path: Path,
) -> Path:
    vuln = [f for f in findings if f.vulnerable]
    sev_counts = {s.value: 0 for s in Severity}
    for f in vuln:
        sev_counts[f.severity.level.value] += 1

    report = {
        "meta": {
            "tool": "LLM Security Evaluation Framework",
            "version": "1.0.0",
            "target": target_name,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_attacks": len(findings),
            "vulnerable_count": len(vuln),
        },
        "summary": {
            "overall_risk": _overall_risk(sev_counts),
            "severity_counts": sev_counts,
            "categories_tested": list({f.payload.category.value for f in findings}),
        },
        "findings": [f.to_dict() for f in findings],
    }

    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output_path


def _overall_risk(sev_counts: dict) -> str:
    if sev_counts.get("critical", 0) > 0:
        return "CRITICAL"
    elif sev_counts.get("high", 0) > 0:
        return "HIGH"
    elif sev_counts.get("medium", 0) > 0:
        return "MEDIUM"
    elif sev_counts.get("low", 0) > 0:
        return "LOW"
    return "NONE"
