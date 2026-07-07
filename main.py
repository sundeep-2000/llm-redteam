#!/usr/bin/env python3
"""
LLM Security Evaluation Framework
Automated red-teaming suite for LLM applications.

Usage:
    python main.py --provider mock --model mock-llm-v1
    python main.py --provider openai --model gpt-4o
    python main.py --provider anthropic --model claude-sonnet-4-6
    python main.py --provider ollama --model llama3
    python main.py --provider openai --model gpt-4o --categories prompt_injection jailbreak
    python main.py --provider openai --model gpt-4o --severity high
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Ensure UTF-8 output on Windows terminals (CP1252 can't encode box-drawing chars)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from attacks import AttackGenerator, AttackCategory, Severity
from targets import create_target
from evaluators import RuleBasedScorer, LLMJudge, SeverityClassifier
from reporting import generate_html_report, generate_json_report


CATEGORY_MAP = {
    "prompt_injection":  AttackCategory.PROMPT_INJECTION,
    "jailbreak":         AttackCategory.JAILBREAK,
    "data_exfiltration": AttackCategory.DATA_EXFILTRATION,
    "model_dos":         AttackCategory.MODEL_DOS,
    "insecure_output":   AttackCategory.INSECURE_OUTPUT,
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="LLM Security Evaluation Framework — Automated Red-Teaming Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--provider", default="mock",
                   choices=["openai", "anthropic", "ollama", "mock"],
                   help="LLM provider (default: mock)")
    p.add_argument("--model", default="mock-llm-v1",
                   help="Model name (default: mock-llm-v1)")
    p.add_argument("--categories", nargs="+", choices=list(CATEGORY_MAP.keys()),
                   help="Attack categories to run (default: all)")
    p.add_argument("--severity", default="low",
                   choices=["low", "medium", "high", "critical"],
                   help="Minimum severity to include (default: low)")
    p.add_argument("--no-judge", action="store_true",
                   help="Skip LLM-as-judge layer (faster, rule-based only)")
    p.add_argument("--judge-provider", default=None,
                   help="Provider for judge LLM (defaults to same as target)")
    p.add_argument("--judge-model", default=None,
                   help="Model for judge LLM (defaults to same as target)")
    p.add_argument("--system-prompt", default="You are a helpful assistant.",
                   help="System prompt to inject into target")
    p.add_argument("--output-dir", default="reports",
                   help="Output directory for reports (default: reports/)")
    p.add_argument("--max-tokens", type=int, default=1024)
    p.add_argument("--timeout", type=int, default=30)
    return p.parse_args()


def print_header():
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║    LLM Security Evaluation Framework  v1.0.0        ║")
    print("║    Automated Red-Teaming Suite                       ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()


def print_finding(finding, idx: int, total: int):
    icon = "🔴" if finding.vulnerable else "✅"
    sev = finding.severity
    print(f"  [{idx:>2}/{total}] {icon} {sev}  {finding.payload.display_name}")
    if finding.vulnerable and finding.judge_result:
        j = finding.judge_result
        print(f"           Judge: {'Vuln' if j.vulnerable else 'Safe'} "
              f"({j.confidence:.0%}) — {j.reasoning[:70]}")


def main():
    args = parse_args()
    print_header()

    # ── Build attack suite ───────────────────────────────────────────────────
    print("📦 Loading attack payloads...")
    gen = AttackGenerator()

    if args.categories:
        cats = [CATEGORY_MAP[c] for c in args.categories]
        suite = gen.load_categories(cats)
    else:
        suite = gen.load_all()

    min_sev = Severity(args.severity)
    suite = suite.filter_by_severity(min_sev)
    s = suite.summary()
    print(f"   {s['total']} payloads loaded "
          f"(min severity: {min_sev.value})")
    print()

    if len(suite) == 0:
        print("⚠️  No payloads match the selected severity filter. Exiting.")
        sys.exit(0)

    # ── Build target ─────────────────────────────────────────────────────────
    print(f"🎯 Connecting to target: {args.provider}/{args.model}")
    try:
        target = create_target(
            args.provider, args.model,
            system_prompt=args.system_prompt,
            max_tokens=args.max_tokens,
            timeout=args.timeout,
        )
    except Exception as e:
        print(f"   ❌ Failed to create target: {e}")
        sys.exit(1)

    if not target.health_check():
        print("   ❌ Health check failed — target unreachable")
        sys.exit(1)
    print(f"   ✅ Target healthy: {target.name}")
    print()

    # ── Build evaluators ─────────────────────────────────────────────────────
    rule_scorer = RuleBasedScorer()
    classifier = SeverityClassifier()
    judge = None

    if not args.no_judge:
        judge_provider = args.judge_provider or args.provider
        judge_model = args.judge_model or args.model
        print(f"⚖️  Setting up LLM judge: {judge_provider}/{judge_model}")
        try:
            judge_target = create_target(judge_provider, judge_model)
            judge = LLMJudge(judge_target)
            print("   ✅ Judge ready")
        except Exception as e:
            print(f"   ⚠️  Judge setup failed ({e}) — running rule-based only")
        print()

    # ── Run attacks ──────────────────────────────────────────────────────────
    print(f"🚀 Running {len(suite)} attacks...")
    print()

    findings = []
    start_time = time.perf_counter()

    for i, payload in enumerate(suite, 1):
        response = target.send(payload.prompt)
        rule_result = rule_scorer.score(response, payload.category)
        judge_result = judge.evaluate(payload.prompt, response, payload.category) if judge else None
        finding = classifier.classify(payload, response, rule_result, judge_result)
        findings.append(finding)
        print_finding(finding, i, len(suite))

    elapsed = time.perf_counter() - start_time

    # ── Summary ──────────────────────────────────────────────────────────────
    vuln = [f for f in findings if f.vulnerable]
    print()
    print("─" * 56)
    print(f"  Results: {len(vuln)}/{len(findings)} vulnerable  "
          f"({elapsed:.1f}s, {elapsed/len(findings):.1f}s/attack)")
    print()

    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    for sev in sev_order:
        count = sum(1 for f in vuln if f.severity.level == sev)
        if count:
            bar = "█" * min(count, 20)
            print(f"  {sev.value.upper():<10} {bar} {count}")
    print()

    # ── Write reports ────────────────────────────────────────────────────────
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe_model = args.model.replace("/", "_").replace(":", "_")
    base = output_dir / f"report_{safe_model}_{stamp}"

    html_path = generate_html_report(findings, target.name, base.with_suffix(".html"))
    json_path = generate_json_report(findings, target.name, base.with_suffix(".json"))

    print(f"📄 HTML report: {html_path}")
    print(f"📊 JSON report: {json_path}")
    print()

    # Exit codes: 0 = clean, 1 = setup/runtime failure, 2 = vulnerabilities found
    return 0 if not vuln else 2


if __name__ == "__main__":
    sys.exit(main())
