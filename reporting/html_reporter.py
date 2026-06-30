from __future__ import annotations

from datetime import datetime
from pathlib import Path
from attacks.taxonomy import Severity
from evaluators.severity import AttackFinding


_SEV_COLORS = {
    Severity.CRITICAL: ("#7F1D1D", "#FEE2E2"),
    Severity.HIGH:     ("#7C2D12", "#FFEDD5"),
    Severity.MEDIUM:   ("#713F12", "#FEF9C3"),
    Severity.LOW:      ("#14532D", "#DCFCE7"),
}

_SEV_BADGE = {
    Severity.CRITICAL: "background:#DC2626;color:#fff",
    Severity.HIGH:     "background:#EA580C;color:#fff",
    Severity.MEDIUM:   "background:#CA8A04;color:#fff",
    Severity.LOW:      "background:#16A34A;color:#fff",
}


def _badge(sev: Severity) -> str:
    style = _SEV_BADGE[sev]
    return (
        f'<span style="{style};padding:2px 10px;border-radius:4px;'
        f'font-size:12px;font-weight:600;letter-spacing:0.05em">'
        f'{sev.value.upper()}</span>'
    )


def generate_html_report(
    findings: list[AttackFinding],
    target_name: str,
    output_path: Path,
) -> Path:
    vuln = [f for f in findings if f.vulnerable]
    safe = [f for f in findings if not f.vulnerable]

    # Count by severity
    sev_counts = {s: 0 for s in Severity}
    for f in vuln:
        sev_counts[f.severity.level] += 1

    overall_risk = _overall_risk(sev_counts)
    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    rows = ""
    for f in sorted(findings, key=lambda x: (
        not x.vulnerable,
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW].index(x.severity.level)
    )):
        status_icon = "🔴" if f.vulnerable else "✅"
        judge = f.judge_result
        judge_cell = (
            f'<span style="color:#16A34A">Safe ({judge.confidence:.0%})</span>'
            if judge and not judge.vulnerable else
            f'<span style="color:#DC2626">Vuln ({judge.confidence:.0%})</span>'
            if judge and judge.vulnerable else
            '<span style="color:#6B7280">—</span>'
        )
        rows += f"""
        <tr style="border-bottom:1px solid #E5E7EB">
          <td style="padding:10px 12px;font-family:monospace;font-size:13px">{f.attack_id}</td>
          <td style="padding:10px 12px">{status_icon} {f.payload.name}</td>
          <td style="padding:10px 12px">{f.payload.owasp_id}</td>
          <td style="padding:10px 12px">{_badge(f.severity.level)}</td>
          <td style="padding:10px 12px;font-size:13px">{f.severity.score}</td>
          <td style="padding:10px 12px;font-size:13px">{judge_cell}</td>
          <td style="padding:10px 12px;font-size:12px;max-width:220px;word-break:break-word">
            {f.severity.rationale[:120]}...
          </td>
        </tr>"""

    # Vulnerable findings detail cards
    detail_cards = ""
    for f in [x for x in findings if x.vulnerable]:
        _, bg = _SEV_COLORS[f.severity.level]
        rule_matches_html = ""
        for m in f.rule_result.matches:
            rule_matches_html += (
                f'<li style="margin:4px 0;font-size:13px">'
                f'<code style="background:#F3F4F6;padding:1px 6px;border-radius:3px">'
                f'{m.rule_id}</code> {m.description} — '
                f'<em style="color:#6B7280">matched: "{m.matched_text}"</em></li>'
            )

        judge_section = ""
        if f.judge_result:
            j = f.judge_result
            flags = []
            if j.bypassed_safety: flags.append("⚠️ Safety bypassed")
            if j.revealed_system_info: flags.append("🔓 System info revealed")
            if j.generated_harmful_content: flags.append("☠️ Harmful content")
            flag_html = " &nbsp;".join(flags) if flags else "None"
            judge_section = f"""
            <div style="margin-top:12px;padding:10px;background:#F9FAFB;border-radius:6px">
              <strong style="font-size:13px">🤖 LLM Judge</strong><br>
              <span style="font-size:13px">Verdict: {'Vulnerable' if j.vulnerable else 'Safe'}
              ({j.confidence:.0%} confidence)</span><br>
              <span style="font-size:13px">Flags: {flag_html}</span><br>
              <span style="font-size:13px;color:#374151">{j.reasoning}</span>
            </div>"""

        detail_cards += f"""
        <div style="background:{bg};border-radius:8px;padding:16px;margin-bottom:16px">
          <div style="display:flex;justify-content:space-between;align-items:flex-start">
            <div>
              <span style="font-family:monospace;font-size:12px;color:#6B7280">{f.attack_id}</span>
              <h3 style="margin:4px 0 8px;font-size:16px">{f.payload.name}</h3>
              <span style="font-size:12px;color:#6B7280">{f.payload.owasp_id} · 
              {', '.join(f.payload.tags[:3])}</span>
            </div>
            <div style="text-align:right">
              {_badge(f.severity.level)}
              <div style="font-size:13px;margin-top:4px">Score: {f.severity.score}/10</div>
              <div style="font-size:11px;color:#6B7280;margin-top:2px">{f.severity.cvss_vector}</div>
            </div>
          </div>
          <div style="margin-top:12px;padding:10px;background:rgba(255,255,255,0.6);border-radius:6px">
            <strong style="font-size:13px">Rule matches:</strong>
            <ul style="margin:6px 0 0;padding-left:18px">{rule_matches_html or '<li style="font-size:13px;color:#6B7280">No rule matches</li>'}</ul>
          </div>
          {judge_section}
          <details style="margin-top:10px">
            <summary style="cursor:pointer;font-size:13px;color:#374151">Model response preview</summary>
            <pre style="margin-top:8px;font-size:12px;white-space:pre-wrap;background:rgba(255,255,255,0.8);padding:10px;border-radius:4px">{f.response.content[:400]}</pre>
          </details>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Security Report — {target_name}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #F9FAFB; color: #111827; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
  h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 4px; }}
  h2 {{ font-size: 18px; font-weight: 600; margin: 32px 0 16px; color: #374151; }}
  .meta {{ font-size: 14px; color: #6B7280; margin-bottom: 32px; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
               gap: 12px; margin-bottom: 32px; }}
  .stat {{ background: #fff; border: 1px solid #E5E7EB; border-radius: 8px;
           padding: 16px; text-align: center; }}
  .stat .num {{ font-size: 32px; font-weight: 700; }}
  .stat .label {{ font-size: 13px; color: #6B7280; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border: 1px solid #E5E7EB; border-radius: 8px; overflow: hidden; }}
  th {{ background: #F3F4F6; padding: 10px 12px; text-align: left;
        font-size: 13px; font-weight: 600; color: #374151; }}
  tr:hover {{ background: #F9FAFB; }}
</style>
</head>
<body>
<div class="container">
  <div style="background:#fff;border:1px solid #E5E7EB;border-radius:12px;padding:24px;margin-bottom:24px">
    <h1>🛡️ LLM Security Evaluation Report</h1>
    <div class="meta">
      Target: <strong>{target_name}</strong> &nbsp;·&nbsp;
      Generated: {now} &nbsp;·&nbsp;
      Total attacks: {len(findings)}
    </div>

    <div style="background:{'#FEE2E2' if overall_risk == 'CRITICAL' else '#FFEDD5' if overall_risk == 'HIGH' else '#FEF9C3' if overall_risk == 'MEDIUM' else '#DCFCE7'};
                border-radius:8px;padding:16px;margin-bottom:24px">
      <strong>Overall Risk: {overall_risk}</strong> &nbsp;—&nbsp;
      {len(vuln)} of {len(findings)} attack payloads succeeded
    </div>

    <div class="stat-grid">
      <div class="stat">
        <div class="num" style="color:#374151">{len(findings)}</div>
        <div class="label">Total Attacks</div>
      </div>
      <div class="stat">
        <div class="num" style="color:#DC2626">{len(vuln)}</div>
        <div class="label">Vulnerable</div>
      </div>
      <div class="stat">
        <div class="num" style="color:#DC2626">{sev_counts[Severity.CRITICAL]}</div>
        <div class="label">Critical</div>
      </div>
      <div class="stat">
        <div class="num" style="color:#EA580C">{sev_counts[Severity.HIGH]}</div>
        <div class="label">High</div>
      </div>
      <div class="stat">
        <div class="num" style="color:#CA8A04">{sev_counts[Severity.MEDIUM]}</div>
        <div class="label">Medium</div>
      </div>
      <div class="stat">
        <div class="num" style="color:#16A34A">{sev_counts[Severity.LOW]}</div>
        <div class="label">Low</div>
      </div>
    </div>
  </div>

  <h2>All Results</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Attack</th><th>OWASP</th>
        <th>Severity</th><th>Score</th><th>Judge</th><th>Notes</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>

  {'<h2>Vulnerability Details</h2>' + detail_cards if detail_cards else ''}

  <div style="margin-top:32px;font-size:12px;color:#9CA3AF;text-align:center">
    Generated by LLM Security Evaluation Framework · Sandeep Tumu
  </div>
</div>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    return output_path


def _overall_risk(sev_counts: dict) -> str:
    if sev_counts[Severity.CRITICAL] > 0:
        return "CRITICAL"
    elif sev_counts[Severity.HIGH] > 0:
        return "HIGH"
    elif sev_counts[Severity.MEDIUM] > 0:
        return "MEDIUM"
    elif sev_counts[Severity.LOW] > 0:
        return "LOW"
    return "NONE"
