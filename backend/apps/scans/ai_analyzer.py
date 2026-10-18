"""
FalconScan — AI-Powered Security Intelligence Engine.

Produces a structured security report from scan findings:
  • Executive summary for non-technical stakeholders
  • Technical finding-by-finding analysis
  • Realistic attack scenario chain
  • Code-level fix recommendations
  • AI-driven severity re-scoring with reasoning
  • Compliance impact notes (OWASP, GDPR, etc.)
"""
from __future__ import annotations

import json
import re
import textwrap
from typing import Any, Dict, List, Optional


# ─── Prompt construction ─────────────────────────────────────────────────────

def _truncate(text: str, max_len: int = 400) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def _build_prompt(scan_data: Dict[str, Any]) -> str:
    """
    Assemble the Gemini prompt from all available scan artefacts.
    Keeps each section concise to stay within token budget.
    """
    app_name       = scan_data.get("app_name", "Unknown")
    package_name   = scan_data.get("package_name", "Unknown")
    threat_level   = scan_data.get("threat_level", "unknown").upper()
    threat_score   = scan_data.get("threat_score", 0)
    total_issues   = scan_data.get("total_issues", 0)
    critical_count = scan_data.get("critical_issues", 0)
    high_count     = scan_data.get("high_issues", 0)
    medium_count   = scan_data.get("medium_issues", 0)
    low_count      = scan_data.get("low_issues", 0)
    version        = scan_data.get("version", "")

    # ── Vulnerability list from static analysis ──────────────────────────────
    vulns: List[Dict] = scan_data.get("vulnerabilities", [])
    vuln_lines = []
    for i, v in enumerate(vulns[:40], 1):           # cap to 40 to stay under token limit
        title    = v.get("title", v.get("type", "Unknown"))
        sev      = v.get("severity", "unknown")
        cat      = v.get("category", "")
        desc     = _truncate(v.get("description", ""), 200)
        vuln_lines.append(f"  [{i}] [{sev.upper()}] {title} ({cat})\n      {desc}")

    # ── Fuzzing findings ─────────────────────────────────────────────────────
    fuzzing  = scan_data.get("fuzzing_analysis") or {}
    fuzz_findings: List[Dict] = fuzzing.get("vulnerabilities", [])
    fuzz_lines = []
    for i, f in enumerate(fuzz_findings[:20], 1):
        title   = f.get("title", f.get("type", "Unknown"))
        sev     = f.get("severity", "unknown")
        comp    = f.get("component", "")
        payload = _truncate(f.get("payload", ""), 120)
        src     = f.get("source", "")
        origin  = f.get("origin", f.get("analysis_origin", ""))
        technique = _truncate(f.get("detection_technique", ""), 180)
        attack_vector = _truncate(f.get("attack_vector", ""), 180)
        fuzz_lines.append(
            f"  [{i}] [{sev.upper()}] {title}\n"
            f"      Component: {comp}  |  Source: {src}  |  Origin: {origin}\n"
            f"      Payload: {payload}\n"
            f"      Detection: {technique or 'Hybrid component fuzzing'}\n"
            f"      Attack Vector: {attack_vector or 'Component-level payload mutation'}"
        )

    # ── Permissions ──────────────────────────────────────────────────────────
    permissions: List[Dict] = scan_data.get("permissions", [])
    dangerous_perms = [
        p.get("permission_name", p) for p in permissions
        if (p.get("is_dangerous") if isinstance(p, dict) else False)
    ][:20]

    # ── Static analysis summary ──────────────────────────────────────────────
    static  = scan_data.get("static_analysis") or {}
    app_info = static.get("app_info") or {}
    sdk_min  = app_info.get("min_sdk", "?")
    sdk_tgt  = app_info.get("target_sdk", "?")

    # ── Assemble prompt ──────────────────────────────────────────────────────
    vuln_section  = "\n".join(vuln_lines)  if vuln_lines  else "  (none)"
    fuzz_section  = "\n".join(fuzz_lines)  if fuzz_lines  else "  (none)"
    perm_section  = ", ".join(dangerous_perms) if dangerous_perms else "(none)"

    prompt = textwrap.dedent(f"""
    You are a senior Android security engineer performing a professional APK security assessment.
    Analyse the following scan results and produce a structured JSON security report.

    ════════════════════════════════════════════
    APPLICATION UNDER TEST
    ════════════════════════════════════════════
    App Name     : {app_name}
    Package      : {package_name}
    Version      : {version}
    Min SDK      : {sdk_min}   |   Target SDK: {sdk_tgt}
    Threat Level : {threat_level}   |   Risk Score: {threat_score}/100
    Findings     : {total_issues} total  ({critical_count} critical / {high_count} high / {medium_count} medium / {low_count} low)

    ════════════════════════════════════════════
    STATIC ANALYSIS VULNERABILITIES
    ════════════════════════════════════════════
{vuln_section}

    ════════════════════════════════════════════
    COMPONENT FUZZING FINDINGS
    ════════════════════════════════════════════
{fuzz_section}

    ════════════════════════════════════════════
    DANGEROUS PERMISSIONS REQUESTED
    ════════════════════════════════════════════
    {perm_section}

    ════════════════════════════════════════════
    REQUIRED OUTPUT — return ONLY valid JSON, no prose, no markdown fences.
    ════════════════════════════════════════════
    Produce a JSON object with EXACTLY these keys:

    {{
      "executive_summary": "<2-4 sentence plain-language summary for a business stakeholder>",
      "overall_risk_assessment": "<1-2 paragraphs: what is at risk, who could be harmed>",
      "business_impact": "<2-3 sentences describing concrete business impact for a non-technical executive: financial risk, reputational damage, legal or regulatory consequences>",
      "attack_surface": [
        {{
          "category": "<one of: Network Communication, Inter-Process Communication, Data Storage, Authentication & Authorization, Cryptography, Code Integrity, Permissions & Privacy>",
          "exposed": <true|false>,
          "severity": "<critical|high|medium|low|safe>",
          "description": "<one sentence about what is exposed or adequately protected>"
        }}
        // include ALL 7 categories
      ],
      "mitre_techniques": [
        {{
          "id": "<e.g. T1437>",
          "name": "<technique name>",
          "tactic": "<e.g. Initial Access, Credential Access, Exfiltration, Command and Control>",
          "relevance": "<one sentence linking this technique to a specific finding>"
        }}
        // include 4-6 relevant techniques mapped to actual findings
      ],
      "threat_intel": {{
        "actor_profile": "<likely threat actor type: opportunistic attacker / nation-state / competitor / automated scanner>",
        "attack_likelihood": "<critical|high|medium|low>",
        "motivation": "<data theft|financial fraud|espionage|sabotage|credential harvesting>",
        "ioc_patterns": ["<pattern 1>", "<pattern 2>"]
      }},
      "risk_breakdown": {{
        "network": <0-100>,
        "data_storage": <0-100>,
        "authentication": <0-100>,
        "components": <0-100>,
        "cryptography": <0-100>
      }},
      "attack_scenario": "<Step-by-step realistic attack chain using 2-4 of the most critical findings — write as a numbered list>",
      "re_scored_findings": [
        {{
          "title": "<exact finding title from above>",
          "original_severity": "<as reported>",
          "ai_severity": "<your revised severity: critical|high|medium|low|info>",
          "reason": "<one sentence explaining revision>"
        }}
        // include ONLY findings where you would change the severity
      ],
      "finding_analyses": [
        {{
          "title": "<exact title>",
          "severity": "<severity>",
          "technical_analysis": "<2-3 sentences: root cause, exploitability, business impact>",
          "attack_vector": "<one-liner: e.g. 'Any installed app can call this exported Activity'>",
          "code_fix": "<concrete code snippet or configuration change>"
        }}
        // include the top 10 most impactful findings
      ],
      "remediation_roadmap": [
        {{
          "action": "<concrete, specific action to take>",
          "priority": <1|2|3>,
          "effort": "<low|medium|high>",
          "impact": "<low|medium|high>",
          "category": "<Network|Data|Auth|Components|Crypto|Permissions|Code>"
        }}
        // 6-10 items ordered by priority (1=urgent, 3=improvements)
      ],
      "top_recommendations": [
        "<Concrete, prioritised action (e.g. Set android:exported=false on Activities X and Y)>"
        // list 5-8 items
      ],
      "compliance_impact": "<OWASP Mobile Top 10 mappings, GDPR/CCPA data risk, or PCI-DSS notes if applicable>"
    }}

    Be direct, technical, and actionable. Do not hallucinate findings not listed above.
    """).strip()

    return prompt


# ─── Gemini caller ────────────────────────────────────────────────────────────

# Model cascade: smallest/cheapest first to preserve free-tier quota.
# Only models confirmed available via ListModels for this API version.
_MODEL_CASCADE = [
    "gemini-2.0-flash-lite",       # largest free-tier allowance
    "gemini-flash-lite-latest",    # alias — independent quota bucket
    "gemini-2.0-flash",            # standard flash
    "gemini-flash-latest",         # alias for latest flash
    "gemini-2.5-flash",            # most capable available free model
]


def _parse_retry_delay(exc: Exception) -> float:
    """Extract the retryDelay seconds from a Gemini 429 error, or return 0."""
    try:
        msg = str(exc)
        m = re.search(r'retryDelay.*?(\d+)', msg)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return 0.0


def _parse_response(raw: str) -> Dict[str, Any]:
    """Strip markdown fences and parse JSON from a Gemini text response."""
    raw = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.MULTILINE)
    raw = re.sub(r'\s*```$', '', raw, flags=re.MULTILINE).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise RuntimeError(f"Gemini returned non-JSON output: {e}\n---\n{raw[:500]}")


def _call_gemini(prompt: str, api_key: str, model: str) -> Dict[str, Any]:
    """
    Send the prompt to  with automatic model-cascade fallback.

    Strategy:
      1. Try the configured model first.
      2. On 429 RESOURCE_EXHAUSTED: wait the delay the API advertises (up to
         2 min), then retry once on the same model.
      3. If still exhausted, cascade through _MODEL_CASCADE (each model has its
         own independent free-tier quota bucket).
      4. Raise RuntimeError with actionable guidance only when every model fails.
    """
    import time as _time
    from google import genai as gai

    client = gai.Client(api_key=api_key)

    # Build ordered list: configured model first, then the rest of the cascade
    ordered = [model] + [m for m in _MODEL_CASCADE if m != model]

    last_err: Exception = RuntimeError("No models attempted")

    for attempt_model in ordered:
        # Up to 2 attempts per model (one retry after the advertised delay)
        for attempt in range(2):
            try:
                response = client.models.generate_content(
                    model=attempt_model,
                    contents=prompt,
                )
                result = _parse_response(response.text)
                if attempt_model != model:
                    result["_model_used"] = attempt_model  # note the fallback
                return result

            except Exception as exc:
                last_err = exc
                err_str = str(exc)

                if "RESOURCE_EXHAUSTED" in err_str or "429" in err_str:
                    if attempt == 0:
                        delay = _parse_retry_delay(exc)
                        if 0 < delay <= 120:   # auto-wait up to 2 minutes
                            print(f"[FALCON-AI] {attempt_model} rate-limited, "
                                  f"waiting {delay:.0f}s before retry…")
                            _time.sleep(delay)
                            continue          # retry same model
                    # Daily quota exhausted or delay too long — try next model
                    print(f"[FALCON-AI] {attempt_model} quota exhausted, "
                          f"trying next model in cascade…")
                    break
                else:
                    raise RuntimeError(f"Gemini error ({attempt_model}): {exc}")

    # Every model failed
    raise RuntimeError(
        f"All Gemini models have exhausted their free-tier quota.\n\n"
        f"Options:\n"
        f"  1. Wait until quota resets (usually resets at midnight Pacific time).\n"
        f"  2. Set GEMINI_MODEL=gemini-2.5-flash in backend/.env for the most capable free model.\n"
        f"  3. Enable billing at https://ai.google.dev to remove free-tier limits.\n\n"
        f"Last error: {last_err}"
    )


# ─── Public entry point ───────────────────────────────────────────────────────

def generate_ai_report(scan) -> Dict[str, Any]:
    """
    Generate (or regenerate) the AI security report for a completed Scan object.

    Returns the structured report dict. The caller is responsible for saving
    it to scan.ai_report.

    Raises:
        ValueError  — no API key configured
        RuntimeError — Gemini call failed or returned unparseable output
    """
    from django.conf import settings

    api_key = getattr(settings, "GEMINI_API_KEY", "") or ""
    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY is not set. Add it to your environment variables "
            "or Django settings to enable AI reporting."
        )

    model = getattr(settings, "GEMINI_MODEL", "gemini-2.0-flash")

    # Serialise the scan into a plain dict for the prompt builder
    scan_data: Dict[str, Any] = {
        "app_name":       scan.app_name,
        "package_name":   scan.package_name,
        "version":        scan.version,
        "threat_level":   scan.threat_level,
        "threat_score":   scan.threat_score,
        "total_issues":   scan.total_issues,
        "critical_issues":scan.critical_issues,
        "high_issues":    scan.high_issues,
        "medium_issues":  scan.medium_issues,
        "low_issues":     scan.low_issues,
        "static_analysis":scan.static_analysis or {},
        "fuzzing_analysis":scan.fuzzing_analysis or {},
        # Flatten vulnerability queryset to list of dicts
        "vulnerabilities": [
            {
                "title":       v.title,
                "severity":    v.severity,
                "category":    v.category,
                "description": v.description,
                "remediation": v.remediation,
            }
            for v in scan.vulnerabilities.all()[:50]
        ],
        "permissions": [
            {
                "permission_name": p.permission_name,
                "is_dangerous":    p.is_dangerous,
            }
            for p in scan.permissions.all()[:60]
        ],
    }

    prompt = _build_prompt(scan_data)
    report = _call_gemini(prompt, api_key, model)

    # Annotate with metadata
    report["_meta"] = {
        "model":      model,
        "scan_id":    scan.id,
        "app_name":   scan.app_name,
        "generated":  __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    return report
