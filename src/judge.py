"""LLM judge for CI injection findings via GitHub Models API.

Uses the OpenAI-compatible GitHub Models endpoint, authenticated with
GITHUB_TOKEN — no separate credentials required in GitHub Actions.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_MODELS_BASE_URL = "https://models.inference.ai.azure.com"
_DEFAULT_MODEL = "gpt-4o-mini"

_SYSTEM_PROMPT = """\
You are a security expert reviewing CI/CD expression injection findings.

For each finding, determine:
1. Is it a TRUE_POSITIVE (real injection risk) or FALSE_POSITIVE?
2. What is the concrete attack scenario?
3. What is the severity: HIGH, MEDIUM, or LOW?

A finding is a TRUE_POSITIVE when:
- The tainted value reaches a shell execution context unquoted or unescaped
- An attacker can realistically control the tainted value (PR title, branch name, commit message)
- There is no defensive sanitization visible in context

A finding is a FALSE_POSITIVE when:
- The value is used in a safe context (e.g., only in an echo for logging, not in eval)
- The expression is inside a condition check, not a command
- The workflow only runs on protected branches or has environment protection gates

Return a JSON object:
{
  "findings": [
    {
      "file_path": "<same as input>",
      "line_number": <same as input>,
      "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE",
      "severity": "HIGH" | "MEDIUM" | "LOW",
      "attack_scenario": "<concrete description of how an attacker exploits this>",
      "remediation": "<specific fix, e.g. use env var intermediary>"
    }
  ]
}

Include ALL input findings in the output array, even FALSE_POSITIVEs.
"""


class JudgeVerdict(StrEnum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class JudgedFinding:
    file_path: str
    line_number: int
    line_content: str
    tainted_variable: str
    category: str
    raw_severity: str
    verdict: JudgeVerdict
    severity: str
    attack_scenario: str
    remediation: str


def _format_findings_for_judge(findings: list[Any]) -> str:
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(f"Finding {i}:")
        lines.append(f"  file_path: {f.file_path}")
        lines.append(f"  line_number: {f.line_number}")
        lines.append(f"  line_content: {f.line_content!r}")
        lines.append(f"  tainted_variable: {f.tainted_variable}")
        lines.append(f"  category: {f.category}")
        lines.append(f"  raw_severity: {f.severity}")
        if f.context_lines:
            lines.append(f"  context:")
            for cl in f.context_lines:
                lines.append(f"    {cl}")
        lines.append("")
    return "\n".join(lines)


def judge_findings(
    findings: list[Any],
    *,
    github_token: str | None = None,
    model: str = _DEFAULT_MODEL,
) -> list[JudgedFinding]:
    """Call GitHub Models LLM to classify raw scanner findings.

    Returns a list of JudgedFinding. Falls back to marking all findings
    as TRUE_POSITIVE if the API call fails (fail-safe / conservative).
    """
    if not findings:
        return []

    token = github_token or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        # No token — skip judge, treat everything as TRUE_POSITIVE conservatively
        return _fallback_judgements(findings)

    try:
        return _call_github_models(findings, token=token, model=model)
    except Exception as exc:
        print(f"::warning::LLM judge failed ({exc}), treating all findings as TRUE_POSITIVE")
        return _fallback_judgements(findings)


def _call_github_models(
    findings: list[Any],
    *,
    token: str,
    model: str,
) -> list[JudgedFinding]:
    try:
        from openai import OpenAI  # type: ignore[import-untyped]
    except ImportError:
        raise RuntimeError("openai package not installed; run: pip install openai")

    client = OpenAI(base_url=_MODELS_BASE_URL, api_key=token)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _format_findings_for_judge(findings)},
        ],
        response_format={"type": "json_object"},
        temperature=0,
    )

    raw = response.choices[0].message.content or "{}"
    data = json.loads(raw)
    judged_map: dict[tuple[str, int], dict] = {
        (item["file_path"], item["line_number"]): item
        for item in data.get("findings", [])
    }

    results: list[JudgedFinding] = []
    for f in findings:
        key = (f.file_path, f.line_number)
        j = judged_map.get(key)
        if j is None:
            # LLM didn't return this finding — conservative fallback
            results.append(JudgedFinding(
                file_path=f.file_path,
                line_number=f.line_number,
                line_content=f.line_content,
                tainted_variable=f.tainted_variable,
                category=f.category,
                raw_severity=f.severity,
                verdict=JudgeVerdict.TRUE_POSITIVE,
                severity=f.severity,
                attack_scenario="Not assessed by judge (conservative).",
                remediation="Use an environment variable intermediary.",
            ))
        else:
            results.append(JudgedFinding(
                file_path=f.file_path,
                line_number=f.line_number,
                line_content=f.line_content,
                tainted_variable=f.tainted_variable,
                category=f.category,
                raw_severity=f.severity,
                verdict=JudgeVerdict(j.get("verdict", "TRUE_POSITIVE")),
                severity=j.get("severity", f.severity),
                attack_scenario=j.get("attack_scenario", ""),
                remediation=j.get("remediation", ""),
            ))
    return results


def _fallback_judgements(findings: list[Any]) -> list[JudgedFinding]:
    return [
        JudgedFinding(
            file_path=f.file_path,
            line_number=f.line_number,
            line_content=f.line_content,
            tainted_variable=f.tainted_variable,
            category=f.category,
            raw_severity=f.severity,
            verdict=JudgeVerdict.TRUE_POSITIVE,
            severity=f.severity,
            attack_scenario="LLM judge unavailable — treated as TRUE_POSITIVE (conservative).",
            remediation="Use an environment variable intermediary.",
        )
        for f in findings
    ]
