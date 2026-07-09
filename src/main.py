"""Entry point for the CI injection scanner GitHub Action.

Wires together:
  1. scanner.py  — pure-Python regex scan of the repo
  2. judge.py    — GitHub Models LLM judge (optional, reduces false positives)
  3. Annotations — GitHub workflow commands (::error::) for inline PR feedback
  4. Exit code   — non-zero when confirmed findings meet the fail threshold
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Allow running from repo root or from the action itself
_src = Path(__file__).parent
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from judge import JudgeVerdict, _fallback_judgements, judge_findings
from scanner import scan_directory

_SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

_SEVERITY_ICONS = {
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
}


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _annotate_error(file: str, line: int, message: str) -> None:
    """Emit a GitHub workflow error annotation."""
    # Escape special characters per GitHub docs
    msg = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error file={file},line={line}::{msg}")


def _annotate_warning(file: str, line: int, message: str) -> None:
    msg = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::warning file={file},line={line}::{msg}")


def _set_output(name: str, value: str) -> None:
    """Write to GITHUB_OUTPUT."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"::set-output name={name}::{value}")  # legacy fallback


def _summary_markdown(judged: list, *, repo_path: str) -> str:
    confirmed = [f for f in judged if f.verdict == JudgeVerdict.TRUE_POSITIVE]
    fps = [f for f in judged if f.verdict == JudgeVerdict.FALSE_POSITIVE]

    lines = ["## CI Injection Scan Results\n"]
    if not confirmed:
        lines.append("✅ **No confirmed CI injection vulnerabilities found.**\n")
        if fps:
            lines.append(f"_{len(fps)} potential finding(s) assessed as false positives by LLM judge._\n")
        return "\n".join(lines)

    lines.append(f"⚠️ **{len(confirmed)} confirmed finding(s)**\n")
    lines.append("| Severity | File | Line | Tainted Variable | Attack Scenario |")
    lines.append("|----------|------|------|-----------------|-----------------|")
    for f in sorted(confirmed, key=lambda x: -_SEVERITY_ORDER.get(x.severity, 0)):
        icon = _SEVERITY_ICONS.get(f.severity, "")
        rel = f.file_path.replace(repo_path, "").lstrip("/")
        scenario = (f.attack_scenario[:100] + "…") if len(f.attack_scenario) > 100 else f.attack_scenario
        lines.append(f"| {icon} {f.severity} | `{rel}` | {f.line_number} | `{f.tainted_variable}` | {scenario} |")

    if fps:
        lines.append(f"\n_{len(fps)} finding(s) filtered as false positives._")

    lines.append("\n### Remediation\n")
    lines.append("Replace direct expression interpolation with environment variable intermediaries:\n")
    lines.append("```yaml")
    lines.append("# ❌ Vulnerable")
    lines.append("- run: echo ${{ github.event.pull_request.title }}")
    lines.append("")
    lines.append("# ✅ Safe")
    lines.append("- run: echo \"$PR_TITLE\"")
    lines.append("  env:")
    lines.append("    PR_TITLE: ${{ github.event.pull_request.title }}")
    lines.append("```")
    return "\n".join(lines)


def main() -> int:
    scan_path = _env("SCAN_PATH", ".")
    fail_on = _env("FAIL_ON_SEVERITY", "HIGH").upper()
    use_judge = _env("USE_LLM_JUDGE", "true").lower() not in ("false", "0", "no")
    github_token = _env("GITHUB_TOKEN")
    judge_model = _env("JUDGE_MODEL", "gpt-4o-mini")

    repo_path = str(Path(scan_path).resolve())
    print(f"Scanning: {repo_path}")

    result = scan_directory(Path(repo_path))
    print(f"Files scanned: {result.files_scanned}")
    print(f"Raw findings: {len(result.findings)}")

    if not result.findings:
        print("::notice::No CI injection patterns detected.")
        _set_output("findings-count", "0")
        _set_output("verdict", "clean")
        _write_step_summary("## CI Injection Scan Results\n\n✅ **No CI injection vulnerabilities found.**\n")
        return 0

    # Judge step
    if use_judge and github_token:
        print(f"Running LLM judge ({judge_model}) on {len(result.findings)} finding(s)…")
        judged = judge_findings(result.findings, github_token=github_token, model=judge_model)
    else:
        if use_judge and not github_token:
            print("::warning::GITHUB_TOKEN not set — skipping LLM judge, treating all findings as TRUE_POSITIVE")
        judged = _fallback_judgements(result.findings)

    confirmed = [f for f in judged if f.verdict == JudgeVerdict.TRUE_POSITIVE]
    fps = [f for f in judged if f.verdict == JudgeVerdict.FALSE_POSITIVE]

    print(f"Confirmed: {len(confirmed)}  False positives filtered: {len(fps)}")

    # Emit GitHub annotations for confirmed findings
    fail_threshold = _SEVERITY_ORDER.get(fail_on, 3)
    should_fail = False

    for f in confirmed:
        rel_path = f.file_path  # already relative from scanner
        sev_val = _SEVERITY_ORDER.get(f.severity, 0)
        msg = (
            f"[CI Injection {f.severity}] {f.tainted_variable} in {f.category} — "
            f"{f.attack_scenario[:200]}"
        )
        if sev_val >= fail_threshold:
            _annotate_error(rel_path, f.line_number, msg)
            should_fail = True
        else:
            _annotate_warning(rel_path, f.line_number, msg)

    # Write step summary
    summary = _summary_markdown(judged, repo_path=repo_path)
    _write_step_summary(summary)

    _set_output("findings-count", str(len(confirmed)))
    _set_output("verdict", "findings" if confirmed else "clean")

    # Emit structured JSON for downstream steps
    findings_json = [
        {
            "file_path": f.file_path,
            "line_number": f.line_number,
            "tainted_variable": f.tainted_variable,
            "category": f.category,
            "severity": f.severity,
            "verdict": str(f.verdict),
            "attack_scenario": f.attack_scenario,
            "remediation": f.remediation,
        }
        for f in confirmed
    ]
    print(f"::group::Findings JSON")
    print(json.dumps(findings_json, indent=2))
    print("::endgroup::")

    return 1 if should_fail else 0


def _write_step_summary(content: str) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write(content + "\n")


if __name__ == "__main__":
    sys.exit(main())
