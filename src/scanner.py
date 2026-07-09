"""CI/CD command injection scanner.

Pure-Python static analysis engine that detects patterns where
attacker-controlled Git metadata (branch names, PR titles, commit
messages, tags) is interpolated into shell execution contexts.

Covers four file categories:

- **Jenkinsfile** — Groovy string interpolation in ``sh``/``bat`` steps
- **GitHub Actions** — ``${{ }}`` expression injection in ``run:`` steps
- **Shell scripts** — unsafe use of tainted CI environment variables
- **Makefiles** — tainted variable expansion in recipes

This module is self-contained: patterns, classification, and all four
scanners live here.  It is used by :meth:`LocalHarness.run_ci_injection_scan`.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath


# ── Tainted variable patterns ────────────────────────────────────────
# Variables/expressions whose values can be controlled by an external
# attacker (e.g., by naming a branch, writing a PR title, or setting a tag).

# -- Groovy / Jenkinsfile tainted sources --

JENKINS_TAINTED_EXPRESSIONS = [
    r"env\.BRANCH_NAME",
    r"env\.CHANGE_BRANCH",
    r"env\.CHANGE_TITLE",
    r"env\.CHANGE_TARGET",
    r"env\.CHANGE_AUTHOR",
    r"env\.CHANGE_AUTHOR_DISPLAY_NAME",
    r"env\.CHANGE_AUTHOR_EMAIL",
    r"env\.GIT_BRANCH",
    r"env\.GIT_LOCAL_BRANCH",
    r"env\.TAG_NAME",
    r"env\.GIT_URL",
    r"env\.GIT_COMMIT",
    r"env\.CHANGE_ID",
    # Direct variable references (without env. prefix)
    r"BRANCH_NAME",
    r"CHANGE_BRANCH",
    r"CHANGE_TARGET",
    r"CHANGE_TITLE",
    r"CHANGE_AUTHOR",
    r"GIT_BRANCH",
    r"TAG_NAME",
    # params.* — user-supplied build parameters
    r"params\.\w+",
]

_groovy_taint_inner = "|".join(JENKINS_TAINTED_EXPRESSIONS)
GROOVY_TAINTED_RE = re.compile(
    rf"\$\{{(?:{_groovy_taint_inner})\}}|"
    rf"\$(?:{_groovy_taint_inner})\b"
)

# -- Shell-level tainted variables --

SHELL_TAINTED_VARS = [
    "BRANCH_NAME",
    "GIT_BRANCH",
    "CHANGE_BRANCH",
    "CHANGE_TARGET",
    "CHANGE_TITLE",
    "CHANGE_AUTHOR",
    "TAG_NAME",
    "GIT_LOCAL_BRANCH",
    "GITHUB_HEAD_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF",
    "pr_branch",
    "PR_BRANCH",
    "SOURCE_BRANCH",
    "TARGET_BRANCH",
    "BRANCH",
    "REF",
    "GIT_TAG",
]

_shell_taint_inner = "|".join(SHELL_TAINTED_VARS)
SHELL_TAINTED_RE = re.compile(rf"(?<!\')(?:\$\{{(?:{_shell_taint_inner})\}}|\$(?:{_shell_taint_inner})\b)")

# -- GitHub Actions expression injection --

ACTIONS_TAINTED_EXPRESSIONS = [
    r"github\.head_ref",
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.label",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.discussion\.title",
    r"github\.event\.discussion\.body",
    r"github\.event\.pages\.\*\.page_name",
    r"github\.event\.commits\.\*\.message",
    r"github\.event\.commits\.\*\.author\.name",
    r"github\.event\.commits\.\*\.author\.email",
    r"github\.ref_name",
    r"github\.ref",
]

_actions_taint_inner = "|".join(ACTIONS_TAINTED_EXPRESSIONS)
ACTIONS_TAINTED_RE = re.compile(rf"\$\{{\{{\s*(?:{_actions_taint_inner})\s*\}}\}}")

# -- Makefile tainted variables --

MAKE_TAINTED_VARS = [
    "BRANCH_NAME",
    "GIT_BRANCH",
    "CHANGE_BRANCH",
    "CHANGE_TARGET",
    "TAG_NAME",
    "BRANCH",
    "REF",
    "GITHUB_HEAD_REF",
    "GITHUB_REF_NAME",
]

_make_taint_inner = "|".join(MAKE_TAINTED_VARS)
MAKE_TAINTED_RE = re.compile(
    rf"(?:\$\((?:{_make_taint_inner})\)|\$\{{(?:{_make_taint_inner})\}}|\$(?:{_make_taint_inner})\b)"
)

# -- Shell high-risk constructs --

EVAL_CONTEXT_RE = re.compile(
    r"\beval\b|\$\(|\`"
    r"|>\s*\(|<\s*\("
    r"|\bxargs\b"
    r"|\bexec\b",
)


# ── Internal finding dataclass (intermediate) ────────────────────────


@dataclass
class _RawFinding:
    file_path: str
    line_number: int
    line_content: str
    severity: str
    category: str
    tainted_variable: str
    description: str
    context_lines: list[str] = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────


def _get_context(lines: list[str], idx: int, window: int = 2) -> list[str]:
    start = max(0, idx - window)
    end = min(len(lines), idx + window + 1)
    return [lines[i].rstrip() for i in range(start, end)]


def _is_unquoted(line: str, match_start: int) -> bool:
    in_single = False
    in_double = False
    for i in range(match_start):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
    return not (in_single or in_double)


# ── File classification ──────────────────────────────────────────────


def classify_file(path: str) -> str | None:
    """Return the scanner category for a file path, or None."""
    name = PurePosixPath(path).name.lower()
    path_lower = path.lower()

    if name == "jenkinsfile" or name.startswith("jenkinsfile."):
        return "jenkinsfile"
    if name == "makefile" or name.startswith("makefile."):
        return "makefile"
    if name.endswith(".groovy") or name.endswith(".jenkinsfile"):
        return "jenkinsfile"
    if name.endswith(".sh") or name.endswith(".bash"):
        return "shell"
    if name.endswith(".mk"):
        return "makefile"
    if ".github/workflows/" in path_lower and (name.endswith(".yml") or name.endswith(".yaml")):
        return "github-actions"

    return None


# ── Jenkinsfile scanner ──────────────────────────────────────────────

# Detects start of a sh/bat step with a double-quoted or triple-double-quoted string
_SH_DOUBLE_QUOTE_START = re.compile(
    r'''\b(?:sh|bat)\s*\(?\s*(?:script\s*:\s*)?"""'''
    r"""|"""
    r'''\b(?:sh|bat)\s*\(?\s*(?:script\s*:\s*)?"'''
)

_TRIPLE_DOUBLE_OPEN = re.compile(r'"""')
_TRIPLE_DOUBLE_CLOSE = re.compile(r'"""')


def _line_has_dq_sh(line: str) -> bool:
    return bool(_SH_DOUBLE_QUOTE_START.search(line))


def scan_jenkinsfile(
    content: str,
    file_path: str,
) -> list[_RawFinding]:
    findings: list[_RawFinding] = []
    lines = content.splitlines()

    in_sh_block = False
    block_start_line: int | None = None

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()

        if _SH_DOUBLE_QUOTE_START.search(raw_line):
            in_sh_block = True
            block_start_line = idx

        if in_sh_block or _line_has_dq_sh(raw_line):
            for match in GROOVY_TAINTED_RE.finditer(raw_line):
                findings.append(
                    _RawFinding(
                        file_path=file_path,
                        line_number=idx + 1,
                        line_content=line,
                        severity="HIGH",
                        category="jenkinsfile",
                        tainted_variable=match.group(),
                        description=(
                            f"Groovy interpolation of {match.group()} inside a "
                            f"double-quoted sh/bat step. An attacker who controls this "
                            f"value (e.g., via branch name) can inject arbitrary "
                            f"shell commands."
                        ),
                        context_lines=_get_context(lines, idx),
                    )
                )

        if in_sh_block:
            tq_count = len(_TRIPLE_DOUBLE_CLOSE.findall(raw_line))
            if tq_count >= 2 or ('"' in raw_line and not raw_line.rstrip().endswith("\\")):
                if '"""' in raw_line and block_start_line != idx:
                    in_sh_block = False
                elif '"""' not in raw_line and '"' in raw_line:
                    if block_start_line == idx:
                        in_sh_block = False

    # Groovy .execute() with tainted input
    for idx, raw_line in enumerate(lines):
        if ".execute()" in raw_line:
            for match in GROOVY_TAINTED_RE.finditer(raw_line):
                findings.append(
                    _RawFinding(
                        file_path=file_path,
                        line_number=idx + 1,
                        line_content=raw_line.strip(),
                        severity="HIGH",
                        category="jenkinsfile",
                        tainted_variable=match.group(),
                        description=(
                            f"Groovy .execute() call with interpolated {match.group()}. "
                            f"Direct command execution with attacker-controlled input."
                        ),
                        context_lines=_get_context(lines, idx),
                    )
                )

    return findings


# ── GitHub Actions scanner ───────────────────────────────────────────

_RUN_STEP_RE = re.compile(r"^\s*run\s*:\s*[|>]?\s*(.*)", re.IGNORECASE)


def scan_actions_workflow(
    content: str,
    file_path: str,
) -> list[_RawFinding]:
    findings: list[_RawFinding] = []
    lines = content.splitlines()

    in_run_block = False
    run_indent: int = 0

    for idx, raw_line in enumerate(lines):
        stripped = raw_line.strip()

        m = _RUN_STEP_RE.match(raw_line)
        if m:
            inline = m.group(1).strip()
            if inline and inline not in ("|", ">", "|+", "|-"):
                _check_actions_line(
                    raw_line,
                    stripped,
                    idx,
                    lines,
                    file_path,
                    findings,
                )
            else:
                in_run_block = True
                run_indent = len(raw_line) - len(raw_line.lstrip())
            continue

        if in_run_block:
            current_indent = len(raw_line) - len(raw_line.lstrip())
            if stripped == "" or current_indent > run_indent:
                _check_actions_line(
                    raw_line,
                    stripped,
                    idx,
                    lines,
                    file_path,
                    findings,
                )
            else:
                in_run_block = False

        if stripped.startswith("name:"):
            _check_actions_line(
                raw_line,
                stripped,
                idx,
                lines,
                file_path,
                findings,
                severity="LOW",
                desc_prefix="Expression in workflow step name",
            )

    return findings


def _check_actions_line(
    raw_line: str,
    stripped: str,
    idx: int,
    lines: list[str],
    file_path: str,
    findings: list[_RawFinding],
    severity: str = "HIGH",
    desc_prefix: str = "Expression injection in Actions run step",
) -> None:
    for match in ACTIONS_TAINTED_RE.finditer(raw_line):
        findings.append(
            _RawFinding(
                file_path=file_path,
                line_number=idx + 1,
                line_content=stripped,
                severity=severity,
                category="github-actions",
                tainted_variable=match.group(),
                description=(
                    f"{desc_prefix}: {match.group()} is interpolated directly into "
                    f"the shell command. An attacker can inject commands via this value. "
                    f"Use an environment variable instead: "
                    f"env: MY_VAR: {match.group()} then reference $MY_VAR."
                ),
                context_lines=_get_context(lines, idx),
            )
        )


# ── Shell script scanner ────────────────────────────────────────────


def scan_shell_script(
    content: str,
    file_path: str,
) -> list[_RawFinding]:
    findings: list[_RawFinding] = []
    lines = content.splitlines()

    for idx, raw_line in enumerate(lines):
        stripped = raw_line.strip()

        if stripped.startswith("#"):
            continue

        for match in SHELL_TAINTED_RE.finditer(raw_line):
            var_name = match.group()

            if EVAL_CONTEXT_RE.search(raw_line):
                severity = "HIGH"
                desc = (
                    f"Tainted variable {var_name} used inside eval/subshell/exec context. "
                    f"If this variable contains shell metacharacters (from a branch "
                    f"name, PR title, etc.), arbitrary commands can be injected."
                )
            elif _is_unquoted(raw_line, match.start()):
                severity = "HIGH"
                desc = (
                    f"Tainted variable {var_name} used unquoted in a shell command. "
                    f"Without quotes, shell word-splitting and globbing can lead to "
                    f"command injection via crafted branch names."
                )
            else:
                severity = "MEDIUM"
                desc = (
                    f"Tainted variable {var_name} found in shell script. While it "
                    f"appears quoted, verify it is not passed to eval, used in "
                    f"arithmetic, or interpolated into another command string."
                )

            findings.append(
                _RawFinding(
                    file_path=file_path,
                    line_number=idx + 1,
                    line_content=stripped,
                    severity=severity,
                    category="shell",
                    tainted_variable=var_name,
                    description=desc,
                    context_lines=_get_context(lines, idx),
                )
            )

    return findings


# ── Makefile scanner ─────────────────────────────────────────────────


def scan_makefile(
    content: str,
    file_path: str,
) -> list[_RawFinding]:
    findings: list[_RawFinding] = []
    lines = content.splitlines()
    in_recipe = False

    for idx, raw_line in enumerate(lines):
        stripped = raw_line.strip()

        if raw_line.startswith("\t"):
            in_recipe = True
        elif stripped and not stripped.startswith("#"):
            in_recipe = ":" not in stripped

        if not in_recipe and ":" not in raw_line:
            continue

        for match in MAKE_TAINTED_RE.finditer(raw_line):
            findings.append(
                _RawFinding(
                    file_path=file_path,
                    line_number=idx + 1,
                    line_content=stripped,
                    severity="MEDIUM",
                    category="makefile",
                    tainted_variable=match.group(),
                    description=(
                        f"Tainted variable {match.group()} in Makefile recipe. "
                        f"If this Makefile is invoked by CI with attacker-controlled "
                        f"branch names in the environment, this could enable injection."
                    ),
                    context_lines=_get_context(lines, idx),
                )
            )

    return findings


# ── Category → scanner dispatch ──────────────────────────────────────

_CATEGORY_SCANNERS = {
    "jenkinsfile": scan_jenkinsfile,
    "github-actions": scan_actions_workflow,
    "shell": scan_shell_script,
    "makefile": scan_makefile,
}


def scan_file_content(
    content: str,
    file_path: str,
) -> list[_RawFinding]:
    """Classify a file by path and run the appropriate scanner."""
    category = classify_file(file_path)
    if category is None:
        return []
    scanner_fn = _CATEGORY_SCANNERS.get(category)
    if scanner_fn is None:
        return []
    return scanner_fn(content, file_path)


@dataclass
class ScanDirectoryResult:
    """Result of scanning a directory tree for CI injection vulnerabilities."""

    findings: list[_RawFinding]
    files_scanned: int


def scan_directory(root: Path) -> ScanDirectoryResult:
    """Walk a directory tree, scanning all CI-related files.

    Returns a :class:`ScanDirectoryResult` with findings and files scanned count.
    """
    findings: list[_RawFinding] = []
    files_scanned = 0

    for dirpath, _dirnames, filenames in os.walk(root):
        for fname in filenames:
            full_path = os.path.join(dirpath, fname)
            rel_path = os.path.relpath(full_path, root)
            category = classify_file(rel_path)
            if not category:
                continue

            try:
                with open(full_path, errors="replace") as f:
                    content = f.read()
            except OSError:
                continue

            files_scanned += 1
            scanner_fn = _CATEGORY_SCANNERS[category]
            findings.extend(scanner_fn(content, rel_path))

    return ScanDirectoryResult(findings=findings, files_scanned=files_scanned)
