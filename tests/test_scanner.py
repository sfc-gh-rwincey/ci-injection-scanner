"""Tests for the CI injection scanner."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner import (
    scan_actions_workflow,
    scan_jenkinsfile,
    scan_shell_script,
    scan_makefile,
    classify_file,
    scan_directory,
)


# ── GitHub Actions ────────────────────────────────────────────────────────────

VULN_ACTIONS = """\
name: CI
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Check title
        run: echo "${{ github.event.pull_request.title }}"
"""

SAFE_ACTIONS = """\
name: CI
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Check title
        run: echo "$PR_TITLE"
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
"""

VULN_HEAD_REF = """\
name: CI
on: [pull_request]
jobs:
  build:
    steps:
      - name: Checkout branch
        run: git checkout ${{ github.head_ref }}
"""


def test_actions_detects_pr_title_injection():
    findings = scan_actions_workflow(VULN_ACTIONS, ".github/workflows/ci.yml")
    assert len(findings) == 1
    assert "pull_request.title" in findings[0].tainted_variable


def test_actions_safe_env_var_no_finding():
    findings = scan_actions_workflow(SAFE_ACTIONS, ".github/workflows/ci.yml")
    assert len(findings) == 0


def test_actions_detects_head_ref_injection():
    findings = scan_actions_workflow(VULN_HEAD_REF, ".github/workflows/ci.yml")
    assert any("head_ref" in f.tainted_variable for f in findings)


def test_actions_multiline_run_block():
    content = """\
jobs:
  build:
    steps:
      - name: Print branch
        run: |
          echo "branch: ${{ github.ref_name }}"
          echo "done"
"""
    findings = scan_actions_workflow(content, ".github/workflows/ci.yml")
    assert len(findings) == 1
    assert "ref_name" in findings[0].tainted_variable


# ── Jenkinsfile ────────────────────────────────────────────────────────────────

VULN_JENKINSFILE = """\
pipeline {
  stages {
    stage('Build') {
      steps {
        sh "git checkout ${env.BRANCH_NAME}"
      }
    }
  }
}
"""

SAFE_JENKINSFILE = """\
pipeline {
  stages {
    stage('Build') {
      steps {
        sh 'git checkout main'
      }
    }
  }
}
"""


def test_jenkinsfile_detects_branch_injection():
    findings = scan_jenkinsfile(VULN_JENKINSFILE, "Jenkinsfile")
    assert len(findings) >= 1
    assert any("BRANCH_NAME" in f.tainted_variable for f in findings)


def test_jenkinsfile_single_quote_safe():
    findings = scan_jenkinsfile(SAFE_JENKINSFILE, "Jenkinsfile")
    assert len(findings) == 0


# ── Shell scripts ─────────────────────────────────────────────────────────────

VULN_SHELL = """\
#!/bin/bash
git checkout $GITHUB_HEAD_REF
"""

SAFE_SHELL = """\
#!/bin/bash
git checkout "${GITHUB_HEAD_REF}"
"""


def test_shell_detects_unquoted_var():
    findings = scan_shell_script(VULN_SHELL, "scripts/build.sh")
    assert any("GITHUB_HEAD_REF" in f.tainted_variable for f in findings)
    assert any(f.severity == "HIGH" for f in findings)


def test_shell_quoted_is_medium_or_less():
    findings = scan_shell_script(SAFE_SHELL, "scripts/build.sh")
    # Quoted usage may still flag at MEDIUM — that's correct
    for f in findings:
        assert f.severity in ("MEDIUM", "LOW")


# ── Makefile ──────────────────────────────────────────────────────────────────

VULN_MAKEFILE = """\
deploy:
\tgit push origin $(BRANCH_NAME)
"""


def test_makefile_detects_tainted_var():
    findings = scan_makefile(VULN_MAKEFILE, "Makefile")
    assert any("BRANCH_NAME" in f.tainted_variable for f in findings)


# ── File classifier ───────────────────────────────────────────────────────────

def test_classify_actions_workflow():
    assert classify_file(".github/workflows/ci.yml") == "github-actions"
    assert classify_file(".github/workflows/release.yaml") == "github-actions"


def test_classify_jenkinsfile():
    assert classify_file("Jenkinsfile") == "jenkinsfile"
    assert classify_file("Jenkinsfile.prod") == "jenkinsfile"


def test_classify_shell():
    assert classify_file("scripts/build.sh") == "shell"


def test_classify_makefile():
    assert classify_file("Makefile") == "makefile"
    assert classify_file("build.mk") == "makefile"


def test_classify_unknown_returns_none():
    assert classify_file("README.md") is None
    assert classify_file("src/main.py") is None


# ── scan_directory smoke test ─────────────────────────────────────────────────

def test_scan_directory_finds_vulns(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(VULN_ACTIONS)
    (tmp_path / "Makefile").write_text(VULN_MAKEFILE)

    result = scan_directory(tmp_path)
    assert result.files_scanned == 2
    assert len(result.findings) >= 2


def test_scan_directory_empty_repo(tmp_path):
    result = scan_directory(tmp_path)
    assert result.files_scanned == 0
    assert result.findings == []
