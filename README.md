# ci-injection-scanner

GitHub Action that detects CI/CD expression injection vulnerabilities in pull requests and pushes.

Covers **GitHub Actions**, **Jenkinsfiles**, **shell scripts**, and **Makefiles**. Uses an optional LLM judge (via GitHub Models) to eliminate false positives.

## Quick start

Add to any repository as a required status check:

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  ci-injection:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      models: read        # required for LLM judge via GitHub Models
    steps:
      - uses: actions/checkout@v4

      - uses: snowflakedb/ci-injection-scanner@v1
        with:
          fail-on-severity: HIGH
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `fail-on-severity` | `HIGH` | Minimum severity to fail the check (`HIGH`, `MEDIUM`, `LOW`, `none`) |
| `use-llm-judge` | `true` | Use GitHub Models LLM to reduce false positives |
| `judge-model` | `gpt-4o-mini` | Model for the judge (`gpt-4o-mini`, `gpt-4o`, `claude-3-5-sonnet`) |
| `github-token` | `${{ github.token }}` | Token for GitHub Models API — automatic in Actions |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of confirmed findings after judge filtering |
| `verdict` | `clean` or `findings` |

## What it detects

### GitHub Actions — expression injection
```yaml
# Vulnerable: attacker controls PR title
- run: echo "${{ github.event.pull_request.title }}"

# Safe: environment variable intermediary
- run: echo "$PR_TITLE"
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
```

Tainted sources checked: `github.head_ref`, `github.ref_name`, `github.event.pull_request.title`, `.body`, `.head.ref`, `github.event.commits[*].message`, and more.

### Jenkinsfile — Groovy interpolation
```groovy
// Vulnerable: branch name injected into sh step
sh "git checkout ${env.BRANCH_NAME}"

// Safe: single-quoted string
sh 'git checkout ' + env.BRANCH_NAME
```

### Shell scripts — unquoted tainted variables
```bash
# Vulnerable: unquoted $GITHUB_HEAD_REF
git checkout $GITHUB_HEAD_REF

# Safe: quoted
git checkout "${GITHUB_HEAD_REF}"
```

### Makefiles — tainted variable expansion in recipes
```makefile
# Vulnerable
deploy:
    git push origin $(BRANCH_NAME)
```

## LLM Judge (GitHub Models)

When `use-llm-judge: true` (default), the action calls the GitHub Models API with your `GITHUB_TOKEN` to assess each raw static finding:

- **TRUE_POSITIVE**: confirmed injection risk — gets annotated and counted
- **FALSE_POSITIVE**: filtered out silently

The judge is fail-safe: if the API call fails for any reason, all findings are treated as TRUE_POSITIVE (conservative).

`gpt-4o-mini` is the default — fast (~3s), low cost, handles the structured classification well. Use `gpt-4o` or `claude-3-5-sonnet` if you need higher accuracy on subtle cases.

## Setting as a required status check

1. Add the workflow to your repo
2. In **Settings → Branches → Branch protection rules**, add `ci-injection / ci-injection` (the job name) to **Required status checks**
3. PRs cannot merge until the scan passes

## Org-wide deployment

To enforce across all repos in an org, add this to an **org-level required workflow** (GitHub Enterprise):

```yaml
# In your org's .github repo: workflow-templates/ci-injection-scan.yml
name: CI Injection Scan
on:
  pull_request:
  push:
    branches: [main]
jobs:
  ci-injection:
    uses: snowflakedb/ci-injection-scanner/.github/workflows/reusable.yml@v1
```

## Relationship to Mythos-Zero

This action handles **real-time enforcement** (blocks PRs, ~15s latency). The Mythos-Zero `github_audit` pipeline handles **org-wide stale approval scanning** (branch protection drift, CODEOWNERS coverage, repos without this action installed).
