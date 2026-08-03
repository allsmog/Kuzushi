# Kuzushi GitHub Action

The repository root now exposes a composite action that installs a pinned
published Kuzushi package, runs the canonical Rust `scan` command, and leaves a
SARIF file for GitHub Code Scanning. The action does not create a second scan
implementation: source binding, findings persistence, lifecycle receipts,
severity gating, and SARIF generation remain owned by `kuzushi scan`.

## Minimal pull-request workflow

```yaml
name: kuzushi

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: allsmog/Kuzushi@v1
        with:
          target: .
          tasks: semgrep,secret-scan,iac-scan
          fail-on: high
          sarif: kuzushi.sarif

      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: kuzushi.sarif
```

The scan exits with Kuzushi's existing contract. Exit `3` means the scan
completed and found a result at or above `fail-on`; operational failures use a
different nonzero exit. Upload SARIF with `if: always()` so evidence remains
available when a security gate blocks the job.

## Model-backed triage

Kuzushi never silently chooses a model. To enable triage, supply an explicit
model and expose the matching provider credential to the step:

```yaml
      - uses: allsmog/Kuzushi@v1
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          target: .
          tasks: agentic-sast,semgrep
          triage: true
          model: anthropic:claude-sonnet-4-6
          fail-on: high
```

The action input contains only the model identifier. Provider credentials stay
in GitHub Actions secrets and are never accepted as action inputs.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | `0.24.0-alpha.9` | Published npm version to install. |
| `target` | `.` | Repository-relative scan target. |
| `mode` | `standard` | `standard` or `whitebox-static`. |
| `tasks` | empty | Optional comma-separated scan task list. |
| `triage` | `false` | Run model-backed triage. |
| `model` | empty | Explicit `provider:model`; exported as `KUZUSHI_MODEL`. |
| `fail-on` | empty | Optional `low`, `medium`, `high`, or `critical` gate. |
| `sarif` | `kuzushi.sarif` | SARIF output path. |
| `doctor` | `true` | Run preflight diagnostics before the scan. |

## Security boundaries

- The action uses Bash arrays rather than `eval`; task and path inputs are not
  reinterpreted as shell source.
- Version, mode, triage, and severity values are validated before execution.
- The action does not request permissions itself. Workflows must grant only the
  permissions they need; SARIF upload normally requires `security-events:
  write` and scanning requires only `contents: read`.
- The action does not upload repository content, findings, or run artifacts to
  a Kuzushi service. Any network use comes from explicitly selected scanners,
  model providers, npm installation, or the caller's upload steps.
