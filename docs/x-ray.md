# x-ray — repository analysis report

Operator guide for the `x-ray` module: Pashov-style X-Ray repository
analysis. It produces a persisted analysis report of the repository's
structure, security-relevant surfaces, and reviewer orientation notes —
review context for humans and downstream tools, not findings.

Use it early in an engagement when you want a structured "what is this
codebase" report; use `threat-model:build` when you want threats and a DFD,
and `scan` when you want findings.

## Tools

| Tool | What it does | Model? |
| --- | --- | --- |
| `x-ray:run` | Analyze repository structure, entry points, invariants, and attack surface; persist the report artifact. | yes |
| `x-ray:read` | Read the latest repository architecture and attack-surface report. | no |

In scan mode the hidden `x-ray:x-ray` DAG task contributes the same report
after `context:build` completes.

## Usage

```bash
# Build context first — X-Ray consumes the repository context snapshot.
kuzushi --target . run context:build --input '{}'

# Run the analysis (requires a configured model).
kuzushi --target . run x-ray:run --input '{}'

# Read the persisted report later, with no model cost.
kuzushi --target . run x-ray:read --input '{}'
```

Options on `x-ray:run`:

| Option | Type | Purpose |
| --- | --- | --- |
| `target` | path | Repository to analyze (defaults to the session target). |
| `model` | string | Per-run model override; otherwise the session model is used. |
| `effort` | string | Runtime reasoning effort hint (advanced). |
| `maxBudgetUsd` | float | Observed-spend stop checked after model turns; the crossing turn may exceed it, and incomplete cost receipts stop follow-up turns or repair (advanced; alias `max_budget_usd`). |

## Output

The report lands under the run's artifact directory
(`.kuzushi/v3/runs/<runId>/`) and is summarized in the tool result envelope.
`x-ray:read` always returns the latest persisted report, so other modules
and operators can consume it without re-spending model budget. Legacy
`threat-leads:*` tooling remains exact-only; new flows should prefer
`x-ray:run`/`x-ray:read` plus `threat-model:build` when they need repository
orientation and threat-model context.

## Notes

- X-Ray output is orientation context: treat its claims as leads to verify
  against source evidence, not as proven findings.
- The Build X-Ray planning task is opt-in for source repositories; the 組
  KUMI-KATA phase picker preselects it only for reverse-engineering
  targets where the artifact is foundational.
