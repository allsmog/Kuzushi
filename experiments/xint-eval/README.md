# Xint-recall eval harness

Goal: run upgraded Kuzushi against pre-patch slices of the codebases where
Theori's [Xint Code](https://theori.io/blog/announcing-xint-code) found public
0-day bugs, and measure recall vs. an oracle.

## Targets

| Slice    | Bug                                  | Notes                                                 |
|----------|--------------------------------------|-------------------------------------------------------|
| linux    | Copy Fail — CVE-2026-31431           | Linux crypto/ subsystem, AF_ALG + splice() chain      |
| postgres | 20-year data-exfil / RCE             | Public detail behind paywall; oracle is best-effort   |
| redis    | ZeroDay Cloud 2025 0day              | Public detail sparse; oracle is best-effort           |
| mariadb  | ZeroDay Cloud 2025 0day              | Public detail sparse; oracle is best-effort           |

Only Copy Fail has a clean public root cause (xint.io blog). The other three
oracles ship with `expected_min_recall: 0.0` and are intended to be edited as
disclosure quality improves.

## Layout

```
experiments/xint-eval/
  oracles/<slice>.json     ground truth
  scope/<slice>.txt        sparse-checkout subdirs (one per line, glob OK)
  slices/<slice>/          git submodule, pinned to pre-patch SHA
  scripts/                 fetch / run / score
  reports/<ISO-ts>/        per-run output; HISTORY.md tracks deltas
```

## Workflow

```bash
# Wiring sanity check (no LLM cost) — runs the integration tests
# against synthetic mini-slices to verify FindingStore → CLI → scorer
# is intact end-to-end. Use this after any architectural change.
scripts/self-test.sh

# Live recall (real LLM, real slices) — requires OAuth credentials
# and pinned pre-patch SHAs.
scripts/verify-tooling.sh          # checks oauth credentials, semgrep, codeql, tree-sitter
scripts/fetch-slices.sh            # add submodules, sparse-checkout, pin SHAs
scripts/run-all.sh                 # 4 tmux panes, one per slice

# Or one slice at a time
scripts/run-slice.sh linux
scripts/score.sh reports/<ts>/
```

## Tolerance modes

The scorer (`crates/kuzushi-eval`) reports each oracle entry under four
tolerance modes simultaneously, so a miss is diagnosable as "wrong file" vs.
"right file, wrong region" vs. "near miss":

- `exact_line`     — start_line == oracle.line
- `pm_lines:10`    — |start_line − oracle.line| ≤ 10  (primary)
- `function`       — finding lands inside the enclosing function (tree-sitter)
- `file_only`      — file_path == oracle.file

CWE match is required for `pm_lines:10` and tighter; `file_only` is permissive.

## Per-slice budget

Default budgets passed to `kuzushi scan --budget`:

```
triage=50       deep-audit=200      full-mode=300
```

Hard ceiling via `KUZUSHI_MAX_USD_PER_RUN` env var.

## Editing oracles

Disclosed CVE detail can change. Oracles are JSON, version-controlled, and
explicitly best-effort. If a finding lands "near" but doesn't match, the
scorer flags it as `near-miss` rather than auto-fail — that's the signal to
update the oracle.
