# Kuzushi Whitebox-Static

`whitebox-static` is Kuzushi's additive static-only analysis mode for source
repositories. It uses the Rust CLI/core path and keeps the existing scan,
triage, verify, patch, and report capabilities available outside this mode.

## Static-Only Contract

Whitebox-static does not perform active exploitation, HTTP replay, fuzzing, live
target scanning, harness execution, or runtime verification. It disables
verification, dynamic analysis, crypto behavioral testing, patching, and
auto-patching within the mode. Runtime exploitability is not assessed in
whitebox mode.

Whitebox-static reports use static proof language:

- `statically confirmed`
- `statically rejected`
- `needs runtime evidence`

If source evidence is insufficient, the finding must say so instead of claiming
runtime exploitability.

## zero-harness repo ingest

The mode ingests repository content without running the application or package
manager. It reuses `context:build` output where available, then reads local
source, manifests, configuration, and existing `.kuzushi` artifacts. Scanner
signals are treated as evidence inputs, not automatic true positives.

## Attack-Surface Map

Whitebox-static builds a source-derived attack-surface map from routes,
handlers, CLI entrypoints, background jobs, deserialization points, file
upload/parse paths, auth boundaries, database query boundaries, and command
execution boundaries. The map is static and may be incomplete when framework
registration is dynamic.

## source-grounded static proof

Every persisted claim must cite repository files and line spans under the repo
root. Static proof connects source evidence to security-sensitive sinks,
sanitizer or guard assessment, assumptions, and missing evidence. A scanner
signal can support a claim, but it does not confirm the claim by itself.

## Prioritized High-Impact Findings

Prioritization favors source-grounded paths that cross attacker-controlled
entrypoints, privilege or trust boundaries, sensitive sinks, weak or missing
guards, and higher-confidence dataflow evidence. Generic scanner noise should
rank below a source-linked flow with a credible impact path.

## Trigger And Impact Narratives

Reports may include a static trigger path and potential impact narrative. These
narratives describe how the code appears to route data from an entrypoint to a
sink and what impact could follow if runtime preconditions hold. They must also
state evidence limits, assumptions, and missing runtime evidence.

## Static Variant Search

When a finding is `statically confirmed`, whitebox-static can derive a reusable
source/sink/missing-guard pattern and scan sibling source files for similar
code shapes. These are review candidates only: generated variants begin as
`code_cited` or `signal_only`, never `statically confirmed` by inheritance.

## Candidate Semgrep Rules

Whitebox-static can also synthesize candidate Semgrep rules from
`statically confirmed` findings. The candidate rules are checked against
positive and negative source fixtures and are written disabled by default; a
passing fixture check only marks them ready for operator review, not enabled.

## False-Positive Memory

Whitebox-static suppression memory lives under
`.kuzushi/v2/whitebox-suppressions.json`. Each suppression records scope,
source evidence, reason, author, creation time, and expiration. Suppression
matching is snippet-hash guarded: when the cited source span changes, the
suppression becomes stale and no longer applies.

Suppressions are audit annotations, not deletion rules. Suppressed findings
remain visible in run artifacts and report/audit output, with
`whitebox-suppressions.json` listing active matches, stale suppressions, and
expired suppressions.

## Diff-Aware PR Mode

Passing `diffBase` to `sast:scan` in `whitebox-static` mode enables local
PR-scoped analysis. Kuzushi computes changed files and line ranges from local
`git diff`, expands static context to nearby callers, callees, and routes, and
writes `whitebox-diff-scope.json` in the run artifact directory. Findings are
tagged `new`, `existing`, `fixed`, or `changed-context`. This mode does not
need a remote git provider.

## Demo Fixture

The deterministic eval fixture under
`evals/kuzushi-whitebox-static/fixtures/demo-repo/` is a zero-harness Express
repository. The paired artifacts under `demo-artifacts/` exercise the full
static-only path: repository inventory, Semgrep signal normalization, CodeQL
SARIF code-flow normalization, static triage states, source citation
validation, static prioritization, and SARIF report output.

The fixture includes one statically confirmed source-to-sink SQL issue, one
statically rejected parameterized-query false positive, one authorization case
that needs runtime evidence, one sibling variant kept at `code_cited`, and one
misleading scanner-noise signal kept at `signal_only`.

## Evidence Limits

Whitebox-static cannot prove that an issue is reachable in a deployed runtime,
that a route is exposed in production, that auth middleware behaves as expected,
or that a sink is exploitable with a concrete request. Those questions remain
outside this static-only mode and should be labeled `needs runtime evidence`.
In short, runtime exploitability is not assessed in whitebox mode.
