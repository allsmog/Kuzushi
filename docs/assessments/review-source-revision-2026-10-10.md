# Review planning across source revisions

New Review drafts freeze optional `observationSources` beside the existing exact
generation selection. Each source record retains the original run's recorded Git
metadata. The form labels its planned Review source separately from the recorded
observation commit and calls out different commits. Missing, malformed or legacy
metadata stays unknown. A matching SHA with dirty content is not labeled unchanged
source. These are recorded metadata facts, not a proof of complete coverage or a
fix. Context, verdict applicability and human decisions retain their existing
separate contracts.

Source capture uses the bounded shared run reader without repair or current-SHA
substitution. Commit syntax and branch size/control characters are checked;
foreign generation/run relationships are rejected. The existing version 1 plan
format accepts absent source records. New fields are additive; Rust literal
construction migration is documented in RELEASING.md. No tool input or dispatch
policy changes.

## Observed gap and verification

Initial J187 had 21 machine passes and 13 native captures. Headless shared
preparation refused stale default Map context and permitted explicit omission.
The form inherited four committed calls, but displayed only the new Review
source and an observation run id. Its assistant judgment is partial, rather than
crediting full source comparison from the passing machine checks.

Final J187 is
`/tmp/kuzushi-review-source-20261010/native/20261010-230303/J187`.
It has 24 machine passes, zero failures and 24 authenticated native captures at
40×12, 60×20, 80×24, 96×89, 120×36 and 160×48, plus no-color restart. Native SHA-256:
`e5a46208fd1906541ab3b515ee668f8b14fad157b029c28f7f90a4913c20d0c1`.
The observation records commit `f29dc288e0660ad20d074fc219c025f98ef7d155`;
the planned Review source is `30baa1f1a56bae4cbb431ba0d453a59a8108a71b`.
The cited public-example file is unchanged. At 40×12, page seven reaches its
recorded commit and page eight completes the source warning; additional pages
stop at a stable tail. This verifies readable provenance, not operator delight.

Report keeps the earlier three-pass Scan study rather than replacing it with
an unlaunched Review draft. It reports earlier source, four committed calls out
of eleven and two protected Review calls. Restart retains those terms and
actual Escape returns to the named campaign. One scoped assistant judgment stays
separate from raw REVIEW_REQUIRED and operator approval false.

The test uses an existing owned revision branch; it creates no commits and never
executes target source. A controller restores fixture main in `finally`, including
after journey failure. Both fixture and Kuzushi end on main. Model configuration
and the context manifest remain byte-identical. The ledger keeps four provider
reservations, six prior work attempts, three observations and one scripted human
false-positive decision. No model request or verdict is added. Two explicitly
prepared offline draft versions remain unapproved and unlaunched.

Twelve focused Core and thirteen TUI tests pass, including three pure projection
tests. One initial TUI assertion incorrectly required a long label and source
identity on the same wrapped line. Pure source projection tests and the native
journey now check the actual presentation contract. Workspace build and the
140-file production risk proxy pass. All ten repository summary gates pass. The initial run stopped on assessment
wording; its failed receipt is retained at
`/tmp/kuzushi-review-source-20261010/failed-wording-verify-receipt.json`.
A focused architecture recheck and then the full summary pass after that wording
correction. The unsigned receipt is
`/tmp/kuzushi-review-source-20261010/precommit-verify-receipt.json`; it records
dirty/drifted state and cannot attest to a clean commit. Final evidence-only edits
receive focused documentation checks.

## Remaining acceptance

Live Review adapters and retries remain pending explicit approval of the already
prepared bounded test. Same-SHA dirty content has focused unit evidence, but no
new native journey in this increment. Cancellation, exhausted allowance, complete
per-tool readiness, context experiments, useful lessons, physical screen
acceptance and full reference parity remain open. No module is promoted, retired
or deleted; none of the nine broad milestones is closed.
