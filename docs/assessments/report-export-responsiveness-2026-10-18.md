# Responsive Report export and consistent reads

Report export previously performed ledger and filesystem work on the terminal
event loop. A slow export could freeze typing, reading and resize. Interactive
export now uses one background filesystem worker, with visible progress and a
completion receipt. Model jobs and investigation spending are unchanged.

## Export ownership and recovery

Submission captures the target, study, format, completeness, destination,
identity policy and review-yield configuration. Another export request is
refused without queuing. Report retains reader key ownership; Escape returns to
the workflow composer while writing continues. Reading, typing, resize and
navigation remain available.
The current selection pins `EXPORTING` beside its path. The footer identifies
the pending operation; exit waits for its result.

Completion preserves the page, draft, cursor and reading position. A receipt
belongs to the submitted target and export selection. Scope changes and target
choice restoration retire that ownership, while cache refreshes preserve it.
Editing the next format or destination cannot inherit an earlier result. A
completion for another view or target announces its actual destination without
redirecting the operator. Worker panic produces an uncertain-output error and
requires destination inspection before an explicit retry.

CLI and scripted exports retain synchronous return values. The TUI continues
through the existing workspace application service. No module name, option,
persisted schema, model policy or additional campaign job is introduced.

## Consistent preparation

Background export can overlap ordinary triage and spending updates. The shared
exporter now prepares findings through the existing SQLite read-snapshot API.
Before publication it checks both projection sequence/generation and the
connection-local change counter. The latter includes commits outside finding
events, such as accounting writes. A change refuses the prepared export and
asks for a refresh and explicit retry. There is no automatic repair loop.

The guard covers workspace and selected-run exports and previews. It runs
before new export files or receipts are published. Existing filesystem artifact
authentication remains in force; the ledger snapshot does not freeze source or
campaign files. Complete-directory publication remains as qualified in the
[bundle assessment](report-bundle-publication-2026-10-17.md).

## Focused evidence

All 220 distinct focused Rust checks pass, including eight background-export
cases, four revision checks, four projection-snapshot cases, existing export
formats and aliases, Report readers/keys, footer bindings, review writes and quit
chords. The locked workspace build, Core/TUI Clippy and risk proxy pass. Focused
Rust checks use an isolated home directory. The final quick repository receipt
is recorded separately with the draft.

Visual inspection also found that a completion notice could consume the entire
findings area at 40 columns while a draft remained active. Compact Review now
reduces passive header guidance independently of composer ownership. Finding,
draft, allowance and notice remain visible together. Active work, approvals,
result cards and budget attention retain their existing chrome contracts. The
six-size rendering regression, twenty chrome checks and twenty-four phase
layout/matrix checks pass. The final risk proxy covers nineteen changed code
files.

The first native candidate exposed a real completion race: the JSON file was
written, but a transient cache refresh discarded its receipt. It stopped with
179 machine passes and one failure. The selection epoch now records operator
scope changes independently of hydration readiness. A controlled refresh
regression protects that repair. Initial test-fixture and SQLite integer-type
compile failures are retained and excluded from passing counts.

The contention fixture uses an asserted exclusive SQLite lock. A separate
probe established that an ordinary WAL write transaction can leave reads
unblocked, so it cannot establish the intended slow-export condition.

The first dedicated latency candidate aimed printable probes at reader controls
and omitted the isolated home on restart. Its 29 machine passes and fifteen
failures are retained. The corrected journey returns through the reader's
visible Back action and verifies input on the real workflow composer, while
keeping the same 300 ms echo allowance and asserted exclusive-lock condition.
Restart uses the complete isolated launch environment. The strengthened unit
case also verifies visible typing and exact multiline paste after the actual
Report return transition. Accepted exports clear their previous owned notice.


## Final native evidence

| Sequential case | Machine passes | Failures | Capture pairs | Pending human judgments |
| --- | ---: | ---: | ---: | ---: |
| J121, complete investigation and report recovery | 210 | 0 | 127 | 20 |
| J331, contended export and no-color restart | 54 | 0 | 36 | 2 |
| Total | 264 | 0 | 163 | 22 |

Both cases use the same frozen build in `native-v5`: thirteen executables,
4,616 source inputs and 811 runtime inputs, authenticated before and after
execution. The main executable SHA-256 is
`b603afc55bd22c72a4c8c3918655670b85aad6ee222e0449205845cef0fb91f5`.

J331 holds an asserted exclusive ledger lock for four seconds at each size.
Independent verification places every typing capture inside its actual lock
window. The six poll-based echo samples are 85, 80, 76, 73, 74 and 5 ms at
120, 160, 96, 80, 60 and 40 columns respectively, below the unchanged 300 ms
allowance. Review and its exact draft remain selected when export completes.
The final 40-column frame explicitly retains the finding beside the notice.
These six samples qualify this controlled contention case. General large-ledger
throughput and physical latency equivalence with reference products remain open.

Actual export bytes and SQLite rows preserve four observations, two findings,
three human-decision records, five committed calls, one unresolved reservation
and two unused protected Review calls. The three fixed Scan jobs and their
plans/queues stay unchanged. JSON, bundle metadata and investigation receipts
match; SARIF preserves the same study and decisions. Unknown dollar consumption
stays unknown. Source bytes, recorded source identity and inactive global context
are unchanged. Export adds no jobs, provider requests or target-source execution.

Twenty-one final terminal-cell reconstructions were visually inspected: eight
Report frames and thirteen contention/completion/restart frames. They use a
chosen font and background and are not OS screenshots or formal operator
approval. All twenty-two human judgments remain pending. Report metadata density
and broader TUI acceptance remain open. A prior otherwise successful latency
candidate observed the restart while its data was still loading; the final
journey waits for the settled allowance row before recording recovery.

Evidence root: `/tmp/kuzushi-report-responsiveness-20261017`, including final
`native-v5` manifests, source/queue/ledger proofs, measured echo samples, capture
provenance, inspection records, focused logs and the dirty draft quick receipt.
Five provider requests are intercepted in the owned investigation; no new live
request is added. Historical real requests remain fourteen with no approved
inference capacity left. Four delivery items are locally verified and five
remain open. This increment remains a draft on main after `f4f85db71a`.
