# Spending control acceptance

Explicit allowance, durable provider reservations and honest unknown-cost states
are implemented and verified locally for the supported investigation workflow.
The selected OAuth runtime enforces finite provider-request limits. Dollar stops
use returned consumption and can overspend before a receipt arrives. The Cost
reader now makes that distinction explicit. Full module usefulness, investigation
exports and operator UX acceptance remain open in their respective requirements.

## Requirement reconciliation

| Requirement | Authoritative behavior and evidence |
| --- | --- |
| Explicit allowance before the first model action | Shared `modules/allowance_dispatch.rs` requires explicit or authenticated inherited accounting. Native runtime query, next-step and loop preflight reject unbound model work before bridge/provider execution. Unsupported runtimes refuse binding. |
| One investigation accounts for context, scope, discovery, Review, Report and learning | Descriptor-owned categories bind the host's `AllowanceWork`. The executor cannot choose a cheaper category, forge a result reference or borrow protected Review capacity for context work. Current ledger and prepared-dispatch tests cover all categories, inherited attribution and zero-call refusal. |
| Reserve atomically before every potentially billable request | `spend/allowance/admission.rs` checks revision, model, fixed work and capacity inside an immediate SQLite transaction before committing a fresh reservation. Independent connections cannot overbook the final calls or work attempts. The admission reply follows the commit. |
| Internal turns and retries consume the same allowance | The bridge requests host admission for each invocation and disables invisible SDK retries. Adapter tests exercise internal turns, retries inside one bridge and outer transport retries. Parallel bridge sessions preserve Review capacity. |
| Cancellation and restart retain commitments | Dropping a reservation does not release its slot. Current tests cancel an in-flight bridge and reopen the ledger with the reservation still committed and unresolved. Settled unknown-price calls consume their slot too. J227 restarts with the same completed call and unknown charge receipt. |
| Revised approval is explicit and cannot reset usage | Approval uses an immediate transaction and optimistic revision checking. Revisions preserve committed calls and the selected protected allocation. Work attempts and input/source/configuration bindings remain authenticated. Stale revisions cannot admit another request. |
| Exact work, model, workers, limits, Review reserve and uncertainty are visible before approval | The published [finite study acceptance](finite-study-acceptance-2026-10-17.md) pins canonical prepared terms through the six-size matrix. It verifies explicit attempt/call revisions, unchanged job membership and no implicit cap doubling. This increment changes only the Cost presentation in production. |
| Enforceable request limits remain distinct from dollar stops | The OAuth adapter does not enforce a conservative bound on every charge or its requested output-token ceiling. Approval discloses unknown dollars and requires explicit provider-call limits. The Cost reader labels `observed stop` and `max stop setting`, explains receipt latency and keeps unknown values and percentages qualified. |
| Finish/report, revise work or approve a specific new allowance at a limit | Finite study J121/J130/J131 cover partial results, parked jobs, cancellation and separately reviewed revisions. Their admission and queue policy sources are unchanged here. Current J227 exports a findings SARIF while the session spending halt remains armed, then refuses another model-backed launch. |
| Shared dispatch and public compatibility | Scan, shell and run consume prepared descriptor input and the same accounting boundary. Governance input is removed before engine parsing, and accounting provenance is host-owned. Current tests include authorization, malformed references, zero capacity, inherited category mismatch and foreign ledgers. No option, runtime policy or persisted schema changes in this increment. |

The original per-operation estimate ledger and session dollar setting remain
observed-spend controls. Estimates and maximum permitted settings do not establish
a conservative upper bound on provider charges. Exact, incomplete and unavailable
cost states remain separate through aggregation and display. A completed request
can be settled while its dollar charge remains unknown.

## Cost reader and native verification

Visual inspection found that Cost described a session stop as a `cap` and its
maximum setting as a `hard ceiling`, without the receipt-latency explanation
already present in Setup. The reader now uses explicit stop labels and explains
that approved call limits apply separately. Values remain before the explanation,
and keyboard paging reaches every wrapped line at all six sizes. Drafts, the
armed halt and the selected amount survive reading and resize.

All 125 distinct focused Rust checks pass: 77 Core, 15 adapter and 33 TUI checks.
Nine bridge admission checks also pass. The changed Cost model and reader's ten
checks were rerun after the wording change and are counted once. The locked
workspace build, all-target TUI Clippy and the two-production-file risk proxy
pass. Final quick repository verification is recorded with this draft.

| Final tmux case | Machine passes | Failures | Capture pairs | Pending human judgments |
| --- | ---: | ---: | ---: | ---: |
| J227, unknown cost, armed halt, export and restart | 36 | 0 | 21 | 3 |
| J166, exact allowance inspection without execution and no-color restart | 18 | 0 | 19 | 3 |
| Total | 54 | 0 | 40 | 6 |

Independent verification checks actual SQLite rows, approvals, attempt counts,
source hashes, the exported SARIF and capture provenance. J227 uses one fully
intercepted request with GPT-5.5 and medium reasoning. It has one settled
reservation with unknown price, one consumed work attempt, no observations or
decisions and one unused protected Review call. Its findings-only SARIF contains
zero results; this does not qualify a full investigation export. J166 retains
three approved jobs, two available non-Review calls and one protected Review call
with zero attempts, reservations, observations or decisions. Reading never starts
those jobs or accepts Map.

Both cases authenticate 13 executables, 4,608 source inputs and 808 runtime inputs
before and after execution. The executable SHA-256 is
`9416ab5672aae9864cbd5a0f78bc54a98598ae9335924862e96b9ea3d12983e9`.
J227 is retained in `native-v3`, J166 in `native-v4`. Their production binaries
and source manifests match. Only J166's idle-exit expectation changed between
runtime bundles, after J227 completed. Twenty terminal-cell replays were visually
inspected across the size matrix, paging, settled Report/export and restart.
They are ANSI reconstructions, not OS screenshots or formal operator approval.
All six human judgments remain pending; transcript metadata is still dense.

Three failed J166 candidates are retained: a checkpointed read-only SQLite
observer failure, an obsolete Map entry expectation and an obsolete idle-exit
confirmation expectation. The observer now uses the existing read-only snapshot
helper; fresh targets enter Setup and idle Ctrl+C exits directly. Original
no-execution and no-phase-completion assertions remain. The Report check was also
strengthened to await settled data and inspect a real export rather than credit
an initial loading frame.

Evidence root: `/tmp/kuzushi-spending-acceptance-20261017`, including focused logs,
build/Clippy/risk results, final native manifests, independent ledger proofs,
visual-inspection records and the draft quick receipt. No live provider request
or target-source execution is added. Historical real requests remain fourteen
with no approved capacity left. Four delivery items are locally verified; five
original delivery items remain open. This increment remains a draft on main.
