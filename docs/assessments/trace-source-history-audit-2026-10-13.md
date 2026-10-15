# Trace results keep their own source history

The Trace reader previously loaded all operator-requested graph steps, unioned
the newest result into them and displayed the newest source status over that
combined list. A later empty result could therefore show earlier steps beside
"0 new steps" and a current source receipt. Recorded generations were preserved
in storage but mixed in presentation.

The reader now authenticates the newest completed or partial result first and
uses exactly its steps, questions, notes and source receipt. Earlier graph rows
and run artifacts remain stored. A later empty result remains empty; it neither
republishes earlier claims nor establishes that a finding is fixed. If no
authenticated result exists, legacy graph history stays readable with an
explicit missing per-run source binding. Corrupt canonical results remain
errors instead of being replaced with legacy rows.

Trace labels now say recorded claims and notes, with an independent-review
warning. Review exposes the same reader with `t`, retains its phase and restores
the exact prior focus on back. Its own surface owns paging, composer and plain
output. Reading and drafting a command start no model work. The existing source
comparison still distinguishes unchanged,
changed, missing and unverifiable source identity. An unchanged source receipt
does not verify model citations, symbols or a data-flow relationship. Finding
generation binding and broader source/scope qualification remain open.

`trace:expand` is now Labs, displayed as **Draft data-flow claims**. Its exact
name, options, Prove authorization and auxiliary status remain. This retained
phase is a compatibility surface for source analysis, not a guided exploit or
reproducer phase. Optional source work uses Discovery accounting, preserving
protected Review capacity. Every successful response is partial, with additive
sourceReferencesVerified=false, dataflowVerified=false and coverage.complete=false.
Existing step, question, note, source and cost fields remain. Historical receipts
retain their statuses. Cancellation before work and after a response prevents
publication at those checks; interruption or atomic publication during the
append batch is not qualified.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | Optional source-flow questions around one finding. Useful tracing, citation accuracy and precision remain unqualified. |
| Phase | Legacy Prove authorization retained; no phase checkpoint or guided Prove work. Discovery accounting preserves Review. |
| Inputs | Resolved finding, target workspace, selected model and explicit allowance. Immutable finding/context/scope binding is unsupported. |
| Execution | Real prepared dispatch uses the source snapshot and static-evidence store, with accounting-aware owned responses. No live provider requests in this increment. |
| Outputs | Partial source claims and preserved cost uncertainty. Store round trips, authenticated canonical results and native consumers are exercised separately. |
| Failure | Missing model/finding/input, protected capacity, cancellation after response, corrupt result and changed source have focused evidence. In-flight append recovery remains open. |
| Resources | Real preparation requires allowance; the owned query reserves Discovery and cannot borrow protected Review. Model turns, complete prompt/output bounds and operation-wide resource limits remain unqualified. |
| Scope | Target-root source policy; no accepted scanContextRef or authenticated citation validation. Complete coverage is explicitly false. |
| Interfaces | Existing JSON/plain and exact dispatch remain. Default Core discovery omits the action; legacy Trace and Replay retain recorded history. Full interface/configuration qualification remains open. |
| Product value | The observed history-mixing defect is corrected. Useful generated hops and full reference UX parity remain unproven. |

One hundred and five distinct focused Rust checks pass across execution, phase policy,
structured contracts, graph storage, authenticated history, reader labels,
source drift, cancellation, lifecycle/cost receipts and shell input handling.
The 184-tool dispatch-policy fingerprint is unchanged. The locked workspace
build and all ten exact quick-plan commands pass, including 391 Node checks
and the CRAP-risk proxy over 577 changed code files. Package commands ran
directly without disabling signature verification. Scoped product-copy review
is CLEAN. The initial CRAP check found 41 logical lines in the executor;
extracting required trace handles resolves it. Older cost tests failed because
they omitted the newly required allowance; they now approve a finite fixture
allowance and exercise real reservation/settlement. A test-only cancellation
reference error was corrected. The full Rust suite was not run.

Initial native setup failed before the TUI launched. A diagnostic rerun hit a
reused receipt id, and the next isolated run correctly refused to let an
auxiliary trace result own a Prove checkpoint. Fixture runs now use the product run-id generator, retaining its timestamp
ordering and collision protection, and record diagnostics before surfacing errors. Direct access from Review removes the need for an artificial phase record.
A later terminal run exposed that UUID-shaped fixture run ids did not follow
the product timestamp ordering, selecting the earlier result. The fixture now
uses the real run-id generator rather than inventing that contract. The fixture uses only labeled
synthetic source receipts. No Prove job, source program, standalone scanner or
provider request runs. Retained failures establish the limits of those attempts;
they are not credited as passing captures.

Corrected J243 records 23 machine passes, zero failures and 18 authenticated
capture pairs across six sizes and no-color restart. It shows the exact latest
claim in Review, excludes the earlier claim from that reader, reopens the
earlier canonical receipt in Replay and retains both source receipts, active
context and the original human decision. The harness uses Escape to return to
the composer; its earlier `i` key belongs to invariant discovery and was
corrected after inspecting the failed capture. No model work ran in that attempt.
Four human questions remain pending, operatorApproved is false and raw status
is REVIEW_REQUIRED. Final product SHA-256:
`5e10ac3d3fd9c7104bd96970168bf04f8192768b83ff0b8b0e82e0745fa81475`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/trace-review-corrected-tui/20261013-231037/J243`.

Sequential J121 on the same immutable product build records 109 machine passes,
zero failures and 87 authenticated captures. Accepted context, three fixed
passes, protected Review, spending halt, partial/final reports, a specific
allowance revision, original-job resume, source reassessment and restart remain
intact. Four responses are fully intercepted, with zero live requests. Fifteen
human questions remain pending and operatorApproved remains false. Captures:
`/tmp/kuzushi-tui-integration-20261012/trace-review-complete-tui/20261013-231356/J121`.

The registry retains 113 visible actions, with 88 Core, 20 Labs and five
Compatibility. Eleven in-scope tools remain unassigned. Model usefulness,
immutable context/finding binding, scoped source tools, citation authentication,
whole-operation bounds and final human UX review remain open. No implementation
is deleted or broad milestone closed. The live allowance stays exhausted at
six of six. Evidence and retained failures:
`/tmp/kuzushi-tui-integration-20261012/trace-source-history-audit`.
