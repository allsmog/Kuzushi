# Exact context source checks

The study context browser now offers `c` to check an inspected exact revision.
`Space` opens all seven context actions in a bounded keyboard menu. Checking
uses shared prepared dispatch, makes no model request and saves an inactive
revision in the same lineage. Inspection and selecting it for a study remain
separate actions. The source document, its recorded scope, active pointer and
compatibility mirror are preserved.

The additive `threatModelRef` option on `threat-model:verify` requires recorded
content identity and SHA to match before checking citations, links and bounded
coverage. Inline scope overlays and different write targets are refused.
`write=false` returns the check without publishing. Existing unbound checks
retain their behavior. Source is checked after a store-lock wait before
publication, and after completion. A post-save SHA change retains the saved
revision with a partial receipt. Cancellation does not publish a revision while
waiting for the store. An object can remain orphaned when validation stops
after its write but before manifest publication.

Exact reads retain the immutable scanner document and add a separate versioned
`sourceState` receipt. The bounded, cancellable content walker compares source
identity and reports progress. SHA, content and dirty-state drift are distinct
from unknown identity. The browser labels the stored stamp as the last recorded
check, rather than current verification, and shows the source state captured at
inspection. A stopped check marks that inspection uncertain. Catalog loading
does not establish missing membership. Source matching does not establish
architecture accuracy, finding truth or complete repository coverage.

Late check results preserve the editor, menu, diagram, paging and raw reading.
Changed selections or targets retain their current state. Exact read receipts
from another target are ignored even when their context reference matches.
The check cannot change an accepted plan, start scans, increase allowances or
invoke another model.

Thirteen focused exact-check tests, 19 existing verification tests, 34 store
regressions, three shared source-snapshot tests and two exact-reader tests pass.
The 81-test study/TUI suite and workspace build pass. The CRAP-risk proxy passes
for 130 changed code files. Repository summary gates and final file/binary
fingerprints are recorded in `/tmp/kuzushi-context-check-20261007/closeout.json`.
These focused checks do not establish that the entire Rust/TUI suite is green;
the prior excluded compatibility failure remains outside this increment.

Final native J106 is
`/tmp/kuzushi-context-check-20261007/tui/20261007-033332/J106`.
It records 26 machine passes, six separately judged ask passes, 12 related-frame
passes and 24 captures across all six supported sizes and real no-color restart.
Native SHA256 is
`272cc6676ee721df788d67234ee5691f85a788dffe003357612ef0697f0f96d7`.
Raw exit 4 and `REVIEW_REQUIRED` are retained separately from the screen review.
The oracle authenticates inactive saves, original objects, active context,
recorded scope, real SHA transitions and source bytes. It proves no new revision
after either drift refusal, exact binding of an unapproved three-pass draft,
and zero scans, model requests or target-source execution.

Predecessors remain. The first run had 25 machine passes but failed screen
review because restart reused a verified label without disclosing drift,
loading was described as missing membership, and the tiny menu had a duplicate
border. Those defects are corrected. A later run captured transient Run Focus
completion instead of the restored context selector. Its screen review fails
that checkpoint; the final recipe explicitly waits for inspection instructions.
The driver is unchanged. Focused test failures from invalid fixtures, source
status precedence, ineffective paging and a missing target in a synthetic read
receipt remain in the evidence directory.

The fixture is labeled and source-only. This is not live context synthesis or
scan-quality evidence. The existing live OAuth receipt still has seven settled
requests, five work attempts, allowance revision three, ten total calls and two
protected review calls. No new live request or allowance approval occurred.
The normal selected model and reasoning level are unchanged.

Shared failure presentation still repeats chained causes and offers generic
recovery suggestions. That polish, selective regeneration, context experiments
and lessons, the full per-tool functional audit and complete investigation/report
acceptance remain open. No full reference parity, physical contrast, worst-case
latency, cross-platform or continuous source-monitoring claim follows. All nine
delivery milestones remain unchecked.
