# Literal file identity in diagram links

Selecting `src/a\b.rs` in a diagram could open findings for `src/a/b.rs` on
Unix. These are different files. Two independent conversions caused the error:
the diagram link replaced backslashes, and the shared exact-file filter treated
them as directory separators. Correcting only the first still loaded both rows.

Diagram finding links and scoped planning now share one private lexical path
helper. It preserves native filenames, rejects traversal, filesystem roots,
outside absolute paths and URLs, and retains existing containment behavior.
The shared `findings:list` and `files:[...]` filter preserves literal Unix
backslashes too. Windows keeps native separator equivalence. Leading `./`
remains accepted. Findings, identities, decisions and saved contexts are not
rewritten; existing public options and stored schemas remain compatible.

This follows published commit `7967008dac` on local main. It is a separate draft
from the saved-scope receipt wording correction. Neither draft is included in
that published checkpoint.

## Evidence

The owned fixture contains two inert source files and two labeled informational
observations. No security defect is claimed. Its topology is declared test data,
not verified deployment architecture. Source is read but never executed.

The meaningful failing regression first produced the nested path instead of the
literal path. After the first conversion was repaired, it still loaded two
findings. The completed regression now executes the asynchronous findings read
and asserts the exact single filepath and title, protecting the real consumer.
An earlier test-setup compile failure is retained separately.

All 55 focused Rust checks pass: eight shared filter tests, twelve diagram
finding-link tests, two shared path tests, seventeen scoped-action tests and
sixteen diagram evidence-model tests. Core/TUI all-target Clippy, workspace build
and the changed-code risk proxy pass. A final import-order cleanup passes TUI
Clippy and a fresh workspace build. Windows-only assertions are not executed on
this macOS host; this does not qualify the platform matrix.

Final native J361 has 34 machine passes, zero failures, nineteen capture pairs
and three pending formal operator judgments. Raw exit code 4 remains
`REVIEW_REQUIRED`. Three separate agent answers and twelve inspected ANSI cell
replays cover the six viewport sizes, nodes, flow, boundary, return and no-color
restart. Replays use a chosen font and background; they are not OS screenshots.

The literal node and flow open only the literal observation. The nested node
and boundary open only the nested observation. Returning preserves the selected
diagram element. No-color restart restores the exact literal selection. Both
observations, zero human decisions, context, source bytes and prior tool results
remain unchanged. No campaign, accounting row, provider request or source
execution is added. The sixteen-request real-model allowance remains exhausted.

All 6,586 repository inputs and thirteen frozen programs remain unchanged during
the final native run. Only this assessment, the implementation plan and the
acceptance ledger change afterward. The CLI SHA-256 is
`8987abf4dffe585acc34193ac95fc4261e1f25689471644a135ee20593980245`.

Evidence root:
`scripts/devex/artifacts/dfd-literal-links-20261025/`.
Final native captures:
`native-attempt-3/native/J361/20261025-015214/J361/`.
Focused logs, frozen input/program manifests, raw reports, persistent-state
checks, review answers and image hashes remain in that root. Draft summary
verification uses its own receipt, preserving the signed published receipt.

## Retained failures and limits

Attempt one records 26 machine passes and three failures. Its result-title wait
could match a previous row while the asynchronous filter read was still running.
The UI disclosed both `previous results` and `Reading filter`; the capture did
not prove the final result. Waiting for the completed exact-filter header fixes
the journey rather than hiding the failed assertions.

Attempt two records 34 machine passes and zero failures, but agent visual review
rejects its 160-column capture because redraw had not reached the footer. The
final attempt adds a bounded one-second resize wait and checks the return
control before capture. Both earlier runs and their answered review questions
remain evidence; neither is relabeled as the final visual result.

Visual review also finds an independent honesty gap. Imported assertions use
`kind: reasoning`, while the presentation labels all such evidence
`model-generated reasoning`. These fixtures made no model request. The
[importer](../../crates/kuzushi-core/src/findings/import/ledger_jsonl.rs) and
[origin presentation](../../crates/kuzushi-tui/src/ui_view_models/findings.rs)
need a separate correction that preserves evidence strength and does not promote
an imported assertion to observed proof. This remains open. Agent assessment is
partial for the broader UI, even though focused path selection is verified.

This increment does not qualify full diagram usefulness, source ancestry,
general module functionality, model quality or reference-level operator delight.
Four broad delivery items retain local acceptance; five remain open. Existing
PR344 still requires independent review, remote signing-key trust and hosted
checks, which currently cannot start because of the account billing/spending
limit. No administrator override or account-setting change is included.
