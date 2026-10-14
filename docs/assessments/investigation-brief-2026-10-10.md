# Immutable operator goals and approved investigation history

The study form now has a visible **Goal and priorities** row. Operators can
write multiline goals and questions, inspect previous and proposed text, save
a reviewed revision, and select it for a new study. Unsaved text and the
composer survive navigation. A compiled plan keeps its selected revision even
when the current target brief changes.

Goals are operator intent. They are not source evidence and are not supplied
to model or scanner prompts in this increment. Saving or selecting them does
not change finding severity, confidence, decisions, active threat models,
allowances or approved work. Model-guided priority integration remains open.

## Shared contract and artifact consumption

`campaign:brief` is an operational, runtime-free workspace metadata tool with
`phase_result=false`. Its descriptor declares read/save mode, brief identity,
exact reference, expected revision and reviewed text. Unknown keys refuse.
Text is bounded to 8192 UTF-8 bytes and the serialized document to 16 KiB.

Version 1 references identify an immutable content-store blob and published
ordinal under `.kuzushi/v3/investigation-briefs/<id>/`. Reads authenticate
digest, size, publication, target, schema and lineage fields. A cancellable
file lock serializes expected-revision saves; stale saves refuse rather than
overwriting another editor's text. Reads never activate context.

Optional `briefRef` is declared on `campaign:study` and
`campaign:context-study`. Plain discovery, scope studies, context matrices
and context-generation plans freeze the full referenced revision before
publication. Child inputs and prompts remain unchanged. Shared plan readers
authenticate that revision. Discovery report readers and JSON exports retain
the frozen brief independently of the current head. Missing publication
refuses reporting instead of substituting today's goal.

## Native terminal evidence

Final J169:
`/tmp/kuzushi-investigation-brief-20261010/final-tui/20261010-103848/J169`.
Native SHA-256:
`5bffa79396a14545c1c84089f03812c890c14f2e3a8c4d3693279b8a482d83e1`.
There are 24 machine passes, zero failures and 27 authenticated live text/ANSI
captures across six viewport sizes, complete narrow review paging and
no-color restart. Three assistant screen judgments qualify this owned
workflow separately from raw REVIEW_REQUIRED and operator approval false.
The review record is `assistant-screen-review.json` under the evidence root.

The actual editor saves exact Unicode/multiline revision 1, preserves an
unsaved addition, and saves revision 2. Native dispatch drafts and approves
three offline license-policy jobs without starting them. Revision 1 remains
readable and its approved plan digest stays unchanged. Source files stay
identical; observations, decisions, provider reservations, work attempts and
queues remain absent. No live provider or target-source execution occurs.

A separate native JSON export on the retained second journey's owned target
keeps revision 1 after head revision 2. `goal-export.json` and its stderr
retain this check. This is a pending study with zero findings, not a clean
repository coverage or vulnerability-quality result.

## Verification and retained failures

Focused Core tests cover immutable history, concurrent saves, cancellation,
malformed/foreign references, prepared dispatch, all four plan bindings and
frozen-goal discovery reports. TUI checks cover editor input ownership,
failed-save recovery, late completion, unsaved selection refusal and report
presentation. There are 221 distinct passing focused Rust checks: 25 Core and
196 TUI. One existing report test, `native_matrix_handoff_fixture`, remains
explicitly ignored because it generates owned native fixtures on request.
`focused-test-evidence.json` records names deduplicated across the focused logs.
The workspace build and all ten repository summary gates pass; the risk proxy
passes for 690 changed code files. `verify-receipt.json` records the quick
verification scope and its omitted CI/platform checks. Its dirty/drift flags
include inherited edits and this session's test-fixture correction during the
run; they do not prove an external writer changed the workspace.

The reviewed policy inventory adds one tuple, `campaign:brief`, and changes
no existing tool policy. There are 181 registered policy tuples. Its
fingerprint is
`7dc0c5debb19e4bdf769ea334c10b02c8572886e47bdef83f1b2dc5b4f140519`.

Initial native failures used the noncanonical `batch` command and assumed
idle Ctrl+C required confirmation. The corrected journey uses `scan batch`
and verifies immediate idle exit. The new scope report fixture initially
selected `license-scan`, which correctly refused exact membership; it now
uses a scope-capable engine for planning only. Retained failures are evidence
of corrected fixtures, not expanded scanner scope or weaker product guards.
The new TUI report fixture also initially omitted approval. It now approves
its exact inactive plan through shared prepared dispatch before loading the
report; the missing-approval product guard remains intact.

## Remaining acceptance

CAS and ordinal publication are preserved if a later head write fails. This
increment does not supply automatic repair for such interrupted publication.
Native concurrent editors, filesystem failure timing, lineage restoration,
large planning latency and every configuration still need qualification.
Scope/matrix brief bindings have focused shared-dispatch coverage, not a new
native monorepo or live-model qualification.

The current catalog has 110 operator tools, with scoped evidence assigned to
66 and 44 unassigned. Seven unassigned reproduction/patch actions are
explicitly excluded and are not required implementations. No existing
module is promoted or retired. All nine broad milestones, the complete live
investigation and full reference-product TUI acceptance remain open. The
specific live test allowance is pending; work stays uncommitted on main.
