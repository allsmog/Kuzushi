# Exact context edits and immutable copies

The study context browser now offers a manual edit flow for the inspected exact
revision. Operators can edit its overview, component descriptions/purposes and
question answers using a multiline field with its own cursor and input owner.
Back keeps the draft in the shell session. Ctrl+S opens a before/after review;
Enter there saves. Discard has a separate confirmation. Saving creates an
inactive copy and returns to context choice for inspection. Selecting it for
study work remains a separate action. Original revisions, their metadata,
the active pointer and compatibility mirror remain unchanged.

The shared `threat-model:revise` descriptor/executor accepts an exact reference,
declared text edits and optional copy label. Protected evidence, source, scope
and verification fields cannot be edited. A mismatched inline target is refused.
The new lineage records its source revision and inherits that revision's source
binding; editing historical context does not refresh it. The old verification
stamp is cleared, with `userEdited` and edit provenance recorded. Legacy string
questions become question/answer objects in the new copy. Exact reads, summary
and Markdown readers retain the human answer. No model requests or jobs start.

Limits are 64 edits, 16 KiB per text field and 2 KiB per copy label. The object
writer enforces the existing 16 MiB reader limit before publishing an unreadable
object. Store-lock acquisition observes cancellation, and cancellation before
publication refuses a revision. A failed or uncertain save keeps the draft and
directs the operator to inspect the catalog before retrying. Session drafts
are not persisted across process exit; saving is their durable boundary.

Ten focused Core edit checks, a Markdown answer check, a storage-size check and
the two built-in policy checks pass. The reviewed policy addition is
Map/Never/WorkspaceWrite/RequiredWorkspace/OptionalFindingStore, with no external
approval effect or runtime fallback. Thirty-four store regressions, 73 batch-study
checks, 12 context-reader checks and the workspace build pass. The CRAP-risk proxy
passes for 120 changed code files. Final layout and repository gates are
recorded in the separate closeout receipt. This does not claim the complete
Rust/TUI suite is green; the prior excluded compatibility failure remains.

Evidence root is `/tmp/kuzushi-context-edit-20261007/`. Final native J105 at
`tui/20261007-014723/J105` records 31 machine passes, seven passing ask judgments
and 11 related-frame judgments. It exercises 120x36, 160x48, 96x89, 80x24,
60x20 and 40x12, exact Unicode paste, retained draft/cursor, actual before/after
review, copy inspection, three-pass draft binding and a real no-color restart.
All 26 captures share native SHA256
`a581413c3fa3840261c41ee608d25c304baf37c9c1e2bc4c373498c8ec4a793d`.
Raw exit 4 and `REVIEW_REQUIRED` remain unchanged. Separate judgments contain
real text/ANSI hashes and capture provenance. The 4 ms echo sample does not
establish worst-case latency, physical contrast, accessibility, platform
coverage or full reference parity.

The fixture uses labeled imported contexts, not generated security-quality
evidence. Its active Beta context stays separate from the edited Alpha copy.
Before saving, the oracle checks that no revision was published. After saving
and restart, it verifies exactly one new lineage/revision, two exact text
changes, source/parent references, unchanged original objects/metadata/mirror,
unchanged target source and a fixed three-job draft bound to the copy. The draft
allowance is unapproved and every job remains unstarted. Source is unversioned;
this journey does not prove real Git SHA transitions. No target source executes.

Failed predecessors remain. `013801` did not independently observe two nested
back steps; the recipe now checkpoints each. `014247` saved a purpose-field edit
where the recipe intended a question answer. Its diff showed that wrong field
honestly, and screen review failed it. The final recipe checkpoints the exact
question and requires that field in the diff. Both raw failures and every
reached judgment remain. The driver is unchanged.

Selective regeneration, explicit synthesis-cache behavior, broader context
editing, approved context permutations, reviewed lessons, complete per-tool
functional evidence and the full live investigation/report remain open. The
normal selected runtime/model and the existing live allowance are unchanged.
All nine implementation milestones remain unchecked.
