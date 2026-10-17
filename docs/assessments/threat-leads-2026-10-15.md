# Bounded legacy threat-to-code hints

The retained threat-lead helper now uses the shared repository inventory instead
of a separate recursive walk. Its two actions are hidden Labs and auxiliary.
They produce experimental context hints without completing Map, scheduling scans
or writing finding observations. This checkpoint qualifies bounded execution and
specific consumers; it does not establish useful vulnerability discovery.

The later [derivation and recovery qualification](threat-lead-recovery-2026-10-15.md)
addresses the linked-field expansion and interrupted-summary gaps recorded
below. The verification counts in this earlier checkpoint remain historical.

## Actual purpose and inputs

The executor reads the legacy `.kuzushi/threat-model.json`, matches a fixed set
of keywords and ranks candidate source paths. The old descriptions and generated
Markdown also named X-Ray evidence, but the executor never read those files.
Those claims and the unused X-Ray dependency metadata are removed. The retained
`sources.xRay` array is empty. DAG metadata still establishes no execution order.

Build consumes a real threat array and records the SHA-256 of the exact document
bytes read. Missing or malformed context fails before publishing cards. Reading
saved hints retains the original document receipt even after current context
changes. Current source equivalence is explicitly unverified. The helper does
not bind an immutable accepted context reference, so it remains outside the
supported primary Map path.

## Finite source inspection

One shared inventory is built per invocation. Existing inventory limits remain
100,000 entries, 512 MiB inspected and 256 KiB per file. The helper then derives
its source selection from that inventory without another directory traversal.
It indexes at most 6,000 files and 16 MiB of source prefixes, capped at 256 KiB
per file. Its byte allowance is reduced by inventory inspection, keeping the
combined inventory and source reads within 512 MiB. The separately bounded legacy
context document remains limited to 16 MiB.

Source read capacity is reserved before file reads. Successful short reads release
unused capacity; failed reads retain their conservative reservation. Empty files
still consume file attempts. Per-entry and per-file cancellation checks stop
before card publication. At most 256 threat rows are processed. Additional rows
remain in the original context and are named as unprocessed in the receipt.

Version-1 `sourceCoverage` records inventory extent, source attempts, known and
reserved bytes, omissions, prefix truncation and limits. Path previews retain
at most 128 entries and count the rest. Human text shows a short preview and
points to the JSON for additional details. Whole-repository coverage is always
false. Ignored and nonselected material is disclosed. Loose Markdown is labeled
documentation, while example and test paths keep their existing roles.

The source index excludes symlinks and uses guarded workspace-relative reads.
Focused tests cover a deep directory tree, cycles, an injected outside symlink,
source and combined byte ceilings, failed-read reservations, empty-file limits,
and bounded path disclosures.

## Outputs and consumers

The existing `.kuzushi/threat-leads.json` and `.kuzushi/threat-leads.md` paths,
schema version and card fields remain. The summary now leads with bounded,
partial or legacy-unverified inspection status. Text includes the context receipt,
limits and path disclosures. Keyword confidence is explicitly separate from
vulnerability validity. No human finding verdict or accepted context changes.

Actual shared prepared dispatch produces JSON and Markdown, and the read action
consumes the saved JSON. A separate test runs the real producer and confirms the
passive actor-context reader consumes its generated Markdown with the coverage
and guidance limits attached. This tests artifact flow without calling a model
or executing discovery. The existing accepted-context reader continues to omit
mutable legacy hint context when a different immutable context is selected.

Legacy JSON without a receipt remains readable as partial and unverified, with
unrecorded inspection values. Invalid or contradictory card counts and
unsupported source receipts fail explicitly. A missing Markdown file is not
listed as an existing artifact.

## Verification and limits

Evidence is retained at `/tmp/kuzushi-threat-leads-20261015`. There are 28 distinct
focused Rust passes across source inspection, shared dispatch, the passive
consumer, dispatch policy and TUI primary-result ownership. The workspace build
and all ten quick repository gates pass. The risk proxy passes over 80 changed
code files with 15 support checks. The draft receipt is dirty and unsigned.

J293 in `native-v4/20261015-213211/J293` records 13 machine passes, zero failures,
17 authenticated text/ANSI capture pairs and three pending human judgments.
Actual dimensions match all six requested sizes. The run exercises a prefix
limit, symlink exclusions, a loose Markdown candidate, source receipts, missing
context without artifact replacement, saved reading, legacy unknown inspection,
malformed-card failure and no-color restart. Its six exact tool attempts record
no model, primary phase attempt, finding observation or campaign job. The first
failed probe retains a test expectation that incorrectly required a long
filename to remain unwrapped; the final probe matches the stable cause and
checks the exact failed run and preserved artifact separately. Final 40x12
paging captures dismiss the notice and expose the resource details. Terminal
amounts use KiB/MiB; JSON retains exact bytes. ANSI replays use a chosen dark
background and are not OS screenshots.

The frozen native SHA-256 is
`5beb51e9895c9f2d447597c1c518d2fe0712938e32c9990e61f38e4bbc9838ce`.
Source and runtime manifests stayed unchanged during native execution. The
journey retains `REVIEW_REQUIRED`; machine checks are not human acceptance.
No current check configures a model or credentials. Real experiment usage stays
at 14 previously approved requests; no new real request is approved or spent.

Fresh headless CLI build/read probes use the same frozen binary and unchanged
owned source/context in an unborn Git repository. Both return partial exit 4
with the real card artifact and no model. The initial non-Git probe records an
explicit shared inventory prerequisite failure before card production. The
standalone inventory's filesystem fallback does not qualify headless non-Git
workspace behavior. No fixture commit is created.

Input validation and cancellation before publication preserve prior cards.
JSON and Markdown are separate atomic writes; interruption between them remains
an experimental failure case. The index receipt does not authenticate a complete
repository snapshot. Exact discovery-scope support, accepted-context isolation,
general hint accuracy and human UX acceptance remain unqualified. No speculative
module removal or Core promotion follows.

Derived linked-node/flow expansion also needs qualification for repeated
references and unusually large fields. The current artifact-size guard runs
after derivation. Bounded input reads alone do not prove a bounded peak memory
footprint. This remains a blocker to promotion beyond Labs.
