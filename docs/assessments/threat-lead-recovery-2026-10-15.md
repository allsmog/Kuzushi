# Bounded hint derivation and summary recovery

This follows the [bounded inventory qualification](threat-leads-2026-10-15.md).
The hidden threat-lead family remains Labs and auxiliary. No accepted Map,
scan jobs, finding observations or finding decisions are created.

## Context derivation

The helper borrows at most 2,048 DFD rows per kind from the parsed legacy
context. It no longer clones the DFD or all of its nested element values.
It examines at most 32 references per array field, removes repeated references,
and skips identifiers or path patterns over 1,024 bytes instead of shortening
their identities. Copied text fields use UTF-8 prefixes of at most 4,096 bytes.
The unchanged source document is still hashed in full within its 16 MiB read
limit. Missing identifiers and duplicate DFD identities are disclosed; duplicate
identities retain the historical last-row behavior and make inspection partial.

Each derived card is measured with a bounded serialization counter before
retention. A card over 128 KiB or a cumulative card set over 4 MiB is omitted.
Measurement includes JSON escapes and pretty formatting and does not accumulate
a serialized buffer. At most 256 threat rows are processed, as before.
Per-field and per-reference bounds apply before card measurement. This closes
the repeated-reference and large-field expansion path identified in the earlier
assessment. These are algorithmic resource bounds, not a measurement of the
process's peak resident memory or proof of general hint accuracy.

The additive `sourceCoverage.contextProjection` receipt records limits,
omissions, duplicates, shortened field projections and retained card bytes.
Omission or shortening makes inspection partial. Terminal and Markdown output
show these limits with KiB/MiB units; old receipts retain unrecorded values.

## Publication and recovery

Both destinations and serialized sizes are checked before publication. JSON is
the commit point. A failed JSON write fails the build; a failed subsequent
Markdown write returns a partial result explicitly saying that JSON was saved.
These remain two atomic file writes, not a cross-file transaction.

Read compares Markdown against a rendering of structurally checked saved JSON. Missing,
stale or unreadable Markdown is disclosed and excluded from the artifact list.
The build descriptor declares `repairSummary`, default false. The explicit
`run threat-leads:build {"repairSummary":true}` action regenerates only Markdown
from saved JSON after structural checks, without inventory, current context,
model or JSON mutation.
Malformed saved JSON, cancellation and invalid destinations fail honestly.

The passive context consumer checks saved JSON structure and derives its hint excerpt
from it. A Markdown source is consumed only when it matches those cards. Stale
Markdown and malformed cards cannot silently enter that context path. Missing
current context does not prevent saved-card inspection or summary repair.

## Remaining product scope

Immutable accepted-context and exact discovery-scope binding, current source
equivalence, broad hint usefulness and human UX acceptance remain unqualified.
Saved-card checks currently cover the array, card count and source receipt, not
a complete per-card/link schema. Invalid or unrecognized threat rows need further
qualification before promotion.
Concurrent writers can still leave a mismatched pair, but the reader discloses
the mismatch and recovery uses the committed JSON. This does not change finding
identity, SHA comparison, nondeterministic recurrence or investigation spending.
The full investigation plan remains active.

## Verification

Evidence is retained at `/tmp/kuzushi-lead-recovery-20261015`. The final build
passes 46 distinct focused Rust checks: 39 hint contracts, five actual passive
context-consumer checks, one TUI primary-result check and one registry policy
check. Two Node checks qualify the extracted publisher path contract, including
negative cases for detached publication and repair paths. The workspace build
and all ten quick repository gates pass. The risk gate passes 85 changed code
files with 15 support checks. The receipt is a dirty, unsigned draft.

J293 at `native-copy-final/20261015-220347/J293` records 17 machine passes, zero
failures, 28 authenticated text/ANSI capture pairs and four pending human UX
judgments. All six requested dimensions match the actual tmux panes. The 40x12
expanded transcript reader exposes the context receipt, omissions and resource
limits through its visible `z` control and page keys. Its captures were inspected
as ANSI cell replays with a chosen dark background, not OS screenshots. This
inspection does not mark the journey's human judgments accepted.

The eight native tool attempts cover partial build, stale-summary reading,
explicit repair without current context, ordinary build failure, saved reading,
legacy unknown inspection, malformed cards and no-color restart. Source files
and fixture configuration remain unchanged. The saved JSON survives summary
repair, and no model, finding observation, campaign or primary phase attempt is
created. Headless build, stale read and `--option repairSummary=true` exercise the
same final binary in a separate owned, unborn Git repository. All three return
partial exit 4, with model null and the expected current/stale/current summary
states. No fixture commits are made.

The final native SHA-256 is
`f76d29068204c48c6355f86a26d8e2a0681e64942e49054cce437a40fcaa5bbe`.
All 4,255 source and 700 runtime inputs remain unchanged during the final native
run. Earlier failed probes and gate output are retained: a paging step scrolled
past its target text, then static checks still named the old writer location
and flagged ambiguous repair-option wording. The final probe uses the corrected
paging, actual extracted writer guards and simpler option description.

Publication failure contracts use an injected writer fault before and after
JSON commit. The native fixture supplies a mismatched summary and exercises real
reading and repair. These checks do not establish OS-crash durability or an
atomic multi-file transaction. No real provider requests were added. Cumulative
experiment usage remains 14, with zero additional requests approved. No commit
or push is performed by this checkpoint.
