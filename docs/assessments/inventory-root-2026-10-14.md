# Bounded inventory keeps safe material and reports missing coverage

Inventory previously recorded file membership and charged bytes using pathname
metadata before the contained read. Git mode refused a symlinked ancestor during
content inspection, but a metadata-only walk could retain that inaccessible path
as a member. The filesystem walk collected an entire directory before checking
cancellation. The source reader's binary sniff could exceed a smaller inspection
reservation if a file grew. These gaps affected the first inventory and scope
decision in the accepted investigation flow.

Unix inventory now retains its initially opened root directory. Directory
enumeration uses that handle and refuses symlinked components; an iterator stays
on its opened directory after pathname replacement. File membership, metadata
and inspection use an authorized regular file. Missing, unsafe and nonregular
tracked paths produce omissions and partial inventory while safe files remain
available. Root replacement aborts publication. Nonblocking regular-file opens
reject FIFOs without waiting for a writer. The byte-limited reader cannot exceed
its reservation even when binary sniffing or file growth would otherwise read
more. Existing entry and byte limits remain unchanged.

Wide-directory collection now reports progress and checks cancellation between
entries. This does not promise a deadline for a filesystem call blocked in the
kernel. One entry of lookahead retains the existing cap-disclosure behavior;
accepted membership stays within the 100,000-entry budget. The default overall
inspection limit remains 512 MiB and the per-file prefix remains 256 KiB.

Native execution exposed an incomplete context snapshot reported as completed.
`context:build` now publishes a partial receipt with its actual inventory cause,
including unavailable paths. Its explanation no longer assumes every limitation
was an inspection cap. The supporting tool cannot complete Map automatically.
Ordinary bounded sample views retain their existing behavior. Explicit repair
and rebuild produce a separate complete receipt; original historical results
remain unchanged. The compatibility shard draft also stays partial and cannot
silently materialize scopes from incomplete inventory.

Existing artifact fields and tool options remain. The lockfile adds the existing
filesystem library as a direct Unix dependency without upgrading its version.
Unused private inventory read wrappers are removed after their caller moved to
the same-handle adapter. No public module is deleted or promoted.

## Evidence

169 distinct focused checks pass: 100 inventory checks, six root/reader checks,
11 shared bounded-file checks, 22 context checks, ten shard checks and 20 TUI
context-reading checks. One live opt-in inventory test is explicitly ignored.
Coverage includes deep trees, static and replaced symlinks, missing membership
with zero content allowance, a growing file, a FIFO, a directory iterator after
replacement, wide-directory cancellation, partial result normalization and
complete-result compatibility. The locked workspace build passes. All ten exact
quick-summary gates pass, including 391 Node tests and the CRAP-risk proxy across
662 changed code files. The full Rust suite was not run.

Final native journeys run sequentially on one immutable product binary:

| Journey | Machine passes | Failures | Capture pairs | Pending human judgments |
| --- | ---: | ---: | ---: | ---: |
| J253 safe members and partial receipts | 13 | 0 | 13 | 3 |
| J228 explicit source repair and context recovery | 14 | 0 | 17 | 2 |
| J229 corrupt Git index with no filesystem fallback | 18 | 0 | 17 | 2 |
| J232 input, cancellation and restart over 16,000 files | 12 | 0 | 14 | 3 |
| J121 complete supported investigation | 109 | 0 | 87 | 15 |

The 166 machine passes and 148 capture pairs do not close the 25 pending human
judgments. Raw outcomes remain REVIEW_REQUIRED. J253's first 40x12 frame leads
with partial status, unrecorded cost and the actual unsafe-path warning. Native
context and scope results retain one safe member and disclose both the symlinked
parent and FIFO. Earlier receipt digests and all inert source bytes are preserved.
J228 keeps the partial result separate from the later explicit complete rebuild.
J229 preserves prior artifacts when Git acquisition fails. J232 confirms a live
Git child before typing/cancellation checks; this is complementary evidence to
the unit check of cancellation during directory collection itself. J121 retains
accepted context, finite passes, aggregation, triage, reporting, source
reassessment and restart. Its four provider responses are fully intercepted.
The other four journeys make no provider requests. No external scanner or target
code executes, and no fixture commit is created by these journeys.

Captures under `/tmp/kuzushi-tui-integration-20261012`:

- `inventory-root-ledger-tui/20261014-094332/J253`
- `inventory-root-recovery-tui/20261014-094802/J228`
- `inventory-root-git-failure-tui/20261014-094853/J229`
- `inventory-root-input-tui/20261014-095029/J232`
- `inventory-root-complete-tui/20261014-095307/J121`

Immutable bundle: `/tmp/kuzushi-tui-integration-20261012/inventory-root-native`.
Product SHA-256:
`c8b291560232ede871e1a36af4ffe5e1fb794fd4721fe78a9f2b56ff3321862b`.
Tests, initial CLI results, canonical-path fixture corrections and the retained
read-only SQLite fixture failure are in
`/tmp/kuzushi-tui-integration-20261012/inventory-root-audit`.

## Remaining qualification

Pinned-directory behavior is verified on this Unix host. Other platforms retain
their existing contained-read adapters and have no new equivalent race evidence.
Inventory is not an atomic snapshot of concurrent source edits, and kernel IO
latency is not bounded by entry/byte limits. Source identity, drift and scope
acceptance remain separate controls. Broad module usefulness, live scope/context
quality and complete reference-product UX acceptance remain open. No broad
delivery milestone closes. The live allowance stays exhausted at six of six.
