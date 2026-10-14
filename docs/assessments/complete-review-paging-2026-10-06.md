# Complete Review paging, October 6, 2026

Review can now navigate the complete matching ledger in pages of at most 500
rows. Ctrl+N and Ctrl+P are available in empty Navigate mode. The range is
visible, including at 40x12. When both directions exist, the footer combines
their hint as `Ctrl+N/P pages`. Prompt editing and history retain their own keys.

The shared Core query matches the full ledger before selecting its window.
This fixes SHA/branch filtering that previously discarded matches beyond row
500. Confidence order is applied globally before paging, and aliases retain
their whole-ledger meaning. Versioned opaque cursors bind target, query, policy,
ledger revision, matching identities and relevant run metadata. Changed,
malformed and oversized cursors fail without repair or additional work.
Anchors allow a refresh to retain the cursored finding; query or grouping
changes start fresh. Alias opening uses carried aliases and a policy-aware
whole-ledger lookup, rather than relabeling a loaded subset.

The `findings:list` descriptor declares cursor, anchor and order. Shared prepared
dispatch consumes them and returns additive `data.page` metadata while retaining
existing count/findings fields. `FindingListReport` and persisted artifacts are
unchanged. The existing dedicated CLI list remains a first-window interface;
continuation is exposed through the tool and interactive Review. The query
still reads the matching ledger, so this increment does not claim lower query
or durable decision-write cost.

Evidence root is `/tmp/kuzushi-experiment-main-20261006/`. Nine Core checks pass:
complete/disjoint pages, stable aliases, previous-page identity, target/query/
ledger invalidation, malformed/oversized cursors, a SHA match beyond row 500,
confidence ordering, anchors after a write and real prepared dispatch. The
legacy filtered tool check passes too. All 172 focused TUI findings checks pass,
including tiny/ordinary/detail-focused controls, complete navigation, alias
opening, refreshed selection, query reset, whole-ledger rail identity and composer
ownership. Nine screen-context checks pass. The CRAP-risk gate passes for 83
changed code files. Workspace build passes without warnings.
The composition suite passes 18 checks, including 120 phase/size/color buffers,
30 plain projections and 30 canonical reference snapshots.

Native predecessors are retained. J102 at `20261006-194619` fails because the
next-page control is hidden at 120 columns. `194859` exposes the subset-alias
lookup failure. `195507` has 29 machine passes but fails the draft judgment:
the recipe sent `Esc` as literal characters. `195706` has correct draft content
but related 80/96-column captures hide the previous-page control in detail
focus. `200525` restores those controls but its 160-column rail displays `F-0452`
while list and detail identify `F-0952`. Screen context now carries the same
alias as the selected detail. A broader test also exposed a completion fixture
with findings only in memory; it now persists them before the durable refresh.
Each defect has a specific repair and focused regression. Timeout
diagnostic captures lack harness provenance files; their judgments disclose
that limitation rather than manufacture metadata. Raw reports remain intact.

The final native J102 at `tui/20261006-201403/J102` has 30 machine passes,
zero machine failures, six passing screen judgments and six passing related
layout judgments. Twenty captures carry the actual binary provenance, matching
native SHA256 `493bdce651a5f6f995a79675aecc8ac986f6f0eb5d91165749d8ab35a561ede9`.
The raw exit 4 and `REVIEW_REQUIRED` report remain intact; `manual-review.json`
is the separate judgment receipt. The one typing sample is 65 ms within its
300 ms allowance. Captured text and ANSI establish these paging interactions,
not full product parity, physical display contrast or worst-case latency.

The owned fixture has 1,000 labeled synthetic findings and same-SHA metadata.
No target source, scanner or provider is executed. Its verification compares
source hashes and observation/decision counts; ordinary review-session history
may record opening details, so the receipt is not evidence that every SQLite
table is unchanged. Wider scale, real Git transitions, complete accessibility
and platform coverage, decision-write responsiveness, accepted lessons and the
complete approved investigation remain open. All nine milestones stay unchecked.
