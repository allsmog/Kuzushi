# Study membership before Review pagination

The previous reader loaded the first global page before applying selected-study
membership. A large history could hide every observation from the selected
study. An empty three-job study also reported 501 matching findings even though
none belonged to it. The failing regression is retained in
`/tmp/kuzushi-review-scope-20261016/before.log`.

The workspace finding-page application service now resolves explicit study
membership before pagination. The descriptor declares `batchId`, `batch_id` and
`batch`; the filter expression accepts `batch:<id>`. Conflicting selectors fail.
The raw store rejects study filters without workspace context. The general
`scope:` filter remains unsupported.

Membership uses durable finding generations from every retained attempt,
including cancelled and superseded work. The same identity projection that
chooses global representatives carries membership into that representative.
This avoids independently guessing identity equivalence from the latest row.
The shared reader honors its caller's identity policy. Existing headless dispatch
selects Legacy while the shell resolves operator policy; this increment does not
change that selection. All three policies are tested for retained membership.
Aliases and decisions remain global. A member reobserved outside the study
stays visible, with its latest global observation rather than a fabricated
study-local copy. Membership is separate from completed-pass recurrence,
confidence, source freshness and a human verdict.

The shell includes selected study identity in background read requests. Old
pages remain hidden until the corresponding read arrives. Opening or clearing
a study resets pagination while preserving the ordinary filter and composer.
Refreshing an unreadable study retains its selector and error instead of silently
clearing membership. Only explicit clearing restores workspace history.
The complete workspace corpus still governs journey completion. A filtered
empty page cannot complete Review.

Plan, queue and gate documents have a 4 MiB per-document limit and contained,
non-linked reads. Missing, malformed, oversized and linked metadata fail without
silently showing workspace history. The report signature also binds page
cursors to study accounting. This does not impose an aggregate limit on a large
ledger or study. Historical artifact formats remain unchanged. Rust filter
literal callers and old opaque cursors have documented migration guidance in
`RELEASING.md`.

## Verification status

There are 402 distinct focused passes: 149 Core and 253 TUI checks. The wider
TUI selector also retained one failure in the compatibility attack-chain screen.
That surface remains unqualified. Its original failure and the separate focused
result remain in the evidence folder. The workspace build, architecture gate,
299-file risk gate with fifteen support checks, and ten summary checks pass.
The receipt remains dirty, unsigned and marked drifted; it is not a publication
verification receipt.

The final sequential J313/J304 runs have 87 machine passes, zero failures,
74 capture pairs and ten pending human judgments. Fourteen frozen programs,
4,329 source inputs and 758 runtime inputs remain unchanged across both runs.
J313 preserves 504 raw observations and three study members behind 500 unrelated
findings. Its history is explicitly synthetic and qualifies reader behavior
only. J304 retains six settled intercepted requests, six observations, one
human fixture decision and retired guidance across restart. It includes local
static scans and checks actual phase consumption. It does not qualify live
model quality.

The first J313 attempt retained one pager-readiness assertion failure. The
corrected journey explicitly enters Navigate mode and waits for the pager,
while requiring the retained two-row limit. All production source and fourteen
programs are identical between attempts. The earlier failed run is preserved.

Evidence is in `/tmp/kuzushi-review-scope-20261016/native-evidence.json` and
`verification-summary.json`. There are no new live provider requests. Fourteen
live experiment requests were already spent; no live allowance remains. The
366-file publication checkpoint remains a draft at the operator's request.

The generic refresh-error wording still mentions previous results while study
rows are hidden. Its clarity remains an open UX judgment. The error keeps the
study selector, shows the failed metadata read and hides unrelated observations.
ANSI cell replays are terminal evidence, not OS screenshots or reference-parity
proof. All nine broad delivery milestones remain open.

The later [study read-recovery checkpoint](study-read-recovery-2026-10-16.md)
replaces the generic failure wording and reconciles the compatibility test with
curated default behavior. Earlier receipts and failures remain preserved.
