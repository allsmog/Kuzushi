# Recorded evidence imports and honest workflow ownership

October 11, 2026. Changes remain uncommitted on main. This audit uses labeled
synthetic recorded HTTP metadata only. No target source executes, no service
is contacted and no provider call occurs.

## Defects and behavior

`recon:import` and both Bounty capture imports previously declared a primary
Scan result. Importing saved hosts, notes or HTTP requests does not demonstrate
repository discovery. The three descriptors now set `phase_result=false` while
preserving their Scan authorization classification and exact dispatch paths.

Native testing exposed a second path: legacy history inferred completed Scan
from classification alone. That reader now respects cached descriptor result
ownership before interpreting historical run kinds. Unknown historical scan
kinds retain their existing reading path. Imported HAR/Burp UUID observations
also remain outside the legacy local-discovery predicate. No raw history is
deleted or rewritten.

Literal filenames retain trailing spaces through both canonical Recon and
Bounty dispatch. JSONL imports check cancellation before reading and between
records. A later record failure preserves its cause and explicitly warns that
earlier evidence may remain. Counts of repeated writes are not presented as
unique persisted rows. The operation remains non-atomic. Storage-fault timing,
cancellation inside reads/SQLite, capture-wide row limits and cancellation of
HAR/Burp/XML remain unqualified.

## Native and interface evidence

Final sequential J207:
`/tmp/kuzushi-passive-import-20261011/settled/20261011-142403/J207`.
Frozen native SHA-256:
`fe008ae37acb59ae9edf3dd98cad8009f0ff4e0253ee45a8c74075c8226e594e`.

There are 32 machine passes, no failures and 24 provenance-checked text/ANSI
capture sets. The transcript reader is exercised at 120x36, 160x48, 96x89,
80x24, 60x20 and 40x12. Compact paging reaches the failed-record warning and
its incomplete-import qualification. Escape restores Logs. Explicit exit
acknowledges unsaved Setup choices before no-color restart.

The first httpx import persists one owned host/service pair and discloses one
scope refusal and one unusable row. A later malformed file retains its first
record and fails on line 2. Canonical HAR and both exact Bounty routes retain
three observations over two informational, unverified imported findings. Review
keeps those observations readable while Map and Scan remain incomplete.
Restart preserves that state. Source hashes remain unchanged, and phase
attempts, investigation jobs, provider reservations and human decisions remain
absent. A suggested follow-up only drafts a command; it launches no work.

Four actual headless runs consume the same owned formats through the CLI/shared
prepared boundary and produce completed receipts with identical scope and
ledger checks. Core tests cover the canonical alias, malformed/unknown input,
missing paths, literal filenames, pre-cancellation and retained earlier records.

Four assistant screen judgments remain separate in `assistant-screen-review.json`.
Raw native status is REVIEW_REQUIRED and operator approval is false. Compact
reading requires paging, long paths wrap, and some Review captures explicitly
show a ledger refresh. Input latency, physical-terminal accessibility and full
reference-product UX equivalence are not established.

## Verification and remaining scope

Ninety-six distinct focused Core/TUI tests, the locked workspace build and the
329-file risk proxy pass. All ten repository summary gates pass. The receipt is
`/tmp/kuzushi-passive-import-20261011/precommit-verify-receipt.json`.
It records local-platform/CI omissions and dirty/drift state, so it remains unsigned.

The first native run exposed false Map/Scan completion, a wrapping-dependent
assertion and an unacknowledged exit. The next run verified the workflow repair
and restart but retained the wrapping assertion failure. A third run reached
the compact warning, then paged past it before its assertion. All failures are
retained. The final journey checks the observed compact page and verifies exact
skip counts in persisted receipts rather than assuming a sentence occupies one
terminal line. No running journey or fixture was edited.

The visible per-tool matrix now has 75 scoped assessments among 112 tools;
37 remain unassigned, including eight excluded actions. Both Bounty imports
receive supplemental evidence without increasing that catalog denominator.
No module is promoted, retired or deleted. All nine broad delivery milestones
remain open, including live-model usefulness and complete UX acceptance.
