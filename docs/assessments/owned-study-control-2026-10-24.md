# Owned study activity, cancellation and exit

The held-request investigation showed `idle` in compact Scan chrome even though
the shell still owned its live dispatcher child. That same omitted child let
Ctrl+C and Ctrl+D take the idle exit path. The study deck's Stop action already
authenticated its own dispatcher, but global cancellation did not use it.

The shell now includes the actual owned child in activity and exit decisions.
Recorded queue states or a displayed PID alone do not establish ownership or
liveness. The deck, global cancellation and explicit exit share the existing
cooperative Stop operation, bound to the original target and study even after
navigation changes. A successful request remains pending until the child is
actually reaped. A failed authentication or write stays visible and permits a
fresh request after repair. No arbitrary process is killed.

Ctrl+C and Ctrl+D request Stop while preserving the draft and cursor. Repeated
chords wait for cleanup. Pending local cancellation cannot hide an uncanceled
owned study, and pending study cancellation cannot hide new local work. Explicit
exit names the original study and target, discloses unknown cost, and explains
that work may continue until the dispatcher stops. Stay remains the default.
Unknown session cost also stays unknown when no budget was configured.

## Verification

Five initial regressions failed before the change. All 112 distinct focused
Rust checks now pass, including nine new ownership/cancellation cases, runtime
ownership, campaign results, existing cancellation sequencing, footer bindings,
exit models and exit rendering. One existing process-group test needed host
process visibility; it passed when rerun with that access. The workspace build,
TUI all-target Clippy and changed-code risk proxy pass. The reducer's first risk
failure was repaired by extracting its cancellation decision. Final repository
summary verification is recorded separately at the committed tree.

Final J121 records **227 machine passes, zero failures, 134 capture pairs and
21 pending human judgments**. The actual native run starts from Setup, accepts
generated Map context, approves three fixed discovery jobs, holds an admitted
request, opens exit disclosure, chooses Stay and cancels with Ctrl+C. It then
retains partial work, stops at the allowance, requires explicit attempt and
allowance revisions, completes the original jobs, triages, exports, restarts
without color and inspects a missing context manifest.

The held dispatcher and provider bridge are authenticated before and after
Stay. The completed pass, queued membership, draft and accounting remain
unchanged. Stop reaps the admitted bridge and preserves one completed pass, one
canceled attempt, one unstarted job and the unsettled reservation. Final
reconciliation retains three fixed Scan jobs, four attempts including the
cancellation, four raw observations, two finding identities and three human
decision records. Accounting remains five of seven calls, one unsettled
reservation and two unused protected Review calls. Dollars remain unknown.
The deliberately removed context manifest is restored byte for byte.

Thirteen frozen programs and 6,520 repository inputs stayed unchanged throughout
the journey. The main executable SHA-256 is
`9547bc195d26b47e30aa9aa74a5af335be321ceb1b5124e58ac1e50e7ab7f1e0`.
The earlier frozen attempt was never run and is not a failed journey.

## Screen review and remaining work

Thirteen ANSI cell replays were inspected for wide and compact activity,
exit head/tail, Stop and partial work, allowance exhaustion, Report paging and
restart. The separate Stay text capture and authenticated process checks verify
return to the same live study. These are terminal-cell reconstructions with
Menlo and a chosen background, not OS screenshots or formal operator approval.
The 40-column activity frame keeps `LIVE`, finite counts, Ctrl+C and the Unicode
draft visible together. Exit preserves paging and Stay controls. Report keeps
the two decisions and shared consumption after restart.

The 21 formal judgments remain open. Metadata density, repeated approval terms,
broader active-surface qualification and reference-product UX parity need more
work. General-context input receipts and grounding verification remain different
facts; missing grounding verification is not proof. This increment closes no
broad delivery milestone.

Provider transport is strictly intercepted, with five fixture requests and no
live provider request or target execution. This tests workflow behavior, not
model usefulness. Cumulative real experiment usage remains sixteen, with no
approved live capacity remaining. The TUI wording check found no applicable
register violations; Liminal-specific product vocabulary does not apply here.

Evidence root: `scripts/devex/artifacts/owned-study-control-20261024/`.
It retains the failed regressions, passing focused checks, frozen inputs and
programs, native logs, capture provenance, replays and independent reconciliation.
The previous fourteen staged files stayed byte-identical through this work.
The operator then authorized committing and merging the combined checkpoint,
including the separate Report retry correction.
