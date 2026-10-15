# Inventory freshness and visible source changes

Live watching now distinguishes Git index cache writes from staged inventory
changes. The watcher fingerprints Git's authoritative staged paths, modes,
object ids and merge stages. An unchanged fingerprint suppresses only the index
event; independent source changes remain. Unknown reads retain the event and
clear the comparison baseline, so a later successful read cannot claim continuity
through an uninspected interval. Raw public event classification remains unchanged.

The probe runs on watcher registration/callback threads, outside rendering. It
uses read-only Git settings, a two-second deadline, 16 MiB stdout ceiling and
4 KiB stderr ceiling. Limit, deadline and failure states remain conservative.
It creates no discovery jobs, provider requests or automatic reindex action.

Full footers place workspace staleness before routing detail. Compact footers
keep the warning with the autonomy ceiling, while retaining finding counts and
available attention detail. The full cause remains available in wider chrome.
This makes actual source changes visible at every requested viewport size.

## Verification

There are 81 distinct passing focused tests: 48 incremental-index contracts,
19 footer contracts and 14 watcher runtime contracts. The real Git regression
changes index bytes by updating its untracked cache, proving that staged inventory
is unchanged, then adds a staged file and confirms that the inventory event
survives. The bounded reader rejects a one-byte output allowance and a zero
deadline. Unknown reads and unrelated source events remain visible. A 40-column
renderer test keeps the warning, the longest operator ceiling and the finding
count together. Workspace build passes.

An initial byte-change assertion over ordinary stat refresh was not portable:
Git did not rewrite that index. The final test uses an explicit cache update.
Early native runs exposed compact warning omission, lower-priority warning
truncation at intermediate widths, protected planner exit and a resize capture
before redraw. Product fixes address visibility; journey changes wait for settled
rendering and explicitly confirm exit without weakening the recovery behavior.
The earlier evidence remains saved.

## Native evidence

Final J191 is
`/tmp/kuzushi-index-freshness-20261011/final-native/20261011-015207/J191`.
It records 15 machine passes, zero failures and 11 authenticated native text/ANSI
captures across all six viewport sizes plus no-color restart. Native SHA-256 is
`b7326dd95277464ce3418eb0b705c279a80a48b1ec14e4400863e3b2c90cffea`.
Actual and requested dimensions match. Two scoped assistant judgments remain
separate from raw REVIEW_REQUIRED and operator approval false.

The owned fixture locally clones main SHA
`f29dc288e0660ad20d074fc219c025f98ef7d155`, completes a real runtime-free default
Map and explicitly accepts it. A cache-only rewrite changes raw index bytes but
preserves staged inventory. The unsent draft remains and no workspace staleness
appears. Adding and staging an inert scope note then produces real inventory
staleness while preserving the draft. Wide captures show the full warning;
60x20 and 40x12 keep the warning beside the ceiling. Restart returns to Map,
where the earlier context is cached but invalid at the changed dirty source.
The operator can stay or explicitly exit the unsubmitted planner.

The fixture keeps the same commit SHA with a deliberate staged content change,
demonstrating why SHA alone cannot establish context applicability. Its provider
reservations, work attempts, observations and review decisions remain zero.
No scanner or target source executes, no commit is made, and no new context is
accepted after the staged change. The original live fixture and owner
configuration remain unchanged.

## Remaining acceptance

The 180-file production risk proxy and all ten repository summary gates pass.
The earlier risk failure is retained in `failed-risk-verify-receipt.json`; compact
warning composition was extracted without changing its behavior. The unsigned
receipt at `/tmp/kuzushi-index-freshness-20261011/precommit-verify-receipt.json`
records dirty/drifted state and cannot attest to a clean commit. Focused final
documentation checks cover these evidence-only updates.

This resolves the observed cache-only stale-inventory notice. Broad platform and
worktree watching, sustained large-index latency, installed scanner functionality,
complete module readiness, live Review approval and physical/operator acceptance
remain open. No module is promoted or retired. All nine broad delivery milestones
remain unchecked.
