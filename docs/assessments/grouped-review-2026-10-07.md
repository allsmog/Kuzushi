# Grouped Review and exact observation navigation

Accepted duplicate relationships now produce source-bound presentation groups
without changing finding identities or verdicts. Components are built over the
complete selected ledger before group and member paging. Related variants and
uncertain matches remain separate. This is an increment on main; the full
investigation goal and its nine milestone checks remain open.

## Behavior

The read-only `findings:groups` tool has descriptor-backed filters, selected Scan
run references, group selection and bounded pages. A group can have more
members than one page. Every member keeps its own alias, source run, finding id,
severity, proof label and recorded decision. Grouping never completes Review.

Accepted links must match both endpoints' current recorded ids, fingerprints,
stable keys and runs. Old-source or excluded endpoints do not silently join a
current group. Iterative traversal handles cycles and deep components. Source
changes and undo invalidate held group references rather than establishing a
fix or applying another merge. The grouping revision binds the target, selection,
members and relationship records. General read receipts do not change it.

The existing relationship surface now also has a group/member reader. `groups`
or Review `G` opens it. Enter moves from a group to bounded member pages and
then to the selected observation's ordinary Review detail. `G` returns to the
same group, member page, selection and scroll. `L` opens that member's
relationships. Unlink remains explicit and reason-required; stale grouping has
a refresh action. Background reads use the existing cancellable hydration pool,
and the group cache retains at most eight pages. No model work starts here.

`generation:<id>` is an additive exact observation reference shared by existing
lookup services. It reads the recorded generation rather than rebinding a
fingerprint to a newer observation. Existing fingerprints, prefixes and aliases
remain compatible. Source/run comparisons remain necessary for current-source
triage; an old generation is historical evidence.

## Verification

Evidence root: `/tmp/kuzushi-review-groups-20261008`.
Seven core tests pass, covering cycles, separate variants/uncertain links,
complete components before paging, undo, source change, cancellation, target
binding, read-receipt stability, 6,000 connected observations and exact old/new
generation navigation. The shared prepared tool test passes with no model,
including invalid/unknown options. Ten relationship TUI tests pass, including
the four new group navigation, real-key dispatch, target-switch and viewport
checks. Native build passes. All ten repository gates pass in
`/tmp/kuzushi-review-groups-20261008/verify-ownership-summary.json`.

Final J115:
`/tmp/kuzushi-review-groups-20261008/tui/20261007-223123/J115`.
Raw REVIEW_REQUIRED and exit 4 remain unchanged: nineteen machine passes,
zero failures and six review questions. `manual-review.json` records separate
scoped passing judgments; `ansi-review.json` records eighteen live frames.
`identity-history-check.json` compares all sixty-five current ids/fingerprints
with the original observations, which predate relationship proposals. Sixty-three
proposal/acceptance histories retain their endpoints, and exactly one relationship
has a later removal. No finding decision or rekey is recorded. Source bytes are
unchanged; exactly one intercepted provider request is accounted. The driver is
unchanged. The binary SHA-256 is
`e26fb738673c29c11cbb362c472f47090ea7128823172413dc81be9c252c76d1`.

The first native run reached the second page of a 64-member group, then failed
because raw database ids were sent to the fingerprint reference resolver. The
new generation reference fixes that path. Narrow captures also exposed generic
page steps skipping lines beneath a sticky header. The reader now supplies its
actual body height to the shared scroll path. Retain the failed run and judge
every final text/ANSI capture separately from raw machine status.

Later runs exposed return-mode restoration, normal hotkeys missing the configured
action handler, and uppercase keys rejected when Shift was present. A real-key
reducer test now covers the shared normal/configured path. Final screen review
also corrected a generic Escape notice and an empty-composer entry that left the
group reader in Prompt mode. The reader enters Navigate when appropriate and
does not announce conflicting Escape instructions. Failed predecessors remain.

## Limits

Fixtures use owned greeting data, labeled observations and intercepted provider
transport. They never execute source or claim live-model finding quality.
Native coverage is 120x36 and 40x12 plus no-color; focused render tests cover six
sizes. Group-wide finding decisions and bulk proposal review are not implemented;
individual observation decisions remain independent. All query/run-scope
combinations and source drift in the native group flow remain unverified.
Group reads still load the complete selected corpus before paging, so large
ledger IO/resource readiness needs additional evidence. Reusable lessons,
monorepo editing, the full module audit and complete reference-quality TUI
acceptance remain open.

The captured global route/posture chip, historical notice copy and singular
member labels remain clarity/polish opportunities. The scoped group workflow
checks pass; this is not complete reference-quality UI acceptance.
