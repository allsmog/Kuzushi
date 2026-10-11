# Filtered Review navigation and external decisions

Review now keeps an explicitly opened finding's detail and manual decision target
consistent outside the active query or component. A guarded alias belongs to its
captured ledger watermark and grouping policy. A changed ledger withholds that
alias while retaining the captured watermark for stale-write protection. List
navigation releases the pin. Current findings' decision history is read once
independently of the list, including suppressed findings and scoped-out pins.
Scanner triage remains separate from append-only human decisions.

Passive refresh recovers once to the first page when its cursor row leaves the
query. It retains the filter, publishes a notice and preserves recorded
decisions. Core exposes a distinct missing-anchor error; explicit invalid
cursor or anchor requests remain strict. Other read errors do not trigger
repair. The existing coherent-snapshot and stale-result guards remain active.
The full-ledger progress projection controls Review access, so an empty filter
cannot lock the phase while Report remains ready.

The pin warning wraps without clipping. Its compact wording keeps identity and
decision target complete at 40x12. Real list focus and navigation return both
detail and action target to the visible row. The product introduces no new
scanner, model, runtime, artifact format or background discovery work.

Evidence is under `/tmp/kuzushi-experiment-main-20261006/`. Ten Core paging
checks pass, including distinct missing-anchor and malformed-cursor errors.
The focused findings suite passes 189 tests, including filtered and component
pins, suppressed history, stale aliases/watermarks, explicit errors and passive
recovery. A wrap check and a full-ledger phase-access check pass. Workspace
build passes. Final keyboard, refresh, composition and repository checks are
recorded in the separate closeout receipt.

Final native J104 is `tui/20261006-235214/J104`. It records 21 machine passes,
six passing ask judgments and six passing related-frame judgments across
120x36, 160x48, 96x89, 80x24, 60x20 and 40x12, including no-color restart.
The raw exit 4 and `REVIEW_REQUIRED` remain unchanged; `manual-review.json`
records judgments separately with text/ANSI hashes and capture provenance.
All 16 captures use native SHA256
`d2013c0573d18cfc2e0bab265a417754d357d65340f4e30300c3bb52a1579217`.
The tiny editable draft appears within 78 ms. This single sample does not
establish worst-case latency, accessibility, physical display contrast, platform
coverage or complete parity with the reference applications.

The owned fixture has 1,000 labeled synthetic findings and 2,000 unchanged
observations. Final verification checks two ordered explicit human decisions on
one identity, from 1,058 to 1,060 decisions, with source/artifact hashes
unchanged. Total native writes in this increment are four, including the
earlier complete run, from 1,056 to 1,060. The source and commit metadata are
synthetic; no source is executed. Restart shows the correct durable decision
and excerpt while honestly reporting that its source comparison is loading.

Raw predecessors remain: `234235` failed on a clipped warning; `234609`
used the wrong composer mode/list focus and an identity id where the CLI needed
a fingerprint. Neither reached a decision write. `234746` passed all 20 machine
checks but failed screen review because the tiny explanation clipped and the
empty query locked Review. Each reached ask has a separate judgment. The
driver is unchanged, and no machine or screen failure is relabeled as a pass.
The fixture helper now records CLI failure output and uses a real fingerprint.

No provider request is made. Live allowance, source hashes, accepted context and
seven settled requests remain unchanged. Underlying full-ledger query and
journal cost, synchronous suppression responsiveness, real Git transitions,
larger-scale and platform evidence, per-tool functional readiness, context
experiments, lessons and the complete finite investigation/report still require
work. All nine implementation milestones remain open.
