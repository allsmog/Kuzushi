# Entry-point cancellation and publication

October 11, 2026. Local changes on main at `f8649511f746`.

`entry-points:extract` now checks cancellation while collecting catalog rows and
authenticating dirty or non-Git source trees. Cancellation remains an execution
error; verification cannot mistake it for stale context and silently degrade it.

The producer serializes and bounds the candidate catalog, then checks the outer
source snapshot, the exact context revision and cancellation before atomic
replacement. Rejected work preserves the prior catalog. The automatic catalog
refresh consumer also validates before publication. A subsequent source-check
failure retains the saved tool result as partial, rather than reporting a failed
save after replacing the artifact. Stale-tree errors name the two explicit
recovery commands. No descriptor, artifact schema or public dispatch changes.

These checks do not lock the source tree. A mutation during or after publication
can make the catalog historical. Consumers must continue authenticating its
source/context identity; this increment does not certify arbitrary concurrent
mutations or repository-wide coverage.

51 focused checks pass: 35 catalog checks, seven real prepared-dispatch Map
contracts, four source-result lifecycle checks and five terminal queue checks.
New cases cover cancellation during row collection and source hashing, late
cancellation, source/context drift, outer validation failure and preservation of
prior bytes. The locked workspace build and 273-file production risk proxy pass.
All ten quick repository gates pass in
`/tmp/kuzushi-entry-point-publication-20261011/precommit-verify-receipt.json`.
The receipt records dirty/drifted state and stays unsigned. The initial
architecture and formatting failures remain in sibling receipts. The
workspace-write rule now checks the actual catalog publication function and
retains the protected-write requirement; its focused repair also passes.

Final sequential J200 is
`/tmp/kuzushi-entry-point-publication-20261011/settled-native/20261011-085918/J200`.
It records 15 machine passes, zero failures and 15 authenticated text/ANSI
captures. Native SHA-256 is
`63f1bc9fe18a8f0cfdad0c6294a18eef03ea83e77736056a05aa245f891cd77e`.
The actual native binary, six viewport dimensions and no-color restart agree.
The owned inert fixture preserves source bytes except for its explicit comment
revision, refuses stale extraction, preserves the prior catalog and rebuilds
only after two requested tool actions. No provider work or source execution
occurs. The original live fixture still has four reservations, six attempts,
three observations and one decision.

Four earlier failed runs remain under `native`, `native-recovery`, `final-native`
and `final-source-bound`. They expose an old direct SQLite reader failure,
an incorrect expectation for collapsed result text, an HTTP-only row assumption
and an early capture during an ordered input burst. The fixture now reuses the
WAL-safe ledger reader, accepts non-HTTP handlers, authenticates actual artifact
completion and verifies the final narrow-detail row. A bounded three-second
settling interval lets the 100-key burst drain; the final capture reaches row
55 of 55. This is not a throughput benchmark.

The native verdict remains `REVIEW_REQUIRED`, with operator approval false.
Assistant judgments are separate in `assistant-screen-review.json`. The compact
gallery exposes only two detail rows, so provenance requires many pages. The
generic Map-ready receipt does not lead with the auxiliary tool's result. The
deterministic legacy Map reader explicitly calls freshness unprovable even when
catalog payloads match. Those UX and provenance qualifications remain open.
No module is promoted or retired, and no broad delivery milestone closes.
