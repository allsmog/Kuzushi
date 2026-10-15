# Supplied advisory metadata, limits and source authority

`ndiff:fetch-cve` is Labs and auxiliary Map work. Its exact public name,
runtime-free dispatch, required workspace and explicit external-action
authorization remain. Reading an advisory record does not establish target
applicability, finding validity or completed Map coverage.

Supplied metadata previously accepted a record whose id differed from the
requested advisory and displayed its claimed source without a qualification.
Non-object `record` or `fixtures` values could also be treated as absent,
allowing an online attempt. Present values now require object shape. A selected
record must match the requested id, case-insensitively, before any fallback.
Case-based fixture lookup and supplied record contents remain unchanged.

The declared `maxMetadataBytes` limits combined encoded contents of the supplied
record and fixture map, from 1 byte to 8 MiB, defaulting to 8 MiB. A counting
writer checks the bound without another serialized allocation, before cloning
and parsing the selected record. The shared advisory reader applies the default
ceiling to other callers. This is a supplied-metadata limit, not a limit on
online retrieval or the entire request envelope.

Existing `data.record` and `primaryPatchUrl` remain. Additive `data.retrieval`
records requested id, retrieval mode, `sourceVerified=false` and metadata-only
meaning. Supplied output explicitly labels its source unverified. The final
heading starts **Unverified supplied metadata**, so a completed receipt does
not hide that qualification at 40x12. Historical receipts are not rewritten.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | Inspect supplied advisory claims and a primary reference. Applicability and useful downstream analysis remain unqualified. |
| Phase | Auxiliary Map metadata. Descriptor and shell tests prevent phase-result ownership; native restart stays in Setup. |
| Inputs | Explicit workspace, advisory id, object-shaped supplied values and matching selected record identity. Existing external-action authorization remains. |
| Execution | Real shared preparation and dispatch, owned JSON/plain CLI and native shell execution without a runtime. |
| Outputs and consumers | Record and primary-link fields retained, unverified-source receipt added. Durable valid output survives a failed mismatch and restart. No patch content is fetched or analyzed. |
| Failure | Malformed values, mismatched selected ids, byte limits, offline misses and unknown options fail honestly. Live transport and cancellation remain unqualified. |
| Resources | Combined supplied metadata ceiling enforced before selected-record parsing. A hermetic executable stub is not invoked for malformed input. Online aggregate work remains unqualified. |
| Scope | Metadata makes no repository coverage or discovery-scope claim. Owned source bytes remain unchanged and source is never executed. |
| Interfaces | Eight final native CLI cases and J238 agree on outcomes. Six sizes and no-color restart exercise reading. Four human UX judgments remain pending. |

## Verification

Thirty-eight distinct focused Rust tests pass: eight metadata contracts,
three existing offline/policy checks and 27 shell phase/result checks.
The metadata and supporting checks were repeated after the heading refinement.
The 184-tool dispatch policy fingerprint remains unchanged. The locked workspace
build and all ten exact quick-plan gates pass, including 391 Node tests and
the CRAP-risk proxy over 532 changed code files. Package commands ran directly
without disabling signature verification. Full Rust-suite acceptance is not
claimed.

The initial five metadata contract checks failed before the fixes. A later
test fixture incorrectly supplied a nonexistent executable and stopped at
shared path validation; the corrected owned executable stub has an invocation
marker that remains absent. Retained tmux failures document an omitted
in-product confirmation step and a fixture-only SQLite reader issue. The reader
now permits SQLite WAL sidecars while enforcing `PRAGMA query_only=ON` for SQL.
The captures also exposed the narrow heading problem that led to the refinement.

The final J238 result is `REVIEW_REQUIRED`: 17 machine passes, zero failures,
18 authenticated capture pairs and four pending human questions. Operator
approval remains false. It covers explicit action choice, the existing
one-time confirmations, supplied metadata, mismatch failure, retained Replay,
six viewport sizes, exit confirmation and no-color restart into Setup.
Two tool receipts remain after restart, with no additional request.

No finding observations, decisions, phase continuations, provider reservations
or model-call events are created. Absent accounting tables are recorded as
absent. There are no network requests, engine queries, target-program executions
or patch operations. This qualifies owned supplied metadata handling only.
Live retrieval, cancellation, target applicability and product value remain
open. Generic Replay still places technical stream details before full metadata
at narrow sizes; complete reading hierarchy and reference UX parity remain open.

Final native SHA-256:
`f959353862996dfcf72a15508a84c3e93a8d5de10e287beec972c55ed53f0255`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/ndiff-metadata-presentation-tui/20261013-172830/J238`.
Tests, CLI receipts, retained failures, manifests and assistant screen review:
`/tmp/kuzushi-tui-integration-20261012/ndiff-metadata-audit`.

The current catalog retains 113 visible actions: 93 Core, 15 Labs and five
Compatibility. Sixteen in-scope actions remain without assigned functional
verdicts. Prior complete-workflow J121 evidence retains its own recorded bundle
and limits; this audit does not replace it. The live allowance remains exhausted
at six of six. Broad delivery milestones remain open. Work stays staged on main
without a commit or push.
