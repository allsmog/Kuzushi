# License policy in scan comparisons

Two prepared-dispatch regressions reproduced gaps in the supported license
scanner path. An unchanged source file first scanned with required SPDX
headers acquired an observation gap when SAST later ran with its default,
disabled missing-header check. A completed empty direct license scan could not
establish covered absence because it recorded no Scan coverage receipt.
The first native comparison then exposed a third gap: direct runs lacked the
per-run `findings.json` snapshot required by the shell comparison reader.

## Implementation

Engine receipts add optional `ruleIds`. New license receipts list enabled checks
independently of whether they produced findings. The missing-header rule appears
only when explicitly enabled; SAST records its actual default policy. A disabled
rule is not reassessed, and legacy unrecorded license policy remains unknown.
The shared rule-aware assessment feeds both ledger comparison and shell run
comparison. Deterministic gap reconciliation applies the same policy guard,
including when another rule produced a positive observation in the later run.

Direct license execution verifies its captured source before committing
findings. Source verification failure persists partial work and partial
coverage, which cannot establish absence. Successful direct runs publish the
existing typed Scan receipt, source references, actual finding delta and run
identity. The authenticated result reader recognizes this host-owned producer
and checks its single engine, target, policy availability and outcome. Other
tools cannot inherit its receipt. No parallel job or persistence system is added.
Direct runs also write the canonical, content-addressed observation snapshot
from the committed run. Empty runs write an explicit empty list. Severity bands
use the existing SAST counting function, moved to the shared receipt surface.

Covered absence retains raw observations and human decisions. The compatibility
event name `FindingDisappeared` remains, but its projection is an observation
gap. It does not establish resolution. The new public comparison helper and
optional Rust field have migration notes in `RELEASING.md`; existing tool ids,
options, aliases and historical bytes remain.

## Verification

Evidence root: `/tmp/kuzushi-license-reassessment-20261016`.
The corrected pre-production regressions both failed on the described product
behavior. Initial harness errors are retained separately: a sampled writer-lock
deadlock, missing application plan and duplicated producing tool call were
fixture defects, not scanner findings. The final fixture uses actual observed
prepared dispatch and settles that call through the same writer.

Current focused checks have 161 distinct Rust passes: 108 Core and 53 TUI.
They cover actual direct/SAST dispatch, rule policy and legacy reading,
post-scan source drift, completed/partial receipt validation, reconciliation,
legacy comparisons, source snapshots and shell comparison projections. The
risk proxy passes for 139 changed code files plus its 15 support checks. The
workspace build passes. Final J295 has 27 machine passes, zero failures and
four pending human judgments across 22 authenticated text/ANSI captures. Its
separately captured page-down frames reach every row of the compact comparison.
Final J159 has 35 machine passes, zero failures and six pending human judgments
across 30 capture pairs. It completes direct repetitions, SAST, Review, JSON
export, oversized-read failure, explicit repair/reuse and no-color restart.
All ten repository summary checks pass. The receipt remains an unsigned dirty
development receipt, not clean-commit or release verification. Final evidence
documentation is checked separately after this update.

Final native SHA-256:
`05a983064409329902de81349eeb6751b2199df6ca94f9f71c013d88e239a561`.
The runner freezes 13 programs, 4,271 source inputs and 720 runtime inputs.
Final native cases are `native/J295/20261016-005304/J295` and
`native/J159/20261016-005339/J159`. Every capture's requested and actual
dimensions, paired text/ANSI hashes and native identity are checked in
`native-evidence-final.json`. Source/runtime manifests remain unchanged during
each final case. ANSI replays are terminal-cell renderings, not OS screenshots;
assistant inspection does not close the ten operator judgments.

The earlier J295 failure remains under `native/J295/20261016-002748/J295` and
`before-findings-artifact`; it correctly displayed unavailable snapshots. Its
copied programs and manifests are retained separately from later validation.
Later failed recipes are also retained. One used Escape to enter Navigate mode,
which correctly left the comparison. A batch of page-down keys did not reach
its final rendered page before capture. Separate page captures now verify both
position and the preserved comparison surface. The older J159 recipe also
matched pending composer text and expected former Review labels; its current
recipe waits for the saved decision and uses the displayed reader controls.
A subsequent J159 failure exposed a real extraction regression: failed output
had lost the underlying license size-limit cause. The adapter restores the
prior full-cause behavior, and a focused test protects both output and error
text. Final native J159 displays the 2,097,152-byte limit before recovery. Its
read-only helper also waits for expected durable run counts, so an earlier
receipt or pending composer text cannot certify another completed scan.

## Limits

Fixtures contain owned inert package/license metadata. Native observations are
local scanner output, while human decisions use explicitly scripted controls.
No source execution, model request, exploit development or vulnerability patch
work is included. Fourteen earlier provider experiment requests remain spent;
this work grants no new allowance.

This qualifies license policy reassessment only. Other engines without explicit
rule receipts retain their existing semantics. Mixed-license architecture,
aggregate read limits, large-read cancellation, every ecosystem and broader
live investigation acceptance remain open. No maturity promotion, retirement,
reference-level UX claim or broad delivery checkbox is justified by this case.
