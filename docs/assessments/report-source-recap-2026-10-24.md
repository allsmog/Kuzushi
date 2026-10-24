# Report recurrence and source comparison, October 24, 2026

This increment closes the two display defects identified by the
[context matrix experiment](context-matrix-evidence-2026-10-23.md).
Report's recurrence recap now includes severity and the exact quoted recorded
location for every observation. It shares the case reader's presentation helper.
Source, model and allowance precede the recurrence list; optional details include
each observation's fingerprint, identity, alternate locations and run references.
The underlying receipt, exported finding paths and human decisions are unchanged.

Run comparison no longer prints an unknown-content warning unconditionally.
Its note reads the same recorded artifacts as its source labels and distinguishes
matching content hashes, differing hashes and unavailable content. Missing or
malformed hashes remain unverified, even at matching Git SHAs. Matching hashes
describe indexed content, not complete repository coverage or a finding verdict.
Plain and interactive output use the same projection; the current checkout does
not supply a substitute identity.

## Verification

Both defects have retained red regressions. Focused checks cover same-title
observations at distinct literal paths, unchanged per-case recurrence, full
observation references, matching and case-varied hashes, differing hashes,
missing hashes and malformed hashes. All 123 distinct focused TUI checks pass,
including existing Report input, comparison, matrix and plain-output checks.
Workspace build and TUI all-target Clippy with warnings denied pass. The risk
proxy passes for 120 changed code files. Final repository summary verification is
recorded separately in an explicit dirty draft receipt, without modifying the
clean signed publication receipts.

Evidence is retained in `scripts/devex/artifacts/report-source-recap-20261023/`.
Final J348 is `native-attempt-1/native/J348/20261024-000040/J348`: 65 machine
passes, zero failures, 72 capture pairs and nine pending operator judgments.
Raw exit 4 remains `REVIEW_REQUIRED`. All 6,474 source inputs and 13 frozen
programs stayed unchanged during this sequential run on dirty main at
`f744320dc3ed4cf0ded3122ebbc012e8d6e58479`. Native SHA-256:
`7677506684d736ec4cb37341862c9e5163a7a5844bd3eb8588997b3cb3f50fee`.

Nine intercepted GPT-5.5 medium requests complete the three explicitly chosen
contexts and three passes each. They start fresh sessions without earlier
observations. Independent checks reconcile nine fixed jobs and attempts, 15 raw
observations, two identities, zero human decisions, nine settled reservations,
one allowance revision and two unused protected Review calls. Source files and
the globally active context stay unchanged. The export sidecar equals its
embedded receipt. Report paging and details, export, accounting failure/recovery
and no-color restart add no requests. Missing observations never establish a fix.

Fourteen final ANSI cell replays were inspected across all six Report sizes,
narrow End/PageUp, observation details, source comparison, export and recovery.
They use Menlo 15 and a chosen dark background, not OS screenshots. The replay
font has no CJK fallback; exact Unicode is checked in captured text and data.
This does not qualify native terminal font fallback or formal operator approval.
Earlier compile diagnostics remain retained alongside the red regressions.

No live request or target-source execution is added. Cumulative live experiment
use remains 16, with no allowance remaining. This is workflow and transport
evidence, not live inference quality. The remaining delivery audit must reconcile
the broader module, scope, experiment, learning and complete operator journey
requirements; no broad delivery checkbox changes from these two display fixes.
