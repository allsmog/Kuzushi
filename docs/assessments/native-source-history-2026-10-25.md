# Native source history qualification

Native SAST observations now retain the authenticated source snapshot and cited
file blobs. Review reads saved bytes for a saved generation, even after another
scan or checkout change. Exports distinguish the run checkout from the actual
observation source and retain older relationship endpoint sources after every
current finding has been observed again. Unknown historical Git metadata stays
unknown. These references do not establish current applicability or a fix.

## Implementation and compatibility

SAST passes its existing pre-execution snapshot into native orchestration. The
standalone native orchestration helper captures one snapshot before discovery.
Before publication, cited files must match the captured tree and all cited
locations must be valid. Retained source shares a 64 MiB batch limit. Source drift,
cancellation, missing or nontext files, invalid citations and retention limits
preserve observations with unavailable grounding. That path does not substitute
live bytes after source authentication fails.

Native coverage writes version 3 and reads versions 1, 2 and 3. Optional
`sourceBinding` records authentication, snapshot/tree identity, retained bytes and
files, the retention limit and any limitation. Source-binding limitations make
coverage partial independently of scanner coverage errors. Successful source
binding authenticates the retained citations, not complete repository coverage.

The indexed exact-generation reader returns `RecordedObservationSource` version
1. Its left join preserves observations whose legacy snapshot metadata is
missing. Run metadata, the current checkout and later observations cannot fill
unknown snapshot fields. Existing observations and human decisions are not
rewritten.

Shared workspace exports add `runGit`, `observationSource` and
`relationshipSources` to provenance. JSON, JSONL, CSV, SARIF and Markdown bundles
retain the same source references. CSV appends three columns without moving old
columns. Markdown places historical endpoint references under relationships,
separately from the current finding's location and source. Endpoint references
are not the complete raw observation log. Format and Rust struct-literal
migrations are documented in `RELEASING.md` and `docs/modules.md`.

Saved-generation Review never substitutes current checkout text while retained
source is missing or loading. Unsaved previews compare surrounding lines and
spacing too. A typed display field keeps the retained identity in the Source
heading, with a shorter `saved / run Git` label in compact layouts. This adds no
code row. Run-checkout metadata is explicitly labeled and is not presented as
observation-snapshot Git metadata.

A durable identity decision can belong to a later observation than the selected
historical generation. The decision source check now names that different basis
without inventing chronological order. Verdict authority and reassessment policy
are unchanged. Existing conflict tokens remain compatibility values; their
names alone do not prove event order.

The terminal reference fixture now uses actual stored generation identities and
hydrates retained bytes through the shared reader. Only temporary identity aliases
are normalized in golden snapshots. Four reviewed Review snapshots change their
heading and normalized identity; existing code rows, including the cited line at
80 columns, remain visible. The fixture's deliberately unseeded source files
remain unavailable rather than gaining fabricated bytes.

## Owned source experiment and terminal evidence

Final sequential J367 uses two existing commits from the authenticated owned
fixture bundle:

- Baseline: `7cac9e253984e19ccc6aaeee3eb157de049ba667`.
- Later: `c557cdbf94b931ecc250b33d33d793f79036a908`.

Two fixed, runtime-free `secret-scan` SAST jobs inspect two explicitly selected
files containing the public AWS example credential. Both findings are observed
at both revisions. The fixture changes surrounding comments while preserving
the cited line, then temporarily removes the current file. One scripted
relationship proposal references the two original generations. It is not a
model opinion or a demonstrated duplicate vulnerability.

The actual terminal opens the exact earlier generation, reads it at 160x48,
120x36, 96x89, 80x24, 60x20 and 40x12, and pages through retained source and
recorded references at the narrowest size. Run comparison displays both complete
Git SHAs, dirty state and content identities. Human actions mark the latest first
finding FP and defer the second. Report performs a real JSON export; five public
export calls independently validate current observation sources and both older
relationship endpoints. No-color restart recovers the earlier source, both human
decisions and the actual Report page.

The final result is 38 machine passes, zero failures, 25 live capture pairs and
four pending formal operator judgments. Agent answers address State, Intent,
Honesty and Craft separately for every question. They do not replace operator
judgment. ANSI cell replays are reconstructions, not OS screenshots.

Final native executable SHA-256:
`f56ea6eb361e8045002706b894f30c92ac03b39be88f6d7d91cded2b9f43c7d3`.
The wrapper authenticates 6,625 repository inputs and 14 frozen programs, and
confirms that repository inputs, HEAD and program bytes stay unchanged during
execution. The final fixture retains four raw observations, two finding
identities, one proposed relationship and two human decisions. All five formats
preserve the later source SHA plus the original relationship endpoint SHA.
No source is executed and no provider request is made. The earlier live-model
experiment total remains sixteen, with no new approved model capacity consumed.

Local evidence root:
`scripts/devex/artifacts/native-source-20261025/`.
The final terminal directory is
`native-attempt-4/native/J367/20261025-094239/J367`; terminal receipts, source/export
checks, frozen inputs and separate agent answers are retained alongside it.

Earlier attempts remain available:

- Attempt 1: 33 machine passes and two failures. Restart displayed later
  surrounding bytes for an earlier generation when its cited line matched.
- Attempt 2: 35 machine passes and zero failures, but agent review failed the
  unsupported claim that a scan followed an earlier FP decision.
- Attempt 3: 38 machine passes and zero failures. The no-color Report wait could
  match Review before navigation completed. Attempt 4 uses Report-only text.

These failures were not converted into acceptance by removing assertions.

## Verification and limits

Focused results include 25 native orchestration checks, 100 persistence checks,
103 SAST checks, six coverage checks, four real export-consumer checks, 58 finding
view-model checks, 31 detail-renderer checks, 12 decision-state checks, one queue
label check and ten reference-fixture checks. Groups overlap; they are not an
additive total. The final viewport suite passes all 19 tests, covering 120
phase/size/profile buffers, 18 investigation snapshots, 30 compatibility snapshots
and plain output. Core/TUI Clippy, workspace build and the risk gate pass. A
preexisting vendored terminal warning remains outside the changed code.

The final shared repository check is recorded separately in
`repair/draft-receipt-final.json` and `repair/quick-summary-final.log`. It includes
this assessment. A dirty, unsigned draft receipt does not authorize publication
or replace clean verification and signing for a new commit. The previously
approved signed verification receipt is preserved.

This experiment qualifies source retention and report provenance in the tested
native SAST path. It does not establish every engine's citation quality, detector
precision, useful duplicate proposals, a complete accepted-context study, model
quality or parity with reference products. Report labels the ad hoc Scan as
legacy inferred and discloses missing scope, coverage and spend information.
Binary and unavailable citations remain unbound. Legacy unknown SHAs are not
backfilled. No module is promoted or retired.

The separate lesson and relationship drafts retain their original bytes and
modes. The broad goal remains open for per-tool qualification, useful monorepo
planning, context experiments, learning at scale and full operator TUI acceptance.
The prepared paid scope experiment remains unapproved. Exploit development,
reproducer work and vulnerability patching are excluded.
