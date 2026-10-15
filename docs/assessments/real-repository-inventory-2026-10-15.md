# Real repository inventory and source-bound scope review

This checkpoint qualifies one isolated local snapshot of Kuzushi at
`426d974216424609281bb497ebcd64acdb8fa13e`. The shallow clone contains 5,771
tracked files and 48,147,850 tracked bytes. Target source is never executed.
No model requests, discovery jobs, findings or human finding decisions are
created. This is structural inventory evidence, not discovery-quality evidence.

The context receipt records 5,644 regular-file members, a 200-file sample,
seven omitted paths and 13 prefix-limited files. Its reported inspection-byte
count is 42,791,340. Limits remain 100,000 entries, 512 MiB overall and 256 KiB
per inspected file. Ignored directories and the tracked `CLAUDE.md` symlink
remain excluded. The result stays partial and cannot establish complete
repository content coverage. Source identity performs separate IO.

## Change and native workflow

Scope coverage previously exposed counts and the first partial-inventory cause,
leaving most omitted and prefix-limited paths in the saved artifact. The shared
coverage projection now names recorded omissions with reasons, prefix-limited
files and the inspection bounds. Each category previews at most 128 paths and
explicitly counts additional recorded entries. The full recorded list stays in
the immutable inventory. This adds no artifact fields or dispatch options.

J277 uses the installed wrapper and a frozen native bundle, with a fresh owned
source clone and isolated HOME. It builds deterministic context, preserves the
whole-repository boundary, reads the first and final membership pages and builds
another draft using the same inventory identity. It reads inspection details
across six terminal sizes, including actual narrow paging. Acceptance without
the inventory acknowledgement refuses; a separate acknowledgement accepts the
exact boundaries and starts no scans or spending.

The fixture then advances only its own Git revision using an identical tree.
Editing the old accepted scope refuses with `Git revision changed`, retains the
entered name and leaves the saved scope intact. No-color restart reads that
historical accepted record without authorizing work at the new SHA. Complete
tracked-file hashes, file-tree identity and zero-work ledger checks are retained.
There are no findings in this test, so it establishes no fix or recurrence claim.

Final J277 at `tui-v5/20261015-043331/J277` records 25 machine passes, zero
failures, 22 plain/ANSI capture pairs and five pending human judgments. Its
`REVIEW_REQUIRED` result is not a human UX approval. The 40-column acceptance
reader has two detail rows and requires repeated paging for long disclosures.
Historical source is labeled with its recorded SHA; this checkpoint does not
qualify a current-source freshness indicator on every reader.

## Verification and limits

The final source passes 175 focused Rust checks: 32 scope-domain checks,
100 inventory checks, 37 scope-application checks and six contained-root checks.
These include deep iterative traversal, symlink exclusion, entry/byte caps,
cancellation, uncovered membership, cache integrity, concurrent revision checks
and unchanged-tree SHA drift. The manually invoked inventory probe is separate
from those checks. The locked workspace build passes. All 4,177 recorded
Rust/build inputs match before tests and after build. The frozen native bundle
contains 13 executables; its main executable SHA256 is
`71efa2c36ee940045d951bf564b901bdb1898a931c41304e2cc25969cae602b7`.

Evidence lives at `/tmp/kuzushi-real-inventory-20261015`. Failed and exploratory
runs remain retained. The first fixture incorrectly rejected the harness's
owned seed Git directory. Subsequent failures captured an asynchronous
membership-page assertion, a combined Escape/character input that did not
dispatch the next action, and an assertion spanning a correctly wrapped line.
The journey now waits for the actual final page, proves return before the next
inventory action and uses a wrapping-safe text check. The shared harness is
unchanged.

An exploratory Git configuration used `/dev/null` for global and system config.
Its device timestamps changed during validation and policy verification refused
work. A direct metadata probe records this. Final fixtures use stable owned
empty regular config files. Device-backed Git configuration remains unqualified;
this checkpoint does not fix that compatibility case.

A separate attribution probe caps enumeration at 5,000 entries. During native
journey work, it reported approximately 0.698 seconds for metadata-only inventory
and 20.906 seconds with content inspection in this local debug build. Both
results are intentionally partial. These are diagnostic observations, not a
release throughput benchmark, an input-latency measurement or evidence of giant
monorepo performance. Optimized-build profiling, larger real repositories and
operator judgments remain open. The complete product outcome, full Rust suite,
CI/platform matrix and reference-product parity are not certified here.
