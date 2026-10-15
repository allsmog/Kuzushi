# Scope membership, staging and historical approval

The module audit reproduced a supported-path defect in `pack:scopes` at
`fa3f844789070d6cfce3ef3048157dfb46219419`. An owned repository contained one
tracked file and one existing untracked file. Staging the second file changed
Git inventory membership without changing Git SHA, working-file bytes, content
tree hash or snapshot hash. The cache returned the old one-file inventory.
Acceptance of that old scope also succeeded after staging. Zero uncovered files
therefore referred to stale inventory. The original native receipts are retained
at `/tmp/kuzushi-scope-membership-20261015/probe`.

## Shared behavior

New scope sources bind `enumerationHash` separately from content identity.
Bounded Git acquisition fingerprints its complete captured path output before
limiting retained names to the processing cap and one overflow witness. Content
inventory uses that captured list rather than acquiring another list during
construction. A metadata pass binds enumerated regular files, omission receipts,
enumeration method and entry count. Both Git and filesystem paths retain their
existing containment and cancellation rules. The metadata pass reserves zero
content-inspection bytes; source identity and policy checks perform separate IO.

Cache lookup includes content snapshot and enumeration binding. Cached membership
must match the captured metadata receipt. Fresh publication rechecks membership.
Edits, acceptance and accepted-scope resolution share that validation, so study
preparation and scanner consumers cannot reuse an old membership after staging.
Staging already tracked content without changing working-file bytes or membership
retains equivalent cache reuse. No model or runtime fallback is added.

Legacy version-1 source fields remain readable through optional deserialization.
Their original records, approval, references and hashes remain intact. New work
requires an explicit inventory rebuild and acceptance, followed by separate study
approval. The shell shows `MEMBERSHIP UNBOUND` with rebuild guidance and labels
content-identity omissions separately. No old plan is silently rewritten or
restarted. New strict-reader compatibility is documented in `RELEASING.md`.

## Evidence

Core checks pass: 44 scope application tests, ten Git-acquisition tests and
100 inventory tests. One manual throughput probe remains ignored in that suite.
These include unchanged-content staging, old-scope refusal and history,
equivalent existing-file staging, filesystem cache reuse, captured-list use after
index change, complete-output fingerprints beyond the retained prefix and refusal
of valid but substituted cached subsets. The first new filesystem test correctly
refused acceptance without its normal inventory-limit acknowledgement; the
fixture now supplies that acknowledgement.

The shell's scope suite covers legacy binding guidance and retained approval.
The workspace builds with the recorded Rust/build inputs frozen. Evidence,
executable bundles, source manifests and all intermediate results live at
`/tmp/kuzushi-scope-membership-20261015`.

Sequential native J278 creates an owned three-file fixture using the real prior
executable, with its exact SHA256 checked. The new executable reads that legacy
approval and refuses its use. An explicit new two-file scope is accepted, then
staging the existing third file causes both acceptance and study preparation to
refuse. A fresh inventory includes the file while SHA and content snapshot hashes
remain unchanged. Explicit acceptance feeds a real three-job, one-worker study
draft through shared dispatch. The plan remains unapproved and unstarted. Source
hashes, legacy history, zero provider requests and zero findings/decisions are
checked across resize, paging and no-color restart. Target source is never
executed. The interim native run has 19 machine passes, zero failures, 18 capture
pairs and five pending human judgments. Copy review then distinguished files
without content identity from the separate membership binding.

Final J278 at `tui-v2/20261015-055453/J278` has 19 machine passes, zero
failures, 18 plain/ANSI capture pairs and five pending human judgments. It exits
`REVIEW_REQUIRED`, not human-approved. The final source passes 193 focused
checks: 154 Core checks and 39 scope UI checks. The Core source remains identical
to its v2 checks; v3 changes only the content-identity label and its UI assertion.
The locked workspace build passes. All 4,181 recorded Rust/build inputs match
before the final UI checks, after build and after native capture. The frozen
bundle contains 13 executables; its main executable SHA256 is
`25d6a7ad0c016cc2f738be521eb499959139cc25f43413a56483744cbd0c188e`.

## Limits

Inventory bounds remain 100,000 entries, 512 MiB inspected content overall and
256 KiB per inspected file. The complete Git path fingerprint remains subject to
the existing 64 MiB subprocess output cap and 30-second acquisition deadline.
Failure, truncation and cancellation retain their honest outcomes. Metadata and
source checks add IO and do not establish an overall latency guarantee.

The native fixture is small and contains no vulnerability findings. It proves
membership and consumer behavior, not detection quality, live model usefulness,
triage accuracy or scan completion. No scans, provider requests or target-source
execution occur in J278. Cache-subset rejection preserves historical artifacts;
it does not automatically repair an invalid cache. Human judgments, broad module
qualification, giant-repository behavior, the full Rust suite and CI/platform
matrix remain open. No broad delivery milestone is closed.
