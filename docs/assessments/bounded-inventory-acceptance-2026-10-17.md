# Bounded inventory acceptance

The bounded iterative inventory and inventory-derived candidate item is
implemented and verified locally. This closes that delivery item only. The
other eight delivery items and the complete operator-experience requirement
remain open.

## Requirements and evidence

| Required behavior | Current evidence |
| --- | --- |
| One bounded content inventory supplies candidate groups | `shard_suggest/candidates.rs` derives groups from the shared inventory without directory-statistics recursion. Scope inventory is cached by source snapshot and captured membership. Current application tests verify reuse, tampered cache refusal and staging-aware invalidation. Source identity and membership verification remain separate bounded IO. |
| Preserve the 100,000-entry, 512 MiB overall and 256 KiB per-file inspection limits | Current inventory tests cover entry and byte exhaustion, prefixes, cancellation and metadata-only continuation. A final-binary shared-dispatch probe against 100,001 owned empty regular-file names stops at 100,000 entries, returns partial status and the documented exit code 4, and preserves the exact configured byte limits. |
| Iterative fallback, containment and symlink exclusion | Current inventory and contained-root tests cover deep trees, cycles, external symlinks, unsafe ancestors, directory replacement and root replacement. No filesystem directory walk consumes recursive Rust calls. |
| Disclose ignored, uninspected and truncated material | Receipts retain omissions, per-file prefixes, entry exhaustion and enumeration completeness. Scope review, acceptance and file paging consume these facts. Unknown legacy completeness remains limited and requires explicit acknowledgement for new acceptance. |
| Preserve loose parent files and keep whole-repository work available | Candidate tests retain loose source and non-source parent/sibling files, bound candidate count and preserve oversized leaves. The default scope draft remains the whole repository. The wide probe retains one oversized repository candidate and installs no scopes. |
| TUI and failure states accompany the increment | Current J330 exercises visible palette entry, six viewport sizes, refusal without acknowledgement, preserved draft revision, explicit boundary acceptance and no-color restart. Source, work and accounting assertions are independent of the captures. |

The 100,001-file case uses empty regular-file hardlinks under an owned temporary
directory. It tests filename scale and the actual entry boundary, not content
throughput or architectural understanding. The final debug binary completes
that inventory probe in approximately 5.7 seconds on this host. This is not a
release benchmark. A supported `pack:scopes` draft over the same fixture also
preserves limited inventory and whole-repository membership.

## Correctness repair found during the audit

The inventory receipt distinguished complete file enumeration from a limited
content prefix, but scope coverage inferred enumeration from the first general
truncation marker. A two-file shared-dispatch probe reproduced conflicting
facts: enumeration was complete in the inventory and incomplete in its scope
projection.

Scope coverage now uses the recorded enumeration flag. Complete enumeration
with content prefixes stays `inventoryLimited`, requires the existing explicit
acknowledgement and cannot establish complete repository coverage. Missing
legacy flags are unrecorded completeness, not evidence of completion. The
reader, category details and acceptance surface display enumeration separately
from inspection and exclusions. Tool options and artifact schemas are unchanged;
the compatibility clarification is in `RELEASING.md` and `docs/modules.md`.

The final binary reads the corrected facts from the earlier immutable scope
record while retaining its reference and original saved run-result bytes. It
does not rewrite historical evidence, accept a scope or start discovery.

## Qualification and limits

All 264 distinct focused Rust tests pass: 35 scope-domain, 45 scope-application,
118 inventory, ten candidate/compatibility, fifty scope TUI and six contained-root
checks. The locked workspace build, Core/TUI all-target Clippy and CRAP-risk
proxy pass. The risk gate covers 41 changed production files across the staged
checkpoint and subsequent drafts. The quick repository gates also pass.

Final sequential J330 records 24 machine passes, zero failures, 17 capture pairs
and three pending human judgments. Thirteen binaries, 4,605 source inputs and
808 runtime inputs are checked before and after execution. Independent checks
confirm two unchanged source files, no campaign directory, only `pack:scopes`
tool receipts, refusal retaining revision 1 and acceptance/restart retaining
revision 2. Uninitialized accounting is recorded as null fields rather than
invented zero usage. No allowance is created.

Ten ANSI cell replays were inspected, including all requested sizes, the narrow
reading continuation, refusal, acceptance and restart. These reconstructions
are not OS screenshots and close no formal human judgments. Requested terminals
are 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48; tmux reserves one status row.
The replay font does not reproduce every terminal symbol faithfully. Broader
information density, reference parity, model usefulness and monorepo workflow
acceptance are outside this item.

Three failed native fixtures remain retained. They exposed assumptions about
lazy accounting initialization and the system SQLite reader. The final fixture
uses isolated configuration and the existing stable checkpointed-ledger helper.
Production Rust is unchanged across those native candidates.

Evidence roots are `/tmp/kuzushi-inventory-boundary-20261017` for the owned wide
and prefix fixtures and `/tmp/kuzushi-inventory-completeness-20261017` for focused
logs, final headless proofs and `native-v4`. No live inference or target-source
execution is added. Historical live requests remain fourteen with no approved
capacity left. The staged 53-file publication checkpoint is unchanged; this
repair and acceptance record remain separate unstaged work.
