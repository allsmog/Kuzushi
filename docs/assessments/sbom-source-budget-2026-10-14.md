# Dependency input allowance and coherent parser inputs

The October 10 module audit identified repeated source reads without an
aggregate byte ceiling. A digest, dependency edge and component could also
come from different reads of a changing file. This increment closes those
specific gaps for `sbom-scan:scan`; it changes no maturity tier and retires
no module.

## Behavior and compatibility

The runtime-free Map inventory declares `maxTotalBytes`, default 64 MiB with
a 512 MiB maximum, and advanced `maxFileBytes`, default and maximum 64 MiB.
Shared prepared dispatch validates both. Standard shell options expose the
aggregate limit, its defaults and the memory tradeoff. Raising tool defaults
does not rewrite frozen approved inputs.

One operation owns a contained directory handle and captured-input store.
Each normalized source path is reserved before its first content read, captured
in cancellation-aware 64 KiB chunks and reused by digest, edge and component
parsers. Referenced Deno import maps use that same allowance and store. A file
that cannot fit is refused before its content is read. Short reads and observed
size changes fail. Reservations and actual bytes read remain distinguishable
on failure. Cached data intentionally stays at its first captured bytes if the
source later changes. Replaced roots and symlink inputs are rejected.

Success adds `data.inspection`: configured limits, reserved/read bytes, captured
files/bytes, per-input hashes and a combined captured-input hash. A failed result
retains available inspection evidence without publishing component claims.
Validation or opening can fail before inspection exists. Legacy report fields
and `scan_sbom` retain their public shape and signature; the additive
`scan_sbom_with_options` API returns inspection separately. The old adapter now
delegates to one cohesive descriptor/executor module.

Captured bytes remain in memory. Parser String copies, parsed objects, output
allocation, CPU and filesystem metadata work have separate costs. The byte
allowance is not an operating-system memory or latency ceiling. This is not
an atomic checkout snapshot, a Git SHA identity, current-source authentication
or complete-repository coverage. The existing walker caps and exclusions remain.

## Native terminal evidence

Evidence root: `/tmp/kuzushi-tui-integration-20261012`.
Final J270:
`sbom-source-budget-verified-tui/20261014-201734/J270`.
Native SHA-256:
`74eda6ddaeaa9fa1284e3f858b92eb02807217db6927a0c7bcf4322b05550fab`.
Thirteen executables were frozen read-only and checked against their manifest.

J270 records 27 machine passes, zero failures and 48 authenticated live
text/ANSI capture pairs. It refuses a two-byte allowance with zero source
bytes read, clears Components, exposes `options sbom-scan:scan`, and then runs
the separately requested exact 260-byte allowance. The completed receipt has
two captured files and 260 bytes reserved, read and captured; the lockfile
digest matches the captured input. Logs disclose both consumption and limits.
Six viewport sizes retain declared constraints and observed versions. Sixteen
40x12 failure pages and twelve component pages expose the full cause, recovery,
freshness qualification and versions. No-color restart recollects components
and retains both canonical outcomes.

The owned package fixture's script remains inert. Source hashes are unchanged;
findings, discovery jobs, phase attempts and provider reservations stay zero.
The helper opens the existing SQLite database with `query_only` SQL so SQLite
can recreate missing WAL sidecars; it cannot create a missing database or write
application rows. This corrects a test-reader failure, not a product verdict.

Raw status remains `REVIEW_REQUIRED` with three human judgments pending.
`sbom-source-budget-assistant-review.json` records qualified content review and
capture hashes separately. Physical contrast, motion, hardware latency,
operator delight and reference-product parity remain unapproved.

Earlier runs are preserved. The first script expected a raw option key before
selecting its human-readable row. A corrected 27-pass run succeeded; its
expanded narrow-reader successor hit the missing-WAL-sidecar reader failure.
The final fresh run verifies every narrow page with the corrected evidence
reader. No running journey or helper was edited.

## Focused verification and remaining work

Eighty-two focused Core tests pass, including existing parser formats,
aggregate admission, captured-byte reuse, dot-path reuse, referenced import
maps, invalid limits, malformed UTF-8, symlink/root replacement, early EOF and
read-chunk cancellation. Thirty-three component-focused TUI tests pass.
One pre-existing Review-selection test used a test-only helper that ignored
the explicit page; it now asserts the real Review page and uses the same
explicit-phase projection as production. Production selection policy is
unchanged. The locked workspace build passes.

All ten `pnpm verify:quick:summary` gates pass, including 391 Node tests,
workspace/all-target checking, model safety, architecture, documentation and
the CRAP-risk proxy over 781 changed code files. The separate focused risk
attempt could not verify the package-manager signature without network access;
the required summary used network access and verified it without bypasses.
An earlier summary stopped at the Review test's formatting, then the focused
format check and final summary passed. The saved receipt describes a dirty
worktree with documentation drift during verification; it is unsigned and
does not attest a clean commit, full Rust suite, release build or CI matrix.

Concurrent inventory-result ordering, every ecosystem and interface,
authenticated source revisions and process-wide parser resource ceilings
remain open. This increment does not qualify vulnerability detection or the
complete investigation journey. The separate six-request live Scan proposal
still awaits its specific operator approval; eight earlier provider requests
remain the entire spent experiment allowance. All broad delivery milestones
remain open. Work stays uncommitted on main.
