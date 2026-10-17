# Direct scanner scope and inspected-file coverage

Direct IaC and Cargo scans now publish their own typed Scan receipts after final
source authentication. The authenticated correlated tool result is the history
reader's authority. A receipt cannot borrow a different run, engine, selected
path, source outcome or observation artifact. Missing typed coverage remains
unknown. Legacy history is retained rather than rewritten.

IaC records the requested directory, enabled rule identifiers and exact files
that received full reads and analysis. Ignored files, excluded symlinks and
truncated reads do not enter that set. Completed empty inspection records an
empty set. Requested directory membership alone cannot establish that a file was
reassessed. The same membership reaches ledger reconciliation and comparison.

Cargo records only the selected Cargo.lock. Findings and structural locators
are rebound to workspace-relative paths, keeping independent selected lockfiles
separate. Advisory policy is not recorded by the adapter. A completed job can
therefore retain a finding as not reassessed when a later database omits its
advisory. Neither absence nor completed inspection establishes a fix, runtime
reachability or a new human verdict.

Report now requests the displayed Scan receipts through the same background
reader as Scan. Native validation found that Report previously stayed at
`scope not recorded` even when authenticated coverage existed. The focused
hydration regression covers Report and Scan, including earlier-source selections.

Both producers publish canonical stored observation snapshots, including empty
`findings.json`, measured deltas and unknown cost. Scan presents the requested
path and inspected-file count before the workspace path. Report preserves a completed engine's
limitation text, including Cargo's unknown advisory policy. It continues to
state that a Scan receipt does not establish complete repository coverage.

## Evidence and qualification

Evidence root: `/tmp/kuzushi-direct-coverage-20261016`.
The initial three prepared-dispatch regressions failed because authenticated
coverage was absent. Current dispatch checks prove selected scope, enabled IaC
families, canonical empty observations, separate lockfile identities, unknown
Cargo policy and excluded-file reassessment refusal. The broader direct-path
run has 56 passing checks. Final focused evidence has 135 distinct Rust passes:
67 Core and 68 TUI. The workspace build and all ten summary checks pass. The risk
proxy passes for 165 changed production files and its 15 support checks. The
summary receipt is dirty, reports `driftedDuringRun: true` and is unsigned; it
is development evidence, not clean-commit or release verification. Final docs
are checked separately after this update.

New J300 and J301 exercise three explicit local jobs each. J300 uses the actual
IaC engine with selected all-family, Dockerfile-only and empty-directory jobs.
J301 uses the installed offline audit engine, a copied local database and two
selected lockfiles. Its third job uses a separate owned database copy with one
advisory document deliberately omitted; target lockfiles do not change. This is
a policy-coverage control, not dependency patching or vulnerability execution.

Final native SHA-256:
`8fda739d20ff8f0b29092430da68d50f3d9b34ab783fdd45ba1121ada02fc5c8`.
Manifests freeze 13 programs, 4,284 source inputs and 732 runtime inputs. J300's
final case is `native/J300/20261016-035449/J300`: 21 machine passes, zero failures,
15 capture pairs and three pending human judgments. J301's final case is
`native/J301/20261016-035527/J301`: 24 machine passes, zero failures, 15 capture
pairs and three pending human judgments. Both cover six terminal sizes and
no-color restart. `native-evidence.json` verifies dimensions, text/ANSI/provenance
hashes, native identity and absence of explicit color in restarted readers.
Source and runtime inputs remain unchanged during both final cases. The installed
audit engine and both database copies also retain their recorded hashes.

Selected ANSI cell replays were visually inspected. They are not OS screenshots
and do not close the six operator judgments. The final Report keeps relative
scope and file count together, before the long workspace path. The narrow diff
keeps its count and paging controls readable; only three document rows fit at
40x12, so this is scoped reading evidence rather than a broad delight claim.

Earlier recipe failures remain at their original timestamps and in the
`before-*` evidence folders. They include wrapped completion text, sending a
second command before asynchronous finding navigation, and wrapped Report text.
The actual missing Report hydration has separate before/after native binaries
and captures. The last layout iteration moves important scope facts first.
J301's earlier recipe reused `F-0001` after a new finding changed display aliases.
The final case opens the original exact `generation:<id>` from the canonical
observation, preserving its decision before and after restart. Display aliases
remain conveniences for the current list; their broader clarity remains a UX
qualification item. No identity-policy or historical-alias migration is claimed.

These checks execute no target source and make zero live model requests. They
create no Git commit. Earlier fourteen provider requests remain spent, with no
new test allowance approved. Human TUI judgments, general scanner usefulness,
whole-operation atomicity, direct CodeQL/Govulncheck qualification and the full
bounded-investigation acceptance plan remain open. No maturity promotion,
module retirement or reference-level UX claim follows from this increment.
