# Bounded configuration inspection and source-qualified signals

October 11, 2026. IaC scanning previously recursed through directories without
entry, depth or total content limits. Oversized and invalid UTF-8 files counted
as skipped without making coverage partial. Direct child-directory findings
also lacked workspace-relative paths and the shared source-binding wrapper.
The registry description claimed Kubernetes support although this executor
recognizes Dockerfiles, GitHub Actions workflows and Terraform.

## Supported behavior

`iac-scan:scan` remains Core as a configuration policy signal reader. Its
heuristics require owner review; `signal_only` never establishes exploitability
or verified vulnerability. It does not build, execute or import target source,
call a model or start a subprocess scanner. Its DAG dependency on context is
metadata, not execution ordering.

The iterative contained walk now visits at most 100,000 entries and 64 directory
levels, with lower entry limits available through declared options. Symlinks,
dependency directories, build output and state directories remain excluded and
are counted. Loose parent files stay outside an explicitly selected child root.
The existing 512 KiB per-file default remains, with supported values from
1 KiB to 64 MiB. Total reads default to and cannot exceed 512 MiB. Invalid limits
fail explicitly instead of being silently clamped.

Opened regular-file reads count actual bytes, including incomplete reads and
truncation probes. Oversized, invalid UTF-8, unreadable and incomplete files are
not parsed as complete documents. Entry or depth limits retain explicit gaps.
Direct results preserve usable observations, partial status, source binding
and workspace-relative paths. A findings-only legacy call refuses an empty
incomplete result. Old serialized reports remain readable and disclose missing
inspection accounting rather than zero consumption. Source authentication
performs separate IO outside the content inspection allowance.

Prepared SAST jobs share entry and content limits across directory roots.
Unsupported exact-file memberships fail before discovery. No automatic
whole-repository widening, subdivision, retry or extra job follows. Exhausted
limits retain observations from earlier roots and record later roots as
uninspected. Errors without a receipt hold the remaining capacity. The shared
JSON and shell/plain consumers read original limits and cumulative consumption.

An internal directory collector and its isolated helper tests were removed
after search established there were no remaining production consumers. The
real bounded IaC walker retains readable/unlistable-directory contracts.
No public module or implementation was retired.

## Terminal evidence

Sequential J192 uses a local clone of the owned inert fixture, on main at
`f29dc288e0660ad20d074fc219c025f98ef7d155`. The added untracked configuration
content is hashed separately. One selected Dockerfile produces one policy
signal, an oversized sibling remains uninspected, a symlink cycle is excluded,
and a parent Dockerfile is outside discovery. No configuration is executed.

The first run reached the partial direct result and all six reading sizes,
then waited at an explicit cached-context prerequisite choice. The fixture
had not exercised that operator decision. The correction selects reuse before
SAST starts. No live journey or helper was edited during its process. The
failed run and original output remain under
`/tmp/kuzushi-iac-audit-20261011/native/20261011-022736/J192`.

The corrected journey then exposed a real identity defect: scoped SAST changed
the finding path but retained its child-relative fingerprint, while the direct
module correctly rebound both. Review showed two rows for the same signal and
Report exported both. This failure remains at
`/tmp/kuzushi-iac-audit-20261011/corrected-native/20261011-023028/J192`.
The shared scanner boundary now delegates path rebinding to a producer hook.
Its default preserves public compatibility. IaC retains its line or structural
discriminator and generates the same workspace-qualified fingerprint through
both paths. Focused prepared-dispatch and structural-identity regressions
protect this behavior. No saved observations or human decisions are rewritten.
The first regression then exposed a second part of the defect: the rebased
direct path was grounded relative to the child directory, so it looked missing.
Direct persistence now resolves those workspace-relative paths against the
workspace root. Discovery and its source receipt still name the selected child.

Final J192 is at
`/tmp/kuzushi-iac-audit-20261011/final-native/20261011-023829/J192`.
It records 16 machine passes, zero failures and 18 authenticated text/ANSI
captures across 160x48, 120x36, 96x89, 80x24, 60x20 and 40x12, plus no-color
restart. Its native SHA-256 is
`672998e5c46aa6abf4b30b4771ce30549f226df80a1f0758716bea4f90636c28`.
Compact paging reaches file counts, the skipped sibling, read limits,
exclusions and the separate source-authentication disclosure. Review shows one
finding and one source from two observations, retaining its actual selected
path and source excerpt. Report preserves the scripted human deferral and
partial-scan warning, with workspace spend unavailable. No-color restart shows
the decision at commit `f29dc288e066`, dirty source and branch main, without
implying the finding was fixed. Ledger counts remain two observations, one
decision and zero provider reservations or investigation attempts.

Two assistant screen judgments remain separate from raw `REVIEW_REQUIRED` and
operator approval false. Transcript reading still requires several compact
pages; long paths and diagnostics crowd the ordinary flow. This is scoped
reading and recovery evidence, not reference-product UX parity or operator
acceptance. The fixture preserves SHA and separate dirty-content hashes; it
does not exercise a real source transition or verify any fix.

## Verification

37 IaC checks, 89 SAST checks, 18 shared scoped-engine checks and six coverage
checks pass, 147 distinct checks after removing overlap. Workspace build and
the 200-file changed-code risk proxy pass. The registry still exposes 111 tools,
now with scoped assessment evidence for 72; 39 remain unassigned, including
eight excluded tools. No maturity promotion or module retirement follows.
The dedicated verification key's existing probe verifies against repository
trust. The original live fixture remains on main with four reservations, six
work attempts, three observations and one human decision. No new model request
or live Review approval was introduced.

All ten repository summary gates pass. The receipt at
`/tmp/kuzushi-iac-audit-20261011/precommit-verify-receipt.json` remains unsigned
and records a dirty tree and drift during verification. It is not a publishable
clean-commit receipt. Tested changes are staged on main, with no new commit or
push. The final documentation-only recording receives a focused docs check.
Human screen acceptance, broad heuristic precision, inner parse/read
cancellation latency, large real repositories, every interface/option path
and full reference-product interaction comfort remain open. This scoped
increment does not close any of the nine delivery milestones.
