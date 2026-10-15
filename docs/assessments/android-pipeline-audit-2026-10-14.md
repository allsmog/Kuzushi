# APK stages need honest limits, source identity and readable outcomes

The APK umbrella dropped timeoutMs before preparation, omitted its child
executable selectors and could return completed despite deliberate scan skips.
Bundled code scanning discarded Semgrep inspection errors. A path alone
identified its external archive input, and failure text hid the preparation
cause from the operator. These defects affect spending decisions, source
comparisons and recovery even when no model is used.

The Android APK module is now Labs. Its visible scan action is auxiliary Scan
with the existing target-write authorization. Canonical options pass to their
own internal stages. Both preparation and the umbrella declare bounded timeout
and archive inspection inputs. The umbrella also exposes executable selectors
and includeLibraries; no per-mode or environment-only option path is added.
Existing public names, finding/stage fields and hidden exact tools remain.

Successful parent results are partial. Stage status, code inspection errors,
finding counts, skips and original archive identity are retained. The readable
output places coverage, archive digest and named outcomes before technical
artifacts. Preparation failures include their cause and a next action in shared
result text. A missing executable message names the file before the full path
so clipping cannot hide the actionable dependency. This shared change retains
the existing diagnostic prefix and full requested path.

timeoutMs is one to 86,400,000, default 600,000, per process. The selected limit
reaches unzip/decompilers and the existing configured Semgrep adapter. A fixed
action can run several processes; no whole-operation deadline follows. Archive
identity inspection is capped by maxApkBytes, default 512 MiB and maximum four
GiB, with streaming reads and cancellation checks. Successful preparation hashes
before extraction and again before publication; the umbrella rechecks once
after scanning. This can read the archive three times. Existing expanded-output,
entry and subprocess-output bounds remain.

The version-one inputReceipt gives the supplied archive path, full content
digest and byte count, with decompiledSourceVerified=false. It is separate from
the repository commit/source snapshot. A matching archive digest does not prove
accurate decompilation, original-source locations, vulnerability validity or a
fix at a later revision. Changed archive bytes during preparation refuse
publication; a later failed recheck retains the successful initial receipt and
prior observations. Failed preparation does not yet retain that original digest.
Concurrent output-generation isolation and race-resistant immutable inputs
remain unqualified. Derived output changes the workspace source snapshot;
existing context is not silently accepted for that new source.

Cancellation prevents later stages from starting at the shared context boundary.
Partial engine errors preserve earlier observations. Existing missing optional
configuration/native-library directories can still be classified as failed
prerequisites; absence from decompiled output is not proof of absence from the
archive. Complete parser/traversal bounds, in-flight finding retention and atomic
whole-operation recovery remain open. No repository Scan checkpoint is created.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | Optional APK configuration/code observations. Useful real decompilers and finding quality remain unqualified. |
| Phase | Labs auxiliary Scan, no phase ownership or automatic downstream scans. |
| Inputs | Explicit archive, target-write consent, selected tools, positive timeout and archive-byte bound. Runtime/model are not required. |
| Execution | Prepared parent dispatch invokes owned stubs, consumes real parsers and persists nonempty configuration observations. |
| Outputs | Partial stage receipts, archive identity, named errors and ledger observations. SAST handoff emits suggestions only. |
| Failure | Authorization, invalid limits, timeout, missing tools, archive drift and prior-output preservation have scoped checks. |
| Resources | Bounded streaming input, inherited process deadline and existing extraction limits. Aggregate IO, parser/traversal and recovery bounds remain open. |
| Scope | Whole APK only. Accepted repository discovery-scope input is rejected; no original-source coverage claim. |
| Interfaces | Shared descriptor options and dispatch reach CLI/shell. Native TUI evidence is recorded below. |
| Product value | Repairs dropped controls and misleading completion, error and source labels. Live engine usefulness and final human UX review remain open. |

Evidence is retained under
`/tmp/kuzushi-tui-integration-20261012/android-pipeline-audit`.
Initial failures are preserved. One test expected a failed JSON envelope for
pre-cancellation; shared dispatch correctly refuses before the module runs.
Two native terminal runs exposed clipped dependency text and a hidden deadline
cause. Their failures are not counted as passing evidence. The copy fixes reach
the shared executable preparation and module result paths.

One hundred eleven distinct focused Rust checks pass. Nine prepared parent
contracts cover retained observations, selected limits, source drift, skips,
authorization and cancellation. The locked workspace build and ten quick gates
pass, including 391 Node checks and the CRAP-risk proxy over 625 changed code
files. Seven native CLI scenarios distinguish invocation failure (exit two),
failed preparation (exit three) and partial observations (exit four); three
additional checks verify final failure/dependency copy and retained output.
Known compiler warnings remain. The full Rust suite was not run.

Final J249 records 14 machine passes, zero failures and 15 authenticated capture
pairs across six sizes and no-color restart. Configuration observations and a
partial code-stage error reach the real ledger and receipt. The archive digest,
exact synthetic human-decision metadata, original source file, active context,
prior derived output and successful result digest remain after failed preparation
and restart. Generated directories change the target source snapshot and the
shell discloses stale files. Four human questions remain pending and
operatorApproved is false. Captures:
`/tmp/kuzushi-tui-integration-20261012/android-pipeline-final-tui/20261014-042907/J249`.

Sequential J121 on the same immutable final bundle records 109 machine passes,
zero failures and 87 authenticated capture pairs. Its four model responses are
fully intercepted; accepted context, finite passes, protected Review, partial
reporting, deliberate allowance revision and source reassessment retain their
receipts. Fifteen human questions remain pending. Captures:
`/tmp/kuzushi-tui-integration-20261012/android-pipeline-final-complete-tui/20261014-042936/J121`.
Final product SHA-256:
`aae5cb5f7607fa234dd195642dc80dc814fcf4189029c6c54ca98d947b460117`.
The raw status of both final journeys is REVIEW_REQUIRED. Text review confirms
visible partial counts, named stage outcomes, archive digest, dependency name
and deadline cause. Receipt space still includes zero-change ledger events;
broader hierarchy and reference-product parity remain open. Machine checks are
not human approval or evidence of delight.

The final registry retains 113 visible tools: 79 Core, 29 Labs and five
Compatibility. Two in-scope tool audits remain unassigned: codeql:create-db and
codeql:scan. Neither this census nor scoped fixture execution proves complete
phase qualification or the broad investigation acceptance checklist.

The live model allowance stays exhausted at six of six. Validation uses only
owned inert archive/tool fixtures and intercepted responses where recorded.
No real decompiler, source execution, network probe, exploit development,
reproducer or vulnerability patch is part of this work. No module is deleted
and no broad milestone closes.
