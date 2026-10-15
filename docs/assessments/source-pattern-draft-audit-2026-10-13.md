# Source-pattern drafting and reviewed reuse

`variant:lift-pattern` produces a model signature from a selected confirmed
finding. It returns an unaccepted draft, without writing a reusable lesson,
changing active context or starting discovery. The action is now Labs and
**Draft source pattern**, with Learning accounting and no Scan checkpoint.
Exact dispatch, the Scan authorization phase and existing fingerprint,
signature and finding payloads remain available. Additive draft, accepted and
contextActivated fields clarify the result. The supported reviewed reuse path
is `findings:lesson-generate`, followed by explicit human acceptance and context
selection.

The earlier executor described the finding as confirmed without consulting its
current Review authority. Both pattern drafting and the existing variant search
now share the same pure confirmation check. Human rejection overrides automated
confirmation; an unreviewed subject is refused before querying a model. Prompts
identify the actual human or automated confirmation. These changes preserve the
search action's existing refusal fields and do not qualify its execution.

An arbitrary JSON object, including an empty object, can no longer pass as a
signature. Four text fields must be nonblank and at most 4,096 bytes each.
Languages and keywords each require one to 32 nonblank strings, limited to
128 bytes per item. The legacy missing_guard spelling and additional fields
remain readable. Schema lengths are character counts; executor byte limits are
stricter for multibyte text. A malformed initial response permits the existing
single structured-output repair, charged to the same approved allowance.
Additional fields and total response size do not gain a new whole-payload cap.

Native testing found a real selected-effort defect: the executor silently forced
high reasoning despite medium runtime configuration. The declared optional
thinkingLevel option, with thinking_level alias, now inherits the runtime when
omitted and preserves an explicit override. No model or runtime fallback is
introduced. Cancellation is checked before work and after the model response;
in-progress interruption remains unqualified.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | An inspectable source-pattern draft. Useful generalization and complementary value against reviewed lessons remain unqualified. |
| Phase | Existing Scan authorization retained; auxiliary Learning work cannot publish a Scan result. |
| Inputs | Workspace, findings store, selected model, allowance and current effective confirmation. Optional declared reasoning inherits the runtime. |
| Execution | Real prepared dispatch succeeds with an accounting-aware query fixture. Native shell runs the real bridge with a fully intercepted response. |
| Outputs | Existing signature fields are retained with explicit unaccepted draft flags. The receipt and Replay survive restart; no lesson or context is activated. |
| Failure | Unreviewed and rejected subjects, incomplete or oversized known fields, invalid reasoning, missing models and undeclared context input are refused. Initial and repair failures remain separate from completion. |
| Resources | Learning reserves before queries, cannot borrow protected Review capacity, and accounts for the optional repair. Native successful drafting commits one call and retains one protected Review call. Unknown dollar consumption stays unavailable. |
| Scope | No immutable scanContextRef or source revision is supported here. Query input includes selected finding metadata and target-root source tools. Scope isolation and confirmation changes during a query remain unqualified. |
| Interfaces | CLI JSON/plain, prepared dispatch and native shell agree. Six sizes, paging, no-color and restart are captured; human quality review remains open. |

Twenty-five distinct focused Rust tests pass: signature validation, confirmation
precedence, actual prompt authority, reasoning inheritance, prepared dispatch,
repair accounting, protected Review and shell phase ownership. The 184-tool
policy fingerprint remains unchanged. The locked workspace build passes.
All ten exact quick-plan commands pass, including 391 Node tests and the
CRAP-risk proxy over 547 changed code files. Package commands ran directly
without disabling signature verification. The full Rust suite was not run.

Final J240 has 11 machine passes, zero failures and 12 authenticated capture
pairs across six sizes and no-color restart. Three human judgments remain open,
operatorApproved is false and the raw status is REVIEW_REQUIRED. One fully
intercepted GPT-5.5 medium request completes the real bridge, with zero returned
tool calls and zero live requests. The source, active context, one observation
and one human decision remain intact. One Learning call is committed and the
protected Review call remains available. The completed receipt has no phase
continuation. Native SHA-256:
`1e8b8c9a735eb4c25cb11d1840641fa371753a124a4c2ae85216c71421ec4634`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/variant-draft-reasoning-tui/20261013-192928/J240`.

The retained failures include a fixture database open that could not inspect
WAL state, early bridge failure and the provider assertion that exposed forced
high reasoning. The successful run follows the product fix, not relaxed
assertions. Fixture SQL readers now use query_only mode while permitting SQLite
to manage its WAL sidecars. Old lesson journeys initially stopped on a replaced
finding heading; their recorded screens already showed the actual finding.
Only the outdated screen checks were updated.

Sequential J118 then J119 on the same immutable bundle recheck the recommended
lesson flow. J118 records 21 machine passes, zero failures, 23 captures and six
human questions. J119 records 26 machine passes, zero failures, 25 captures and
five human questions. Both remain REVIEW_REQUIRED with operator approval false.
J118 preserves Unicode input, explicit draft and acceptance, selective immutable
context copying, retirement and restart. J119 makes one fully intercepted
medium request for one approved lesson job, preserves protected Review,
requires explicit acceptance and resumes without another request. These are
workflow tests, not evidence of real model usefulness. Captures:
`/tmp/kuzushi-tui-integration-20261012/variant-draft-lessons-corrected-tui/20261013-193517`.

The current catalog contains 113 visible actions: 91 Core, 17 Labs and five
Compatibility. Fourteen in-scope tools remain unassigned. Useful model output,
source-version isolation, large cases and full reference UX parity remain open.
No module is deleted and no broad milestone closes. The approved live allowance
remains exhausted at six of six. All tests in this increment add zero live
spending, target execution, standalone security scanners or patch operations.
Evidence and immutable manifests:
`/tmp/kuzushi-tui-integration-20261012/variant-draft-audit`.
