# Related source observations and honest search receipts

`variant:hunt` performs a separate source search based on a currently confirmed
finding. It reads the original finding and confirmation, asks an agent for
related observations, normalizes them and imports them into the ledger. It does
not consume a saved lifted pattern. The registered DAG dependency on
variant:lift-pattern is display metadata; this executor does not use it to
schedule either action. No new search or follow-up job is created automatically.

The action is now Labs and **Search related observations**, retaining exact
dispatch, options, Scan authorization and its existing result fields. It cannot
complete Scan. Every successful response is partial because neither the
requested source guidance nor the returned rows prove complete coverage or an
authenticated source revision. Additive coverage fields and warnings make those
limits explicit. New observations require independent Review, and a valid empty
array neither resolves nor changes the original confirmed finding.

Previously an arbitrary object, including an empty one, became zero observations
and a completed result. The structured contract now requires an actual variants
array. Every row must be an object with nonblank file, severity and confidence
fields. Existing file_path and start_line aliases remain supported. An optional
source line must be an integer from one through u32::MAX; omitted lines keep the
legacy line-one default. Invalid initial output may use the existing one repair
attempt, with both requests governed by the same allowance. This shape check
does not authenticate paths, enforce vendored exclusions, ground claims,
validate all label vocabularies or add a total-response byte ceiling.

Optional thinkingLevel, with thinking_level alias, inherits the selected runtime
instead of forcing high reasoning. Explicit overrides reach the prepared query.
The shared declaration and parser serve both pattern drafting and related search.
Cancellation is checked before work and after the model response, preventing
publication at those boundaries. Interruption during an agent session or an
in-progress publication batch remains unqualified.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | Independently reviewed observations related to a confirmed subject. Useful generalization and complementary coverage remain unqualified. |
| Phase | Scan authorization and Discovery accounting remain. Labs output has no phase checkpoint and always discloses partial coverage. |
| Inputs | Workspace/store, explicit model, approved allowance, current effective confirmation and existing target/vendor guidance. Reasoning inherits runtime unless explicitly overridden. |
| Execution | Real prepared dispatch with owned accounting-aware responses imports a candidate and preserves the original decision. The native real bridge receives one fully intercepted medium response. |
| Outputs | Existing variants, originalFinding, scope and persisted fields remain with additive coverage. New observations remain unreviewed and cannot inherit original confirmation. |
| Failure | Empty objects, malformed rows and invalid source lines cannot become clean results. One bounded repair, missing models, invalid reasoning, protected Review and cancellation boundaries are checked. |
| Resources | Discovery reserves before queries, cannot borrow protected Review, and accounts for the repair. Dollar consumption is unavailable rather than an exact zero. |
| Scope | No immutable scanContextRef is declared. Vendor and first-party instructions are prompt guidance, not proven containment. Exact source identity, full coverage and path authentication remain open. |
| Interfaces | Prepared dispatch, JSON/plain and shell retain honest outcomes and prerequisites. Six sizes, independent Review and no-color restart are captured; human usability approval remains pending. |

Fifty-nine distinct focused Rust tests pass. They cover confirmation authority,
structured shape, empty and malformed output, cancellation, protected Review,
actual observation import, effort selection, original decisions, drafting and
phase ownership. The existing registry integration test was stale against the
required allowance policy. It now uses an owned accounting adapter, explicit
approval, distinct draft/search work ids and actual prepared dispatch. Its
expected search status reflects partial coverage. The 184-tool policy fingerprint
is unchanged. The locked workspace build and all ten exact quick-plan commands
pass, including 391 Node tests and the CRAP-risk proxy over 554 changed code
files. Package commands ran directly without disabling signature verification.
The full Rust suite was not run.

Final J241 records 14 machine passes, zero failures and 14 authenticated
capture pairs across six sizes, fingerprint selection and no-color restart.
Four human judgments remain open, operatorApproved is false and raw status
is REVIEW_REQUIRED. Captures:
`/tmp/kuzushi-tui-integration-20261012/variant-hunt-reading-tui/20261013-200045/J241`.

Native SHA-256:
`794a16ef561a4ebc352f3394b3a4f77d0bc13cccf2caf42f512a86a3dfb6c96b`.
The successful search returns one labeled greeting observation, with one fully
intercepted GPT-5.5 medium request and zero returned tool calls. The source and
active context remain unchanged; the ledger has two observations and its single
original human decision. One Discovery call is committed and one protected
Review call remains. The receipt has no phase continuation. This is source-only
transport and workflow evidence, not evidence of model detection quality.

Retained failures include the stale unapproved registry test, a fixture that
assumed the new finding would have a particular display alias, and an input
readiness assertion that matched old Replay text before the command executed.
Display aliases reflect the current ledger ordering. The corrected fixture uses
the returned fingerprint, verifies that its command is rendered before Enter,
and waits for the finding-detail heading before reading the selected observation.
No identity or verdict policy was weakened.

The adjacent J240 draft journey on this bundle has 11 machine passes, zero
failures and 12 captures with three human questions. The complete J121 journey
has 109 machine passes, zero failures and 87 captures with 15 human questions.
Accepted context, three fixed passes, protected Review, allowance halt,
partial/final export, specific allowance revision, original-job resume,
source reassessment and restart remain intact. Four completely intercepted
requests in J121 add no live spending. Both remain REVIEW_REQUIRED with
operatorApproved false. Captures:
`/tmp/kuzushi-tui-integration-20261012/variant-hunt-identity-tui/20261013-195642`.

The catalog retains 113 visible tools: 90 Core, 18 Labs and five Compatibility.
Thirteen in-scope tools remain unassigned. Useful detection, full source-scope
isolation, dirty-observation authentication, larger cases and complete reference
UX parity remain open. The shell's global cost subtotal can still show a zero
lower bound marked incomplete while Replay correctly says metering is
unavailable; a clearer unknown-cost header remains a UX follow-up.
No module is deleted and no broad milestone closes. All requests in this
increment are completely intercepted, with zero live model spending, target
execution, standalone scanner execution or patch operations. The approved live
allowance remains exhausted at six of six. Tests, CLI, failures and manifests:
`/tmp/kuzushi-tui-integration-20261012/variant-hunt-audit`.
