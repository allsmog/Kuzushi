# Advisory context produces partial source observations

`ndiff:hunt-variants` previously declared Map while discovering source findings,
forced high reasoning and returned a completed result without demonstrated
coverage. Ordinary query limits and vendor guidance were not declared options.
Any JSON object could be treated as valid output, including an empty object
without a variants array.

The action is now Labs and auxiliary Scan, displayed as **Search advisory-guided
observations**. Exact dispatch remains. An explicitly supplied pattern is
required. Its fixShape and vulnerableShape accept their legacy snake-case keys
and require nonblank text of at most 4,096 bytes each. This does not authenticate
the pattern's source or accept a reusable lesson. The DAG dependency on
extraction remains metadata; neither prepared dispatch nor shell prerequisite
handling performs an automatic extraction for this action.

Reasoning inherits the selected runtime unless thinkingLevel is supplied.
Declared maxOutputTokens requests 256 to 32,768 response tokens, default 4,096;
maxModelTurns allows one to 16 turns, default four. The one structured repair
uses the same limits and selected model, and requires another provider
reservation. Requested output tokens are not a strict provider or dollar
ceiling. maxFindings accepts one to 100, retaining the descriptor default of 25.
The direct capability retains its historical default of 15 but rejects invalid
limits instead of clamping or substituting defaults.

includeVendored retains its historical true default and is now declared with a
snake-case alias. It supplies prompt guidance, not enforced discovery scope.
scanContextRef remains unsupported and is rejected by prepared dispatch.
Existing record and fixtures options remain for compatibility, but this executor
consumes the explicit pattern rather than deriving it from those fields.

Valid output must contain an explicit variants array. Reported locations and
severity remain model claims. New findings stay unreviewed without proof, and
valid receipts are partial with coverage.complete=false,
observationsVerified=false, candidateLocationsVerified=false and
patternAccepted=false. Legacy advisoryId, pattern, findings, persisted and cost
fields remain. The summary leads with the coverage and review qualification.
An empty result cannot establish that a prior finding was fixed.

The host captures source identity before work and retains that identity in the
receipt. A source change during the response is disclosed by the shared stale
source path. Cancellation is checked before work and before final ledger
publication. These checks do not qualify cancellation inside per-node append,
total filesystem/memory bounds, exact finding-generation isolation or paid
partial recovery after a failed multi-observation result.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | Source observations guided by explicit historical context. Complementary detection and precision remain unqualified. |
| Phase | Scan posture and Discovery allowance replace Map attribution. No phase result is published. Existing historical receipts remain readable. |
| Inputs | Workspace, findings store, selected model, supplied pattern and approved allowance. Required shapes are checked before a request. Exact accepted discovery scope is unsupported. |
| Execution | Real prepared dispatch exercises model construction, same-limit repair, normalization, ledger publication and host source binding using owned responses. |
| Outputs | Explicit empty and nonempty observations remain partial; nonempty findings have no triage or static proof. Pattern acceptance stays false. |
| Failure | Invalid patterns/settings, missing model, malformed output, protected Review, cancellation and source drift have focused checks. Whole-operation recovery remains open. |
| Resources | Every model request requires Discovery capacity; protected Review cannot be borrowed. Requested output and turn bounds reach initial and repair queries. Provider token enforcement and aggregate IO/memory remain open. |
| Scope | Vendor guidance is visible but does not enforce file membership. Coverage and location verification are explicitly false. |
| Interfaces | Prepared dispatch accepts canonical options and declared aliases. The shell uses the same executor and preserves auxiliary phase ownership. |
| Product value | Misleading phase/completion labels and hidden reasoning are removed. Useful real detection and final human UX review remain unqualified. |

Verification is recorded under
`/tmp/kuzushi-tui-integration-20261012/advisory-search-audit`.
Eighty distinct focused Rust checks and the locked workspace build pass. These
include nine prepared-dispatch checks, 42 capability checks, the 184-tool policy
inventory, 27 phase/result fixture checks and one admitted shell dispatch. The
policy fingerprint changes only for the reviewed Map-to-Scan tuple; the prior
inventory is checked with that explicit migration removed. The full Rust suite
was not run. Eight native CLI JSON/plain cases reject missing model/pattern,
unsupported scope, invalid reasoning and excessive limits before execution.

J245 records 12 machine passes, zero failures and 13 authenticated capture pairs
across six sizes and no-color restart. One GPT-5.5 medium response is fully
intercepted, with zero live requests and zero returned tools. The exact human
decision, source and active context remain unchanged. One Discovery call is
committed and one protected Review call remains. No phase continuation is
created. Native OAuth does not forward the requested output-token cap; provider
enforcement is not claimed. The displayed cost is unavailable, not zero.
Four human questions remain pending and operatorApproved is false. Raw status
is REVIEW_REQUIRED. Product SHA-256:
`a9c8b27458df899118ea6b94eddc22c4f92c0121a41afd62232162f1ac8ffc51`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/advisory-search-tui/20261014-010307/J245`.

Sequential J121 on the same immutable build records 109 machine passes, zero
failures and 87 authenticated capture pairs. Four responses are fully intercepted;
finite plans, protected Review, partial reports, source reassessment and restart
retain their receipts. Zero live requests or source execution occur. Fifteen
human questions remain pending and operatorApproved is false. Captures:
`/tmp/kuzushi-tui-integration-20261012/advisory-search-complete-tui/20261014-010413/J121`.

The ten checked-in quick gates pass, including 391 Node checks and the CRAP-risk
proxy over 594 changed code files. These cover the accumulated worktree and do
not establish final UX parity or useful real detection.

Retained failures include initial Rust type/field errors and an outdated shell
bridge without provider admission. Updating it to the shared admitted fixture
keeps reservation enforcement intact. A later assertion incorrectly looked for
the summary in the result log rather than the tool log; the final test checks
both the partial tool summary and the source-qualification body. The wording
gate required a clearer description of input checks. Earlier attempts remain
recorded and are not credited as passes.

The visible catalog retains 113 actions: 86 Core, 22 Labs and five Compatibility.
Nine in-scope tools remain unassigned. Full pattern/prompt byte bounds, source
location authentication, finding-generation isolation, useful real output and
final human UX review remain open.

No live provider request, target execution, exploit, reproducer or patch
generation is part of this audit. The six-request live allowance remains
exhausted. No module is deleted and no broad milestone closes.
