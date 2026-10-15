# Taint candidate discovery, prerequisites and decision history

`taint-iris-next:finding-review` runs fresh candidate discovery. It builds
context, collects source/sink evidence, asks an agent for observations and
imports them. It does not review selected ledger findings or apply the agent's
triage array as human decisions. Its declared Scan phase is appropriate, but
the earlier description of one scoped session was too strong: malformed model
output can require a second agent session, and scope isolation remains open.

The action now appears as Labs and **Discover taint candidates**. Exact dispatch,
options, prompt paths, runtime requirement and output formats remain. It cannot
publish a Scan checkpoint until its scope, coverage and useful outcomes qualify.
Default discovery curates the action without deleting its implementation.
An undeclared `scanContextRef` is rejected instead of implying accepted
discovery-scope support. The existing `targetSubdir` does not establish complete
candidate or backend isolation.

Cancellation is checked before target resolution, after evidence collection
and immediately before findings publication. Already canceled work cannot
create observations or start a finding run. These checks do not prove
interruption during inventory, backend work or an in-progress publication batch.

The human-history check initially assumed that another observation could carry
an FP without authenticated source identity. The actual ledger retained the
decision history and correctly left the new unverified observation unreviewed.
The test now checks both facts. No identity policy was weakened. Carrying a
verdict across a different SHA or unverified dirty source remains unsupported.

Native testing exposed a shared error-classification defect: a typed
missing-model refusal was wrapped as an exhausted allowance. The admission
boundary now preserves the existing pre-execution refusal. It remains blocked,
with no work started, but no longer adds misleading allowance guidance. Actual
allowance errors retain their admission failure class. Protected-review,
cross-workspace/model, revision and inherited-accounting checks remain intact.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | Discover new candidates and observations. Existing-finding Review and useful detection are unqualified. |
| Phase | Scan authorization retained, auxiliary output until qualified. Descriptor and shell tests prevent checkpoint ownership. |
| Inputs | Explicit selected model and approved allowance, workspace/store and context prerequisites. Existing public options remain. |
| Execution | Real prepared dispatch under an owned approved no-query allowance reaches missing-context failure. No model or scanner is invoked. |
| Consumers | Existing publisher imports owned metadata and retains human decision history. Unverified observations receive no inherited current verdict. |
| Failure | Missing model and undeclared context fail honestly; canceled publication creates no finding run. Backend, malformed output and interruption remain scoped gaps. |
| Resources | Admission precedes execution. Zero requests occur in these fixtures. Outer initial/repair calls and internal provider turns remain subject to shared accounting; live effectiveness and total backend work are unqualified. |
| Scope | No accepted exact-file context support is declared. Subdirectory filtering does not certify backend containment. |
| Interfaces | Native JSON/plain and shell agree on blocked prerequisites. Six sizes and no-color restart preserve the receipt without new work. |

Thirty-five distinct focused Rust checks pass. They cover descriptor/maturity,
prepared prerequisites, rejected scope references, cancellation, retained human
history, admission classification, accounting and shell phase ownership. The
184-tool dispatch policy fingerprint remains unchanged. The locked workspace
build and all ten exact quick-plan commands pass, including 391 Node tests
and the CRAP-risk proxy over 537 changed code files. Package commands ran
directly without disabling signature verification. The full Rust suite was
not run.

Retained failures include an incorrect test preparation argument, an unapproved
test allowance, the incorrect FP-carry expectation, and length limits that led
to focused helper/test extraction. Initial native runs also disclosed an
unconfigured bridge in the isolated HOME and an incorrect failed-status fixture
expectation. A blocked prerequisite is distinct from executed failure. These
fixture corrections do not bypass product prerequisites.

Final J239 records 14 machine passes, zero failures and 14 authenticated capture
pairs across six sizes and no-color restart. Three human judgments remain open,
operator approval is false and the raw status is `REVIEW_REQUIRED`. The bridge
path is explicitly configured in the owned HOME; model and credentials remain
unset. No provider request, target execution, standalone security scanner,
network request or patch operation runs. No observations, decisions, phase
continuation or reservation are created. Absent tables are recorded as absent.

Native SHA-256:
`907d9b222485b668bcd3b0aa86ad36a3dcc6f10de52f7b58c97b9019b6605c53`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/taint-candidate-corrected-tui/20261013-184404/J239`.
Tests, retained failures, CLI and immutable manifests:
`/tmp/kuzushi-tui-integration-20261012/taint-candidate-audit`.

The catalog retains 113 visible actions: 92 Core, 16 Labs and five Compatibility.
The complete J121 journey also retains 109 machine passes, zero failures and
87 captures on the same bundle. Accepted context, three fixed passes,
protected Review capacity, allowance halt, partial/final export, specific
allowance revision, original-job-only resume, source reassessment and restart
remain intact. Four completely intercepted requests add no live spending;
15 human judgments remain open. Captures:
`/tmp/kuzushi-tui-integration-20261012/taint-candidate-complete-tui/20261013-184545/J121`.

Fifteen in-scope actions remain unassigned. Scope isolation, complete coverage,
backend interruption, real-model usefulness and full reference UX parity remain
open. The live allowance stays exhausted at six of six; this audit adds no live
spending and closes no broad delivery milestone.
