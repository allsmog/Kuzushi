# Native session admission and question recovery

The native adapter now refuses direct query, next-step and model-work preflight
calls without an approved host allowance binding. This closes the request path
below shared module dispatch that could previously bypass investigation
accounting. Admission occurs before bridge spawn. Credential readiness,
authentication ping and tool-policy acknowledgement remain available separately.
Bound requests retain the same durable reservations for each provider attempt,
including transport retries and internal turns. No model is substituted.

## Questions and persisted outcomes

An unstarted allowance refusal restores the failed question, shows that no
provider request started and records a blocked run. The model audit's attempt
flag and typed failure determine this state. A refusal after attempted work
remains failed with consumption uncertainty; error text alone cannot erase
spending. Existing Answers draft ownership, recovery and terminal persistence
are reused. Explicitly choosing exit still acknowledges the unsent-draft prompt.

This is a request guard and recovery increment. Ordinary session Ask and natural
language planning still need an operator-facing approved finite question/plan
path. A blocked-only surface is not the completed product contract. The next
implementation should reuse context-study approval and shared prepared dispatch,
bind accepted context and source identity, and offer one explicit question job
with visible resource terms. It must not introduce automatic job selection,
recursive work or reuse a consumed job's authorization.

## Verification

145 adapter tests pass, including direct unbound queries, next-step and loop
preflight before bridge spawn, credential readiness without allowance, and
approved requests with retry/cancellation/accounting behavior. Existing synthetic
transport fixtures now negotiate the real admission protocol with explicit model
and finite allowances. Their fixture processes are local and make no network
requests. Test-only pipe/parser helpers remain explicitly separate from product
model dispatch.

22 distinct focused TUI checks pass: 12 Answers failure/recovery checks and 11
model failure checks with one overlap. They cover blocked persistence, restored
question and focus, retained newer drafts, and uncertain cost after attempted
work. Locked workspace build and all ten repository summary gates pass. The
360-file risk proxy passes. The summary receipt is
`/tmp/kuzushi-session-admission-20261011/precommit-verify-receipt.json`; it records
dirty/drifted state and local-platform/CI omissions and remains unsigned.

Final sequential J214 is
`/tmp/kuzushi-session-admission-20261011/edited-native-session/20261011-174528/J214`.
The frozen native SHA-256 is
`3ea2cdbf6df4917d6eb9409ac9f35fe8a476e9ac8c8f651315c537c0a8e7928f`.
It records 21 machine passes, zero failures and 16 source-authenticated live
capture sets at six terminal sizes, including actual question editing/undo,
explicit exit confirmation and no-color restart. The native query starts no
model call. The human FP decision, accepted context and clean source SHA
`f29dc288e0660ad20d074fc219c025f98ef7d155` remain unchanged. Accounting stays
at six committed requests, no unresolved reservations and no protected Review
capacity, with unknown dollar consumption. No source is executed and no new
allowance or job plan is approved.

The first J214 predecessor stopped at the unsent-draft exit confirmation:
`/tmp/kuzushi-session-admission-20261011/native-session/20261011-174044/J214`.
Its raw failure is retained. The process was confirmed terminal before updating
the journey. A subsequent read-only recovery run added explicit exit confirmation;
the final run also exercised editing. Observation never restarted provider work.

Raw successful native verdicts remain `REVIEW_REQUIRED`; assistant capture
judgments are recorded separately and do not constitute operator UX acceptance.
The approved positive Ask workflow, full per-tool readiness, larger source and
scope behavior, context experiments, learning, physical-terminal accessibility
and reference-product interaction acceptance remain open. No module is promoted
or removed and no broad delivery milestone closes.
