# Evidence-backed retirement candidates

This list proposes future review. It authorizes no deletion, contract removal,
commit or publication. Different engines need outcome evidence before their
overlap can justify retirement.

| Candidate | Evidence | Current action | Evidence needed before removal |
| --- | --- | --- | --- |
| `taint-iris-next:source-sink-trace` exact alias | It calls the same planner as `taint-iris-next:dataflow-plan` with the same forced mode, option list and payload. Native prerequisite outcomes agree. Maintaining a second name adds command, documentation and test surfaces without a distinct executor result. See the [planning audit](taint-planning-audit-2026-10-13.md). | Retain exact dispatch as Compatibility and recommend the canonical planning name. | Consumer/use-history evidence, a reviewed migration for saved commands/plans/artifacts, a defined compatibility window, nonempty outcome parity where relevant, and explicit operator approval. |

No other retirement is proposed from names, code size, registration or scoped
failure tests. Existing Labs and Compatibility classifications are discovery
choices, not evidence that implementations should be deleted.
