# Module audit consistency and current context evidence

The audit matrix omitted `sourcePaths` from `threat-model:build` and omitted four
explicit Labs discovery overrides. A fresh isolated-home catalog confirms 118
visible tools, 81 Core defaults and 42 visible owning modules. Effective tool
tiers and owning module tiers are different facts; flattening the public catalog
must not turn a tool override into an owner reclassification.

The five metadata rows are corrected without changing any descriptor, tier,
default, executor, public dispatch name or retirement recommendation. Four
context-related rows now retain the completed source-only live experiment and
current reader evidence. Historical synthesis failures and the two disconnected
data-type process nodes remain explicit. No broad qualification follows from
that one completed request. See the
[context reader and live-test assessment](context-reader-live-2026-10-23.md).

## Automatic consistency contracts

Three new Core Rust contracts compare the checked-in matrices with the real
registry, constructed without optional adapter environment discovery:

- Every visible tool has one matrix row, with current owner/effective maturity,
  explicit override, phase, runtime, headless status, workspace/finding-store
  requirements, phase-result ownership and required/canonical option names.
- Every visible row binds the complete serialized `ToolDescriptor` with
  `descriptorSha256`. The digest covers recursively key-sorted compact JSON,
  preserving array order. It includes aliases, defaults, limits, prompts,
  authorization and allowance policy rather than copying the full descriptor
  into the audit. Python catalog projection and Rust canonical hashing agree
  independently for all 118 captured descriptors.
- Visible and internal matrices form an exact non-overlapping partition of all
  189 registered actions. All 71 internal rows are checked against their actual
  owner and descriptor, including DAG membership as metadata. All 110 in-scope
  visible actions retain explicit values for the nine audit dimensions.

Descriptor consistency does not prove useful execution, source containment,
complete artifacts, cancellation, restart, cost accuracy or model quality. Those
claims still require the named per-tool evidence and limits. DAG membership
cannot establish execution ordering. The digest is an audit fact, not an
execution permission or verification signature. Internal rows check their named
metadata fields, not a complete descriptor digest.

`descriptorSha256` and the named consistency checkpoint are additive audit JSON
fields under schema version 1. Historical snapshots and source commits keep
their existing labels. Public module manifests and `.kuzushi` artifact formats
are unchanged. The contract runs in the existing workspace Rust-test CI job;
the quick gate does not run the complete Rust suite.

## Evidence and boundaries

The initial red run has two passing contracts and one failure. It identifies
all five stale fields and the absent descriptor digests. After refresh, all
three contracts pass, including an explicit assertion that no internal metadata
row was skipped. Focused logs, the original matrix, isolated catalogs, captured
owner tiers and the independently checked metadata update are retained under
`scripts/devex/artifacts/module-readiness-20261023/`.

The three new contracts, existing 189-tuple dispatch-policy fingerprint, locked
workspace build, Core Clippy and all ten repository quick checks pass. Their
terminal results are recorded in `verification-results.json` and
`draft-receipt.json` under that root. The rebuilt tool/default/module catalogs
are unchanged and the product binary remains byte-identical to the final
reader build, SHA-256
`3304dc9fd6541df96eea78ba75bf28170e65f8db53179f632125ceb6084d6c13`.
The existing tmux evidence therefore covers the same product executable; no
new terminal journey was needed for test and audit-data changes.

This increment changes audit data and test contracts. It does not change a TUI
surface or execute a tool, scanner, target program, model request, exploit,
reproducer or vulnerability patch. Existing final reader evidence remains
60 tmux machine passes, zero failures and three pending operator judgments;
these checks add no new TUI acceptance claim. Cumulative real experiment use
stays at 16 with no approved allowance left and unknown dollar consumption.

The earlier 16-file reader checkpoint stays staged with its exact tree and
publication request unchanged. These audit changes are separate unstaged work.
Four broad delivery items remain locally verified and five remain open. The
per-tool functional audit, scope-proposal usefulness, experiment comparisons,
review/learning acceptance and complete operator journey are not closed by this
metadata repair. No tool is promoted, removed or speculatively retired.
