# Capability recovery guidance, October 6, 2026

The capability picker now keeps preparation guidance readable and follows the
actual input owner. An empty picker loads a draft after target selection. A
typed draft owns editing. Without a target, Enter opens explicit target
selection. None of these actions starts an executor or grants spending approval.
Work remains on `main`, now at `0912eecdc97a4762aa22c99fde69d5e95947dd01`.
The checkout advanced externally between checkpoints; this work made no commit
or push and preserves all inherited pending changes.

## Changes and evidence

Three regressions failed before the change: plain output omitted the selected
recovery step, compact output clipped the options command, and an unsupported
provider received a generic input-review hint. Modal and plain output now share
one recovery renderer. It keeps a remedy together when possible and wraps it
before allocating action rows. The runtime-backed selection uses the existing
pure model/auth binding policy. Invalid configuration shows `RUNTIME CONFIG`
and a `doctor` route without reading credentials, changing the model or creating
a runtime. Explicit deterministic inputs bypass that check.

Native inspection found additional defects. Decorative vertical margins hid
the remedy at 40x12. The catalog now uses its available body. The compact footer
keeps move, load and back controls visible and deduplicates Enter hints. Once a
draft is loaded, the modal names editing instead of advertising another Enter
load. Targetless Enter names and opens the target picker. Navigation remedies
describe the relevant command or preparation, independently of input ownership.

The existing 80x16 action-list regression remains passing. The reviewed plain
snapshot replaces a spacer with recovery guidance and removes the unconditional
targetless Enter promise. Public dispatch, descriptor options, artifacts,
maturity tiers and module implementations are unchanged.

Evidence root: `/tmp/kuzushi-experiment-main-20261006/`.

- `catalog-guidance-before.log` and `catalog-compact-before.log` retain the
  failing regressions.
- `catalog-guidance-verified-tests.log` records 79 unit/behavior passes, two
  integration passes and the plain snapshot pass. These include the native
  minimum-body geometry, actual footer controls, draft ownership, targetless
  guidance, model overrides and unchanged configuration. They do not establish
  executor usefulness.
- `catalog-guidance-verified-build.log` records the workspace build.
- `final-catalog-guidance-gates.json` records the final quick gates. Independent
  before/after pending-change and native fingerprints are recorded beside it.
  Preserve the verifier's conservative dirty/drift flags and inspect those
  independent fingerprints for actual content changes.

Final J99: `tui/20261006-152837/J99/`. The raw harness result remains
`REVIEW_REQUIRED`, with 39 machine passes, zero failures and six review items.
Separate `manual-review.json` records six passing screen judgments with actual
text/ANSI hashes and capture provenance. All six viewport sizes, no-color,
loaded draft, explicit exit, targetless browsing and target-picker return were
read. The isolated home retains its synthetic unsupported model; no tool,
scanner, provider or fixture source program is executed.

Earlier native evidence is retained. `150630` has ten passes and eight raw
failures, including hidden recovery and driver exit/notice failures. `151225`
passes machine checks but fails screen review for hidden movement guidance and
a stale draft-loading cue. `151655` retains that cue defect. `152130` passes
the selected-target scope; targetless consent is added in the final run. Each
has separate judgments, and none of its raw reports is rewritten.

## Remaining acceptance

These are selected-action preparation and interaction checks. Credentials,
external dependencies, accepted scope support, enforced allowance, cancellation
and useful executor outputs still require individual-tool evidence. No module
is promoted or retired. Complete reference parity, platform/accessibility
coverage and the full live investigation journey remain open.

The live source and ledger were reread and match the preceding checkpoint:
seven settled requests of ten approved, five attempts, zero unresolved request
reservations and two protected Review requests. Dollars remain unavailable.
The separately prepared three-pass study and proposed total ceiling of 21
remain unapproved and unstarted. All nine delivery milestones remain unchecked.
