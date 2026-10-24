# Context catalog phase ownership

Three Core context readers incorrectly declared that they produced a Map result:
`threat-model:models`, `threat-model:revisions` and `threat-model:diff`. A completed
empty lineage listing made a fresh target bypass Setup and open Map without any
Map artifact. Descriptor-driven phase ownership also admitted these tools as
phase results. This was a workflow defect, not evidence of false Map acceptance;
the TUI checks actual Map evidence separately.

The correction sets `phase_result: false` on those three existing descriptors.
Shared startup classification, TUI result ownership, both ledger writers and
historical recovery consume the same policy. No parallel orchestration or
tool-name allowlist was added. The registered catalog remains 118 visible tools,
81 default Core tools and 189 registered actions. Comparison with the preceding
frozen catalog finds exactly three changed fields, all `phase_result`.

Historical catalog-only attempts disappear from the selectable phase projection
without rewriting their raw events or run receipts. The regression preserves the
prior genuine Map attempt and all seven recorded attempts. Unknown historical
tools retain their existing handling. Actual context artifacts independently
support resume; reading a catalog cannot manufacture them.

## Evidence

Local retained evidence is under
`scripts/devex/artifacts/phase-readiness-audit-20261024/`.

- `attempt-3/` records the before control with frozen binary
  `7677506684d736ec4cb37341862c9e5163a7a5844bd3eb8588997b3cb3f50fee`:
  fresh target opens Setup, an actual empty `threat-model:models` receipt opens
  Map, and auxiliary operational readers leave Setup intact.
- `startup-red.log` and `phase-origin-red.log` retain the failing regressions.
- `green-checks/` and `metadata-refresh-checks/` have 66 distinct focused passes:
  30 Core and 36 TUI, including shared
  dispatch comparison, startup, phase admission, registry metadata and history
  recovery. Workspace build and Core/TUI all-target Clippy pass.
- `native-attempt-2/` freezes 6,477 source inputs and 13 programs. The binary is
  `ef74a1c420a5a6f2e8b87e61ff42103ef467ef10305e029385c3696c48e7e903`.
  J349 has 12 machine passes, zero failures, two pending operator judgments and
  ten live capture pairs. Source and programs are unchanged through the run.
- J349 uses normal onboarding, the canonical wrapper and an isolated home with
  no credentials. Fresh Setup remains Setup after a real empty catalog read.
  A real `context:build` with enrichment disabled creates a current one-file
  inventory; no-color restart opens Map with acceptance incomplete. Explicit
  Setup remains available. No provider request, finding, campaign, phase attempt
  or target-source execution occurs.
- Eight ANSI cell replays were inspected, including Setup at 160x48, 120x36,
  96x89, 80x24, 60x20 and 40x12. All eight Setup rows and Start Map remain
  visible. Compact layouts omit secondary detail. Replays use Menlo 15 and a
  chosen dark background; they are not OS screenshots or operator acceptance.

The first J349 attempt retained ten machine passes and one failed exit check.
After explicit Setup, the shell correctly required confirmation for unsaved
planning state. The journey now uses that visible confirmation before requiring
exit. No product guard or timeout was weakened.

The first final repository gate rejected a 43-line history test. A shared
selection-refusal assertion keeps each function within the 40-line limit and
checks both ledger writers. The history regression also compares both raw
ledger files byte for byte. The failed gate and focused risk results are retained.

## Limits

This qualifies the three tools' phase role and the reproduced startup path.
It does not qualify every option or detector, general model accuracy, complete
operator acceptance, reference-product parity or all investigation requirements.
No module was removed or promoted. The broader implementation goal remains open.
