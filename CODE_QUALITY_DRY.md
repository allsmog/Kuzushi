# Code Quality — DRY Assessment

Audit run: 2026-04-30. Branch: `worktree-agent-a79cbc891b388d83d`.
Scope: `src/` only. Tests untouched in this pass.

The codebase is generally well factored. Several large helpers
(`computeDetectionFingerprint`, `severityStyle`, `runLens`, etc.) are
already centralised. The duplications below are the high-signal ones
left over.

## Inventory of duplications

### D1. Inline `error instanceof Error ? error.message : String(error)` (HIGH)

73 occurrences across 35 files, despite `toErrorMessage(error)` already
existing in `src/utils.ts:15`. Sample sites:

- `src/cli/errors.ts:74,76`
- `src/cli/commands/scan-pipeline.ts:163,202,219`
- `src/agent-runtime/execution.ts:296`
- `src/testing/module-shape.ts:56`
- `src/testing/assertions.ts:96`
- `src/copilot/shell.ts` (12+ sites: 889, 991, 1043, 1067, 3838, 3846, 4055, 4591, 4662, 7525, 7608, …)
- `src/copilot/dispatcher/*.ts`
- `src/sessions/manager.ts`
- `src/copilot/diff-scope.ts`, `src/copilot/resource.ts`, `src/copilot/core.ts`
- `src/copilot/context-build-runner.ts`
- `src/agent-runtime/model-validation.ts`
- many more

Severity: high (volume).
Proposed: replace every textual match of `<x> instanceof Error ? <x>.message : String(<x>)` with `toErrorMessage(<x>)`.
Risk: very low — `toErrorMessage` is identical behaviourally.
Confidence: high.

### D2. Duplicate `SEVERITY_ORDER` / `severityRank` (MED)

Existing canonical: `src/ui/severity.ts` exports `SEVERITY_ORDER` and `severityRank`.

Local duplicates:

- `src/ui/components/FindingsView.tsx:170-175` — `SEVERITY_ORDER` record.
- `src/ui/components/FindingsView.tsx:404-407` — local `severityRank`.
- `src/ui/components/ThreatSummaryExport.tsx:42` — `SEVERITY_ORDER` array.
- `src/copilot/finding-alias.ts:32-37` — `SEVERITY_ORDER` record + local `severityRank`.
- `src/copilot/shell.ts:2939-2945` — `SEVERITY_ORDER` record (different ordering: ascending rank).
- `src/report-sarif.ts:355` — `severityRank` for SARIF levels (different domain — keep as-is).

Severity: medium.
Proposed: replace the FindingsView/ThreatSummaryExport/finding-alias
local copies that match the canonical (critical→0, high→1, medium→2,
low→3) order with helpers from `ui/severity.ts`. The shell.ts copy is
inverted (critical→4 highest) for `>=` comparisons; reuse via
`severityRank` and flip the comparison so we still have one source.
Risk: low — pure helper, well covered.
Confidence: high for FindingsView/ThreatSummaryExport/finding-alias;
medium for shell.ts (slightly different semantics — must invert
compare). Will tackle the easy ones; leave shell.ts inversion as-is to
avoid regressions.

### D3. Duplicate `stripAnsi` helpers (LOW)

- `src/copilot/print.ts:49` (exported)
- `src/ui/components/ContextBuildView.tsx:584` (private)
- `src/ui/components/FindingsView.tsx:157,161` (inline regex + `pad`)

Severity: low (only 3 copies, regex is small).
Proposed: keep `print.ts`'s `stripAnsi` exported and consume it from
the two UI sites; consolidate `pad`/`padEndColored` likewise.
Risk: low — visible change is import only.
Confidence: high.

### D4. Local `isRecord` duplicate (LOW)

- `src/utils.ts:4` — canonical, exported.
- `src/threat-model-patch.ts:458` — duplicate (uses `Boolean(value)` vs `value !== null`).

Severity: low (single duplicate).
Proposed: import from `utils.js`.
Risk: minimal — semantics equivalent.
Confidence: high.

### D5. Multiple `formatDuration` (LOW-MED)

- `src/ui/format.ts:81` — canonical, full ladder ms/s/m/h.
- `src/scoring/run-metrics.ts:191` — proper subset of the above.
- `src/report-pr-comment.ts:116` — different format (`12s`, `1m 2s`, no ms).

Severity: low (3 sites, formats not all identical).
Proposed: replace the `scoring/run-metrics.ts` copy with an import
from `ui/format.ts` (output equivalent for the values it sees).
Skip `report-pr-comment.ts`: PR comment intentionally renders without
`ms` and without `.1s` decimals — different aesthetic.
Risk: negligible — `run-metrics` only formats long durations.
Confidence: high (run-metrics); skip pr-comment.

### D6. Repeated `totalCostUsd` accumulation pattern (LOW)

`if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) { costUsd = message.totalCostUsd; }` appears in 15+ task/module files. Each callsite is one clean line embedded in a different `for await` loop.

Severity: low — extraction would be cosmetic and `normalizeCostUsd` already covers the `>= 0` finite case.
Proposed: SKIP. The savings (one ternary vs three lines) don't justify a new helper or import in each site.
Confidence: low.

### D7. Multiple local `clamp` helpers (LOW)

Six separate definitions, mostly with different signatures (string trim, numeric range with NaN guard, string-clamp, etc.). Not real duplication — same name, different work.

Proposed: SKIP.

### D8. Multiple `truncate` helpers (LOW)

Six versions, different behaviour: ellipsis char (`…` vs `...`), fence treatment, middle-truncate variant. Not a clean DRY win without behaviour decisions.

Proposed: SKIP.

### D9. Duplicate `extractJsonObject` in pi-ai.ts (LOW)

`src/agent-runtime/pi-ai.ts:1366` shadows `src/utils.ts:36` with a `string | null` return shape (returns null on empty input, otherwise behaves like the util).

Proposed: SKIP. The signature differs and the local helper is private to its parser. Forcing a shared helper would either widen the util's contract or add a wrapper for no real gain.

### D10. Duplicate `JSON.parse(JSON.stringify(...))` deep-clone (LOW)

Only 2 callsites (`threat-model-patch.ts`, `mcp-bridge.ts`).

Proposed: SKIP — too few uses to warrant a helper.

## Plan — what I will do

1. **D1**: search-and-replace 73 sites with `toErrorMessage`, importing
   from `../utils.js` (or relative path) where missing.
2. **D2**: switch `FindingsView.tsx`, `ThreatSummaryExport.tsx`, and
   `finding-alias.ts` to use `severityRank` / `SEVERITY_ORDER` from
   `ui/severity.ts`.
3. **D3**: switch `ContextBuildView.tsx` and `FindingsView.tsx`'s
   `stripAnsi`/`pad` to consume from `copilot/print.ts` (or, if the
   layering is wrong, promote to a shared `ui/ansi.ts`). I'll use
   `copilot/print.ts`'s exported `stripAnsi` which UI files can import.
4. **D4**: replace the duplicate `isRecord` in `threat-model-patch.ts`.
5. **D5**: replace `scoring/run-metrics.ts`'s `formatDuration` with an
   import from `ui/format.ts`.

## Plan — what I will NOT do

- **D6, D7, D8, D9, D10**: skipped per reasoning above.
- Will not touch try/catch blocks, type-weakness, or unused-code (other
  agents own those concerns per task brief).
- Will not modify tests in this pass.
- Will not introduce new abstractions when only two callsites exist.
- Will not change `report-pr-comment.ts`'s `formatDuration` (different
  aesthetic intentionally).
