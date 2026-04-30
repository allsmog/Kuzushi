# CODE_QUALITY_TYPES — Type Definition Audit

Scope: every `export type | export interface | export enum` and unexported
sibling under `src/`. Goal: identify *actual* duplicate definitions (same
concept, same shape) vs. intentional aliasing through a Zod-derived chain.

## Method

1. Enumerated every type/interface/enum declaration under `src/`
   (~991 exported, ~236 internal).
2. Bucketed by name and inspected co-located siblings:
   `Verdict`, `ScanMode`, `ProofVerdict`, `BusBackend`, `AgentRuntimeBackend`,
   `DataSensitivity`, `DynamicAnalysisStatus`, `DynamicCoverageMode`,
   `PatchStatus`, `Precedents`, `ExploitChain`, `DiffScope`,
   `ModuleEventScope`, `EventHandler`, `LogLevel`, `ProblemDetails`,
   `PipelineRunRecord`, `ErrorCategory`, `RunState`, `RunMetaRow`,
   `TriageOutput`, `PromptOptionKey`.
3. Skimmed canonical aggregator files: `src/types.ts`, `src/contracts.ts`,
   `src/schemas.ts`, `src/modules/types.ts`, `src/modules/host-handles.ts`,
   `src/scanners/types.ts`.
4. Cross-referenced consumers via grep to verify safe direction of
   re-export (no circular dependencies).

## Canonical locations already in place

| File                            | Owns                                            |
| ------------------------------- | ----------------------------------------------- |
| `src/contracts.ts`              | Wire-value enums (`VERDICTS`, `SCAN_MODES`, …)  |
| `src/schemas.ts`                | Zod schemas + `*Z` aliases                       |
| `src/types.ts`                  | TS-facing aggregator (`Verdict = VerdictZ` …)   |
| `src/scanners/types.ts`         | `Finding`, `TaskId`, scanner plugin contracts   |
| `src/modules/types.ts`          | `CopilotModule`, `ModuleTool`, `DagTool`, `ExecutionContext` |
| `src/modules/host-handles.ts`   | Narrow host handles (intentionally re-declared) |
| `src/precedents.ts`             | `Precedents` (loader + interface)               |
| `src/store.ts`                  | `PipelineRunRecord` (DB row type)               |
| `src/ui/severity.ts`            | `Severity` palette + tier union                 |

## Duplicate map

### Aliased through Zod (NOT real duplicates — keep)

These appear "duplicated" between `src/contracts.ts` and `src/types.ts`,
but the chain is `array → schema → type alias`. Both names resolve to the
same union. Removing either side would defeat the design (`contracts.ts`
is the wire value, `types.ts` is the consumer-facing TS surface).

- `Verdict`        contracts:11 / types:126
- `ScanMode`       contracts:20 / types:77
- `ProofVerdict`   contracts:31 / types:154
- `BusBackend`     contracts:17 / types:74
- `AgentRuntimeBackend` contracts:23 / types:80
- `DataSensitivity` contracts:43 / types:618
- `DynamicAnalysisStatus` contracts:75 / types:162
- `DynamicCoverageMode`  contracts:78 / types:164
- `PatchStatus`    contracts:89 / types:168

→ **Skip.** Documented design.

### Same-name, intentionally distinct (keep)

- `ErrorCategory` × 3 — `errors.ts`, `ui/error-format.ts`,
  `agent-runtime/error-classification.ts`. Three different domains
  (typed-error hierarchy / UI presentation / provider classification);
  member sets diverge (`unknown`, `billing`, `context_overflow`, etc.).
  Merging would either lose categories or pollute one domain with
  the others'. → **Skip.**
- `EventHandler` — `bus/types.ts` (typed `EventEnvelope` handler) vs
  `bus/module-events.ts` (raw payload pub/sub). Different signatures,
  different transports. → **Skip.**
- `DiffScope` — taint-analysis pass selection vs shell `/since` view.
  Different fields, different concept. → **Skip.**
- `ProblemDetails` — `modules/problem-details.ts` is the base RFC-7807
  shape; `http-error-response.ts` extends it with category/retryable.
  Already correctly structured (uses `extends BaseProblemDetails`).
  → **Skip.**
- `LogLevel` × 2 — `logger.ts` (host-side pino-compat) vs
  `testing/mocks/logger.ts` (`keyof ToolLogger`, module-side stub).
  Same string union by accident; different domains. → **Skip.**
- `RunState` × 2 — orchestrator pipeline state vs taint-artifact
  worker state. Different fields. → **Skip.**
- `RunMetaRow` × 2 — both private 2-field interfaces inside report
  generators. Low value to consolidate; cross-import would couple two
  reporters that should stay independent. → **Skip.**
- `TriageOutput` × 2 — wrapper `{result, costUsd}` vs LLM-output shape
  for assertion checks. → **Skip.**
- `PromptOptionKey` × 2 — module-specific (sast vs copilot prompt-edit).
  → **Skip.**
- `ModuleEventScope` × 2 — `host-handles.ts` re-declares the
  `bus/module-events.ts` shape on purpose so the public SDK surface
  doesn't leak the bus path. The docstring explicitly calls this out.
  → **Skip** (documented choice; structural compatibility is enforced
  at the consumer site).

### Real duplicates — consolidate (HIGH confidence)

#### 1. `Precedents` — `src/types.ts:293` ↔ `src/precedents.ts:5`

- Identical 3-field interface.
- All 5 real importers already pull from `src/precedents.ts`.
- The `src/types.ts` declaration is dead duplication.
- Action: delete from `src/types.ts`, add `export type { Precedents } from "./precedents.js"` so any external consumer that did the natural `import { Precedents } from "kuzushi/types"` keeps working.
- Risk: none.

#### 2. `ExploitChain` — `src/types.ts:307` ↔ `src/agents/tasks/chain-analysis.ts:18`

- Field-by-field identical (`id`, `name`, `steps`, `overallSeverity`, `preconditions`, `impactDescription`).
- All 5 cross-module consumers already import from `src/types.ts`.
- `chain-analysis.ts` only uses it locally for `chains: ExploitChain[]` and a couple of `ExploitChain["steps"]` index accesses.
- Action: drop the local declaration and import the canonical type from `../../types.js` (already imports `TriageResult` from there).
- Risk: none.

#### 3. `PipelineRunRecord` — `src/store.ts:53` ↔ `src/copilot/replay.ts:27`

- `replay.ts` declares `export type PipelineRunRecord = NonNullable<ReturnType<typeof getRunFn>>` — a derived alias that intentionally tracks `store.ts`.
- No external consumer imports the alias from `replay.ts` (only `shell.ts` consumes it from `store.ts`).
- Action: replace the derived alias with an explicit `export type { PipelineRunRecord } from "../store.js"` so the type is named, not inferred.
- Risk: none — both already resolve to the same shape; the change just removes the inferred indirection.

## Do / Skip ledger

| Item                                  | Action      | Confidence |
| ------------------------------------- | ----------- | ---------- |
| `Precedents` in `types.ts`            | Re-export   | High       |
| `ExploitChain` in `chain-analysis.ts` | Import canonical | High  |
| `PipelineRunRecord` in `replay.ts`    | Re-export   | High       |
| Zod-aliased pairs                     | Skip        | High       |
| `ErrorCategory` × 3                   | Skip        | High       |
| `EventHandler` × 2                    | Skip        | High       |
| `DiffScope` × 2                       | Skip        | High       |
| `ProblemDetails` × 2                  | Skip (already extends) | High |
| `ModuleEventScope` × 2                | Skip (documented) | High |
| `LogLevel` × 2                        | Skip        | High       |
| `RunState` × 2                        | Skip        | High       |
| `RunMetaRow` × 2                      | Skip (low value) | Med  |
| `TriageOutput` × 2                    | Skip        | High       |
| `PromptOptionKey` × 2                 | Skip        | High       |

## Out of scope (other agents)

- Removing unused exports (e.g. `DisplaySeverity` in `contracts.ts` is
  declared but every consumer inlines the same union). → agent 3.
- Removing `unknown` / `any`. → agent 5.
