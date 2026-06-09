# Weak-Type Audit — Kuzushi src/

> Historical audit — archived snapshot, not current operator guidance.

## Phase 1 — Inventory

Repository-wide grep over `src/` (excluding tests, generated, dist):

| Pattern                                | Count  | Notes                                            |
| -------------------------------------- | -----: | ------------------------------------------------ |
| `: any` / `<any>` / `as any`           |      0 | (Only matches in src/ are inside doc comments / strings.) |
| `: unknown` / `<unknown>` / `as unknown` |  ~970 | The vast majority are correct trust-boundary uses (JSON parse, config IO, MCP/SDK payloads, error catches, structured-output parser shims). |
| `Record<string, any>`                  |      0 |                                                  |
| `Record<string, unknown>`              |  ~640 | Mostly: logger meta args, JSON-Schema literals passed to Anthropic SDK, parsed-config layers, stats blobs. Mostly correct boundary use. |
| `: Function` / `: object`              |      9 | All in `src/modules/host-handles.ts` and the matching mocks — these are the **public SDK contract** for `WorkspaceHandle` and are intentionally `object` so concrete host types are structurally assignable without import. CLAUDE.md guardrail explicitly forbids breaking this contract. **KEEP.** |
| `as unknown as <T>` double-casts       |   ~120 | The real debt — see Phase 2.                    |

`tsconfig.json` already enables `"strict": true`. So the only remaining
weak-type debt is intentional `unknown`/`Record<string, unknown>` at
boundaries, plus the `as unknown as T` escape-hatch casts.

## Phase 2 — Critical assessment

### Justified `unknown` (KEEP)

These are correct system boundaries — values originate from `JSON.parse`,
unverified config files, Anthropic SDK callback payloads, MCP server
responses, or `Promise.catch(error)`. Every one of these is followed by
an explicit guard (`isRecord`, Zod parse, `typeof` check) before
downstream typed use. Examples:

- `src/utils.ts:4` — `isRecord(value: unknown)` typeguard.
- `src/utils.ts:15` — `toErrorMessage(error: unknown)` for catch blocks.
- `src/repo-context.ts` — `asString`/`asStringArray` Zod-style coercers.
- `src/config.ts` — `normalize*` functions on raw JSON.
- `src/logger.ts` — `info(msg, ...args: unknown[])` (matches console.log shape).
- `src/report-json.ts:34`, `src/report-jsonl.ts:9` — JSON.stringify
  reviver signatures (the standard library shape requires `unknown`).
- `src/http-error-response.ts:12,22,31` — `details` field is RFC 7807
  free-form metadata (string-keyed JSON).
- `src/operator-context.ts:242,311` — generic helper shape.
- `src/retry.ts:30` — `lastError` from caught throws.

### Justified `Record<string, unknown>` (KEEP)

- **Logger metadata** (`ToolLogger.info(meta?: Record<string, unknown>)`)
  — meta is intentional structured-key blob.
- **JSON-Schema literals** passed to `query({ schema })` calls — the
  Anthropic SDK declares `schema: Record<string, unknown>`, which forces
  the cast. The schema itself is a literal frozen value; safe.
- **Config patches in tests** — `Record<string, unknown>` is the
  established test-fixture shape.
- **Module event payloads** — explicitly typed as `unknown` in the
  module SDK contract (cross-module pub/sub is by design opaque).

### Justified `object` in `host-handles.ts` (KEEP)

`WorkspaceHostStore.upsert(input: object)` etc. are the **public SDK
contract** (CLAUDE.md guardrail). Comments at L114-118 explain the
deliberate choice — concrete `better-sqlite3`-backed stores are
structural supersets that drop in without modules importing host
internals. Mocks in `src/testing/mocks/workspace.ts` mirror the
interface and must stay `object[]` to satisfy declaration merging.

### Lazy `as unknown as T` casts — REPLACE candidates

| Site                                      | Current cast                                    | Strong replacement                                | Confidence |
| ----------------------------------------- | ----------------------------------------------- | ------------------------------------------------- | ---------- |
| `src/ui/severity.ts:214`                  | `chalk as unknown as Record<string, ChalkInstance>` | `Record<InkColor, ChalkInstance>` (narrower keys) | HIGH       |
| `src/repo-context.ts:221,224`             | `... as unknown as FileIndex`                   | `... as FileIndex` (already narrowed by isRecord) | HIGH       |
| `src/copilot/print.ts:103-112`            | `this as unknown as Record<string, unknown>`    | Properly typed `keyof` indexing                   | HIGH       |
| `src/agents/tasks/*-detect.ts` (~12 sites)| `item as unknown as XxxFinding`                 | `as XxxFinding` (already isRecord-checked)         | MEDIUM (per-file)|
| `src/scoring/run-metrics.ts:51,133`       | `f as unknown as Record<string, unknown>`       | Define enriched-Finding interface                 | LOW (cross-cuts) |
| `src/cli/scan-config.ts:142,143`          | `config as unknown as Record<string, unknown>`  | Add `githubPr`/`githubComment` to `KuzushiConfig` | LOW (schema change) |
| `src/bus/workers/github-worker.ts:139-147`| `config as unknown as Record<string, unknown>`  | Same — depends on schema change above             | LOW        |
| `src/copilot/shell.ts:491`                | `config as unknown as { preset?: string }`      | Add `preset` to `KuzushiConfig` (CLI-only field)  | LOW        |
| `src/streaming.ts:185`                    | `event.payload.stats as unknown as Record<string, unknown>` | Serialization boundary           | KEEP       |
| `src/threat-model-patch.ts:93` & similar  | `XYZ_SCHEMA as unknown as Record<string, unknown>` | Anthropic SDK requires this cast — KEEP          | KEEP       |
| `src/modules/define.ts:92,125`            | `spec as unknown as ...`                        | Type-erasure step in generic helper — KEEP       | KEEP       |
| `src/bus/event-log.ts:105,113,115`        | Monkey-patch publish on bus                     | Inherent to instance-method shadowing — KEEP     | KEEP       |
| `src/agent-runtime/claude.ts:113,815,1177`| SDK options/process casts                       | Vendor SDK has missing/undocumented hook field    | KEEP       |
| `src/copilot/options.ts:94-120`           | `T` casts in generic option-coercer             | Generic-function shape — `as T` is canonical      | KEEP       |
| `src/testing/index.ts:53,86,142`          | Mock fixture casts                              | KEEP — kept to short-circuit repeated boilerplate |

## Phase 3 — Implementation

High-confidence wins applied (see commit on this branch):

1. `src/ui/severity.ts:214` — `Record<string, ChalkInstance>` → `Record<InkColor, ChalkInstance>`.
2. `src/repo-context.ts:221,224` — drop redundant `unknown` intermediate in `as` cast.

Skipped (with reasons documented above):

- Schema additions to `KuzushiConfig` (`githubPr`, `githubComment`,
  `preset`) — adding fields to the public config schema is out of scope
  for a type-cleanup pass; would require touching default-merge,
  serialization, and CLI tests.
- `print.ts` capture rebinding — works correctly, the cast is the
  conventional pattern for safe method shadowing.
- `*-detect.ts` finding casts — pattern is consistent across ~12 files
  and gives uniform behaviour; switching one would create inconsistency.

## Phase 4 — Build/Test status

Reported in commit message.
