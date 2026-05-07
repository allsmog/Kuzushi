# Fix Verification Loop: Orchestrator-Integrated Closed-Loop Patching

Status: historical TypeScript pipeline design spec. It is retained for
architecture context; CLI flags such as `--verify` in this document are not
current Rust operator examples.

## Context

Kuzushi has a patch synthesis system (`src/patch.ts`) with iterative generation, 5-step validation (apply, build, PoC re-run, tests), and git worktree isolation. However, it's CLI-only (`kuzushi patch --fingerprint <fp>`) and not integrated into the automated pipeline. There is no closed-loop: after generating a patch, the scanner never re-runs on the patched code to confirm the vulnerability is actually gone.

This spec adds a **patch phase** to the orchestrator pipeline that automatically generates, validates, and re-verifies patches for confirmed vulnerabilities.

---

## Pipeline Flow

```
scan → triage → verify → PoC → PATCH SYNTHESIS → RE-VERIFY → report
```

The patch phase is opt-in (`--auto-patch`) and slots after the existing PoC harness phase. It reuses the existing `runPatchPipeline()` function from `src/patch.ts` for synthesis/validation and adds a new re-verification step that runs the scanner on patched code.

**Key implementation notes:**
- The patch synthesis function is `runPatchPipeline(db, options)` (a standalone function, not a class)
- The patch result store function is `insertPatchResult()` in `src/store/patch-results.ts` (insert, not upsert — update verified status via a new `updatePatchResultStatus()` function)
- Worktree creation is handled internally by `runPatchPipeline()` via `createDisposableWorktree()` — to keep the worktree alive for re-verification, the worker must pass `skipCleanup: true` option and manage cleanup after re-verification completes
- All events must use the `EventEnvelope<Type, Payload>` pattern from `src/bus/events.ts`, not plain interfaces

---

## Configuration

All config fields have 1:1 CLI flag parity. Config fields use camelCase, CLI flags use kebab-case.

### New Config Fields (KuzushiConfig)

| Config field | Type | Default | Description |
|---|---|---|---|
| `autoPatchEnabled` | `boolean` | `false` | Enable automatic patch generation in pipeline |
| `autoPatchAfter` | `"verify" \| "poc" \| "triage"` | `"verify"` | Trigger threshold for patch generation |
| `patchVerifyDepth` | `"scanner" \| "triage" \| "full"` | `"scanner"` | How deeply to re-verify after patching |
| `patchConcurrency` | `number` | `2` | Max concurrent patch synthesis tasks |

### Existing Config Fields (unchanged)

| Config field | Default | Description |
|---|---|---|
| `patchMaxIterations` | `3` | Max synthesis iterations per finding |
| `patchBuildCommand` | auto-detect | Build command for validation |
| `patchTestCommand` | auto-detect | Test command for validation |

### CLI Flags

| Flag | Maps to config | Type |
|---|---|---|
| `--auto-patch` | `autoPatchEnabled: true` | boolean |
| `--auto-patch-after <trigger>` | `autoPatchAfter` | `verify\|poc\|triage` |
| `--patch-verify-depth <depth>` | `patchVerifyDepth` | `scanner\|triage\|full` |
| `--patch-concurrency <n>` | `patchConcurrency` | integer |

### Zod Schema Additions (schemas.ts)

```typescript
autoPatchEnabled: z.boolean().optional(),
autoPatchAfter: z.enum(["verify", "poc", "triage"]).optional(),
patchVerifyDepth: z.enum(["scanner", "triage", "full"]).optional(),
patchConcurrency: z.number().int().positive().optional(),
```

---

## Architecture

### New Components

#### 1. `src/bus/orchestrator/patch-dispatcher.ts`

Event-driven dispatcher following the existing triage-dispatcher/verification-dispatcher pattern.

**Responsibilities:**
- Subscribe to trigger events based on `autoPatchAfter` config:
  - `"verify"` → subscribe to `verification:result` where `exploitable === true`
  - `"poc"` → subscribe to `poc-harness:result` where `pocExecVerdict === "PASS"`
  - `"triage"` → subscribe to `triage:result` where `verdict === "tp"`
- Maintain a patch queue with configurable concurrency (`patchConcurrency`)
- Dispatch eligible findings to patch-worker
- After patch-worker returns `SOUND`, dispatch to patch-verify-worker
- Track `patchDispatching` state in `RunState`

**Eligibility check:**
- Finding must not already have a `SOUND` patch (check `patch_results` table)
- Finding must have `fixPatch` or triage rationale (provides synthesis context)
- Budget check: respect `costBudgetUsd` pipeline cap

#### 2. `src/bus/workers/patch-worker.ts`

Worker that wraps the existing `runPatchPipeline()` from `src/patch.ts`.

**Events:**
- Subscribes to: `patch:requested`
- Publishes: `patch:start`, `patch:complete`, `patch:error`, `patch:queue-depth`

**Behavior:**
- Calls `runPatchPipeline(db, options)` with `skipCleanup: true` to keep worktree alive for re-verification
- Captures `PatchResult` (status, diff, iterations, history)
- Stores result via `insertPatchResult()` in `src/store/patch-results.ts`
- If status is `SOUND`, publishes `patch:complete` with worktree path for re-verification
- If status is anything else, publishes `patch:complete` with failure status (worktree cleaned up immediately)
- Retry logic: max 2 retries with backoff (matching existing dispatcher retry pattern), dead-letter on persistent failure

#### 3. `src/bus/workers/patch-verify-worker.ts`

Re-verification worker that runs the scanner on patched code in the worktree.

**Events:**
- Subscribes to: `patch-verify:requested`
- Publishes: `patch-verify:start`, `patch-verify:complete`, `patch-verify:error`

**Behavior by depth:**

**`scanner` (default):**
1. Run configured scanners (`config.scanners`) against worktree path
2. Check if the original finding's fingerprint is present in results
3. If absent → `patchVerified: true` (finding is gone)
4. If present → `patchVerified: false` (mark as `STILL_VULNERABLE`)

**`triage`:**
1. Run scanners against worktree
2. If original fingerprint found, run triage on it
3. If triage returns `fp` → `patchVerified: true` (scanner flags it but triage says it's fixed)
4. If triage returns `tp` → `patchVerified: false`

**`full`:**
1. Run scanners against worktree
2. If original fingerprint found, run triage + verification + PoC
3. If any stage says "not exploitable" → `patchVerified: true`
4. If still exploitable → `patchVerified: false`, feed back into patch synthesis for another iteration

**After re-verification:**
- Update `patch_results` row with verified status via new `updatePatchResultStatus(db, patchRunId, status)` function
- Update finding's `findingMetadata` with `latestPatchRunId` and verified flag
- Clean up worktree via the `cleanup()` function returned by `createDisposableWorktree()`

---

## Event Types

New events in `src/bus/events.ts`, using the existing `EventEnvelope<Type, Payload>` pattern. All payloads include `context: RunContext`. Events must be added to the `KuzushiEvent` discriminated union.

```typescript
// Patch synthesis events
type PatchRequestedEvent = EventEnvelope<"patch:requested", {
  context: RunContext;
  fingerprint: string;
  trigger: "verify" | "poc" | "triage";
}>;

type PatchStartEvent = EventEnvelope<"patch:start", {
  context: RunContext;
  fingerprint: string;
}>;

type PatchCompleteEvent = EventEnvelope<"patch:complete", {
  context: RunContext;
  fingerprint: string;
  status: PatchStatus;
  worktreePath: string | null;
  costUsd: number;
  iterations: number;
}>;

type PatchErrorEvent = EventEnvelope<"patch:error", {
  context: RunContext;
  fingerprint: string;
  error: string;
  attempt: number;
}>;

type PatchQueueDepthEvent = EventEnvelope<"patch:queue-depth", {
  context: RunContext;
  depth: number;
}>;

// Patch re-verification events
type PatchVerifyRequestedEvent = EventEnvelope<"patch-verify:requested", {
  context: RunContext;
  fingerprint: string;
  worktreePath: string;
  depth: "scanner" | "triage" | "full";
}>;

type PatchVerifyStartEvent = EventEnvelope<"patch-verify:start", {
  context: RunContext;
  fingerprint: string;
}>;

type PatchVerifyCompleteEvent = EventEnvelope<"patch-verify:complete", {
  context: RunContext;
  fingerprint: string;
  verified: boolean;
  depth: "scanner" | "triage" | "full";
  details: string;
}>;

type PatchVerifyErrorEvent = EventEnvelope<"patch-verify:error", {
  context: RunContext;
  fingerprint: string;
  error: string;
}>;
```

All 9 event types must be added to the `KuzushiEvent` union at the bottom of `src/bus/events.ts`.

---

## RunState Extensions

In `src/bus/orchestrator.ts` RunState (all fields are NEW — none exist today):

```typescript
patchCandidates: Set<string>;   // fingerprints eligible for patching
patchQueue: string[];            // ordered queue
patchInFlight: number;           // currently synthesizing
patchCompleted: number;          // synthesis done (any status)
patchVerified: number;           // re-verify confirmed finding gone
patchFailed: number;             // synthesis or verify failed
```

### PipelineStats Extensions

Add to `PipelineStats` in `src/bus/events.ts` (carried by `pipeline:complete`):

```typescript
patchGenerated?: number;
patchVerified?: number;
patchFailed?: number;
patchCostUsd?: number;
patchErrors?: number;
```

### Audit Log

All patch events are captured by the existing audit-worker when `auditLog` is enabled. No additional wiring needed — the audit-worker subscribes to all event types via a wildcard pattern.

---

## Report Integration

### Terminal Summary (src/report.ts)

Add patch section to `printSummary()`:

```
  Patches generated:  5
  Patches verified:   3 (finding eliminated after patch)
  Patches failed:     2 (STILL_VULNERABLE: 1, BUILD_FAILED: 1)
  Patch cost:        $0.0234
```

### Structured Reports (JSON, SARIF, Markdown)

Each format includes patch results per finding:
- `patchStatus`: SOUND | STILL_VULNERABLE | BUILD_FAILED | etc.
- `patchVerified`: true/false/null
- `patchDiff`: the unified diff (for SOUND patches)
- `patchIterations`: number of synthesis attempts

---

## Database Changes

No new migration needed — the existing `patch_results` table from migration 017 already stores all patch data. The `verified` status is stored via the existing `status` field (extend to include `VERIFIED` as a new PatchStatus value).

Add to `PatchStatus` type:
```typescript
export type PatchStatus =
  | "APPLY_FAILED"
  | "BUILD_FAILED"
  | "STILL_VULNERABLE"
  | "TESTS_FAILED"
  | "SOUND"
  | "VERIFIED"    // NEW: patch is SOUND and re-verification confirmed finding is gone
  | "UNKNOWN";
```

---

## File Structure

### New files

```
src/bus/orchestrator/patch-dispatcher.ts   — Event-driven patch queue dispatcher
src/bus/workers/patch-worker.ts            — Wraps runPatchPipeline() for event-driven execution
src/bus/workers/patch-verify-worker.ts     — Re-runs scanner on patched worktree
```

### Modified files

| File | Change |
|------|--------|
| `src/types.ts` | Add `autoPatchEnabled`, `autoPatchAfter`, `patchVerifyDepth`, `patchConcurrency` to KuzushiConfig. Add `VERIFIED` to PatchStatus. |
| `src/config/defaults.ts` | Add defaults for new config fields |
| `src/schemas.ts` | Add Zod schemas for new config fields. Update `PatchStatusSchema` to include `"VERIFIED"`. |
| `src/cli.ts` | Add `--auto-patch`, `--auto-patch-after`, `--patch-verify-depth`, `--patch-concurrency` flags |
| `src/cli/scan-config.ts` | Add fields to ScanCommandOptions, apply overrides |
| `src/bus/events.ts` | Add 9 new event types (patch:*, patch-verify:*), add to `KuzushiEvent` union, add patch fields to `PipelineStats` |
| `src/bus/orchestrator.ts` | Add patch RunState fields, wire patch-dispatcher, populate PipelineStats patch fields |
| `src/store/patch-results.ts` | Add `updatePatchResultStatus()` function. Update `parsePatchStatus()` for `VERIFIED`. |
| `src/patch.ts` | Add `skipCleanup` option to `runPatchPipeline()` to keep worktree alive for re-verification. Export `createDisposableWorktree()` for patch-verify-worker cleanup. |
| `src/report.ts` | Add patch summary section to `printSummary()` |
| `src/report-markdown.ts` | Include patch results per finding |
| `src/report-json.ts` | Include patch results per finding |

---

## Implementation Sequence

### Phase 1: Config + Events
1. Add config fields to `src/types.ts`
2. Add defaults to `src/config/defaults.ts`
3. Add Zod schemas to `src/schemas.ts`
4. Add CLI flags to `src/cli.ts` + `src/cli/scan-config.ts`
5. Add event types to `src/bus/events.ts`
6. Add `VERIFIED` to PatchStatus

### Phase 2: Workers
7. Create `src/bus/workers/patch-worker.ts` — wrap PatchPipeline
8. Create `src/bus/workers/patch-verify-worker.ts` — re-run scanner on worktree

### Phase 3: Dispatcher + Orchestrator
9. Create `src/bus/orchestrator/patch-dispatcher.ts` — queue + dispatch logic
10. Wire into `src/bus/orchestrator.ts` — add RunState fields, instantiate dispatcher

### Phase 4: Reporting
11. Update `src/report.ts` — patch summary in terminal
12. Update `src/report-markdown.ts` and `src/report-json.ts` — per-finding patch data

### Phase 5: Testing
13. Unit tests: `tests/bus/patch-worker.test.ts`, `tests/bus/patch-verify-worker.test.ts`
14. Unit tests: `tests/bus/patch-dispatcher.test.ts`
15. Integration test: full pipeline with `--auto-patch --patch-verify-depth scanner`

---

## Verification

1. `pnpm typecheck` — no type errors
2. `pnpm test` — all tests pass
3. Manual: `kuzushi scan <repo> --verify --auto-patch --patch-verify-depth scanner`
   - Verify patch events appear in audit log
   - Verify patches are generated for exploitable findings
   - Verify re-verification runs scanner on worktree
   - Verify report includes patch results
4. Manual: `kuzushi scan <repo> --auto-patch --auto-patch-after triage` — verify broadest trigger works
5. Config file: verify `{"autoPatchEnabled": true, "autoPatchAfter": "poc"}` in `.kuzushi/config.json` works identically to CLI flags
