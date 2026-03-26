# Incremental Scanning: Finding-Level Caching with Dependency Tracking

## Context

Kuzushi re-scans and re-triages every file on every run, even when most files haven't changed. The scanner cache (`src/scanner-cache.ts`) is fully implemented but never wired into the pipeline. The resume system (`getTriagedFingerprints()`) can skip re-triage but only activates on explicit `--resume`. The import graph (`collectImportGraph()`) exists but isn't used for invalidation.

This spec wires these existing systems together and adds auto-diff detection to cut repeat scan times by 60-90%.

---

## 4 Layers

### Layer 1: Scanner Cache (existing code, needs wiring)
- `src/scanner-cache.ts` has `partitionCachedFiles()`, `persistScanResults()`, `getCachedFindings()` — all ready
- Content-addressed by `(scanner, config_hash, blob_hash, file_path)` — git blob hash auto-invalidates on file change
- Wire into each scanner's `scan()` call path

### Layer 2: Auto-Diff Detection (new)
- Store `head_ref` (current HEAD commit) in `pipeline_runs` table after successful scan
- On next run, compute `git diff --name-only <last_head_ref>...HEAD` to get changed files
- Pass changed file set as a filter to scanners — only scan these files + cached results for unchanged

### Layer 3: Dependency Propagation (leverages existing import graph)
- After computing changed files, build reverse dependency map from `collectImportGraph()`
- Expand changed set: add files that import any changed file (1-hop transitivity)
- The expanded set is the scan scope

### Layer 4: Triage Skip (existing, needs activation)
- `getTriagedFingerprints()` in `src/store.ts` returns fingerprints already triaged
- Enable this when `incrementalCache: true`, not just on `--resume`
- Findings from unchanged files with matching fingerprints skip re-triage entirely

---

## Configuration

| Config field | CLI flag | Default | Description |
|---|---|---|---|
| `incrementalCache` | `--incremental` / `--no-incremental` | `true` (existing) | Enable incremental scanning |
| `incrementalDepTracking` | `--incremental-dep-tracking` | `true` | Include importers of changed files |
| `incrementalCacheTtlDays` | `--incremental-cache-ttl <n>` | `30` | Prune cache entries older than N days |

Note: `incrementalCache` already exists in config and defaults to `true`. The `--fresh` flag already exists and clears prior results — it should also clear the scanner cache.

---

## Implementation

### Step 1: Migration — add head_ref + file_path index

New migration `021_add_incremental_scanning_support.ts`:

```sql
ALTER TABLE pipeline_runs ADD COLUMN head_ref TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_file_path ON findings(file_path);
```

The `head_ref` column stores the git commit hash at scan time. The file_path index enables efficient queries for finding-level caching.

### Step 2: Config additions

Add to `src/types.ts` KuzushiConfig:
```typescript
incrementalDepTracking?: boolean;   // default true
incrementalCacheTtlDays?: number;   // default 30
```

Add defaults to `src/config/defaults.ts`.
Add Zod schemas to `src/schemas.ts`.
Add CLI flags to `src/cli.ts` + `src/cli/scan-config.ts`.

### Step 3: Store head_ref on scan completion

In `src/bus/orchestrator.ts`, when publishing `pipeline:complete`:
- Compute `git rev-parse HEAD` for the scanned repo
- Store it in `pipeline_runs.head_ref` via existing `updateRunStatus()` or new helper

Add `getLastSuccessfulHeadRef(db, repo)` to `src/store.ts`:
```typescript
function getLastSuccessfulHeadRef(db, repo): string | null {
  // SELECT head_ref FROM pipeline_runs WHERE repo = ? AND status = 'completed' ORDER BY completed_at DESC LIMIT 1
}
```

### Step 4: Compute changed files

New function in `src/incremental.ts`:

```typescript
export function computeChangedFiles(repoRoot: string, baseRef: string): string[] {
  // git diff --name-only baseRef...HEAD
  // Returns relative file paths
}

export function expandWithDependents(
  changedFiles: string[],
  importGraph: ImportGraphEdge[],
): string[] {
  // Build reverse map: file -> files that import it
  // For each changed file, add its importers to the set
  // Return expanded set
}
```

### Step 5: Wire scanner cache into scan pipeline

In `src/bus/workers/scan-worker.ts`:

**Before running each scanner:**
1. If `incrementalCache` is enabled:
   - Call `ensureScannerCacheSchema(db)` once per run
   - Get `lastHeadRef` from store
   - If available, compute `changedFiles` via `computeChangedFiles()`
   - If `incrementalDepTracking`, expand with `expandWithDependents()`
   - Call `partitionCachedFiles(db, scanner, config, allFiles)` to get cached vs uncached
   - Filter uncached to only changed files (intersection)
2. Run scanner on uncached/changed files only
3. After scanning, call `persistScanResults(db, scanner, config, findings)` to cache
4. Merge cached findings + fresh findings

**On `--fresh`:**
- Clear scanner cache: `DELETE FROM scanner_cache WHERE repo = ?`

### Step 6: Activate triage skip

In `src/bus/orchestrator.ts` post-scan finding processing:
- When `incrementalCache: true`, load `getTriagedFingerprints()` (already exists)
- Filter out findings that have identical fingerprints with existing TP/FP verdicts
- Log count of skipped findings: "Skipped N findings (unchanged since last run)"
- This logic already exists for `--resume` — just enable it when `incrementalCache: true`

### Step 7: Cache pruning

On startup when `incrementalCache: true`:
- Call `pruneScannerCache(db, ttlDays)` (already exists in `scanner-cache.ts`)
- Delete entries older than `incrementalCacheTtlDays`

---

## Report Integration

Add to terminal summary:
```
  Incremental:       42 cached, 8 rescanned, 3 dependency-expanded
```

Add to `PipelineStats`:
```typescript
incrementalCachedFiles?: number;
incrementalRescannedFiles?: number;
incrementalDepExpandedFiles?: number;
```

---

## File Structure

### New files

```
src/incremental.ts                              — computeChangedFiles(), expandWithDependents()
src/migrations/021_add_incremental_scanning_support.ts — head_ref column + file_path index
```

### Modified files

| File | Change |
|------|--------|
| `src/types.ts` | Add `incrementalDepTracking`, `incrementalCacheTtlDays` |
| `src/config/defaults.ts` | Add defaults |
| `src/schemas.ts` | Add Zod schemas |
| `src/cli.ts` + `src/cli/scan-config.ts` | Add CLI flags |
| `src/bus/workers/scan-worker.ts` | Wire scanner cache partition/persist, filter by changed files |
| `src/bus/orchestrator.ts` | Store head_ref on completion, activate triage skip for incrementalCache |
| `src/bus/events.ts` | Add incremental fields to PipelineStats |
| `src/store.ts` | Add `getLastSuccessfulHeadRef()` |
| `src/report.ts` | Add incremental stats to summary |
| `src/migrations/index.ts` | Register migration 021 |

---

## Verification

1. `pnpm typecheck` — clean
2. `pnpm test` — all tests pass
3. Manual test:
   - Run `kuzushi scan <repo>` — first run scans everything, stores head_ref
   - Modify 1 file in repo
   - Run `kuzushi scan <repo>` again — should only re-scan modified file + importers
   - Verify report shows "X cached, Y rescanned"
   - Verify findings from unchanged files retain previous verdicts
4. `kuzushi scan <repo> --fresh` — verify cache is cleared
5. `kuzushi scan <repo> --no-incremental` — verify full scan runs
