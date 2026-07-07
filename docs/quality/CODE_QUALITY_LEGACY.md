# Legacy / Deprecated Code Audit

> Historical audit — archived snapshot, not current operator guidance.

Scope: this branch only. Sibling agents own try/catch (#6), weak types (#5),
AI-slop comments (#8), unused-code (#3). I stay in legacy/dual-path lane.

## Will delete (high confidence)

### 1. `src/scanners/run-agentic.ts` — `@deprecated` re-exports
- `AGENTIC_SCHEMA` (alias of `FINDING_SCHEMA`)
- `AgenticFinding` (alias of `NormalizedFinding`)
- `AgenticOutput` (alias of `FindingOutput`)
- All three are explicitly tagged `@deprecated` with "Will be removed in a
  future major version." No callers outside this file. Internal usages
  (`AgenticOutput` parameter types, `AgenticFinding` parameter type) get
  inlined to the canonical types.
- Risk: low — internal-only.

### 2. `src/ui/layout-context.tsx` — `selectionGlyph` field
- Marked `@deprecated Use glyphs.selection. Kept for one release for any
  out-of-tree consumers...`. No in-tree callers. Project explicitly
  forbids backwards-compatibility shims (CLAUDE.md).
- Risk: nil — never read.

### 3. `src/ui/format.ts` — `secondary()` helper
- Comment says "Delegates to tokens.muted — kept for backwards
  compatibility with older call sites." No callers anywhere in the
  repository.
- Risk: nil — never imported.

### 4. `src/copilot/shell-commands.ts` — `deprecatedSince` field +
   `"deprecated"` variant of `CommandSurfaceKind`
- No `ShellCommandEntry` is marked `metadata: { surface: "deprecated" }`.
  No reader inspects `deprecatedSince`. Dead future-proofing.
- Risk: low — type narrows, no behavior change.

### 5. `src/cli.ts` — hidden `compare-runs` deprecation alias
- The command is hidden, prints a deprecation warning, and is fully
  superseded by `kuzushi runs compare`. No tests reference it.
- Risk: low — operators using this since 0.18.x get a warning today;
  removal is the whole point of deprecation.

## Will NOT delete (intentional fallback or load-bearing)

### A. `src/agent-runtime/` — same-model retries, batch→sequential, stale-model warnings
CLAUDE.md "Model & runtime safety" section explicitly mandates these
fallbacks. Skipped entirely.

### B. `src/config.ts` — `agentRuntimeConfig.{apiKey,baseUrl}` legacy retarget
User-facing config keys; live operator scripts depend on them. Migration
path is the whole reason the legacy regex exists.

### C. `src/streaming.ts` — `STREAM_LEGACY_EVENTS_PATH` ("/")
External SSE consumers. Removal would break running clients silently;
the code already returns a `Deprecation: true` header which is the
correct HTTP-level deprecation signal.

### D. `src/store.ts` — `legacy-pre-reset` schema state
Migration runtime state for users with older databases on disk. Removing
breaks startup for any pre-reset DB.

### E. `src/agents/types.ts` — `repoRoot` (`@deprecated` alias for `workRoot`)
Used everywhere across `src/agents/tasks/*` (40+ call sites). Active
field, not a shim. The "deprecated" annotation is misleading; agent-8
can fix the comment, but the field stays.

### F. `src/migrations/_legacy/*`
Historical migrations preserved for fresh-DB-vs-pre-reset detection
in `src/migrations/100_schema_reset.ts`.

### G. `src/agents/tasks/taint-analysis/label.ts` — legacy checkpoint format
On-disk format compat for `.kuzushi/v3/runs/*` checkpoints. Removing
invalidates any persisted operator state.

### H. `src/scanners/run-agentic.ts` — `parseAgenticOutput` / `selectAgenticFindings` /
   `computeAgenticFingerprint`
Tests + `src/scanners/agentic.ts` use them. Names are slightly legacy
but they're the only export for these operations.

### I. `src/copilot/core.ts` — `sast:*` → new-name aliases
Comment says "for one release". Removing now without a release-window
audit risks breaking saved operator scripts. Leave for an explicit
deprecation release.

### J. `src/scanners/finding-selection.ts`
Tests-only consumer; deleting it + its tests is agent-3's "unused-code"
lane, not legacy.

### K. `src/modules/threat-hunt/threat-hunt.ts` — `legacyKey` parameter
The only legacy distinction is `THREAT_HUNT_PROMPT` vs `promptOverride`,
which is a real persisted-config compatibility path. Skip.

### L. `src/agents/handoff.ts` — `getUpstreamOutput` raw/handoff dual unwrap
Active dual-shape API; both raw outputs and `TaskHandoff` are emitted by
live tasks today.

### M. `src/modules/sast/findings-bridge.ts` — comment-only "legacy"
Comments are agent-8's lane.
