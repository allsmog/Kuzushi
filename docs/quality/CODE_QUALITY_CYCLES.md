# Circular Dependency Assessment — Kuzushi

> Historical audit — archived snapshot, not current operator guidance.

**Date:** 2026-04-30
**Branch:** `worktree-agent-a79b220e0c30fe3db`
**Tool:** `madge` (v8.x via `npx --yes madge`)
**Tree state at audit:** clean, on top of `4f32704 feat: scan resume, SAST task selection, model validation, TUI options view`

## TL;DR

**There are zero circular dependencies in `src/`.** Both the
plain `--circular` run and the tsconfig-aware run agree.

```
$ npx madge --circular --extensions ts,tsx src/
- Finding files
Processed 640 files (7.4s) (13 warnings)
✔ No circular dependency found!

$ node_modules/.bin/madge --circular --extensions ts,tsx --ts-config tsconfig.json src/
Processed 640 files (9.7s) (2 warnings)
✔ No circular dependency found!
```

No remediation work was required. With deps uninstalled madge reports
13 warnings (NodeNext `.js` import-extension quirk for missing
type-resolution); after `pnpm install` that drops to 2. Neither count
masks a cycle: madge still walks both directions of the import graph
and reports graph-internal cycles regardless of unresolved leaf edges.

## What was checked

- `npx --yes madge --circular --extensions ts,tsx src/`
- `npx --yes madge --circular --extensions ts,tsx --ts-config tsconfig.json src/`
- `npx --yes madge --warning --extensions ts,tsx src/` for orphan/skip info

## Hot zones inspected (per CLAUDE.md guidance)

The CLAUDE.md guide flagged the following as the most likely cycle
hosts. All were confirmed clean by madge:

- `src/modules/types.ts` ↔ `src/modules/host-handles.ts` — no cycle.
- `src/copilot/core.ts` ↔ `src/modules/registry.ts` — no cycle.
- `src/agents/index.ts` (DAG bootstrap) ↔ `src/modules/dag-registry.ts` —
  no cycle.
- `src/agent-runtime/enforcement.ts` ↔ `src/agent-runtime/{claude,
  pi-ai, codex}.ts` — no cycle (single-direction: adapters import
  enforcement, not vice versa).
- Shell ↔ UI state (`src/ui/state.ts`, `src/copilot/shell.ts`,
  `src/ui/components/*`) — no cycle.

## Cycle list

_None._

## Do / Skip list

| Action | Decision | Reason |
| --- | --- | --- |
| Break cycles | _Skip_ | None exist. |
| Convert eager imports to `import type` | _Skip_ | Not motivated by a cycle; would be churn-only. |
| Extract shared-types leaf modules | _Skip_ | Already done where needed (`src/modules/types.ts`, `src/modules/host-handles.ts`, `src/agent-runtime/types.ts`). |
| Resolve madge's 13 skip warnings | _Skip_ | Tooling artefact (NodeNext `.js` extensions); not a code-quality issue and does not mask cycles. |

## Confidence

- Cycle-freeness: **high.** Two independent madge invocations (with
  and without tsconfig path resolution) over 640 files agree.
- Skipped-file false-negative risk: **low.** A cycle would have to live
  entirely among the 13 skipped files to evade madge — implausible
  given those files are scattered leaf imports, not a tightly coupled
  cluster.

## Recommendation

No changes to the dependency graph are warranted. The module-system
discipline encoded in CLAUDE.md (narrow `host-handles.ts`, leaf
`types.ts`, single-direction enforcement boundary) is being respected
in practice.
