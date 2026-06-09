# Code Quality — Unused Code Audit

> Historical audit — archived snapshot, not current operator guidance.

## Tooling

- `pnpm dlx knip@latest` — knip 6 with default config (`knip.json` ignores `tests/**` + `dist/**`).
- Manual cross-checks via `grep -rEn` over `src tests scripts` for every candidate
  to filter out string-based dynamic loading (`builtin:<id>`, `<moduleId>:<action>`,
  manifest entries) and tests that import directly from a sub-path while a barrel
  looks dead.

## Knip summary (truncated)

```
Unused files               56
Unused devDependencies      6  (biome/commitlint/husky/lint-staged/madge/tsx — all genuinely-used build tools, false positives)
Unlisted binaries           9  (commitlint/lint-staged/biome/husky/tsx/tsc/vitest/madge/biome — false positives)
Unused exports            283
Unused exported types     487
```

The unused-export volume is dominated by

1. **Public-API exposure on barrels** (e.g. `src/agent-runtime/index.ts`,
   `src/strategies/index.ts`, `src/copilot/dispatcher/index.ts`) — these are
   intentional library exports re-imported by external consumers (tests in
   the e2e/benchmark trees) and the published `kuzushi/...` entry points
   declared in `package.json#exports`. Trimming them risks breaking
   downstream module-authoring contracts described in `docs/modules.md`.
2. **`*Schema`/`*Z` Zod re-exports in `src/types.ts` and `src/schemas.ts`** —
   these are part of the published Kuzushi SDK surface that custom modules
   import for input validation.
3. **`__internal*` test hooks** — every `__deepSemanticHuntInternals`,
   `__systemsHelperInternals`, `__corePromptArmorInternals` etc. is
   imported by `tests/**/*.ts`, which knip ignores per `knip.json`.

So the high-confidence wins are the **whole-file unused** candidates.

## File-level audit

### Confirmed unused (deleted)

For each file, verified with `grep -rEn` over `src tests scripts` for both
`from "...<basename>..."` and the bare basename — no consumer found.

| File                                            | Reason                                                                   |
| ----------------------------------------------- | ------------------------------------------------------------------------ |
| `src/agent-runtime/context-guards.ts`           | No imports. Stale helper.                                                |
| `src/agent-runtime/error-classification.ts`     | No imports.                                                              |
| `src/agents/task-wrappers.ts`                   | `withCache` wrapper, never imported.                                     |
| `src/banner.ts`                                 | `printBanner`/`playStartupSound` only mentioned in a comment in `plain-renderer.ts`. |
| `src/copilot/index.ts`                          | Barrel re-exporting `CopilotCore`/`startShell`/`executeRun`; no importers — every consumer goes through specific files. |
| `src/copilot/local-analytics.ts`                | Stale duplicate of `recordLocalUsageEvent` in `shell.ts`.                |
| `src/crypto-behavioral/index.ts`                | Barrel; consumers import sub-files directly.                             |
| `src/hooks/index.ts`                            | Barrel; consumers import sub-files directly.                             |
| `src/invariant.ts`                              | `invariant()` helper, no callers.                                        |
| `src/scanner-cache.ts`                          | Per `docs/superpowers/specs/2026-03-25-incremental-scanning-design.md`: "fully implemented but never wired into the pipeline." Doc is design intent, not a contract. |
| `src/scanners/index.ts`                         | `createDefaultRegistry` re-export; tests import `ScannerRegistry` directly from `registry.ts`. |
| `src/scoring/prompt-versioning.ts`              | `computePromptHash` — no callers.                                        |
| `src/prompts/index.ts`                          | Barrel; nothing imports `from "...prompts/index..."`.                    |
| `src/utils/index.ts`                            | Barrel re-exporting `safe-json`; consumers import `safe-json` directly.  |
| `src/ui/components/AnimatedCounter.tsx`         | Component never mounted.                                                 |
| `src/ui/components/CompactHeader.tsx`           | Replaced by `ConfigBanner`/`SectionBox` framing.                         |
| `src/ui/components/DiffSinceView.tsx`           | Only mentioned in a `_printDiffSinceView` comment + state docstring.      |
| `src/ui/components/DiffView.tsx`                | Replaced by inline diff rendering.                                       |
| `src/ui/components/ErrorCard.tsx`               | Only mentioned in `error-format.ts` comment.                             |
| `src/ui/components/ExportActions.tsx`           | Component never mounted.                                                 |
| `src/ui/components/ProgressBar.tsx`             | `PipelineIndicator` has its own `buildStageProgressBar`.                 |
| `src/ui/components/SectionBox.tsx`              | Mentioned in tokens docstring; not imported.                             |
| `src/ui/components/StageHeader.tsx`             | `PipelineIndicator` has its own `StageHeaderLine`.                       |
| `src/ui/components/ToolRunningStatus.tsx`       | Mentioned in comments only.                                              |
| `src/ui/hooks/useCursorVisibility.ts`           | Only referenced in a docstring comment in `render.ts`.                   |
| `src/ui/hooks/useFocusTrap.ts`                  | Hook with no consumers.                                                  |
| `src/ui/primitives/Breadcrumb.tsx`              | Re-exported by primitives barrel; barrel itself is unused.               |
| `src/ui/primitives/ConfirmDialog.tsx`           | Same.                                                                    |
| `src/ui/primitives/MultilineText.tsx`           | Mentioned in `Markdown.tsx` comment only.                                |
| `src/ui/primitives/index.ts`                    | Barrel; only its own self-mention in a docstring.                        |

### Kept — knip-flagged but intentional

| File                              | Why we keep                                                                           |
| --------------------------------- | ------------------------------------------------------------------------------------- |
| `src/migrations/_legacy/*` (25)   | `src/migrations/index.ts` docstring explicitly says they live there as "historical reference". Pre-v100 user databases rely on the reset branch in `initDb()` honouring the same migration shape — deleting them would silently drop history that other code-paths consult during the bak-restore code path. |
| `src/ui/demo.tsx`                 | Whitelisted in `biome.json` and `package.json#mock-tui` shows the project ships visual-test harnesses; this is one. Documented dev tool. |
| `src/agent-runtime/index.ts` exports | Public SDK surface — module authors import `createAgentRuntimeInstance`/`ClaudeAgentRuntime`. |
| `src/types.ts` / `src/schemas.ts` re-exports | Published Kuzushi SDK surface for custom modules.                                  |
| All `__*Internals` exports        | Imported from `tests/**` which knip's `ignore` glob excludes from analysis.           |

### Unused exports / types — not removed in this pass

Knip flagged 283 exports + 487 types as unused inside otherwise-live files.
Auditing each one safely against tests (which knip ignores) and the
published-SDK contract is its own multi-hour task and risks breaking
external consumers that bind via the `kuzushi`/`kuzushi/modules`/
`kuzushi/testing` entry points declared in `package.json#exports`. We
deliberately leave these for a follow-up after a manual SDK audit.

## Verification plan

1. After each batch of file deletions: `pnpm exec tsc --noEmit`.
2. After all deletions: `pnpm test`. Baseline (pre-change) is **6 failing
   tests** in `tests/migrations/schema-reset.test.ts` (snapshot drift)
   and `tests/scanners/run-semgrep.test.ts` (timeout). Pass rate must
   not regress beyond that.
3. If any test newly breaks, restore the offending file and document
   it as a false positive.
