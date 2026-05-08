# Kuzushi enhancements — remaining work

Historical/retired planning note. This file predates the Rust cutover cleanup
and is retained as reference material, not current operator guidance.

Branch: `claude/kuzushi-enhancements-307jX`.
Plan file: `/root/.claude/plans/take-a-look-at-logical-nova.md`.

## Status

| Phase | Module / piece | State | Commit |
| --- | --- | --- | --- |
| A | `variant-hunter` module + tests | done | `3965726` |
| B.1 | `src/intel/cve-feed.ts` + `n-day-patterns` knowledge | done | `f72f06a` |
| B.2 | `n-day-diff-hunter` module + tests | done | `b28fb40` |
| C scaffold | `parser-attack-surface` knowledge, `src/fuzz/{sandbox,runners,crashes}.ts` + tests | done | `cd687c9` |
| **C.4** | `src/modules/fuzz-forge.ts` — the module itself (5 tools) | **pending** | — |
| **C.5** | fuzz-forge module tests + fixture fuzz targets | **pending** | — |
| **D** | `exploit-primitive` module + tests | **pending** | — |
| — | final typecheck + full-suite test + commit + push | **pending** | — |

Total code so far: 2,899 lines of source + 1,180 lines of tests across 4 commits. 55 new tests, all passing. Typecheck clean. Two pre-existing environmental test failures in `tests/analysis-support/simple-index.test.ts` (git-signing server) are unrelated.

## What's left — in build order

### 1. `src/modules/fuzz-forge.ts` (the headline module)

Implements five tools using the scaffolding we already shipped:

| Tool | headless | Backing scaffolding |
| --- | --- | --- |
| `fuzz:map-attack-surface` | true | `parserAttackSurfaceModule` knowledge to prime the prompt; LLM reads source, emits ranked list of `{ entryFn, fileLoc, inputContract, complexityScore, untrustedInputPath }`. |
| `fuzz:synthesize-harness` | true | Language-specific prompt templates mirroring `pocHarnessSystemPromptPrefix` (anti-hallucination: real imports only, skip with reason when not isolatable). Calls `findRunnersForLanguage` to pick the runner and returns `{ harness_path, build_cmd, run_cmd, language, dictionary?, seed_corpus_strategy, skipped, skip_reason }`. |
| `fuzz:build-corpus` | true | LLM reads constants/magic bytes from source, emits N seed files + libFuzzer dictionary. |
| `fuzz:run` | **false** (needs approval) | `runner.buildRunPlan()` → `sandboxExec()`. Enforce `maxBudgetUsd`, wall-clock cap, refuse when `backend === "plain"` unless `allowUnsandboxed: true` is explicit. |
| `fuzz:triage-crashes` | true | `collectUniqueCrashes()` first (FREE), then parallel LLM classification (reuse the 5-concurrent semaphore in `claude.ts`) that emits Findings conforming to `src/scanners/normalize-findings.ts`. Feed into existing `triage.ts`. |

Module factory `createFuzzForgeModule()`. Wire into `src/copilot/core.ts` under `case "fuzz-forge":` and export from `src/modules/index.ts`.

Budget/safety: per-campaign `maxBudgetUsd`, wall-clock cap, stack-hash dedup before any LLM call, rate-limited triage queue. `fuzz:run` must stay `headless: false`.

### 2. Phase C tests + fixture targets

- `tests/modules/fuzz-forge.test.ts` — unit tests mocking the runtime (mirror `variant-hunter`/`n-day-diff-hunter` test style). Assert each tool surface, mapping of LLM output → Finding, sandbox backend refusal path.
- `tests/fixtures/fuzz-targets/` — minimal vulnerable fixtures (one per language) so a Phase-C end-to-end run can actually trigger a crash:
  - `c-parser/` (C with a planted off-by-one)
  - `go-parser/` (Go varint with a planted overflow)
  - `rust-parser/` (Rust panic on oversized length)
  - `js-parser/` (JS JSON-like parser with prototype pollution)
  - `py-parser/` (Python unpickle with untrusted input)
- End-to-end smoke test (skipped on CI when toolchains missing) that runs attack-surface-map → harness-synth → short campaign against a fixture and verifies at least one Finding emits.

### 3. Phase D — `src/modules/exploit-primitive.ts`

Depends on the crash outputs from Phase C. Two tools:

- `primitive:classify` — input `{ crashPath, harnessPath }`; LLM inspects the crash (optionally running `gdb`/`lldb` via sandboxExec) and returns `{ primitive: "OOB-W"|"UAF"|"type-confusion"|..., controlSurface, attackerControlScore }`.
- `primitive:chain-suggest` — takes a classified primitive and proposes a chain (info leak → ASLR bypass → arb-write). Output is a reasoning trace; not required to be actually exploitable.

Extend `src/poc-harness.ts` with `mode: "observation" | "primitive"` switch so the existing harness pipeline handles both source-level taint observability and native-crash primitive classification.

New knowledge module `src/knowledge/modules/exploit-primitives.ts` (OOB categories, UAF → type-confusion bridges, heap grooming hints) — follow the same shape as `parser-attack-surface`.

Tasks: `primitive-classify` (dependsOn `fuzz-crash-triage`), `primitive-chain` (dependsOn `primitive-classify`, outputKind `report`).

Tests: fixture crash files with known primitives + deterministic classifier mock; assert the chain output schema.

### 4. Final validation

- `pnpm typecheck`
- `pnpm test` — confirm the 55 new tests stay green alongside the pre-existing 1621 and note the 2 env-related failures are unchanged.
- Commit message template mirrors prior commits (`feat(modules): ...`).
- Push to `claude/kuzushi-enhancements-307jX`. Do NOT push to `main` and do NOT open a PR without explicit user confirmation.

## Known constraints / deferred decisions

1. **Real sandbox on the host**: `sandboxExec` falls through to `plain` when `bwrap`/`podman` are missing. `fuzz:run` must refuse `plain` by default (callers opt-in via `allowUnsandboxed: true`) so this ships safely even in bare dev environments.
2. **Dict/corpus storage**: plan says repo-local `<repo>/.kuzushi/fuzz-corpus/` — do that first; document in CLAUDE.md if it lands.
3. **MCP surface for fuzz-forge tools**: defer to a follow-up.
4. **Running fuzz-forge as a pipeline task (not just tools)**: the `AgentTask` DAG wiring (C.4 in the original plan) can be added later — the module-tool surface is enough to validate the approach first.
5. **Approval gating**: existing `ModuleTool.headless = false` path already forces confirmation in run/pipeline modes. Follow that pattern for `fuzz:run` and `primitive:classify` (when it runs a debugger).

## Quick-start for the next pickup

```bash
git fetch origin claude/kuzushi-enhancements-307jX
git switch claude/kuzushi-enhancements-307jX
pnpm install
pnpm typecheck
pnpm vitest run tests/modules tests/fuzz tests/intel   # 55 tests, all green

# Start with:
#   src/modules/fuzz-forge.ts
# Wire into:
#   src/modules/index.ts
#   src/copilot/core.ts (loadBuiltinModule switch)
# Add tests:
#   tests/modules/fuzz-forge.test.ts
```

The existing `src/modules/variant-hunter.ts` is the closest stylistic template; `src/modules/n-day-diff-hunter.ts` is the closest functional template (same tool count, JSON-schema outputs, resolveRepo usage). Mirror both.
