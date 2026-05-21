# DX-3: Lint & Format Assessment

_Scope: `/workspaces/Kuzushi` — Node 22+, TypeScript 5.7, React 18 (Ink), pnpm 10.30.0._

Status: historical pre-Rust-cutover assessment. The shipped interactive shell is
Rust Ratatui; retain Ink/React references below only as release history.

## 1. Starting state (pre-DX-3)

Before this change, Kuzushi shipped with **zero** linting or formatting
infrastructure:

| Concern             | State before DX-3                                  |
| ------------------- | -------------------------------------------------- |
| ESLint              | Not installed, no config                           |
| Prettier            | Not installed, no config                           |
| Biome               | Not installed, no config                           |
| Stylelint           | N/A — no CSS in repo                               |
| `.editorconfig`     | Missing                                            |
| Pre-commit hooks    | None (DX-5 will wire these)                        |
| Format-on-save      | No editor config checked into repo                 |
| `pnpm fix` script   | Did not exist                                      |
| Style enforcement   | Purely social (review comments, taste)             |

Concretely, 577 `.ts`/`.tsx` source files (`src/`, `tests/`, `benchmarks/`,
`perf/`) had never been processed by a unified formatter. Style drifted across
subsystems:

- Mixed `"double"` vs. `'single'` quotes in imports (dominant: double).
- Inconsistent trailing-comma usage in multiline call-sites.
- Occasional lines past 100 cols that editors had soft-wrapped.
- Inconsistent `import type` vs. runtime import splitting.
- A mix of `const`/`let` patterns where `const` would suffice.
- Occasional unused imports / dead variables.

This produced low-value review friction: style debates on PRs, "did you mean
`import type`?" nits, and inconsistent formatting from different editor
autoformatters.

**Goal of DX-3:** make auto-fix the default; remove style as a conversation
topic. `pnpm fix` is the single command devs need.

## 2. Tool choice: Biome

We selected **[Biome 2.x](https://biomejs.dev)** as the single tool for both
formatting and linting.

### Why Biome over ESLint + Prettier

| Criterion                         | Biome 2.x                           | ESLint (flat) + Prettier                 |
| --------------------------------- | ----------------------------------- | ---------------------------------------- |
| Single binary, zero plugins       | Yes (Rust)                          | No (many JS plugins)                     |
| Format **and** lint               | Yes (one command: `biome check`)    | Two tools, two configs, coordination     |
| Speed on 577 files                | Sub-second                          | Seconds to tens of seconds               |
| Sensible defaults                 | Yes (`recommended` rule set)        | Config soup; dozens of knobs             |
| Auto-fix coverage                 | Broad, safe default + `--unsafe`    | Partial — Prettier formats, ESLint fixes |
| TypeScript & React (JSX)          | First-class                         | First-class (via plugins)                |
| JSON/JSONC formatting             | Built-in                            | Prettier-only                            |
| Install footprint                 | 1 devDep                            | 5–15 devDeps (eslint, configs, plugins)  |
| Config format                     | 1 file (`biome.json`)               | 2+ files (`eslint.config.js`, `.prettierrc`) |
| Ink/React terminal-UI linting     | Covered by `a11y` opt-out + recommended | Requires `eslint-plugin-react*`          |

For a **CLI tool** (not a web app), we don't need the long-tail of
ESLint plugins. Biome's recommended ruleset covers the correctness and style
rules that matter here: `noUnusedImports`, `useImportType`, `useConst`,
`noVar`, `noExplicitAny` (as warning), `noFloatingPromises` equivalents, etc.

The trade-off is smaller plugin ecosystem. That is acceptable for Kuzushi
today; if we later need a rule Biome doesn't ship (e.g. a security-specific
check), we can layer ESLint in narrowly. Until then, fewer moving parts wins.

### Why Biome 2 specifically

- Biome 2 introduced the single-array `files.includes` syntax with negation
  (`!dist/**`), which is cleaner than the old `include`/`ignore` split.
- The `style` / `suspicious` / `correctness` rule groups are stable.
- VCS integration (`vcs.enabled` + `useIgnoreFile`) removes the need to
  duplicate `.gitignore` patterns.

## 3. Philosophy

Three principles drove rule selection:

1. **Auto-fix by default, don't bikeshed.** If a rule can't be safely
   auto-fixed, it has to earn its place. Rules that generate warnings the
   human has to resolve manually are expensive.
2. **Defer to `recommended` unless we have a concrete reason.** We don't
   pre-disable rules to "be safe"; we only disable ones that fire noisily
   on _this_ codebase or contradict the CLI's nature.
3. **Respect load-bearing project rules from `CLAUDE.md`.** In particular:
   the Ink UI rule that forbids `console.log` in `src/ui/**` is encoded as
   a lint rule — one more source of truth, enforced.

## 4. Enabled rules & deliberate opt-outs

### Enabled globally

- `linter.rules.recommended = true` — the full Biome recommended set.
- `style.useImportType = "error"` — auto-fixable. Cleanly separates runtime
  and type imports, improves tree-shaking, reduces diff churn.
- `style.useExportType = "error"` — counterpart to `useImportType`.
- `style.useNodejsImportProtocol = "error"` — forces `node:fs`, `node:path`
  etc.; the codebase is already 99% this way.
- `correctness.noUnusedImports = "error"` — auto-fixable.

### Deliberately disabled globally (with justification)

| Rule                          | Why disabled                                                                     |
| ----------------------------- | -------------------------------------------------------------------------------- |
| `style.noNonNullAssertion`    | The CLI uses `!` pragmatically (SQLite row access, Map lookups for keys we just inserted, etc.). Recommended by DX-3 brief. |
| `suspicious.noExplicitAny`    | Downgraded to `warn`. Agent runtime boundaries use structured `any` for SDK payloads; replacing wholesale is out of scope. |
| `style.useFilenamingConvention` | Mix of kebab-case and lowercase in `src/` is intentional; rule fights house style. |
| `complexity.noForEach`        | `.forEach` is used readably throughout the event bus. Not worth churning. |

### Per-path overrides

- **`src/cli.ts`, `src/report.ts`, `src/logger.ts`, `scripts/**`, `benchmarks/**`, `perf/**`, `tests/**`** — `suspicious.noConsole = "off"`.
  These are the intentional stdout/stderr surfaces of a CLI.
- **`src/ui/**`** — `suspicious.noConsole = "error"` (stays on, enforced).
  This is the load-bearing Ink rule from `CLAUDE.md`: terminal output flows
  through Ink, not raw `console.log`. Biome now enforces it.
- **`tests/**`, `benchmarks/**`, `perf/**`** —
  - `suspicious.noExplicitAny = "off"` (test fixtures / harness flexibility)
  - `style.useImportType` stays on (cheap hygiene)

### Files excluded from Biome entirely

- `node_modules/**`, `dist/**`, `coverage/**`, `.kuzushi/**`
- `**/*.generated.*` (future-proofing for DX-4)
- `benchmarks/**/repo/**` (cloned target repos used by benchmarks)
- Plus anything in `.gitignore` via `vcs.useIgnoreFile`

## 5. Formatter decisions

| Option           | Value       | Rationale                                                  |
| ---------------- | ----------- | ---------------------------------------------------------- |
| `indentStyle`    | `space`     | Matches existing codebase (all files use spaces).          |
| `indentWidth`    | `2`         | Matches existing codebase + matches `.editorconfig`.       |
| `lineWidth`      | `100`       | Reasonable for TS; the repo already largely sits at ≤100.  |
| `lineEnding`     | `lf`        | Linux/macOS/WSL consistency; Windows handled by Git + editorconfig. |
| `quoteStyle`     | `double`    | Matches dominant existing style (keeps initial diff small). |
| `semicolons`     | `always`    | Explicit > implicit for a codebase that already uses them. |
| `trailingCommas` | `all`       | Cleaner diffs on add-a-line changes. Auto-fixed everywhere. |
| `arrowParentheses` | `always`  | Consistent with `trailingCommas=all`.                      |

JSON formatter uses Biome defaults (no trailing commas in `.json`).

## 6. Commands (the `pnpm fix` default)

```bash
pnpm lint        # biome lint .
pnpm format      # biome format .
pnpm check       # biome check .             (lint + format, report only)
pnpm fix         # biome check --write .     (the default auto-fix path)
pnpm fix:unsafe  # biome check --write --unsafe .
```

**`pnpm fix` is the single command devs run.** It is safe by default. If
you want the aggressive fixes (e.g. `useImportType` rewrites that change
emit semantics in edge cases), use `pnpm fix:unsafe`.

## 7. Noise measurement (post-setup)

After running `pnpm fix` once and committing the formatting delta, we ran
`pnpm lint` on the full tree. Results are captured in the assessment
checkpoint (see commit history for `style: biome auto-fix (initial formatting)`
and the follow-up `chore: tune biome rules to reduce noise`).

Any rule that fired >10 times **and** wasn't a clear correctness win was
downgraded to `warn` or disabled, with the reason recorded in the
"Deliberately disabled globally" table above. The target was **near-zero
warnings on `pnpm lint`** after the initial auto-fix commit. Remaining
warnings are kept around only where they carry signal (e.g. `noExplicitAny`
at runtime boundaries — actionable, just not today).

## 8. TypeScript project references

As part of DX-3 we enabled **TypeScript project references** so that
`tsc -b` can build `src/`, `benchmarks/`, and `perf/` in parallel and cache
across them. Concretely:

- Root `tsconfig.json` now has `compilerOptions.composite = true` and a
  `references` array pointing at `benchmarks/tsconfig.json` and
  `perf/tsconfig.json`.
- `benchmarks/tsconfig.json` and `perf/tsconfig.json` each set
  `composite: true` and declare a reference back to the root so they can
  resolve `../src` without re-parsing the whole tree.
- `pnpm check:types` still runs `pnpm typecheck && pnpm typecheck:benchmarks`
  but each call is faster because of the shared build info cache.

This is a low-risk change — `tsc --noEmit` semantics are unchanged — and
it makes future monorepo-ification straightforward.

## 9. Gaps and follow-ups

- **Markdown & YAML formatting:** Biome does not format Markdown or YAML
  today. The repo has ~20 Markdown files (docs, READMEs) and a handful of
  GitHub YAML. Adding Prettier _just_ for these would add a second tool and
  a second config for minor gain. **Decision: not worth it now.** If
  Markdown drift becomes a recurring review topic, revisit with
  `prettier --write "**/*.{md,yml,yaml}"` wired into `pnpm fix`.
- **`noExplicitAny`:** kept at `warn`. A future pass can tighten this to
  `error` once agent-runtime boundaries are re-typed (overlaps with DX-4 /
  Zod work).
- **Pre-commit hooks:** out of scope for DX-3. DX-5 will layer
  `lint-staged` + a `pre-commit` hook that runs `biome check --staged`.
- **CI enforcement:** out of scope. DX-2 will add a `pnpm check` step to
  CI so PRs fail when `pnpm fix` wasn't run locally.

## 10. Summary for devs

- Run `pnpm fix`. That's it.
- If `pnpm fix` says "nothing to change" but `pnpm lint` still complains,
  the remaining issue is not auto-fixable — read the diagnostic and fix
  by hand or suppress with `// biome-ignore lint/...: reason`.
- Never add raw `console.log` to `src/ui/**`. Biome will refuse it.
- See `biome.json` for the source of truth.
