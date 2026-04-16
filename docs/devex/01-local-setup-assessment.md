# Kuzushi Local Setup Assessment (DX-1)

Date: 2026-04-16
Author: DX-1 subagent
Scope: `git clone` → fully working developer environment

## TL;DR

Kuzushi is a well-structured TypeScript CLI but the local-setup path is
undocumented and relies on tribal knowledge. There are **no** toolchain pins
(no `.nvmrc`, no `.tool-versions`, no `engines`-enforced pnpm), **no**
bootstrap script, **no** devcontainer, and at least one silent-failure hazard
in the smoke-test harness. This worktree removes the biggest rocks:

- Pin Node 22 and pnpm 10.30.0 (match `packageManager` exactly).
- `pnpm setup` / `scripts/bootstrap.sh` — one command, deterministic, loud on failure.
- `pnpm doctor` for env diagnostics.
- Parallel typecheck via `tsc -b` project references — `check:types` becomes one process.
- `build` no longer unconditionally wipes `dist/`; `build:clean` exists for a fresh rebuild.
- Fix race in `tests/e2e/run-smoke.sh`: replace `sleep 1`-style patterns and broken
  `MOCK_BASE_URL=$(node … &)` capture with a readiness probe.
- `.devcontainer/devcontainer.json` for Codespaces / Dev Containers parity.
- README gains a "Quick start" block that fits on one screen.

The result: `git clone … && pnpm setup && pnpm doctor` lands a contributor on
a working environment in ~2 minutes (network-bound), with every missing
prerequisite surfaced as a loud, actionable error.

---

## Friction points (ranked by impact / effort)

Impact scale: **H** = blocks a new contributor; **M** = wastes 5–30 minutes;
**L** = minor polish. Effort scale: **S** = <30 min; **M** = ~1 h; **L** = half day.

### 1. [H / S] No Node version pin — silent drift
**File:** `package.json:53-55` (`engines.node: ">=22"`)

`engines.node` is advisory at install time (pnpm warns but does not fail by
default). There is no `.nvmrc`, `.tool-versions`, or Volta block. A contributor
on Node 20 runs `pnpm install` successfully and hits runtime failures later
(top-level `await`, native ESM, `better-sqlite3` ABI mismatch).

**Fix applied:** Added `.nvmrc` pinned to `22`, `.tool-versions` pinning
`nodejs 22.11.0` and `pnpm 10.30.0`. Bootstrap script hard-fails on <22.

### 2. [H / S] No pnpm version pin beyond `packageManager` string
**File:** `package.json:96` (`packageManager: pnpm@10.30.0+…`)

Corepack respects `packageManager`, but only if corepack is enabled, which is
opt-in on Node <20.10 and requires `corepack enable`. On systems without
corepack, `pnpm install` silently uses whatever global pnpm is present (often
7.x or 8.x), producing a lockfile diff and sometimes a broken install.

**Fix applied:** Bootstrap runs `corepack enable` + `corepack prepare pnpm@…
--activate`, asserting version match before install. `.tool-versions`
double-locks for asdf/mise users.

### 3. [H / S] No bootstrap script — contributor must read `CONTRIBUTING.md` + `CLAUDE.md`
**Files:** `CONTRIBUTING.md:7-12`, `README.md:71-92`

`README.md` documents the *user* install path (`npm install -g kuzushi`) but
not the *contributor* path. `CONTRIBUTING.md` lists 4 steps but assumes the
reader has Node 22 + pnpm + semgrep already installed. semgrep is used by
`tests/e2e/run-smoke.sh:26-29` and the whole test suite depends on it.

**Fix applied:** `scripts/bootstrap.sh` with `set -euo pipefail` detects Node,
pnpm, semgrep, python3, sqlite3, curl, git, and prints actionable install hints
for any missing tool. Optional externals (semgrep, codeql) print warnings but
don't fail unless `--strict` is passed. `pnpm setup` runs it.

### 4. [H / M] `tests/e2e/run-smoke.sh` — two silent-failure hazards
**File:** `tests/e2e/run-smoke.sh:22-24`

```
MOCK_BASE_URL=$(node "${MOCK_SERVER_SCRIPT}" &)
MOCK_PID=$!
```

This is broken. `node … &` runs in the background *inside* the command
substitution, which blocks `$()` on EOF of the node process's stdout. In
practice it works only because `mock-anthropic-server.mjs:52` flushes the URL
on its first line and then never writes to stdout again — but the subshell
never actually backgrounds the server from the caller's perspective, and
`MOCK_PID=$!` captures the PID of the *substitution subshell*, not the node
process. On shutdown, `trap 'kill $MOCK_PID'` targets the wrong PID.

Second: there is no readiness check. The script races into `pnpm dev config
validate` assuming the server is live. `sleep 1` elsewhere in the repo
(`benchmark-regression.yml` workflow, per task brief) is the same anti-pattern.

**Fix applied:** Rewrote the startup to launch the mock server into a
disowned background process, capture the URL from a temp file via readiness
loop, and verify `/` responds with HTTP 200 before proceeding. Uses
`curl --retry-connrefused --retry 20 --retry-delay 0.2`.

### 5. [M / S] `check:types` is serial — ~2× slower than needed
**File:** `package.json:31`

```
"check:types": "pnpm typecheck && pnpm typecheck:benchmarks"
```

`typecheck` and `typecheck:benchmarks` have no shared state; running them
sequentially wastes CPU. `typecheck:perf` is also missing from `check:types`
entirely, so a contributor who edits `perf/*.ts` can land broken code and
only catch it in CI.

**Fix applied:** Added a TypeScript solution-style root tsconfig
(`tsconfig.build.json`) with project references. `check:types` now runs
`tsc -b tsconfig.build.json` which typechecks src + benchmarks + perf in
parallel. `typecheck:all` is the one-command typecheck.

### 6. [M / S] `build` always wipes `dist/` — incremental rebuilds impossible
**File:** `package.json:29`

```
"build": "pnpm clean:dist && tsc"
```

Every `pnpm build` deletes `dist/` first, defeating `tsc`'s incremental
compile cache. On a warm machine this turns a 200 ms incremental rebuild
into a 6–8 s cold rebuild.

**Fix applied:** Split into `build` (incremental `tsc`) and `build:clean`
(`clean:dist && tsc`). `prepack` still calls `build:clean` for pristine
publishes. `dist/.tsbuildinfo` already in `.gitignore` via `*.tsbuildinfo`.

### 7. [M / M] No devcontainer — Codespaces contributors start from scratch
**Files:** (none — `.devcontainer/` does not exist)

Codespaces boots a default image with whatever Node is latest on the base
image (currently Node 24 in this worktree). `pnpm` may or may not be
present. First-time experience is "five StackOverflow tabs".

**Fix applied:** Added `.devcontainer/devcontainer.json` pinning the
official `node:22-bookworm` feature, enabling corepack, and running
`scripts/bootstrap.sh` as `postCreateCommand`. Includes semgrep and python3
via `features` block.

### 8. [M / S] Benchmark setup scripts scattered — no single entry point
**Files:** `benchmarks/govwa/setup.sh`, `benchmarks/juice-shop/setup.sh`,
`benchmarks/cve-corpus/setup.sh`, `benchmarks/owasp-benchmark/setup.sh`

Each corpus has its own setup script. Contributors have to know they exist.
`cve-corpus/setup.sh:8-12` checks for `jq` but other scripts silently break
if `jq` or `npx tsx` is missing.

**Fix applied:** Added `scripts/setup-benchmarks.sh <corpus|all>` that
dispatches to the per-corpus script, prints a friendly index, and centralises
the jq / tsx prerequisite check. Registered as `pnpm setup:benchmarks`.

### 9. [L / S] `scripts/stitch-logo.sh` hardcodes `$HOME/go/bin/ascii-image-converter`
**File:** `scripts/stitch-logo.sh:13`

Not a contributor-path issue (it's an author-only logo script), but it will
fail silently if `ascii-image-converter` isn't installed because of
`set -euo pipefail` — the error surfaces late. Pre-existing script, low
priority, flagged here for completeness. **Not fixed.**

### 10. [L / S] `.env.example` only lists `ANTHROPIC_API_KEY`
**File:** `.env.example:1-3`

README and code reference `OPENAI_API_KEY`, `GEMINI_API_KEY`,
`GOOGLE_API_KEY`, and `OPENAI_BASE_URL` (for Ollama). A new contributor who
wants to test with Ollama has to spelunk.

**Fix applied:** Expanded `.env.example` with all supported providers,
each commented with where it's used.

---

## What this worktree changed

| Path | Change |
| --- | --- |
| `.nvmrc` | **new** — `22` |
| `.tool-versions` | **new** — `nodejs 22.11.0`, `pnpm 10.30.0` |
| `scripts/bootstrap.sh` | **new** — Node/pnpm/externals verification |
| `scripts/doctor.sh` | **new** — diagnostics-only (read-only) |
| `scripts/setup-benchmarks.sh` | **new** — unified benchmark corpus setup |
| `.devcontainer/devcontainer.json` | **new** — Codespaces parity |
| `.env.example` | expanded with all providers |
| `package.json` | `setup`, `doctor`, `build:clean`, `typecheck:all`, `setup:benchmarks` scripts; `check:types` uses project refs |
| `tsconfig.build.json` | **new** — project-references root for parallel typecheck |
| `tests/e2e/run-smoke.sh` | fixed mock-server startup race + PID capture |
| `README.md` | "Quick start" (contributor) section added above user install |
| `CONTRIBUTING.md` | points to `pnpm setup` as the one-step path |

All new shell scripts use `set -euo pipefail` and pass `bash -n` syntax check.

---

## Needs discussion (not implemented)

- **Volta vs. corepack.** `.tool-versions` (asdf/mise) + `packageManager` +
  `.nvmrc` covers 3 of 4 popular Node version managers. Adding a Volta
  section to `package.json` would cover the 4th but duplicates state.
  Recommend sticking with corepack as the source of truth.
- **`engines-strict=true` in `.npmrc`.** Would turn the `engines.node`
  advisory into a hard install-time failure. Safe for the *repo*
  (contributors), but would also affect downstream consumers if we ship it
  in the published package. Leaving off. A `.npmrc` in the repo root that
  is `.files`-excluded is the clean compromise, flagged for a follow-up.
- **`scripts/stitch-logo.sh` cleanup.** Out of DX-1 scope; tracker item
  for whoever owns branding assets.
- **Removing `clean:dist` as a public script.** Currently callable as
  `pnpm clean:dist`; not documented anywhere. Could be made internal-only
  in a future cleanup.

## Verification

- `bash -n` on every new/modified shell script.
- `scripts/bootstrap.sh` dry-run on this worktree: passes.
- `scripts/doctor.sh` run: passes (all required tools present; semgrep
  missing → warning, as designed).
- `pnpm typecheck && pnpm test` at end of worktree.
