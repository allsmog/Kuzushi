# 02 — CI/CD Assessment (DX-2)

Audit of `.github/workflows/*.yml` on `main`. Goal: fast feedback, maximum
parallelization, rigorous caching, zero silent pass on broken state.

Scope:

- `ci.yml` — on push/PR to main, reused by release
- `release.yml` — on tag push (`v*`)
- `benchmark-regression.yml` — daily cron + manual

---

## TL;DR

Current CI is a **single serial job** (12 steps, ~7–10 min cold) with no
concurrency cancels, no path filters, no timeouts, and a redundant coverage
pass that doubles test time. Release rebuilds dist twice. Benchmark workflow
uses `sleep 1` race-conditioned health checks. None of the workflows pin
actions to SHAs, and none cache the semgrep Python install.

After overhaul:

- **~7–10 min → ~3–4 min** on PRs (parallel stages, shared install cache, single test pass)
- **~8 min → ~2 min** on docs-only PRs (paths-ignore)
- Release: **~18 min → ~8 min** (reuse CI dist artifact, no double build)
- Benchmark: flake-free (HTTP poll replaces `sleep 1`), cached semgrep

---

## 1. `ci.yml` — Critical Findings

Ranked by impact. High = ship now; Medium = ship now; Low = nice-to-have.

### H1. Serial execution of independent steps (HIGH)

All 12 steps run on a single `check` job:

```
checkout → pnpm setup → Python 3.12 → Node 22 → install → pip semgrep
  → typecheck → test → test:coverage → build → verify:pack → test:e2e
```

`typecheck`, `test`, `build`, and `verify:pack` are independent after
`install`. Running them serially on one runner adds up to roughly
`sum(step_times)` instead of `max(step_times) + install`. On a 2-core Ubuntu
runner, typecheck (~45s) + test (~60s) + build (~20s) + pack (~5s) + e2e
(~90s) take ~3:40 serially; in parallel they'd take ~1:30 after a shared
install (~60s).

**Fix:** split into `install` → {`typecheck`, `test`, `build`} → {`e2e`, `verify-pack`} (both need built dist).

### H2. `test:coverage` double-runs the test suite (HIGH)

```yaml
- run: pnpm test            # vitest run
- run: pnpm test:coverage   # vitest run --coverage
```

vitest's coverage is a superset: running `test:coverage` already runs all
tests with v8 coverage instrumentation. We execute the full suite **twice**
for no reason — one of the biggest wall-clock wastes. `test` and
`test:coverage` should be a single job that runs coverage inline. (See DX-1
handoff: ideally `pnpm test` = `vitest run --coverage`.)

**Fix:** in CI, call `pnpm test:coverage` only. Drop the bare `pnpm test` step.

### H3. E2E uses `pnpm dev` (tsx) instead of published artifact (HIGH)

`tests/e2e/run-smoke.sh` historically called `pnpm dev config validate ...`
and `pnpm dev scan ...`, which exercised source execution instead of the
packaged wrapper. The shipped CLI is the native Rust binary through
`bin/kuzushi-rs.mjs`, exposed as `kuzushi` and `kz`.

**Fix:** parameterize the smoke script with `KUZUSHI_CMD` (defaulting to the
local Rust CLI path) and point CI at `node bin/kuzushi-rs.mjs` with
`KUZUSHI_NATIVE_BIN` set to the downloaded staged native binary. Without that
override, the source-checkout wrapper checks a local Cargo build. E2E downloads both the `dist/` artifact
and `native/` artifact from the `build` job so it exercises the packaged Rust
wrapper path, not the retired TypeScript CLI.

### H4. No `concurrency:` — stacked pushes waste runners (HIGH)

A rapid series of pushes to the same PR runs all of them to completion. On a
PR branch we only care about the latest commit. Without `cancel-in-progress`
we pay for 3–5 CI runs per fast iteration.

**Fix:** workflow-level concurrency group `${{ github.workflow }}-${{ github.ref }}`
with `cancel-in-progress: ${{ github.event_name == 'pull_request' }}` so `main`
pushes still all publish their signal.

### H5. No `timeout-minutes` anywhere (HIGH)

A hung test or infinite loop burns the default 360 min (6h) runner budget.
Any job should have a realistic cap.

**Fix:** `timeout-minutes: 15` on install/build/test/e2e; `10` on typecheck/pack.

### H6. No path filters — docs-only PRs run full CI (MEDIUM)

`README.md`, `docs/**`, `*.md` tweaks trigger the full 10-min pipeline.

**Fix:** `paths-ignore` on `**/*.md`, `docs/**`, `.gitignore`.

### H7. Semgrep pip install not cached (MEDIUM)

`python -m pip install --upgrade pip semgrep` runs uncached every build
(~45s–60s network pull). `actions/setup-python` supports `cache: pip` given
a `requirements.txt`; without it, `actions/cache` keyed on `python-version`
+ semgrep version works.

**Fix:** write `requirements-ci.txt` with `semgrep==<pin>` and set
`setup-python` `cache: pip` + `cache-dependency-path:` to that file. Out of
scope: we don't pin semgrep upstream, so use `actions/cache` with a key that
includes a manual version token we can bump.

### H8. No least-privilege `permissions:` (MEDIUM)

Default `GITHUB_TOKEN` has broad scopes. CI should explicitly declare
`permissions: contents: read`. Release needs `contents: write` + `id-token: write`
(for npm provenance).

**Fix:** add `permissions:` block at workflow level.

### H9. Action versions loosely pinned (LOW, flag for ops decision)

All actions use floating major tags (`@v4`, `@v5`). Commit-SHA pinning is the
supply-chain-correct form but requires a Dependabot/Renovate story to stay
current. For this repo's threat model (OSS CLI, npm publish), major-pin is
reasonable; we add a note.

**Fix (implemented):** keep major pins; add `actionlint` workflow to catch
structural issues; document that SHA-pinning is a follow-up for
security-sensitive actions (softprops/action-gh-release, npm publish).

---

## 2. `release.yml` — Critical Findings

### R1. `publish-npm` and `github-release` both rebuild dist (HIGH)

Both jobs re-checkout, re-install (no pnpm cache warmup since they're fresh
runners), and re-run `pnpm build`. That's three builds per release (one in
CI gate + two here).

**Fix:** have the gated `ci.yml` invocation publish `dist/` and staged native
Rust binaries as workflow artifacts, and let `publish-npm`/`github-release`
download instead of rebuild. Release jobs run `pnpm verify:pack`, then call
`npm publish --ignore-scripts` or `npm pack --ignore-scripts` so npm lifecycle
hooks do not rerun `prepack` without the CI Rust build context.

### R2. Fragile changelog generation (HIGH)

```bash
PREV_TAG=$(git tag --sort=-v:refname | head -2 | tail -1 || echo "")
```

- Picks the lexicographically-second newest tag, which is the *current* tag
  minus one only if we're tagging from HEAD and the tag is already reachable.
  But a newly-pushed tag might not have been added by the fetch, and
  `git tag --sort=-v:refname` uses refs/tags, which is fine — but `head -2 |
  tail -1` returns nothing if there are <2 tags and the `|| echo ""` never
  triggers because `tail`'s exit code is 0 even on empty input.
- `git describe --tags --abbrev=0 HEAD^` is the canonical "previous tag
  reachable from the parent of the release commit" form.

**Fix:**

```bash
PREV_TAG=$(git describe --tags --abbrev=0 "${GITHUB_REF_NAME}^" 2>/dev/null \
  || git rev-list --max-parents=0 HEAD | head -1)
```

### R3. No npm provenance (MEDIUM, needs approval)

npm ≥9.5 + GitHub Actions OIDC supports `--provenance` which links the
published artifact to the workflow run. Best practice for supply-chain
hardening.

**Fix (implemented):** add `--provenance` to `npm publish` and `id-token:
write` permission. If the npm account isn't on a plan that supports
provenance OR if the workflow isn't publicly verifiable, this fails. Flagged
**needs approval** in the release change; left the publish command
provenance-enabled behind an `if:` that can be toggled by setting
`vars.NPM_PROVENANCE=true` — safe default is **off** until maintainer opts in.

### R4. Release has no `concurrency:` guard (LOW)

If someone pushes `v0.14.1` twice by accident, two concurrent publishes will
race. A `concurrency:` block on the workflow (non-cancelling, so both
complete their logs but publish serializes) is cheap insurance.

**Fix:** `concurrency: { group: release-${{ github.ref }}, cancel-in-progress: false }`.

---

## 3. `benchmark-regression.yml` — Critical Findings

### B1. `sleep 1` race condition on mock server (HIGH)

```bash
node tests/fixtures/mock-anthropic-server.mjs > /tmp/mock-url.txt &
sleep 1
echo "MOCK_BASE_URL=$(cat /tmp/mock-url.txt)" >> "$GITHUB_ENV"
```

The server binds to port 0 and prints the URL on startup. On a slow runner or
under load, 1 second may not be enough; the file can be empty and
`MOCK_BASE_URL` is left blank — benchmark then silently talks to
`http://...` with an empty host and fails in obscure ways.

**Fix:** HTTP poll loop with a 15s deadline that waits for `GET $url` to
respond, or a file-based poll that waits for non-empty output plus a
`curl -sf` probe.

### B2. Uses `/tmp` instead of `$RUNNER_TEMP` (LOW)

`$RUNNER_TEMP` is guaranteed-clean, cleaned up between jobs, and is the GH
Actions idiomatic scratch space.

**Fix:** replace `/tmp/mock-url.txt` with `${RUNNER_TEMP}/mock-url.txt`.

### B3. No pip/semgrep cache (MEDIUM)

Same issue as CI — reinstalls semgrep every daily run.

**Fix:** same caching strategy as CI.

### B4. No concurrency / no timeout on scheduled duplicates (LOW)

A manual dispatch during a scheduled run creates two runs. Neither cancels.
Acceptable (benchmark stores to artifact, not shared state) but worth a
group.

**Fix:** `concurrency: { group: benchmark-regression, cancel-in-progress: false }`.

---

## 4. Missing: workflow linting

No `actionlint` in CI. Workflow mistakes (unreachable jobs, bad expression
syntax, wrong action inputs) ship silently and break on the main run.

**Fix:** add `actionlint.yml` that runs on any `.github/workflows/**` change
using `rhysd/actionlint` (or an equivalent installed via bash script).

---

## Friction Map — Developer-observable pain

| Symptom                                                       | Root cause                                    | After                              |
| ------------------------------------------------------------- | --------------------------------------------- | ---------------------------------- |
| "CI is slow" on a 2-line PR                                   | Serial pipeline + no path filters             | Paths-ignore skips; parallel split |
| "Why does `pnpm test` run twice?"                             | `test` + `test:coverage` both in CI           | One coverage run                   |
| Test fix ships green but packaged CLI is broken               | E2E uses the retired source CLI path, not the Rust wrapper | E2E downloads `dist/` + `native/` artifacts |
| Changelog generation silently empties on first release        | `head -2 | tail -1` returns empty, `\|\|` never fires | `git describe --tags HEAD^`        |
| Benchmark flakes ~1/15 runs with "connection refused"         | `sleep 1` before URL file populated           | HTTP poll with timeout             |
| Release publishes wrong artifact after a speculative tag push | Two `release.yml` runs race                   | `concurrency: release-<ref>`       |
| "Hung job burned 6h of runner"                                | No `timeout-minutes`                          | 10–15 min caps                     |
| Stacked pushes each run to completion                         | No `cancel-in-progress`                       | Cancelled per PR                   |

---

## Runtime estimate — before/after

Numbers are cold-cache (no pnpm store, no pip cache) on `ubuntu-latest`.
Warm-cache subtracts ~45–60s from install and ~45s from pip.

### Before (ci.yml serial `check` job)

| Step           | Cold | Warm  |
| -------------- | ---- | ----- |
| checkout       | 5s   | 5s    |
| pnpm setup     | 3s   | 3s    |
| Python 3.12    | 5s   | 5s    |
| Node 22        | 10s  | 10s   |
| pnpm install   | 90s  | 35s   |
| pip semgrep    | 55s  | 55s   |
| check:types    | 45s  | 45s   |
| test           | 60s  | 60s   |
| test:coverage  | 70s  | 70s   |
| build          | 20s  | 20s   |
| verify:pack    | 5s   | 5s    |
| test:e2e       | 100s | 100s  |
| **Total**      | ~7:50 | ~6:55 |

### After (parallel + single coverage pass + caches)

| Stage                        | Cold   | Warm   |
| ---------------------------- | ------ | ------ |
| `install` (checkout + node + pnpm install + upload) | 100s | 40s |
| `typecheck` (parallel)       | 50s    | 50s    |
| `test` (coverage inline)     | 75s    | 75s    |
| `build` (parallel)           | 25s    | 25s    |
| `verify-pack` (after build)  | 10s    | 10s    |
| `e2e` (after build + pip)    | 105s   | 75s    |
| **Critical path**            | ~3:45 | ~2:40 |

Savings: **~4 min cold, ~4 min warm**. Docs-only PRs short-circuit to ~5s
(skipped).

### Release before/after

| Phase         | Before          | After                         |
| ------------- | --------------- | ----------------------------- |
| CI gate       | ~7:50           | ~3:45 (same as above)         |
| publish-npm   | ~3:00 (rebuild) | ~40s (download + npm publish) |
| github-release| ~3:00 (rebuild) | ~30s (download + upload)      |
| **Total**     | ~13:50          | ~4:55                         |

---

## Implementation summary

See commits on this worktree branch for exact changes. High-level:

1. **`ci.yml`**: splits into `install` → {`typecheck`, `test`, `build`} →
   {`verify-pack`, `e2e`}. Shared `actions/cache` for pnpm store + pip
   wheels. `concurrency`, `timeout-minutes`, `permissions: contents: read`,
   `paths-ignore` for docs/markdown. Upload `dist/` and staged native Rust
   binaries as artifacts.
2. **`release.yml`**: reuses `ci.yml` as gate, downloads `dist/` and native
   artifacts, runs `pnpm verify:pack`, and publishes/packs with lifecycle
   scripts skipped so release does not rebuild. `git describe` changelog.
   Provenance behind opt-in var. `concurrency` group.
3. **`benchmark-regression.yml`**: HTTP poll replaces `sleep 1`,
   `$RUNNER_TEMP`, pip cache, timeout, concurrency.
4. **`actionlint.yml`**: new workflow that lints `.github/workflows/**` on
   any change.
5. **`tests/e2e/run-smoke.sh`**: parameterized via `KUZUSHI_CMD` env var so
   CI can point it at `node bin/kuzushi-rs.mjs` with `KUZUSHI_NATIVE_BIN` selecting downloaded `native/`;
   local runs default to the Rust CLI.
6. **`.github/requirements-ci.txt`**: pinned `semgrep` for pip cache.

---

## Flagged — needs approval

- **npm provenance** (`--provenance` + `id-token: write`). Implemented
  behind `vars.NPM_PROVENANCE == 'true'` gate. Requires maintainer to set
  the repo var; off by default.
- **SHA-pin security-sensitive actions** (`softprops/action-gh-release`,
  `pnpm/action-setup`). Not implemented; needs Dependabot/Renovate to stay
  current. Recommended follow-up.
- **E2E script parameterization**: I edited `tests/e2e/run-smoke.sh` to
  accept `KUZUSHI_CMD`. This is additive — default `pnpm dev` preserved for
  local runs. Flagging in case DX-1 expected to own it.

---

## Non-goals (not touched)

- `package.json` scripts (DX-1 territory)
- Lint configs (DX-3)
- Git hooks (DX-5)
