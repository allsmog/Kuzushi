# Claude Remote Merge Progress

Start: 2026-05-06
Base branch: `main`
Base commit: `c4521210`

## Start Checks

- `git status --short --branch`: clean, `## main...origin/main`
- `git fetch --prune origin`: completed; repository reported existing `.git/gc.log` / unreachable loose-object warning
- `git pull --ff-only`: already up to date

Iteration 2 refresh:

- `git status --short --branch`: clean, `## main...origin/main`
- `git fetch --prune origin`: completed; updated `origin/claude/agentic-security-pipeline` and `origin/claude/ratatui-design-views`; repository again reported existing `.git/gc.log` / unreachable loose-object warning
- `git pull --ff-only`: already up to date
- Current `main`: `c4521210`
- Note: original checkout Git metadata cannot create `ORIG_HEAD.lock` or object temporary files, so merges and commits are performed in writable local clone `/private/tmp/kuzushi-claude-merge-work` seeded from the same fetched refs.

## Authoritative Unmerged Branch Inventory

Recomputed with:

```sh
git branch -r --no-merged main | sed 's/^ *//' | rg '^origin/claude/'
```

- `origin/claude/implement-index-html-zkHMO`
- `origin/claude/ratatui-design-views`
- `origin/claude/diagnose-rust-tui-ux-M8ycq`
- `origin/claude/check-ratatui-tui-Jj2eH`
- `origin/claude/vercel-security-harness-comparison-YQKnA`
- `origin/claude/agentic-security-pipeline`

## Planned Merge Order

1. `origin/claude/implement-index-html-zkHMO`
2. `origin/claude/ratatui-design-views`
3. `origin/claude/diagnose-rust-tui-ux-M8ycq`
4. `origin/claude/check-ratatui-tui-Jj2eH`
5. `origin/claude/vercel-security-harness-comparison-YQKnA`
6. `origin/claude/agentic-security-pipeline`

## Branch Notes

### `origin/claude/implement-index-html-zkHMO`

- Status: integrated in commit `62dd986c` (`merge: integrate implement-index-html-zkHMO`)
- Commits: `705e592c design: add Ratatui shell TUI mockups`
- Scope: adds static React design/mockup files under `design/`
- Conflict preview: failed in original checkout due `.git` temporary-file sandboxing; passed in writable temp clone with tree `aee8ca268d6e3379365b9c768fb11f56ee30f2ac`
- Decision: full merge; preserve as design artifacts only
- Checks: `cargo fmt --all --check` passed; `cargo check --workspace` passed

### `origin/claude/ratatui-design-views`

- Status: integrated in commit `64893e3c` (`merge: integrate ratatui-design-views`)
- Commits: 20 commits through `7bdcac53 feat(core+tui): ScanProgress + cached recon/carlini/agentic snapshots`
- Scope: Rust Ratatui design view updates, TUI renderer helpers, structured recon/carlini/agentic snapshots, scan progress type, and plain fixture tests
- Conflict preview: `git merge-tree --write-tree main origin/claude/ratatui-design-views` reported one content conflict in `crates/kuzushi-tui/src/app.rs`
- Decision: full merge with semantic conflict resolution; kept current extracted `app/state_transitions.rs` key/tick/budget handlers, added branch snapshot fields/cache plumbing, adapted spinner rendering to current `spinner_phase`, preserved paste/mouse/resize-aware event loop, and kept strict plain output guidance including `First finding`
- Offline build adjustment: dropped the new `insta` dev dependency because crates.io DNS is unavailable and converted snapshot tests to direct checked fixture comparison; refreshed stale fixture counts/costs against current main behavior
- Checks: `cargo fmt --all --check` passed; `cargo check --workspace` passed; `cargo test -p kuzushi-tui` passed; `cargo test -p kuzushi-core` passed; `cargo test -p kuzushi-cli --test cutover_cli` passed

### `origin/claude/diagnose-rust-tui-ux-M8ycq`

- Status: integrated by subset in commit `1ed52b5b` (`merge: integrate useful diagnose-rust-tui-ux-M8ycq changes`)
- Commits: six branch-local TUI UX commits plus an old merge from `main`
- Scope inspected: Rust shell editing/scrolling, plan-card navigation, tune/prompts/actor-detail interactions, spinner behavior, and a TypeScript plain-renderer import reorder
- Conflict preview: `git merge-tree --write-tree main origin/claude/diagnose-rust-tui-ux-M8ycq` reported conflicts in `crates/kuzushi-tui/src/app.rs`, `crates/kuzushi-tui/src/renderer.rs`, and `crates/kuzushi-tui/src/theme.rs`
- Decision: subset integration, not full merge. Full branch diff is stale against current main and would remove current extracted files (`app/state_transitions.rs`, `renderer/plain.rs`), current crates, design artifacts, and this progress ledger. Kept current Rust Ratatui/extracted structure and integrated useful branch deltas: plan row cursor/skip support, Tune action cursor/activation, Prompts row actions, ActorDetail filter cycle/reset, renderer affordances, and updated snapshot fixture.
- Skipped: stale TypeScript/Ink-side import reorder in `tests/ui/plain-renderer.test.ts`; stale whole-file TUI/theme rewrites that conflict with current extracted modules and design palette.
- Checks: `cargo fmt --all --check` passed; `cargo check --workspace` passed; `cargo test -p kuzushi-tui` passed; `cargo test -p kuzushi-cli --test cutover_cli` passed

### `origin/claude/check-ratatui-tui-Jj2eH`

- Status: integrated by subset in current working commit
- Commits inspected: `87fe9ecf` eval defaults/scorer tests, `f858bad9` vuln_source/static-context scorer reporting, `36f2c829` tree-sitter backend, `b0054a67` deep-audit static-evidence context, `49e0fe31` diff-scope cleanup, plus older already-overlapping merge history
- Scope inspected: `git log --oneline --max-count=20 main..origin/claude/check-ratatui-tui-Jj2eH`, `git diff --name-status main...`, `git diff --stat main...`, and `git merge-tree --write-tree main origin/claude/check-ratatui-tui-Jj2eH`
- Conflict preview: broad conflicts across `Cargo.lock`, CLI main/tests, core config/diff-scope/findings/lib/runtime, OpenAI runtime, xint scripts/docs, and bridge script. The branch has multiple merge bases and stale broad history.
- Decision: subset integration. Full merge would reintroduce stale core/runtime/harness edits and add new tree-sitter dependencies that are not needed for the current regex code-nav path and cannot be fetched reliably in this sandbox.
- Integrated: `kuzushi-eval` proof-state and `vuln_source` hit breakdowns with `staticProofState`/`vulnSource` JSON aliases and focused unit tests; new `static_context` prompt assembler using current `static_evidence`, `static_narrative`, `static_ranking`, and `static_registry` APIs; default-on deep-auditor prompt injection with opt-out config and tests; public re-export for downstream smoke use.
- Skipped: tree-sitter backend/dependency additions; stale diff-scope deletion and broad runtime/script/test changes already represented or superseded by current main.
- Checks: `cargo fmt --all --check` passed; `cargo check --workspace` passed; `cargo test -p kuzushi-core` passed; `cargo test -p kuzushi-eval` passed; `cargo test -p kuzushi-cli --test xint_recall_cli` passed

### `origin/claude/vercel-security-harness-comparison-YQKnA`

- Status: integrated by documentation/example subset in current working commit
- Commits inspected: executor/gateway/history/TUI work from `7a04225f` through `aa387d11`, plus `1c758cb0 examples/sandbox-backend: reference Vercel + Kubernetes adapters`
- Scope inspected: `git log --oneline --max-count=20 main..origin/claude/vercel-security-harness-comparison-YQKnA`, `git diff --name-status main...`, `git diff --stat main...`, and `git merge-tree --write-tree main origin/claude/vercel-security-harness-comparison-YQKnA`
- Conflict preview: broad production conflicts in `Cargo.lock`, CLI main, `findings.rs`, `lib.rs`, `modules.rs`, `runtime.rs`, `kuzushi-openai`, and Ratatui app/renderer.
- Decision: subset integration. The production executor/CLI/runtime changes are stale against current main's `kuzushi-sandbox` verification crate, extracted TUI structure, classifier/spend roles, and no-silent-fallback runtime contracts. Full merge would add uncached `ureq` dependencies and resurrect obsolete executor wiring.
- Integrated: preserved the non-invasive sandbox backend cookbook and Vercel/Kubernetes reference adapter examples, with explicit status notes that current `main` does not wire the old `SandboxExecutor`/`--executor sandbox:<url>` path.
- Skipped: old `Executor`/`SandboxExecutor` production module, gateway shortcut, metrics/status/init/audit CLI expansion, TUI rewrites, analysis-history schema changes, and scanner-via-executor routing. These either conflict with current main contracts or are superseded by current sandbox/verification and pipeline work.
- Checks: `cargo fmt --all --check` passed; `cargo check --workspace` passed; `pnpm build` passed after symlinking the original checkout's existing `node_modules` into the temp clone for tool resolution

### `origin/claude/agentic-security-pipeline`

- Status: pending inspection

## Final Result

- Pending
