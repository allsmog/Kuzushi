# Local Rust build disk usage

Kuzushi is a large Rust workspace, so local build artifacts can grow much faster
than the source tree. The growth is usually the sum of several independent
Cargo build roots rather than one corrupt cache:

- the checkout's normal `target/` tree;
- a legacy `target-dev/` tree left by older DevEx gate runs;
- cargo-llvm-cov's instrumented `target/llvm-cov-target/` tree;
- one `target/` tree for each Git or coding-agent worktree;
- incremental and test executables accumulated under each of those roots.

The evidence-loop gate now reuses the checkout's normal Cargo target by default.
Set `KUZUSHI_EVIDENCE_LOOP_TARGET_DIR` only when an isolated gate build is
needed for diagnosis.

## Measured root cause of runaway growth

Cargo does not auto-prune workspace build artifacts, and rustc's incremental
compilation mints one session directory per crate compile-unit and flag
variant under `target/debug/incremental/<crate>-<hash>/`. Every distinct
invocation shape — `cargo test -p <one-crate>` versus `--workspace`, coverage
RUSTFLAGS, a different feature unification — produces a new `<hash>`, and
stale variants are never garbage-collected. On a working checkout this
compounded to a 94.3 GiB `target/` with 57.7 GiB of incremental data
(`kuzushi_core` alone held 33 variant directories totalling 42.6 GiB).
rustc also hardlinks incremental workproducts into `deps`, so the incremental
tree inflates both categories at once.

## Disk-bounded defaults

Ordinary dev and test builds are disk-bounded by two defaults in
`.cargo/config.toml`:

- `debug = "line-tables-only"` for workspace code and no debug data for
  dependencies (line-numbered panic backtraces remain available);
- `incremental = false` for the dev profile (the test profile inherits it), so
  no incremental session trees accumulate at all.

Opt back in explicitly when you need full debugger metadata or incremental
rebuild speed for a focused edit loop:

```bash
# Full debug info + incremental compilation, in its own target/debugging tree:
cargo build --profile debugging
cargo test --profile debugging

# Or re-enable incremental for one ordinary invocation (env overrides profile):
CARGO_INCREMENTAL=1 cargo test -p kuzushi-tui
```

Cargo targets are intentionally not shared across worktrees: concurrent agent
builds would contend on the target lock, branch switches would thrash each
other's caches, and a shared root could not be pruned safely while any
worktree builds. Each worktree keeps its own bounded root, and the tooling
below reports and prunes all of them together.

## Find where the disk went

Run this from any Kuzushi worktree:

```bash
pnpm disk:report          # or: bash scripts/build-disk.sh --report
```

The report includes all worktrees registered with Git, known local agent
worktree directories (`.claude/worktrees`, `.codex/worktrees`, `.worktrees`),
`CARGO_TARGET_DIR`, and an explicitly configured
`KUZUSHI_EVIDENCE_LOOP_TARGET_DIR`. Relative configured targets are resolved
from the current worktree root. Each build root is broken down into
incremental data, compiled dependencies, release artifacts, coverage output,
and scratch output, with a separate read-only report for Cargo, rustup,
native, and npm package caches.

## Budget check

```bash
pnpm disk:check           # exit 1 when aggregate usage exceeds the budget
bash scripts/build-disk.sh --check-budget --budget-gib 60
```

The default budget is 40 GiB across every discovered build root (the runaway
state above was 94.3 GiB, more than twice over). Configure it with
`--budget-gib` or `KUZUSHI_BUILD_DISK_BUDGET_GIB`. The check only reports and
sets an exit code — nothing is ever deleted by the report or budget modes, and
nothing runs automatically at startup; wire `pnpm disk:check` into your own
routine where you want the signal.

## Reclaim disk safely

Prune commands are dry-runs unless `--apply` is present. Applying refuses any
build root that is in use — an executable running from the target tree, or a
Cargo/rustc/rustdoc process in the owning worktree — and fails closed when
process liveness cannot be determined. Refusal deletes nothing.

Remove only rustc incremental caches across every discovered worktree,
preserving compiled dependencies:

```bash
pnpm disk:prune           # dry run
pnpm disk:prune:apply     # delete
```

Remove legacy DevEx, coverage-build, and old mutation scratch trees while
preserving the normal compiled dependency cache:

```bash
bash scripts/build-disk.sh --prune-aux
bash scripts/build-disk.sh --prune-aux --apply
```

Remove all Cargo build roots across every discovered worktree:

```bash
bash scripts/build-disk.sh --prune-all
bash scripts/build-disk.sh --prune-all --apply
```

After first pulling the disk-bounded profile change, run `--prune-all --apply`
once if old full-debug or incremental artifacts dominate the report. Cargo
cannot convert those old objects in place; subsequent builds will repopulate
the smaller profile.

The Rust coverage script deletes its instrumented build tree after producing
`target/llvm-cov/lcov.info`. Set `KUZUSHI_KEEP_COVERAGE_BUILD=1` only while
debugging the coverage toolchain itself.
