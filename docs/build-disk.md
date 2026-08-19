# Local Rust build disk usage

Kuzushi is a large Rust workspace, so local build artifacts can grow much faster
than the source tree. The growth is usually the sum of several independent
Cargo build roots rather than one corrupt cache:

- the checkout's normal `target/` tree;
- the DevEx gate's legacy `target-dev/` tree;
- cargo-llvm-cov's instrumented `target/llvm-cov-target/` tree;
- one `target/` tree for each Git, Claude, or Codex worktree;
- incremental and test executables accumulated under each of those roots.

Cargo does not currently auto-prune workspace build artifacts. Also, the default
Rust development profile emits full debugger metadata, and the test profile
inherits that development profile. Kuzushi therefore uses line-table debug
information for ordinary builds and omits debug information from third-party
dependencies. Line-numbered panic backtraces remain available.

Use the opt-in profile when a debugger needs full symbols for Kuzushi code:

```bash
cargo build --profile debugging
cargo test --profile debugging
```

## Find where the disk went

Run this from any Kuzushi worktree:

```bash
bash scripts/build-disk.sh
```

The report includes all worktrees registered with Git plus known local agent
worktree directories. It shows each `target` or `target-dev` root, its largest
top-level entries, and a separate read-only report for Cargo, rustup, native,
and npm package caches.

## Reclaim disk safely

Prune commands are dry-runs unless `--apply` is present.

Remove legacy DevEx, coverage-build, and old mutation scratch trees while
preserving the normal compiled dependency cache:

```bash
bash scripts/build-disk.sh --prune-aux
bash scripts/build-disk.sh --prune-aux --apply
```

Remove only rustc incremental caches across every discovered worktree:

```bash
bash scripts/build-disk.sh --prune-incremental
bash scripts/build-disk.sh --prune-incremental --apply
```

Remove all Cargo build roots across every discovered worktree:

```bash
bash scripts/build-disk.sh --prune-all
bash scripts/build-disk.sh --prune-all --apply
```

After first pulling the lower-debug profile change, run `--prune-all --apply`
once if old full-debug artifacts dominate the report. Cargo cannot convert
those old objects in place; subsequent builds will repopulate the smaller
profile.

The Rust coverage script now deletes its instrumented build tree after producing
`target/llvm-cov/lcov.info`. Set `KUZUSHI_KEEP_COVERAGE_BUILD=1` only while
debugging the coverage toolchain itself.
