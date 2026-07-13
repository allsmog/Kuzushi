# Plan 020: Materialize bound patch trees without copying Git history per attempt

> Executor: retain immutable commit binding, separate synthesis and validation
> roots, hook suppression, sandboxing, and cleanup on every exit path.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: availability/performance/remediation
- **Depends on**: Plan 010
- **Planned at**: commit `775a4134f2cb`, Cycle 5

## Why this matters

Every synthesis and validation attempt performs a local clone with
`--no-hardlinks`, copying the complete object database. In this repository that
is roughly 611 MiB per checkout: default retries can copy several GiB and the
maximum can exceed 10 GiB before validation completes.

## Steps

1. Characterize the exact files and Git semantics required by prompt building,
   `git apply`, build/test commands, and cleanup. Measure bytes written for a
   multi-attempt fixture with substantial unreachable history.
2. Replace per-attempt history clones with a path-safe materialization of only
   the bound commit tree. Prefer a streamed `git archive`/index export into a
   fresh directory with validated relative entries and bounded total files and
   bytes. A minimal fresh `.git` may be initialized only if a proven consumer
   requires it; do not share mutable refs, hooks, config, or object writes with
   the source repository.
3. Preserve distinct disposable synthesis and validation directories for every
   attempt, exact bound-commit verification, source-tree mutation barriers,
   prompt resolution inside the snapshot, and sandbox write/network rules.
4. Make extraction cancellation/deadline aware and ensure partial directories
   are removed after errors, timeouts, panics at controlled boundaries, and
   validation failures.

## Verification

- A repository with a large unrelated object history writes work proportional
  to the bound tree, not object-database/history size or retry count.
- Source hooks/config never run; source refs/objects/worktree remain unchanged.
- Synthesis and validation observe the same bound commit despite concurrent
  live-tree/HEAD mutation and never share a writable root.
- Archive path traversal, symlink, oversized tree, cancellation, and partial
  extraction fixtures fail safely; remediation/patch/Clippy/CRAP tests pass.

## Done criteria

Patch retries remain snapshot-correct while disk and copy work scale with the
checked-out tree rather than the repository's full history.

## Completion evidence

- Replaced history-copying local clones with an exact, bounded raw-object
  materializer: `ls-tree` preflights the bound commit, `cat-file --batch`
  streams through a hard-capped spool, and a fresh hookless repository is
  rebuilt from verified blob, tree, and commit object IDs.
- Rejected symbolic links, gitlinks, reserved/escaping paths, duplicate and
  file/directory collisions, and case-folded component collisions on
  case-insensitive filesystems. Executable modes and detached bound `HEAD` are
  preserved without checkout, reset, smudge filters, source config, replace
  refs, alternates, or shared mutable objects.
- One absolute deadline and cancellation signal cover Git subprocesses and
  extraction; RAII cleanup removes partial checkouts after errors and panics,
  including dangling checkout symlinks.
- Verified with 37 focused remediation tests, five streamed-subprocess tests,
  the CRAP-risk gate, model/artifact/env/dispatch/workspace contract gates, and
  scoped Clippy. The Windows workspace cross-check reached the pre-existing
  `ring` C build and stopped because the host lacks MSVC system headers; the
  Windows-only file-open branch remains source-gated and uses
  `FILE_FLAG_OPEN_REPARSE_POINT`.
