# Plan 033: Initialize ignored runtime state before clean-source binding

> Executor: retain the strict clean Git snapshot gate. Kuzushi-created runtime
> artifacts must not make a clean repository dirty, while real tracked,
> staged, or untracked source changes must continue to block patch execution.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: run lifecycle/patch correctness
- **Depends on**: Plans 003, 004, and 027
- **Planned at**: commit `775a4134f2cb`, Cycle 7

## Why this matters

`kuzushi run patch:finding` records its run under `.kuzushi/v3/runs` before
the registry binds the source commit. Run-directory creation bypasses
`WorkspaceTarget::ensure_state_dir`, so a fresh Git repository without a root
ignore sees Kuzushi's own state as untracked and patch preparation rejects
itself. The same ordering can leave ordinary headless run state visible to Git,
and an existing unsafe or insufficient `.kuzushi/.gitignore` is currently
accepted without proving that generated v3 state is excluded.

## Steps

1. Add one safe workspace-state initialization boundary used before the first
   run artifact, finding store, trace, or patch worktree write. It must create
   the canonical no-follow state directories and ignore policy before run
   start, in CLI, shell, and scan paths that own a workspace.
2. Validate an existing `.kuzushi/.gitignore` as a regular in-workspace file
   and prove its rules exclude generated v3 state while preserving the
   intentionally trackable scope, prompt, and config surfaces. Do not overwrite
   an operator policy silently; return an actionable error when it is unsafe or
   insufficient.
3. Bind `patch:finding` only after initialization and before its start receipt
   can change source status. Workspace-free run artifacts keep their documented
   cwd behavior but receive the same safe initialization when the cwd is used
   as the artifact target.
4. Keep the clean-source check strict for all non-ignored tracked, staged,
   untracked, and submodule changes. Do not add a blanket `git status` filter
   for `.kuzushi` as a substitute for correct state ownership.

## Verification

- In a newly committed repository with no root `.gitignore`, first-use CLI and
  TUI `patch:finding` preparation writes its receipt, remains `git status
  --porcelain` clean, binds HEAD, and reaches the approved runtime fixture.
- Ordinary `kuzushi run` first-use state is ignored; a subsequent real
  untracked source file, staged edit, tracked edit, or dirty submodule still
  blocks patch binding.
- Existing valid custom ignore policy is preserved. Empty, insufficient,
  symlinked, directory, and outside-target ignore nodes fail before generated
  state is written and never overwrite outside data.
- Workspace, run-artifact, patch, CLI/TUI full suites, formatting, Clippy, and
  CRAP gates pass.

## Done criteria

Kuzushi's own state never falsifies the clean-snapshot gate, and the gate still
rejects every genuine source mutation.

## Implementation notes

- The local policy now proves ownership by construction: a root `*` rule and a
  `v3/*` rule may expose only `scope.toml`, `prompts/**`, and `v3/config.toml`.
  A finite list of generated filenames is no longer sufficient, and a nested
  `v3/.gitignore` is rejected because it could invert that ownership.
- Run-history, latest-pointer, and strategy locks initialize and verify ignored
  state before creating an index or lock, including direct public read APIs.
- Workspace-state tests pass 24/24 and direct fresh-repository page, cursor,
  pointer-repair, and strategy-read cleanliness tests pass.
- Concurrent initialization, run-artifact, and strategy-lock regressions pass,
  and the complete offline workspace plus strict Clippy and workspace-write
  policy gates are green.
