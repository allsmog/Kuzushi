# Plan 027: Keep TUI preparation tests isolated and aligned with hardened inputs

> Executor: production clean-snapshot and immutable-prompt behavior is the
> contract. Repair hermetic fixtures and assertions; do not weaken either gate
> to make a dirty-worktree test pass.

## Status

- **State**: DONE
- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Category**: test fidelity/regression coverage
- **Depends on**: Plans 001, 003, and 010
- **Planned at**: commit `775a4134f2cb`, Cycle 5 verification

## Why this matters

The full TUI suite has three failures after the prompt and patch snapshot
hardening. One patch-confirmation fixture is not a committed Git repository, a
patch bridge fixture dirties its source repository after the fixture commit,
and a prompt test still expects raw file contents even though prepared prompt
input now carries the immutable safety envelope. These failures hide future
regressions and make the complete workspace gate red despite correct focused
behavior.

## Steps

1. Make the patch-confirmation fixture a minimal clean committed repository
   before preparation, and assert that the approval-bound launch keeps its
   resolved build/test commands and source-commit binding.
2. Keep patch runtime helpers outside the source repository and ignore only
   canonical Kuzushi runtime artifacts where the product contract permits it.
   Prove the source repository is clean immediately before dispatch; do not
   bypass or relax `ensure_clean_patch_source`.
3. Update the path-like prompt test to assert the complete hardened envelope,
   the expected untrusted file payload, and idempotent second preparation. It
   must prove a payload that names another file is not recursively hydrated.
4. Retain explicit failure tests for genuinely dirty patch repositories and
   malformed prompt overrides.

## Verification

- The three previously failing tests pass in isolation and in the complete
  `kuzushi-tui` suite.
- A deliberately untracked source file still blocks patch dispatch.
- Prompt preparation contains the immutable policy once, contains the first
  file's bytes as untrusted data, and never reads the named second file.
- TUI Clippy, formatting, prompt-hardening, patch/remediation, and CRAP gates
  pass.

## Done criteria

The full suite is green for hermetic reasons while the production prompt and
clean-snapshot gates remain fail closed.
