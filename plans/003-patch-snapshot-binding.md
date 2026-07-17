# Plan 003: Bind patch synthesis and validation to one repository snapshot

> Executor: preserve the existing dirty tree. Do not discard user changes,
> commit, push, or clean untracked files.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: correctness/security
- **Planned at**: commit `775a4134f2cb`, 2026-07-12

## Why this matters

Patch synthesis reads the live working tree, while validation clones and checks
out committed `HEAD`. Dirty tracked or untracked source can therefore produce a
patch against one state and validate against another; approval can also outlive
a HEAD change.

## Current state

- `crates/kuzushi-core/src/remediation/patch/build_patch_prompt.rs` reads live
  source context.
- `detect_validation_plan.rs` binds commands before approval.
- `ensure_git_repository.rs::create_disposable_worktree` clones locally and
  runs `checkout --detach --force HEAD`.
- `modules/application/sast_scan/write_whitebox_diff_scope_json.rs` builds
  nested `sast:patch` input.
- Existing isolation tests cover only a clean initialized repository.

## Decision

Use the conservative contract: patching requires a clean Git source snapshot.
Bind its exact commit SHA into canonical prepared input/fingerprint, verify it
again at execution, and check out that SHA in the disposable clone. This avoids
silently omitting untracked files or inventing a partial snapshot policy.

## Steps

1. During canonical patch input binding, require a Git repository with no
   tracked, staged, or untracked source changes (ignored `.kuzushi` artifacts
   do not count), resolve exact HEAD SHA, and add an internal canonical field.
2. Include the field in operation fingerprint/approval disclosure and propagate
   it through `sast:scan` auto-patch nested input.
3. Immediately before execution, recheck clean status and exact SHA. Fail with
   an actionable message if either differs.
4. Make the disposable clone checkout the bound SHA, never ambient `HEAD`.
5. Add tests for dirty tracked, staged, and untracked files; ignored runtime
   artifacts; HEAD movement after prepare; exact checkout; and SAST propagation.

## Verification

```text
cargo test -p kuzushi-core remediation::patch --offline
cargo test -p kuzushi-core operation_authorization --offline
cargo test -p kuzushi-core sast_patch --offline
```

## Done criteria

- Dirty source refuses before model synthesis/approval.
- Approval identifies the exact source commit.
- Execution refuses drift and validates the bound commit.
- No source changes are copied, deleted, or reset.

## STOP conditions

Stop if nested SAST patch calls cannot carry the bound value through the shared
descriptor input without a new mode-specific path, or if clean-state detection
would include ignored `.kuzushi` runtime output.
