# Plan 011: Strengthen MCP file identity and Windows root capabilities

> Executor: keep all reads bounded and root-authorized. Do not relax the Unix
> `openat`/`O_NOFOLLOW` path while adding cross-platform behavior.

## Status

- **State**: DONE
- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Category**: correctness/security/portability
- **Planned at**: commit `775a4134f2cb`, Cycle 4

## Why this matters

Tree-sitter cache identity uses only length, mtime, device, and inode; an
equal-length rewrite with restored mtime can return a stale AST. The non-Unix
open path authorizes canonically, checks only the leaf symlink, and then opens
by path, leaving a Windows parent-junction race.

## Steps

1. Extend `ReadFileIdentity` with a kernel-controlled change token: Unix ctime
   seconds/nanoseconds and a Windows file identity/change-time equivalent.
2. Where a reliable token is unavailable, compute a bounded content digest
   before accepting a cache hit. Do not make an unbounded read.
3. On Windows, retain a root directory handle and perform capability-relative,
   reparse-safe opens, or verify the final opened handle path and volume/file
   identity against that root. Parent swaps must fail closed.
4. Keep consumer byte caps, source-size caps, query limits, and the 16-entry
   tree-sitter LRU intact.

## Verification

- Equal-length rewrite plus restored mtime invalidates the cached AST.
- Concurrent mutation cannot return bytes under a mismatched identity.
- Add Windows-only parent-junction swap and final-handle containment tests.
- Run MCP common/tree-sitter/all artifact-server tests and cross-target check
  where the toolchain is available; document only a real external blocker.

## Done criteria

Cache identity changes whenever file content can change, and all supported
platforms prove the opened handle remains under the retained read root.
