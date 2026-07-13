# Plan 002: Reauthorize and bound every MCP filesystem read

> Executor: work in the current dirty tree; preserve all unrelated changes and
> do not commit or push. Stop if a safe no-follow strategy cannot be implemented
> on a supported platform without changing the MCP JSON contract.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Category**: security/perf
- **Planned at**: commit `775a4134f2cb`, 2026-07-12

## Why this matters

Artifact attachment is checked during planning, but several MCP children later
open environment-provided paths directly, without read-root authority or byte
limits. A swapped symlink/path can cross the target boundary, and oversized
artifacts or source files can exhaust the child.

## Current state

- `scripts/langgraph-bridge/mcp.mjs`: `READ_CAPABILITY_SERVERS` currently names
  only treesitter, Joern, and CodeQL; artifact paths are copied to child env.
- `crates/kuzushi-mcp-common/src/read_capability.rs`: common canonical read-root
  capability already exists and is the required extension point.
- Artifact servers with raw `read_to_string`: `kuzushi-mcp-context`,
  `kuzushi-mcp-entry-points`, `kuzushi-mcp-threat-model`,
  `kuzushi-mcp-threat-intel`, and `kuzushi-mcp-x-ray`.
- `crates/kuzushi-mcp-treesitter/src/tools.rs`: capability resolution is
  followed by a second unbounded open; query/caller result limits are uncapped.
- Keep MCP tool names and response JSON stable.

## Steps

1. Extend `ReadRootCapability` with a single bounded UTF-8/binary open/read API
   that canonicalizes/authorizes at consumption, rejects non-regular files and
   symlink escapes, and enforces a documented maximum before allocation.
2. Revalidate every planned artifact immediately before spawn and pass
   `KUZUSHI_MCP_READ_ROOTS` to every artifact-backed server. Reject an artifact
   outside the roots instead of attaching it.
3. Refactor all five artifact servers to build the capability at startup and
   use the bounded API for the primary artifact and x-ray sibling artifacts.
4. Refactor tree-sitter reads to use the same bounded operation. Clamp query and
   caller limits to named constants. Add a small shared LRU keyed by canonical
   path, language, size, and modification identity; a changed file must miss.
5. Audit CodeQL SARIF ingestion through this path and add an explicit maximum
   before JSON parsing if it is not already bounded.
6. Add Rust and bridge tests for allowed reads, outside-root paths, symlink
   replacement, oversized files, changed-file cache invalidation, and excessive
   result limits.

## Verification

```text
cargo test -p kuzushi-mcp-common --offline
cargo test -p kuzushi-mcp-treesitter --offline
cargo test -p kuzushi-mcp-context -p kuzushi-mcp-entry-points -p kuzushi-mcp-threat-model -p kuzushi-mcp-threat-intel -p kuzushi-mcp-x-ray --offline
pnpm vitest run tests/langgraph-bridge/mcp-plan.test.ts
```

## Done criteria

- Every filesystem-reading MCP receives and enforces a read-root capability.
- Authorization and bounded read are one consumer operation.
- Tree-sitter repeated parses are cached without stale results.
- Oversized file/result tests fail closed and existing MCP schemas remain stable.

## STOP conditions

Stop on public tool-schema drift, a required unsafe canonicalize-then-open race,
or a platform regression that cannot be covered by a conservative fail-closed
implementation.
