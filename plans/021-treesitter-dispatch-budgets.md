# Plan 021: Enforce tree-sitter request and response budgets at dispatch

> Executor: descriptors document the contract but are not an enforcement
> boundary today. Test the actual registry/handler call path.

## Status

- **State**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Category**: correctness/security/resource management
- **Depends on**: Plan 011
- **Planned at**: commit `775a4134f2cb`, Cycle 5

## Why this matters

Direct MCP dispatch passes raw JSON to handlers without validating descriptor
schemas. The common stdio transport also uses unbounded `read_line` and writes
an unbounded duplicated text/structured response. Tree-sitter casts `u64`
line/column values to `usize`, performs unchecked offset addition, compiles
unbounded query text, and caps matches but not captures or serialized output.
Extreme direct arguments can wrap/panic or consume unbounded CPU/memory despite
the advertised schema.

## Steps

1. Give the common MCP JSON-RPC transport an exact frame limit on input and
   serialized output. Read incrementally without allowing `read_line` to grow
   past the cap, drain/reject an oversized frame safely, and avoid constructing
   both unlimited pretty-text and structured copies of a tool result.
2. Add a real common dispatch-validation boundary for required fields, types,
   integer ranges, unknown-key policy, and bounded strings/arrays, or prove and
   implement equivalent strict parsing in every tree-sitter handler. Descriptor
   metadata alone is insufficient.
3. Convert numeric inputs with checked conversions, reject zero/out-of-range
   lines and columns, and use checked byte-offset arithmetic against source
   length. Invalid positions return stable tool errors, never panic or wrap.
4. Cap query bytes/pattern count, cursor work/match limits, captures per match,
   aggregate captures, captured source text, and serialized response bytes.
   Surface truncation explicitly; do not silently claim completeness.
5. Apply the same output budget to `node_at`, `query`, and `callers`, including
   parent chains and unusually long source lines. Keep normal limits and tool
   names compatible.

## Verification

- Direct registry dispatch tests bypassing schema-aware clients reject
  `u64::MAX`, oversized queries, huge columns, capture explosions, and unknown
  malformed shapes without panic.
- Common transport tests reject limit+1 unterminated and newline-terminated
  frames and oversized tool responses with bounded allocation, then either
  recover at the next frame or terminate with a stable protocol error.
- Property/fuzz tests cover checked line/column/byte arithmetic.
- Valid requests preserve ordering and cache behavior; truncated results state
  their limit.
- MCP common/tree-sitter tests, Clippy, cross-platform cfg checks, and CRAP pass.

## Done criteria

The live dispatch path enforces finite request, compute, and response budgets
regardless of client behavior.
