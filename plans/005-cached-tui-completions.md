# Plan 005: Remove synchronous completion I/O from the TUI render path

> Executor: preserve behavior and the dirty tree. Rendering and keystroke
> handling must become pure over already-hydrated state.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: perf
- **Planned at**: commit `775a4134f2cb`, 2026-07-12

## Why this matters

Every prompt render asks for completion candidates. Depending on the command,
that call recursively walks up to 5,000 files, opens SQLite, or scans every run
directory on the Ratatui thread, making typing latency scale with workspace
size.

## Current state

- `renderer/chrome/prompt/mod.rs` calls `app.completion_preview()` per render.
- `app/file_picker.rs` recursively discovers and sorts attach candidates.
- `app/services/findings.rs` can synchronously open/load the findings store.
- `app/line_editor/is_word_char/completion_sources.rs` scans run directories.
- Existing generation-tagged view hydration is the required async pattern.

## Steps

1. Add target-generation-tagged cached vectors for file, finding, and run-id
   completion sources. Completion rendering may read these vectors only.
2. Populate them through existing background hydration/effect machinery on
   target activation and relevant completion events. Never mutate app state
   from the renderer.
3. Define invalidation/refresh for target changes, finding-store changes, run
   start/terminalization, and workspace file refresh. While pending, retain the
   last same-generation cache or show no preview; never block.
4. Add tests using I/O-trapping adapters or counters proving repeated rendering
   performs zero filesystem/SQLite calls, stale generations are ignored, and
   refresh events update candidates without changing Tab semantics.

## Verification

```text
cargo test -p kuzushi-tui completion --offline
cargo test -p kuzushi-tui view_hydration --offline
cargo test -p kuzushi-tui renderer --offline
pnpm quality:crap-risk
```

## Done criteria

- Render/keypress completion paths perform no filesystem or database I/O.
- Cache invalidation is explicit and generation safe.
- Existing completion strings and Tab behavior remain covered by tests.

## STOP conditions

Stop if the implementation requires a second background runtime, blocks target
activation, or keeps stale candidates across target generations.
