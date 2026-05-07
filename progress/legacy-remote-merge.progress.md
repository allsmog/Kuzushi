# Legacy Remote Branch Merge Progress

Scope: non-Claude remote branches requested for cleanup after the Claude merge
round. `origin/claude/investigate-tui-ux-NqMt1` was intentionally left alone.

## Result

- `origin/agent/docs-devex-consolidation` - merged as content.
  The Rust TUI design prompt was updated with current-state references and an
  explicit Rust-native target boundary.
- `origin/agent/rust-tui-ux-consolidation` - recorded as superseded.
  The branch-local TUI behavior is already present in current Rust TUI files
  after the later TUI/Uncle Bob integrations.
- `origin/agent/verify-mcp-sandbox` - recorded as superseded.
  Native codeindex, MCP, sandbox, and verify crates are already present on
  `main` via the later verify MCP sandbox integration.
- `origin/backup/local-staged-ralph-20260506` - recorded as archival.
  This is a backup snapshot that would delete current Rust, TUI, whitebox, and
  design work if merged as content.
- `origin/kuzushi-whitebox-static` - recorded as superseded.
  The useful WB-012 through WB-014 behavior is already covered by the later
  WB-012 through WB-022 whitebox-static sequence on `main`.
- `origin/worktree-agent-a7f41ccc8b1d062af` - recorded as archival.
  This partial TypeScript plain-renderer pass conflicts with the current
  Rust-native TUI cutover direction and was not applied as content.

## Verification

- `git branch -r --no-merged main | sed 's/^ *//' | sort` now reports only
  `origin/claude/investigate-tui-ux-NqMt1`, which was excluded by request.
- No code checks were required for the marker merges because they preserve the
  current `main` tree. The only content change was documentation.
