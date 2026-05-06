# Legacy TypeScript/Ink UI

This directory is retained for reference-only and test-only coverage while the
Rust Ratatui shell in `crates/kuzushi-tui` is the operator-facing CLI/TUI path.

Do not add new runtime CLI behavior here. The packaged `kuzushi` binary must
continue to enter through `bin/kuzushi-rs.mjs` and the native Rust binary, not
through these Ink/React components.

The remaining Ink/React dependencies are dev-only because Vitest snapshots,
mock TUI scenarios, and migration parity tests still compile this directory.
Delete those tests and components in one scoped removal when the Rust snapshots
fully replace them.
