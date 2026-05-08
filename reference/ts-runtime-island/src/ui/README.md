# Shared TypeScript UI Helpers

The TypeScript/Ink TUI has been removed. The operator-facing CLI/TUI path is
the Rust Ratatui shell in `crates/kuzushi-tui`.

This directory now contains only shared, non-visual TypeScript helpers still
used by migration/reference code: `UIStore` state, CI/plain-text renderers,
formatting helpers, notifications, and summary builders.

Do not add new terminal UI behavior here. New operator-facing shell work belongs
in `crates/kuzushi-tui`.
