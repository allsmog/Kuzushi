// This crate flattens its module tree with pervasive `pub(crate) use mod::*`
// re-exports and `use super::*` so sibling modules — and especially the
// `#[cfg(test)]` submodules — share a single namespace. The compiler can't see
// the test-only uses when linting the lib target, so it reports ~190
// false-positive `unused_imports`. Removing them (e.g. via `cargo fix`) breaks
// the test build. Suppress the lint crate-wide rather than churn 100+ files.
#![allow(unused_imports)]

pub(crate) use app::*;
pub(crate) use commands::*;
pub(crate) use renderer::*;
mod app;
mod build_provenance;
mod commands;
mod renderer;
pub mod scene3d;
mod theme;
pub mod ui_theme;
pub mod ui_view_models;
pub mod ui_views;

pub use app::{
    run_shell, run_shell_with_plain, ActivitySession, ChatTurn, InputMode, OptionsFilter,
    OptionsView, PaneFocus, ReconSnapshot, ScanPanelState, ShellApp, ShellView, ThreatView,
    WorkbenchPane,
};
pub use build_provenance::{
    build_provenance, build_summary, build_version, build_version_static, BuildProvenance,
};
pub use commands::{parse_command, ShellCommand};
pub use kuzushi_core::ScanProgress;
pub use renderer::{render_app, render_plain_app};
