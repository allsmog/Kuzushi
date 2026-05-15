use super::*;
pub(in crate::renderer) use super::*;

/// Returns `(option-name, formatted-value)` for every tool-scoped
/// option in this module that has a stored value in the session/global
/// option store.  Used by `module_lines` OPTIONS section to mirror
/// `design/mockups/modules-detail.jsx::s2`.

/// Render the "RECENT … ACTIVITY" rows for a given module from projected
/// activity rows. The view model prefers structured cached snapshots over the
/// bounded transcript fallback.

/// One-row streaming cursor block — a single styled cell at the end of the
/// transcript that mirrors the design's `<span className="cursor">` from the
/// running mockups (sast-running.jsx, carlini-running.jsx, agentic-sast-running.jsx).
use crate::ui_view_models::{
    context_snapshot_model, module_progress_model, module_run_live_activity, module_run_summary,
    ContextSnapshotModel, ModuleProgressKind, ModuleProgressModel, ModuleProgressRow,
    ModuleProgressSection, ModuleRunLiveActivity, ModuleRunSummary,
};
pub(in crate::renderer) use append_findings_preview::*;
pub(in crate::renderer) use append_progress_section::*;
pub(in crate::renderer) use append_sast_pipeline_progress::*;
pub(in crate::renderer) use from_app::*;
pub(in crate::renderer) use module_lines::*;
pub(in crate::renderer) use recent_module_activity_lines::*;
mod append_findings_preview;
mod append_progress_section;
mod append_sast_pipeline_progress;
mod from_app;
mod module_lines;
mod recent_module_activity_lines;
pub(crate) use append_findings_preview::streaming_cursor_line;
pub(crate) use from_app::module_run_lines;
pub(crate) use module_lines::module_lines;
pub(crate) use recent_module_activity_lines::recent_module_activity_lines;
pub(crate) use recent_module_activity_lines::transcript_finding_line;
