use super::*;
pub(in crate::renderer) use super::*;

/// Returns `(option-name, formatted-value)` for every tool-scoped
/// option in this module that has a stored value in the session/global
/// option store.  Used by `module_lines` OPTIONS section to mirror
/// `design/mockups/modules-detail.jsx::s2`.

/// Pull the most recent N log lines that look like they came from the given
/// module (by prefix or body match). Returns oldest-first.

/// Render the "RECENT … ACTIVITY" rows for a given module, preferring
/// structured cached snapshots over freeform `app.log` grep where possible.
///
/// The grep path (`recent_module_log`) is brittle — it depends on log line
/// shape and disappears when the bounded `app.log` ring is truncated.
/// Whenever a tool dispatcher has populated a `*_snapshot` field on the
/// app (`recon_snapshot`, `carlini_snapshot`, `agentic_sast_snapshot`),
/// we render directly from typed data here. The grep is the fallback when
/// no snapshot has been cached yet.

/// Format a recon snapshot as one transcript line per host/service hit,
/// matching the design mockup `design/mockups/recon.jsx::hit()`:
///   `▸ host:port  service  banner`
/// Up to `take` rows total. If services are empty, falls back to one row
/// per host (so single-host fingerprint scans still surface the host).

/// Format a carlini-threat-hunt snapshot as a small transcript block:
/// actor / finding counts plus cost. Top finding lines are added when
/// they fit, mirroring the textual `output()` summary on the report.
/// Transcript-style finding row with severity tint.  Mirrors the mockup
/// finding row colour split (`design/mockups/findings.jsx::findingRow`):
///
///   `▸ <severity>  <rule-id>  <path>:<line>`
///   warn glyph + severity-tinted severity + accent rule-id + muted location.

/// Format an agentic-sast snapshot as a one-line summary plus up to
/// five top finding rows. Mirrors the `AgenticSastReport::output` shape
/// but as styled transcript lines.

/// One-row streaming cursor block — a single styled cell at the end of the
/// transcript that mirrors the design's `<span className="cursor">` from the
/// running mockups (sast-running.jsx, carlini-running.jsx, agentic-sast-running.jsx).
use crate::ui_view_models::{sast_tasks_model, SastTasksModel};
pub(in crate::renderer) use append_findings_preview::*;
pub(in crate::renderer) use append_progress_section::*;
pub(in crate::renderer) use append_sast_pipeline_progress::*;
pub(in crate::renderer) use carlini_snapshot_lines::*;
pub(in crate::renderer) use from_app::*;
pub(in crate::renderer) use module_lines::*;
pub(in crate::renderer) use recent_module_activity_lines::*;
mod append_findings_preview;
mod append_progress_section;
mod append_sast_pipeline_progress;
mod carlini_snapshot_lines;
mod from_app;
mod module_lines;
mod recent_module_activity_lines;
pub(crate) use append_findings_preview::streaming_cursor_line;
pub(crate) use carlini_snapshot_lines::agentic_sast_snapshot_lines;
pub(crate) use carlini_snapshot_lines::carlini_snapshot_lines;
pub(crate) use from_app::module_run_lines;
pub(crate) use module_lines::module_lines;
pub(crate) use recent_module_activity_lines::recent_module_activity_lines;
pub(crate) use recent_module_activity_lines::recon_snapshot_lines;
pub(crate) use recent_module_activity_lines::transcript_finding_line;
