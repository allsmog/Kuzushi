pub(in crate::renderer) use super::prelude::*;
pub(in crate::renderer) use super::*;

/// Returns `(option-name, formatted-value)` for every tool-scoped
/// option in this module that has a stored value in the session/global
/// option store.  Used by `module_lines` OPTIONS section to mirror
/// `design/mockups/modules-detail.jsx::s2`.

/// Walk `<target>/.kuzushi/prompts/<module>/` and return every `*.md`
/// file as (verb, relative-path).  Per the agent guide in `CLAUDE.md`
/// this is exactly the directory `executeTool` reads from for prompt
/// overrides.  Empty when the dir doesn't exist.

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
mod prelude;
pub(in crate::renderer) use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
mod items_5;
mod items_6;
mod items_7;
mod items_8;
mod module_lines;
pub(crate) use items_3::recent_module_activity_lines;
pub(crate) use items_3::recon_snapshot_lines;
pub(crate) use items_3::transcript_finding_line;
pub(crate) use items_4::agentic_sast_snapshot_lines;
pub(crate) use items_4::carlini_snapshot_lines;
pub(crate) use items_5::module_run_lines;
pub(crate) use items_8::streaming_cursor_line;
pub(crate) use module_lines::module_lines;
