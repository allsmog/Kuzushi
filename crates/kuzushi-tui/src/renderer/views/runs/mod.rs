pub(in crate::renderer) use super::prelude::*;
pub(in crate::renderer) use super::*;

mod siblings;
pub(crate) use siblings::*;
mod items_2;
mod items_3;
mod items_4;
/// Walk `<target>/.kuzushi/runs/` and parse each subdir's optional
/// `summary.json` for status/findings/target.  Missing or unreadable
/// summaries fall back to the run-id directory name + "unknown" status.

/// Parse a `trace.jsonl` artefact into typed steps.  Each line is a
/// JSON object with at minimum a `kind` (string) and `label` (string);
/// `n`, `latency_ms`, `cost_usd` are optional and default sensibly.
mod runs_lines;
pub(crate) use items_3::parse_trace_jsonl;
pub(crate) use items_3::replay_lines;
pub(crate) use items_3::trace_lines;
pub(crate) use items_3::TraceStep;
pub(crate) use items_4::alias_reference_lines;
pub(crate) use items_4::run_artifact_detail;
pub(crate) use items_4::run_artifact_path;
pub(crate) use items_4::trace_step_line;
pub(crate) use runs_lines::runs_lines;
