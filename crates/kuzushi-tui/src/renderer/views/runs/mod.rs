use super::*;
pub(in crate::renderer) use super::*;

pub(in crate::renderer) use replay_lines::*;
pub(in crate::renderer) use runs_lines::*;
pub(in crate::renderer) use runs_row::*;
pub(in crate::renderer) use trace_step_line::*;
mod replay_lines;
/// Walk `<target>/.kuzushi/runs/` and parse each subdir's optional
/// `summary.json` for status/findings/target.  Missing or unreadable
/// summaries fall back to the run-id directory name + "unknown" status.

/// Parse a `trace.jsonl` artefact into typed steps.  Each line is a
/// JSON object with at minimum a `kind` (string) and `label` (string);
/// `n`, `latency_ms`, `cost_usd` are optional and default sensibly.
mod runs_lines;
mod runs_row;
mod trace_step_line;
pub(crate) use replay_lines::parse_trace_jsonl;
pub(crate) use replay_lines::replay_lines;
pub(crate) use replay_lines::trace_lines;
pub(crate) use replay_lines::TraceStep;
pub(crate) use runs_lines::runs_lines;
pub(crate) use trace_step_line::alias_reference_lines;
pub(crate) use trace_step_line::run_artifact_detail;
pub(crate) use trace_step_line::run_artifact_path;
pub(crate) use trace_step_line::trace_step_line;
