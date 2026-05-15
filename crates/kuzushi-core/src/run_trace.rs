//! Kuzushi run-trace boundary.
//!
//! Run traces are append-only execution records under `.kuzushi/runs/<id>/`.
//! Producers emit trace steps; UI and reports read the resulting artifacts.

pub use crate::run_artifacts::{
    append_run_trace_step, current_parent_step, next_run_trace_step_number, BroadcastSink,
    JsonlSink, ParentScope, RunTraceStep, TraceHandle, TraceSink, TraceStepBuilder,
};
