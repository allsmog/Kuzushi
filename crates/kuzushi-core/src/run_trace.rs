//! Kuzushi run-trace boundary.
//!
//! Run traces are append-only execution records under `.kuzushi/v3/runs/<id>/`.
//! Producers emit trace steps; UI and reports read the resulting artifacts.

pub use crate::run_artifacts::{
    current_parent_step, with_parent_step, ParentScope, RunActivityBuilder, TraceHandle,
};
