//! Operator-requested deeper trace over a finding's data flow.
//!
//! The Trace screen answers "where does this value travel"; when the recorded
//! path stops short, the operator requests an expansion. The capability runs a
//! bounded read-only agent around the finding, parses the versioned
//! [`TraceExpansionResult`] contract, and appends the intermediary steps to
//! the static-evidence store as `DataflowStep` nodes chained by `FlowsTo`
//! edges — tagged with the finding fingerprint and "requested by operator"
//! provenance, so the Trace screen re-renders from the durable store rather
//! than a session snapshot.

mod contract;
mod expand;
mod history;
mod persist;
#[cfg(test)]
mod tests;

pub use contract::{
    TraceExpansionRequest, TraceExpansionResult, TraceStep, MAX_TRACE_EXPANSION_STEPS,
    TRACE_EXPANSION_CONTRACT_VERSION,
};
pub use expand::{run_trace_expansion, TraceExpansionOutcome};
pub use history::{load_latest_trace_expansion, RecordedTraceExpansion, TraceExpansionSource};
pub use persist::{
    append_trace_expansion_evidence, list_operator_trace_steps, TraceEvidenceReceipt,
    OPERATOR_TRACE_PROVENANCE,
};
