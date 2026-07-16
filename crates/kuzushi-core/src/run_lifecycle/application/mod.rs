mod metrics;
mod observation;
mod preparation_rejection;
mod presentation;
mod projection;
mod question_identity;
mod reducer;
mod terminal_persistence;

pub(crate) use metrics::{
    record_coalesced_progress, record_degraded_replay, record_legacy_fallback,
    record_writer_saturation,
};
pub use metrics::{run_lifecycle_metrics_snapshot, RunLifecycleMetricsSnapshot};
pub use observation::{ObservedRunTask, RunObservationHandle, RunPlanHandle, RunTaskHandle};
pub use preparation_rejection::{
    emit_preparation_rejection, observe_preparation_rejection, ObservedPreparationRejection,
};
pub use presentation::*;
pub use projection::*;
pub use question_identity::{deterministic_choice_id, deterministic_question_id};
pub(crate) use reducer::apply_envelope;
pub use reducer::reduce_run_items;
pub use terminal_persistence::{
    emit_persisted_terminal_outcome, emit_persisted_terminal_outcome_for_call,
    emit_result_persistence_failure, verified_result_artifact_reference,
    verified_run_artifact_reference,
};
