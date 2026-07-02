//! First-run onboarding flow: model picker, auth-method picker, and the
//! planning-stage multi-select.
//!
//! The shell decides which of these views to open at startup via
//! [`initial_onboarding_phase_for`]; the picker mechanics themselves live
//! under `app/state_transitions/` (key handling), `renderer/chrome/cards/`
//! (rendering), and `app/onboarding/` (state + dependency graph).

mod controls;
mod dependencies;
mod failure;
mod initial_view;
mod phase;
mod planning_options;
mod recommend;
mod runner;
mod target_candidates;
mod task_id;
mod task_row;

pub use controls::{
    build_execution_plan, row_disposition, toggle_planning_row, RowDisposition, ToggleOutcome,
};
pub use dependencies::{
    direct_dependencies, direct_dependents, topological_order, transitive_dependencies,
};
pub use failure::{FailedPlanningTask, PendingRetry, RetryAdjustment};
pub use initial_view::{
    initial_onboarding_phase, initial_onboarding_phase_for, provider_has_multiple_auth_methods,
    skip_onboarding_env, InitialOnboardingPhase, OnboardingInputs,
};
pub use phase::WorkflowPhase;
pub(crate) use planning_options::{planning_task_explicit_input, planning_task_preset_input};
pub use planning_options::{PickerFocus, PlanningOptionEdit, PlanningOptionOverrides};
pub use recommend::{
    applicable_tasks_for_phase, model_recommended_in_phase, recommended_tasks_for_phase,
    TargetProfile,
};
pub use target_candidates::{
    discover_target_candidates, record_recent_target, TargetCandidate, TargetCandidateScope,
};
pub use task_id::PlanningTaskId;
pub use task_row::{artifact_state, cli_is_on_path, ArtifactState, PlanningTaskRow};
