//! First-run onboarding flow: model picker, auth-method picker, and the
//! planning-stage multi-select.
//!
//! The shell decides which of these views to open at startup via
//! [`initial_onboarding_phase_for`]; the picker mechanics themselves live
//! under `app/state_transitions/` (key handling), `renderer/chrome/cards/`
//! (rendering), and `app/onboarding/` (state + dependency graph).

mod controls;
mod dependencies;
mod initial_view;
mod runner;
mod task_id;
mod task_row;

pub use controls::{build_execution_plan, toggle_planning_row, ToggleOutcome};
pub use dependencies::{
    direct_dependencies, direct_dependents, topological_order, transitive_dependencies,
};
pub use initial_view::{
    any_planning_artifact_missing, initial_onboarding_phase, initial_onboarding_phase_for,
    provider_has_multiple_auth_methods, skip_onboarding_env, InitialOnboardingPhase,
    OnboardingInputs,
};
pub use task_id::PlanningTaskId;
pub use task_row::{artifact_state, cli_is_on_path, ArtifactState, PlanningTaskRow};
