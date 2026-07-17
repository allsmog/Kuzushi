use super::task_id::PlanningTaskId;
use super::task_row::{ArtifactState, PlanningTaskRow};
use kuzushi_core::V2Config;
use std::path::Path;

/// Front-door phases. Target consent remains separate; every other fresh
/// workspace prerequisite is projected together on Setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitialOnboardingPhase {
    /// First gate: pick what to scan. Only offered from the interactive
    /// terminal launch (`allow_target_gate`); never silently defaults to cwd.
    TargetPicker,
    Setup,
    Catalog,
}

/// Inputs that drive `initial_onboarding_phase`. Split out so the
/// decision is fully testable without a live `ShellApp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingInputs<'a> {
    pub model: Option<&'a str>,
    pub provider_auth_ready: bool,
    /// Whether the shell was launched against a real workspace target.
    pub has_target: bool,
    /// Whether this target has no persisted findings and no known map
    /// artifacts. Only fresh targets auto-open the phase walker; returning
    /// workspaces land on the Workbench and invoke the walker with `next`.
    pub workspace_is_fresh: bool,
    pub skip_onboarding_env: bool,
    /// Whether the caller may open the launch-time target picker. Set only by
    /// the interactive terminal launch; construction and target activation
    /// pass `false` so headless and test apps keep their targetless default.
    pub allow_target_gate: bool,
}

/// Ordered onboarding gate: explicit Target consent, then aggregate Setup.
/// Model and credential requirements are plan-aware inside Setup, so a
/// deterministic Map plan is never blocked by absent provider configuration.
pub fn initial_onboarding_phase(inputs: &OnboardingInputs<'_>) -> InitialOnboardingPhase {
    if inputs.skip_onboarding_env {
        return InitialOnboardingPhase::Catalog;
    }
    if !inputs.has_target {
        return if inputs.allow_target_gate {
            InitialOnboardingPhase::TargetPicker
        } else {
            InitialOnboardingPhase::Catalog
        };
    }
    if inputs.workspace_is_fresh {
        InitialOnboardingPhase::Setup
    } else {
        InitialOnboardingPhase::Catalog
    }
}

/// Convenience wrapper that builds `OnboardingInputs` from live config +
/// target paths and returns the next phase. Reads the
/// `KUZUSHI_SKIP_ONBOARDING` env var. Callers here never open the launch-time
/// target picker (`allow_target_gate = false`); that gate belongs to the
/// interactive terminal launch alone.
pub fn initial_onboarding_phase_for(
    config: &V2Config,
    target: Option<&Path>,
    auth_ready: bool,
    workspace_is_fresh: bool,
) -> InitialOnboardingPhase {
    let inputs = OnboardingInputs {
        model: config.model.as_deref(),
        provider_auth_ready: auth_ready,
        has_target: target.is_some(),
        workspace_is_fresh,
        skip_onboarding_env: skip_onboarding_env(),
        allow_target_gate: false,
    };
    initial_onboarding_phase(&inputs)
}

pub fn skip_onboarding_env() -> bool {
    match std::env::var("KUZUSHI_SKIP_ONBOARDING") {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> OnboardingInputs<'static> {
        OnboardingInputs {
            model: None,
            provider_auth_ready: false,
            has_target: false,
            workspace_is_fresh: false,
            skip_onboarding_env: false,
            allow_target_gate: false,
        }
    }

    /// A target-anchored session: past the target gate, ready to weigh model
    /// and credentials.
    fn targeted_inputs() -> OnboardingInputs<'static> {
        let mut i = inputs();
        i.has_target = true;
        i
    }

    #[test]
    fn skip_env_short_circuits_to_catalog() {
        let mut i = inputs();
        i.skip_onboarding_env = true;
        i.model = None;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::Catalog
        );
    }

    #[test]
    fn skip_env_beats_the_target_gate() {
        let mut i = inputs();
        i.skip_onboarding_env = true;
        i.allow_target_gate = true;
        i.has_target = false;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::Catalog
        );
    }

    #[test]
    fn no_target_with_gate_opens_target_picker() {
        let mut i = inputs();
        i.allow_target_gate = true;
        i.has_target = false;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::TargetPicker
        );
    }

    #[test]
    fn no_target_without_gate_lands_on_catalog() {
        let mut i = inputs();
        i.allow_target_gate = false;
        i.has_target = false;
        i.model = None;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::Catalog
        );
    }

    #[test]
    fn fresh_target_without_model_opens_plan_aware_setup() {
        let mut i = targeted_inputs();
        i.workspace_is_fresh = true;
        assert_eq!(initial_onboarding_phase(&i), InitialOnboardingPhase::Setup);
    }

    #[test]
    fn fresh_target_with_missing_credentials_still_opens_setup() {
        let mut i = targeted_inputs();
        i.model = Some("anthropic:claude-sonnet-4-6");
        i.provider_auth_ready = false;
        i.workspace_is_fresh = true;
        assert_eq!(initial_onboarding_phase(&i), InitialOnboardingPhase::Setup);
    }

    #[test]
    fn returning_target_without_model_resumes_instead_of_reopening_setup() {
        let i = targeted_inputs();
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::Catalog
        );
    }

    #[test]
    fn auth_ready_with_a_fresh_target_opens_setup() {
        let mut i = targeted_inputs();
        i.model = Some("anthropic:claude-sonnet-4-6");
        i.provider_auth_ready = true;
        i.workspace_is_fresh = true;
        assert_eq!(initial_onboarding_phase(&i), InitialOnboardingPhase::Setup);
    }

    #[test]
    fn auth_ready_with_returning_target_lands_on_catalog_for_workbench_start() {
        let mut i = targeted_inputs();
        i.model = Some("anthropic:claude-sonnet-4-6");
        i.provider_auth_ready = true;
        i.workspace_is_fresh = false;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::Catalog
        );
    }

    #[test]
    fn auth_ready_without_a_target_lands_on_catalog() {
        let mut i = inputs();
        i.model = Some("anthropic:claude-sonnet-4-6");
        i.provider_auth_ready = true;
        i.has_target = false;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::Catalog
        );
    }
}
