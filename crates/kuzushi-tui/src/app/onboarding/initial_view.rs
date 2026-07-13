use super::task_id::PlanningTaskId;
use super::task_row::{ArtifactState, PlanningTaskRow};
use kuzushi_core::V2Config;
use std::path::Path;

use crate::app::settings::AuthProvider;

/// Distinct phases of the first-run onboarding sequence. The shell
/// transitions through them in this order — Target → Model → Credentials →
/// Planning — but may short-circuit when a phase is already satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitialOnboardingPhase {
    /// First gate: pick what to scan. Only offered from the interactive
    /// terminal launch (`allow_target_gate`); never silently defaults to cwd.
    TargetPicker,
    ModelPicker,
    /// Inline credential entry (API-key paste / OAuth / offline demo) for a
    /// credentialed provider whose credentials are missing.
    AuthMethodPicker {
        provider: String,
    },
    PlanningPicker,
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

impl<'a> OnboardingInputs<'a> {
    pub fn provider(&self) -> Option<&str> {
        self.model.and_then(|model| model.split(':').next())
    }
}

/// Ordered onboarding gate: Target → Model → Credentials → Planning. Each
/// stage is skipped once it is already satisfied.
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
    if inputs.model.is_none() {
        return InitialOnboardingPhase::ModelPicker;
    }
    if let Some(phase) = auth_phase(inputs) {
        return phase;
    }
    if inputs.workspace_is_fresh {
        InitialOnboardingPhase::PlanningPicker
    } else {
        InitialOnboardingPhase::Catalog
    }
}

/// Credentials gate: open inline credential entry when a *credentialed*
/// provider has no wired credentials. Providers that need no credentials
/// (e.g. `local:`) are never gated.
fn auth_phase(inputs: &OnboardingInputs<'_>) -> Option<InitialOnboardingPhase> {
    if inputs.provider_auth_ready {
        return None;
    }
    let provider = credentialed_provider(inputs.provider()?)?;
    Some(InitialOnboardingPhase::AuthMethodPicker {
        provider: provider.to_string(),
    })
}

/// The providers whose credentials are gated by the onboarding flow. Anything
/// else (`local:`, unknown) needs no credentials and returns `None`.
pub fn credentialed_provider(provider: &str) -> Option<&str> {
    match AuthProvider::from_scene_provider(provider) {
        Some(AuthProvider::OpenAi | AuthProvider::Anthropic) => Some(provider),
        Some(AuthProvider::GitHubCopilot) | None => None,
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
    fn targeted_session_without_model_opens_model_picker() {
        let i = targeted_inputs();
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::ModelPicker
        );
    }

    #[test]
    fn credentialed_provider_with_no_creds_opens_credential_entry() {
        let mut i = targeted_inputs();
        i.model = Some("anthropic:claude-sonnet-4-6");
        i.provider_auth_ready = false;
        match initial_onboarding_phase(&i) {
            InitialOnboardingPhase::AuthMethodPicker { provider } => {
                assert_eq!(provider, "anthropic");
            }
            other => panic!("expected AuthMethodPicker, got {other:?}"),
        }
    }

    #[test]
    fn openai_with_no_creds_opens_credential_entry() {
        let mut i = targeted_inputs();
        i.model = Some("openai:gpt-5.5");
        i.provider_auth_ready = false;
        match initial_onboarding_phase(&i) {
            InitialOnboardingPhase::AuthMethodPicker { provider } => {
                assert_eq!(provider, "openai");
            }
            other => panic!("expected AuthMethodPicker, got {other:?}"),
        }
    }

    #[test]
    fn uncredentialed_provider_never_gates_on_auth() {
        let mut i = targeted_inputs();
        i.model = Some("local:llama");
        i.provider_auth_ready = false;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::Catalog
        );
    }

    #[test]
    fn credentialed_provider_recognizes_the_gated_set() {
        assert_eq!(credentialed_provider("anthropic"), Some("anthropic"));
        assert_eq!(credentialed_provider("openai"), Some("openai"));
        assert_eq!(credentialed_provider("openai-codex"), Some("openai-codex"));
        assert_eq!(credentialed_provider("local"), None);
    }

    #[test]
    fn auth_ready_with_a_fresh_target_opens_the_phase_walker() {
        let mut i = targeted_inputs();
        i.model = Some("anthropic:claude-sonnet-4-6");
        i.provider_auth_ready = true;
        i.workspace_is_fresh = true;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::PlanningPicker
        );
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
