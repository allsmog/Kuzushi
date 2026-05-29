use super::task_id::PlanningTaskId;
use super::task_row::{ArtifactState, PlanningTaskRow};
use kuzushi_core::V2Config;
use std::path::Path;

/// Distinct phases of the first-run onboarding sequence. The shell
/// transitions through them in this order, but may short-circuit when
/// a phase is already satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitialOnboardingPhase {
    ModelPicker,
    AuthMethodPicker { provider: String },
    PlanningPicker,
    Catalog,
}

/// Inputs that drive `initial_onboarding_phase`. Split out so the
/// decision is fully testable without a live `ShellApp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingInputs<'a> {
    pub model: Option<&'a str>,
    pub provider_auth_ready: bool,
    pub provider_has_multiple_auth_methods: bool,
    /// Whether the shell was launched against a real workspace target. The
    /// phase walker opens at 組 KUMI-KATA · map whenever there is a target to
    /// act on — it offers reuse-or-rebuild for any cached artifacts rather than
    /// only appearing when something is missing.
    pub has_target: bool,
    pub skip_onboarding_env: bool,
}

impl<'a> OnboardingInputs<'a> {
    pub fn provider(&self) -> Option<&str> {
        self.model.and_then(|model| model.split(':').next())
    }
}

pub fn initial_onboarding_phase(inputs: &OnboardingInputs<'_>) -> InitialOnboardingPhase {
    if let Some(phase) = pre_auth_phase(inputs) {
        return phase;
    }
    if let Some(phase) = auth_phase(inputs) {
        return phase;
    }
    if inputs.has_target {
        InitialOnboardingPhase::PlanningPicker
    } else {
        InitialOnboardingPhase::Catalog
    }
}

/// Phases that precede auth: an explicit skip, or no model chosen yet.
fn pre_auth_phase(inputs: &OnboardingInputs<'_>) -> Option<InitialOnboardingPhase> {
    if inputs.skip_onboarding_env {
        return Some(InitialOnboardingPhase::Catalog);
    }
    if inputs.model.is_none() {
        return Some(InitialOnboardingPhase::ModelPicker);
    }
    None
}

/// Auth gating: pick an auth method when several exist and none is wired, or
/// fall back to the catalog when the chosen provider has no credentials.
fn auth_phase(inputs: &OnboardingInputs<'_>) -> Option<InitialOnboardingPhase> {
    if inputs.provider_has_multiple_auth_methods && !inputs.provider_auth_ready {
        let provider = inputs
            .provider()
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        return Some(InitialOnboardingPhase::AuthMethodPicker { provider });
    }
    (!inputs.provider_auth_ready).then_some(InitialOnboardingPhase::Catalog)
}

/// Convenience wrapper that builds `OnboardingInputs` from live config +
/// target paths and returns the next phase. Reads the
/// `KUZUSHI_SKIP_ONBOARDING` env var.
pub fn initial_onboarding_phase_for(
    config: &V2Config,
    target: Option<&Path>,
    auth_ready: bool,
    has_multiple_auth_methods: bool,
) -> InitialOnboardingPhase {
    let inputs = OnboardingInputs {
        model: config.model.as_deref(),
        provider_auth_ready: auth_ready,
        provider_has_multiple_auth_methods: has_multiple_auth_methods,
        has_target: target.is_some(),
        skip_onboarding_env: skip_onboarding_env(),
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

pub fn provider_has_multiple_auth_methods(provider: &str) -> bool {
    matches!(provider, "anthropic" | "openai" | "openai-codex")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> OnboardingInputs<'static> {
        OnboardingInputs {
            model: None,
            provider_auth_ready: false,
            provider_has_multiple_auth_methods: false,
            has_target: false,
            skip_onboarding_env: false,
        }
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
    fn no_model_opens_model_picker() {
        let i = inputs();
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::ModelPicker
        );
    }

    #[test]
    fn model_with_multiple_auth_and_no_creds_opens_auth_picker() {
        let mut i = inputs();
        i.model = Some("anthropic:claude-sonnet-4-6");
        i.provider_has_multiple_auth_methods = true;
        i.provider_auth_ready = false;
        match initial_onboarding_phase(&i) {
            InitialOnboardingPhase::AuthMethodPicker { provider } => {
                assert_eq!(provider, "anthropic");
            }
            other => panic!("expected AuthMethodPicker, got {other:?}"),
        }
    }

    #[test]
    fn model_with_single_auth_and_no_creds_falls_through() {
        let mut i = inputs();
        i.model = Some("local:llama");
        i.provider_has_multiple_auth_methods = false;
        i.provider_auth_ready = false;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::Catalog
        );
    }

    #[test]
    fn auth_ready_with_a_target_opens_the_phase_walker() {
        let mut i = inputs();
        i.model = Some("anthropic:claude-sonnet-4-6");
        i.provider_auth_ready = true;
        i.has_target = true;
        assert_eq!(
            initial_onboarding_phase(&i),
            InitialOnboardingPhase::PlanningPicker
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

    #[test]
    fn known_multi_auth_providers() {
        assert!(provider_has_multiple_auth_methods("anthropic"));
        assert!(provider_has_multiple_auth_methods("openai"));
        assert!(provider_has_multiple_auth_methods("openai-codex"));
        assert!(!provider_has_multiple_auth_methods("local"));
    }
}
