//! Explicit consent before an OAuth credential choice changes the model.
//!
//! Kuzushi never switches model without the operator's say-so. Choosing the
//! OAuth method for a provider whose OAuth transport uses another model
//! namespace therefore parks the choice behind a `ModelSwitch` confirmation:
//! yes continues the choice (reuse or login) exactly as before, no keeps the
//! current model and leaves the credential picker open.

use super::*;
use crate::app::{auth_provider_label, display_model_selector, AuthModelSwitch};
use crate::{ConfirmKind, PendingConfirm};

/// The credential choice that waits on the operator's model-switch answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingModelSwitchConsent {
    pub(crate) provider: String,
    pub(crate) reuse_stored_credential: bool,
}

impl ShellApp {
    /// Ask before an OAuth credential choice switches `selection` in.
    pub(crate) fn request_oauth_model_switch_consent(
        &mut self,
        provider: &str,
        selection: &AuthModelSwitch,
        reuse_stored_credential: bool,
    ) {
        let request = PendingConfirm {
            kind: ConfirmKind::ModelSwitch,
            tool: format!("{} OAuth", auth_provider_label(provider)),
            target: self.model_switch_target_label(selection),
            rationale: Some(format!(
                "Choosing OAuth switches {}. y switches · n keeps the current model",
                self.model_switch_scope_label()
            )),
            allowlist: None,
            actor: None,
            remembered: false,
        };
        self.request_confirm(request);
        self.advisory_mut().pending_confirm_model_switch = Some(PendingModelSwitchConsent {
            provider: provider.to_string(),
            reuse_stored_credential,
        });
    }

    /// Continue or abandon the parked choice once the operator answered.
    pub(crate) fn resolve_model_switch_consent(&mut self, approved: bool) -> Vec<ShellEffect> {
        let Some(consent) = self.advisory_mut().pending_confirm_model_switch.take() else {
            return Vec::new();
        };
        if !approved {
            self.set_info_notice(
                "onboarding",
                "Model unchanged; choose another credential method, or confirm the OAuth switch.",
            );
            return Vec::new();
        }
        self.continue_oauth_choice(&consent.provider, consent.reuse_stored_credential)
    }

    fn model_switch_target_label(&self, selection: &AuthModelSwitch) -> String {
        let to = display_model_selector(&selection.model);
        if self.pending_auth_switch_is_step_scoped() {
            return format!("paused step → {to}");
        }
        let from = self
            .config()
            .model
            .as_deref()
            .map(display_model_selector)
            .unwrap_or_else(|| "no model".to_string());
        format!("{from} → {to}")
    }

    fn model_switch_scope_label(&self) -> &'static str {
        if self.pending_auth_switch_is_step_scoped() {
            "the paused step's model"
        } else {
            "the configured model"
        }
    }
}
