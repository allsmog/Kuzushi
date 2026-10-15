use super::{AgentCallAudit, AgentEvent, CostedWorkerError};
use kuzushi_core::runtime::{
    model_failure_metadata, safe_model_failure_message, RuntimeFailureMetadata,
};

const PERSISTENCE_FAILURE: &str = "; additionally, terminal run persistence failed";

impl AgentCallAudit {
    pub(crate) fn refused_before_provider_request(&self) -> bool {
        !self.call_attempted
            && self.failure.as_ref().is_some_and(|failure| {
                failure.error_class == kuzushi_core::RuntimeFailureClass::AllowanceRefused
            })
    }

    pub(crate) fn with_failure(mut self, error: &anyhow::Error) -> Self {
        self.failure = Some(model_failure_metadata(error));
        self
    }

    pub(crate) fn failure_metadata(&self, message: &str) -> RuntimeFailureMetadata {
        self.failure
            .clone()
            .unwrap_or_else(|| model_failure_metadata(&anyhow::anyhow!("{message}")))
    }

    pub(crate) fn failure_summary(&self, message: &str) -> String {
        let Some(failure) = &self.failure else {
            return safe_model_failure_message(message);
        };
        let mut summary = failure.public_message();
        if message.ends_with(PERSISTENCE_FAILURE) {
            summary.push_str(PERSISTENCE_FAILURE);
        }
        summary
    }
}

pub(super) fn failed_agent_event(error: CostedWorkerError, audit: AgentCallAudit) -> AgentEvent {
    let audit = audit
        .with_outcome(error.cost, error.call_attempted)
        .with_failure(&error.error);
    AgentEvent::Failed {
        error: audit.failure_summary(""),
        audit,
    }
}

#[cfg(test)]
mod tests;
