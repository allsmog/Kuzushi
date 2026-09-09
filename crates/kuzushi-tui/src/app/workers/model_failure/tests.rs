use super::*;
use kuzushi_core::runtime::{RuntimeFailure, RuntimeFailureClass as Class};

#[test]
fn model_failure_keeps_every_typed_category_across_the_worker_boundary() {
    let classes = [
        Class::Authentication,
        Class::BridgeInternal,
        Class::Cancelled,
        Class::McpTimeout,
        Class::McpUnavailable,
        Class::ProviderRejected,
        Class::ProviderResponseInvalid,
        Class::ProviderUnavailable,
        Class::RateLimited,
        Class::SdkClientValidation,
        Class::Timeout,
        Class::Transport,
        Class::RuntimeError,
    ];
    for class in classes {
        let metadata = RuntimeFailureMetadata::new(class, Some(400), Some("PRIVATE_SOURCE"));
        let failure = anyhow::Error::new(RuntimeFailure::new(metadata.clone()))
            .context("wrapper with PRIVATE_SOURCE");
        let event = failed_agent_event(
            CostedWorkerError::unresolved(failure),
            AgentCallAudit::test(),
        );
        let AgentEvent::Failed { error, audit } = event else {
            panic!("failed event expected")
        };
        assert_eq!(error, metadata.public_message());
        assert_eq!(audit.failure, Some(metadata));
        assert!(audit.call_attempted);
        assert!(!audit.settlement_cost().is_complete());
        assert!(!error.contains("PRIVATE_SOURCE"));
    }
}

#[test]
fn model_failure_legacy_errors_keep_only_the_category_and_preflight_cost_truth() {
    let error = anyhow::anyhow!("network connection failed PRIVATE_SOURCE");
    let event = failed_agent_event(
        CostedWorkerError::before_call(error),
        AgentCallAudit::test(),
    );
    let AgentEvent::Failed { error, audit } = event else {
        panic!("failed event expected")
    };
    assert_eq!(audit.failure.unwrap().error_class, Class::Transport);
    assert!(!audit.call_attempted);
    assert!(!error.contains("PRIVATE_SOURCE"));
    assert!(!error.contains("HTTP"));
}

#[test]
fn model_failure_summary_keeps_persistence_disclosure_without_provider_text() {
    let error = anyhow::Error::new(RuntimeFailure::new(RuntimeFailureMetadata::new(
        Class::ProviderRejected,
        Some(400),
        None,
    )));
    let audit = AgentCallAudit::test().with_failure(&error);
    let summary = audit.failure_summary(&format!("PRIVATE_SOURCE{PERSISTENCE_FAILURE}"));
    assert_eq!(
        summary,
        format!("Provider rejected the request (HTTP 400).{PERSISTENCE_FAILURE}")
    );
    assert_eq!(audit.failure_summary(&summary), summary);
}

#[test]
fn model_failure_classification_never_invents_http_status_from_legacy_text() {
    let event = failed_agent_event(
        CostedWorkerError::unresolved(anyhow::anyhow!("PRIVATE_SOURCE 401 token=secret")),
        AgentCallAudit::test(),
    );
    let AgentEvent::Failed { error, audit } = event else {
        panic!("failed event expected")
    };
    assert_eq!(audit.failure.unwrap().error_class, Class::Authentication);
    assert_eq!(error, "Provider authentication failed.");
}
