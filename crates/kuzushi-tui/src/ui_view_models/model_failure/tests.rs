use super::*;
use kuzushi_core::runtime::{RuntimeFailure, RuntimeFailureMetadata};

fn audit(class: Class, status: Option<u16>, detail: Option<&str>) -> AgentCallAudit {
    AgentCallAudit::test().with_failure(&anyhow::Error::new(RuntimeFailure::new(
        RuntimeFailureMetadata::new(class, status, detail),
    )))
}

#[test]
fn model_failure_recovery_distinguishes_request_rejection_from_credentials() {
    let rejected = model_failure_text(
        &audit(Class::ProviderRejected, Some(400), None),
        "private",
        Some("agent-run"),
    );
    assert!(rejected.contains("Provider rejected the request (HTTP 400)."));
    assert!(rejected.contains("Check the selected model with /model"));
    assert!(rejected.contains("Details: /trace agent-run"));
    assert!(!rejected.contains("/auth"));
    assert!(!rejected.contains("private"));

    let auth = model_failure_text(
        &audit(
            Class::Authentication,
            Some(401),
            Some("OpenAI OAuth authentication failed"),
        ),
        "private",
        None,
    );
    assert!(auth.contains("Open /auth to check credentials for the selected provider"));
    assert!(!auth.contains("kuzushi auth login"));
    assert!(!auth.contains("/trace"));
}

#[test]
fn model_failure_recovery_preserves_only_canonical_client_validation_detail() {
    let audit = audit(
        Class::SdkClientValidation,
        None,
        Some("temperature and thinking PRIVATE_SOURCE"),
    );
    let text = model_failure_text(&audit, "RAW_PROVIDER_RESPONSE", None);
    assert!(text.contains("omit the pinned temperature"));
    assert!(!text.contains("PRIVATE_SOURCE"));
    assert!(!text.contains("RAW_PROVIDER_RESPONSE"));
}

#[test]
fn model_failure_recovery_explains_unavailable_model_without_settings_or_auth_guess() {
    let detail = "The selected model is unavailable for this provider or account. Choose an available model explicitly.";
    let text = model_failure_text(
        &audit(Class::ProviderRejected, Some(400), Some(detail)),
        "PRIVATE_PROVIDER_RESPONSE",
        Some("agent-run"),
    );
    assert!(text.contains("Provider rejected the request (HTTP 400)."));
    assert!(text.contains(detail));
    assert!(text.contains("Open /model and explicitly select an available model before retrying."));
    assert!(!text.contains("/config"));
    assert!(!text.contains("/auth"));
    assert!(!text.contains("PRIVATE_PROVIDER_RESPONSE"));
}

#[test]
fn model_failure_recovery_has_one_action_for_every_known_category() {
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
        assert_eq!(
            RECOVERY_STEPS
                .iter()
                .filter(|(candidate, _)| *candidate == class)
                .count(),
            1
        );
        let text = model_failure_text(&audit(class, None, None), "RAW_PROVIDER_RESPONSE", None);
        assert!(text.contains("Next: "), "{class}");
        assert!(!text.contains("RAW_PROVIDER_RESPONSE"));
    }
}
