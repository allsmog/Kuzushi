use super::*;

#[test]
fn missing_model_refusal_does_not_masquerade_as_exhausted_allowance() {
    let error = crate::runtime::require_configured_model("owned-model-check", None)
        .unwrap_err()
        .context("Owned prerequisite check");
    let error = refused(error);
    assert!(crate::runtime::is_pre_execution_refusal(&error));
    assert!(crate::runtime::runtime_failure_metadata(&error).is_none());
    assert!(format!("{error:#}").contains("requires an explicit model"));
    assert!(!format!("{error:#}").contains("allowance refused"));
}

#[test]
fn actual_allowance_errors_retain_their_admission_failure_class() {
    let error = refused(anyhow::anyhow!("Owned exhausted allowance"));
    assert!(!crate::runtime::is_pre_execution_refusal(&error));
    assert_eq!(
        crate::runtime::runtime_failure_metadata(&error)
            .unwrap()
            .error_class,
        crate::RuntimeFailureClass::AllowanceRefused
    );
}
