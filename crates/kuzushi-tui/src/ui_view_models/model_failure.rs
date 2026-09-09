use crate::app::AgentCallAudit;
use kuzushi_core::runtime::RuntimeFailureClass as Class;

pub(crate) fn model_failure_text(
    audit: &AgentCallAudit,
    error: &str,
    run_id: Option<&str>,
) -> String {
    let failure = audit.failure_metadata(error);
    let mut lines = vec![audit.failure_summary(error)];
    let next = recovery_step(failure.error_class, failure.detail.as_deref());
    // Canonical client/model details add a repair step beyond the class guidance.
    // Legacy auth detail contains a CLI login command that is shell-only now.
    if matches!(
        failure.error_class,
        Class::SdkClientValidation | Class::ProviderRejected
    ) {
        lines.extend(failure.detail);
    }
    lines.push(format!("Next: {next}"));
    lines.push("Commands: Ctrl+G opens the command palette.".to_string());
    if let Some(run_id) = run_id {
        lines.push(format!("Details: /trace {run_id}"));
    }
    lines.join("\n")
}

fn recovery_step(class: Class, detail: Option<&str>) -> &'static str {
    if class == Class::ProviderRejected && detail.is_some() {
        return "Open /model and explicitly select an available model before retrying.";
    }
    RECOVERY_STEPS
        .iter()
        .find_map(|(candidate, step)| (*candidate == class).then_some(*step))
        .unwrap_or("Open /doctor to check the runtime before retrying.")
}

const RECOVERY_STEPS: &[(Class, &str)] = &[
    (
        Class::Authentication,
        "Open /auth to check credentials for the selected provider and reconnect, then retry.",
    ),
    (
        Class::BridgeInternal,
        "Open /doctor to check the runtime before retrying. Inspect the run if the failure persists.",
    ),
    (
        Class::Cancelled,
        "The request stopped. Review the question before sending it again.",
    ),
    (
        Class::McpTimeout,
        "Inspect the timed-out tool in the run trace. Retry after checking its availability and scope.",
    ),
    (
        Class::McpUnavailable,
        "Open /doctor and restore the missing code-analysis component before retrying.",
    ),
    (
        Class::ProviderRejected,
        "Check the selected model with /model and its request settings with /config before retrying.",
    ),
    (
        Class::ProviderResponseInvalid,
        "Retry with the selected model. If it fails again, inspect the run and check provider compatibility.",
    ),
    (
        Class::ProviderUnavailable,
        "Wait for the provider to recover, then retry with the selected model.",
    ),
    (
        Class::RateLimited,
        "Wait for provider capacity or quota to reset, then retry with the selected model.",
    ),
    (
        Class::SdkClientValidation,
        "Check /config for incompatible model request settings. Correct them before retrying.",
    ),
    (
        Class::Timeout,
        "Check the provider's availability and request scope, then retry when ready.",
    ),
    (
        Class::Transport,
        "Check network access to the provider, then retry with the selected model.",
    ),
    (
        Class::RuntimeError,
        "Open /doctor to check the runtime before retrying. Inspect the run if the failure persists.",
    ),
];

#[cfg(test)]
mod tests;
