//! Partial imports remain inactive drafts until explicit Map review.
use super::*;

pub(super) fn validate_activation(
    input: &Value,
    verification: &ThreatModelVerification,
) -> Result<()> {
    if verification.has_partial_catalog() {
        anyhow::ensure!(
            input["activate"] == false,
            "Partial context imports require activate=false. Inspect the saved draft and acknowledge partial evidence during Map review before planning scans."
        );
    }
    Ok(())
}

pub(super) fn warning(verification: &ThreatModelVerification) -> Option<String> {
    verification.has_partial_catalog().then(|| {
        verification.grounding_degraded.clone().unwrap_or_else(|| {
            "Entry-point coverage is partial; unseen entry points remain unknown.".into()
        })
    })
}

pub(super) fn result(
    summary: String,
    output: String,
    data: Value,
    warning: Option<String>,
) -> Value {
    let Some(warning) = warning else {
        return crate::module_result::completed_output_result(summary, output, data);
    };
    crate::module_result::partial_output_result(
        summary,
        format!("{output}\n{warning}"),
        vec![json!(warning)],
        data,
    )
}
