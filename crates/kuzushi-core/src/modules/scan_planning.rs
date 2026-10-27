//! Reuse scanner selection validation before publishing a study draft.
use anyhow::Result;
use serde_json::Value;
mod inactive_options;
mod task_preview;
pub use inactive_options::{inactive_scan_task_options, InactiveScanTaskOptions};
pub use task_preview::ScanTaskPreview;

pub(crate) fn bind_dispatch_scan_scope(
    name: &str,
    input: Value,
    ctx: &super::ToolExecutionContext<'_>,
) -> Result<Value> {
    if name != "sast:scan" {
        return Ok(input);
    }
    validate_study_scan_selection(&input)?;
    let Some(workspace) = ctx.workspace else {
        return Ok(input);
    };
    super::application::sast_scan::bind_accepted_sast_scope_input(input, ctx).and_then(|input| {
        super::application::sast_scan::bind_sast_scope_input(input, workspace.root())
    })
}

pub(crate) fn validate_study_scan_selection(input: &Value) -> Result<()> {
    let selection = super::application::sast_scan::prepare_sast_task_selection(input)?;
    selection.ensure_non_empty()
}

/// Capability-only preview. This does not authenticate source, dependencies,
/// credentials or allowance. Prepared dispatch remains the admission boundary.
pub fn validate_scan_scope_contract(input: &Value) -> Result<()> {
    super::application::sast_scan::requested_scope_contracts(input)?.ensure_non_empty()?;
    if input.get("scanScopeRef").is_some() {
        super::application::sast_scan::validate_exact_scope_request(input)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn capability_preview_uses_the_executor_scope_contract_without_reading_saved_objects() {
        let reference = json!({"proposal":{"proposalId":"absent","revision":1,"recordHash":"a".repeat(64)},"scopeId":"repository"});
        for task in ["secret-scan", "semgrep", "agentic"] {
            validate_scan_scope_contract(
                &json!({"taskMode":"manual","tasks":[task],"scanScopeRef":reference}),
            )
            .unwrap();
        }
        for task in [
            "offense-review",
            "systems-hunt",
            "codeql",
            "dep-hygiene",
            "unknown",
        ] {
            assert!(validate_scan_scope_contract(
                &json!({"taskMode":"manual","tasks":[task],"scanScopeRef":reference})
            )
            .is_err());
        }
        assert!(validate_scan_scope_contract(&json!({"taskMode":"manual","tasks":["secret-scan"],"scanScopeRef":reference,"paths":["."]})).is_err());
    }

    #[test]
    fn study_rejects_unknown_names_before_any_work_is_published() {
        for tasks in [
            json!(["[\"secret-scan\"]"]),
            json!(["nonexistent-scanner"]),
            json!([]),
        ] {
            let result =
                validate_study_scan_selection(&json!({"taskMode":"manual", "tasks":tasks}));
            assert!(result.is_err(), "invalid explicit selection accepted");
        }
        validate_study_scan_selection(&json!({"taskMode":"manual","tasks":["secret-scan"]}))
            .unwrap();
        validate_study_scan_selection(&json!({"taskMode":"manual","tasks":["agentic"]})).unwrap();
    }
}
