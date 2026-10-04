//! Reuse scanner selection validation before publishing a study draft.
use anyhow::Result;
use serde_json::Value;

pub(crate) fn validate_study_scan_selection(input: &Value) -> Result<()> {
    let selection = super::application::sast_scan::prepare_sast_task_selection(input)?;
    selection.ensure_non_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn study_rejects_unknown_names_before_any_work_is_published() {
        for tasks in [json!(["[\"secret-scan\"]"]), json!(["nonexistent-scanner"]), json!([])] {
            let result = validate_study_scan_selection(&json!({"taskMode":"manual", "tasks":tasks}));
            assert!(result.is_err(), "invalid explicit selection accepted");
        }
        validate_study_scan_selection(&json!({"taskMode":"manual","tasks":["secret-scan"]})).unwrap();
        validate_study_scan_selection(&json!({"taskMode":"manual","tasks":["agentic"]})).unwrap();
    }
}
