use super::*;

pub(crate) fn failed_tool_result_with_context(
    target: &Path,
    run_id: &str,
    tool: &str,
    error: &str,
    artifacts: &[RunArtifact],
) -> Value {
    output_with_run_fallback_context(target, run_id, failed_tool_result(tool, error, artifacts))
}

fn failed_tool_result(tool: &str, error: &str, artifacts: &[RunArtifact]) -> Value {
    let error = crate::session_transcript::redaction::redact_text(error);
    let mut result = crate::module_result::failed_output_result(
        format!("{tool} failed"),
        error.clone(),
        serde_json::json!({
            "tool": tool,
            "error": error,
        }),
    );
    if let Some(object) = result.as_object_mut() {
        object.insert("artifacts".to_string(), serde_json::json!(artifacts));
    }
    result
}
