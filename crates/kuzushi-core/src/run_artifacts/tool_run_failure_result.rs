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
    serde_json::json!({
        "ok": false,
        "status": "failed",
        "summary": format!("{tool} failed"),
        "artifacts": artifacts,
        "warnings": [],
        "errors": [error],
    })
}
