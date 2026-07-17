use super::*;

pub(in crate::modules) fn write_verify_jsonl(
    artifacts: &SastRunArtifacts,
    verify_output: &Value,
) -> Result<()> {
    append_jsonl(
        artifacts,
        SAST_VERIFY_JSONL_FILE,
        json!({
            "type": sast_event_type("verification", verify_output),
            "fingerprint": verify_output.pointer("/data/fingerprint").cloned().unwrap_or(Value::Null),
            "data": verify_output.get("data").cloned().unwrap_or(Value::Null),
        }),
    )
}

pub(in crate::modules) fn write_patch_jsonl(
    artifacts: &SastRunArtifacts,
    fingerprint: &str,
    patch_output: &Value,
) -> Result<()> {
    append_jsonl(
        artifacts,
        SAST_PATCH_JSONL_FILE,
        json!({
            "type": sast_event_type("patch", patch_output),
            "fingerprint": fingerprint,
            "data": patch_output.get("data").cloned().unwrap_or(Value::Null),
        }),
    )
}

pub(in crate::modules) fn sast_event_type(prefix: &str, output: &Value) -> String {
    let status = match crate::module_result::tool_result_status(output) {
        crate::module_result::ToolResultStatus::Completed => "complete",
        crate::module_result::ToolResultStatus::Partial => "partial",
        crate::module_result::ToolResultStatus::Skipped => "skipped",
        crate::module_result::ToolResultStatus::Failed => "failed",
    };
    format!("{prefix}:{status}")
}

pub(in crate::modules) fn append_jsonl(
    artifacts: &SastRunArtifacts,
    leaf: &str,
    value: Value,
) -> Result<()> {
    artifacts.append_jsonl(leaf, &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonl_event_type_preserves_skipped_and_failed_truth() {
        assert_eq!(
            sast_event_type("triage", &json!({"status": "skipped"})),
            "triage:skipped"
        );
        assert_eq!(
            sast_event_type("verify", &json!({"ok": false, "status": "failed"})),
            "verify:failed"
        );
    }
}
