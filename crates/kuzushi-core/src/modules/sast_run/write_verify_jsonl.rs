use super::*;

pub(in crate::modules) fn write_verify_jsonl(
    artifacts: &SastRunArtifacts,
    verify_output: &Value,
) -> Result<()> {
    append_jsonl(
        &artifacts.verify_jsonl,
        json!({
            "type": "verification:complete",
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
        &artifacts.verify_jsonl,
        json!({
            "type": "patch:complete",
            "fingerprint": fingerprint,
            "data": patch_output.get("data").cloned().unwrap_or(Value::Null),
        }),
    )
}

pub(in crate::modules) fn append_jsonl(path: &Path, value: Value) -> Result<()> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(&value)?)
        .with_context(|| format!("Could not write {}", path.display()))
}
