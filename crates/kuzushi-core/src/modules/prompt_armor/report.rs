use super::prelude::*;
use super::*;

pub(in crate::modules) fn report(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let out_dir = target.join(".prompt-armor");
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("Could not create {}", out_dir.display()))?;
    let output = string_input_any(&input, &["output"])
        .map(|path| resolve_input_path(&target, &path))
        .unwrap_or_else(|| out_dir.join("report.md"));
    let mut entries = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&out_dir) {
        for entry in read_dir.filter_map(|entry| entry.ok()) {
            entries.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    entries.sort();
    let body = format!(
        "# PromptArmor Report\n\nArtifacts in `.prompt-armor`: {}\n",
        if entries.is_empty() {
            "none".to_string()
        } else {
            entries.join(", ")
        }
    );
    fs::write(&output, &body).with_context(|| format!("Could not write {}", output.display()))?;
    Ok(json!({
        "ok": true,
        "output": format!("prompt-armor:report complete\nReport: {}", output.display()),
        "data": {
            "reportPath": output.display().to_string(),
            "artifacts": entries,
        },
    }))
}
