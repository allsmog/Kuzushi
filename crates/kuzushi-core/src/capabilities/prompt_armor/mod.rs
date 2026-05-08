use anyhow::{Context, Result};
pub(crate) use build_prompt::build_prompt;
pub(crate) use report::{config, diff, report};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
pub(crate) use structured_output::{findings_schema, require_json_object};
mod build_prompt;
mod report;
mod structured_output;

pub(crate) fn command_from_tool_name(tool_name: &str) -> &str {
    tool_name.trim_start_matches("prompt-armor:")
}

pub(crate) fn requires_authorization(command: &str) -> bool {
    matches!(command, "scan" | "attack")
}

pub(crate) fn unauthorized_response(tool_name: &str) -> Value {
    json!({
        "ok": false,
        "output": format!("{tool_name} refuses to run: pass authorized=true to confirm you have authorization to test the target endpoint. This command can generate real traffic."),
    })
}

pub(crate) fn output_dir(target: &Path) -> PathBuf {
    target.join(".prompt-armor")
}

fn json_summary(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}
