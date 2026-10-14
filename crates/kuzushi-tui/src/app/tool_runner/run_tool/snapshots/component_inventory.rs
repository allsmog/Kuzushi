use super::*;
use serde_json::Value;
use std::path::Path;

pub(super) fn cache_result(app: &mut ShellApp, result: &Value) {
    let Some(target) = result.pointer("/data/target").and_then(Value::as_str) else {
        app.log("components", "Inventory receipt has no target. Previous evidence is kept; inspect the recorded outcome.");
        return;
    };
    if app.target() != Some(Path::new(target)) {
        return;
    }
    let update = inventory_result(result);
    if !app
        .session_mut()
        .apply_component_inventory(Path::new(target), update)
    {
        app.log(
            "components",
            "Inventory receipt is available. Reopen Setup to collect this target's facts.",
        );
    }
}

fn inventory_result(result: &Value) -> Result<kuzushi_core::SbomScanReport, String> {
    if kuzushi_core::tool_result_status(result) != kuzushi_core::ToolResultStatus::Completed {
        return Err(result.get("error").and_then(Value::as_str)
            .or_else(|| result.pointer("/errors/0").and_then(Value::as_str))
            .or_else(|| result.get("summary").and_then(Value::as_str))
            .unwrap_or("Dependency inventory did not complete. Inspect its recorded outcome before retrying.").to_string());
    }
    serde_json::from_value(result["data"].clone()).map_err(|error| {
        format!("Dependency inventory receipt is malformed: {error}. Inspect its recorded outcome.")
    })
}
