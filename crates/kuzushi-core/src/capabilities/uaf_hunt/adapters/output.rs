use crate::capabilities::uaf_hunt::domain::UafHuntReport;
use serde_json::{json, Value};

pub fn report_to_tool_json(report: &UafHuntReport) -> Value {
    let mut summary = json!({
        "count": report.count,
        "compileCommandsPath": report.compile_commands_path,
        "clangToolCalls": report.clang_tool_calls,
        "stepsUsed": report.steps_used,
        "truncated": report.truncated,
        "costUsd": report.cost_usd,
    });
    if let (Some(err), Some(map)) = (report.first_clang_error.as_deref(), summary.as_object_mut()) {
        map.insert(
            "firstClangError".to_string(),
            Value::String(err.to_string()),
        );
    }
    json!({
        "ok": true,
        "data": report,
        "summary": summary,
    })
}
