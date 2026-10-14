//! Setup names the chosen import source without reading it or starting work.
use super::*;

pub(super) fn import_row(app: &ShellApp) -> SetupReadinessRow {
    let input = match app.validated_context_import_input() {
        Ok(input) => input,
        Err(error) => {
            return readiness_rows::blocked_row(
                SetupRowId::ThreatModel,
                "Context import",
                "DOCUMENT",
                format!("{error}. Enter opens the document options."),
            )
        }
    };
    let source = import_source_label(&input);
    let pointer = if input["activate"] == true {
        "changes the active context"
    } else {
        "saves an inactive revision"
    };
    readiness_rows::ready_row(SetupRowId::ThreatModel, "Context import", "READY", format!("{source} · {pointer}. Document and source checks run during import. Inspect and accept the Map result before scanning. No model request. Enter edits import options."))
}

fn import_source_label(input: &serde_json::Value) -> String {
    if input.get("document").is_some_and(|value| !value.is_null()) {
        return "Inline JSON document".into();
    }
    input["path"]
        .as_str()
        .unwrap_or("document source unavailable")
        .into()
}
