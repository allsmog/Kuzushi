//! Report exact historical context without reading the active context or goal.
use super::*;
use crate::capabilities::threat_model::{inspect_goal_guidance, load_exact_threat_model};
use crate::ThreatModelRef;
use serde_json::json;

mod source_context;

pub(in crate::workspace::application::investigation_report) struct RecordedContextReport {
    pub(in crate::workspace::application::investigation_report) guidance: Value,
    pub(in crate::workspace::application::investigation_report) evidence: Value,
}

pub(in crate::workspace::application::investigation_report) fn recorded_context_report(
    workspace: &WorkspaceTarget,
    input: &Value,
) -> RecordedContextReport {
    match input.get("threatModelRef") {
        None => unavailable("unbound", "This historical input has no explicit context reference. No active context was inspected."),
        Some(Value::Null) => unavailable("omitted", "Threat-model context was explicitly omitted."),
        Some(selected) => inspect_or_unavailable(workspace, selected),
    }
}

fn inspect_or_unavailable(workspace: &WorkspaceTarget, selected: &Value) -> RecordedContextReport {
    match inspect_selected(workspace, selected) {
        Ok(report) => report,
        Err(error) => unavailable("unavailable", &format!("Recorded context guidance unavailable: {error}. No current context or goal substituted.")),
    }
}

fn unavailable(status: &str, message: &str) -> RecordedContextReport {
    let guidance = json!({"status":status,"message":message});
    RecordedContextReport {
        evidence: json!({"schemaVersion":1,"status":status,"message":message}),
        guidance,
    }
}

fn inspect_selected(
    workspace: &WorkspaceTarget,
    selected: &Value,
) -> Result<RecordedContextReport> {
    let reference: ThreatModelRef = serde_json::from_value(selected.clone())
        .context("Recorded context reference is malformed")?;
    let document = load_exact_threat_model(workspace.root(), &reference)?;
    let mut guidance = inspect_goal_guidance(workspace.root(), &document);
    guidance["contextRef"] = json!(reference);
    let evidence = json!({"schemaVersion":1,"status":"recorded","contextRef":reference,
        "verification":document.get("verification"),
        "repositoryInventory":document.pointer("/provenance/repositoryInventory"),
        "sourceContext":source_context::project(&document)});
    Ok(RecordedContextReport { guidance, evidence })
}
