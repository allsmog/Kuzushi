use super::*;
use crate::capabilities::threat_model::{inspect_goal_guidance, load_exact_threat_model};
use crate::ThreatModelRef;
use serde_json::json;

pub(in crate::workspace::application::investigation_report) fn recorded_context_guidance(
    workspace: &WorkspaceTarget,
    input: &Value,
) -> Value {
    let Some(selected) = input.get("threatModelRef") else {
        return json!({"status":"unbound","message":"This historical input has no explicit context reference. No active context was inspected."});
    };
    if selected.is_null() {
        return json!({"status":"omitted","message":"Threat-model context was explicitly omitted."});
    }
    match inspect_selected(workspace, selected) {
        Ok(goal) => goal,
        Err(error) => {
            json!({"status":"unavailable","message":format!("Recorded context guidance unavailable: {error}. No current context or goal substituted.")})
        }
    }
}

fn inspect_selected(workspace: &WorkspaceTarget, selected: &Value) -> Result<Value> {
    let reference: ThreatModelRef = serde_json::from_value(selected.clone())
        .context("Recorded context reference is malformed")?;
    let document = load_exact_threat_model(workspace.root(), &reference)?;
    let mut state = inspect_goal_guidance(workspace.root(), &document);
    state["contextRef"] = json!(reference);
    Ok(state)
}
