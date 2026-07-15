use super::*;

#[cfg(test)]
pub(crate) fn parse_plan_json(goal: &str, body: &str) -> Result<PlanProposal> {
    parse_plan_json_for_phase(goal, body, None)
}

pub(crate) fn parse_plan_json_for_phase(
    goal: &str,
    body: &str,
    phase_intent: Option<WorkflowPhase>,
) -> Result<PlanProposal> {
    let parsed = parse_planner_json(body)?;
    Ok(PlanProposal {
        goal: goal.to_string(),
        summary: plan_summary(&parsed, goal),
        changes: plan_changes(&parsed, phase_intent),
        unsupported: plan_unsupported(&parsed),
    })
}

fn parse_planner_json(body: &str) -> Result<serde_json::Value> {
    let json_start = body
        .find('{')
        .context("planner response had no JSON object")?;
    let json_end = body
        .rfind('}')
        .context("planner response had no closing JSON brace")?;
    if json_end <= json_start {
        anyhow::bail!("planner response had unbalanced JSON");
    }
    serde_json::from_str(&body[json_start..=json_end]).context("planner JSON did not parse")
}

fn plan_summary(parsed: &serde_json::Value, goal: &str) -> String {
    parsed
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(goal)
        .to_string()
}

fn plan_changes(
    parsed: &serde_json::Value,
    phase_intent: Option<WorkflowPhase>,
) -> Vec<PlanChange> {
    parsed
        .get("changes")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| parse_plan_change(item, phase_intent))
        .collect()
}

fn parse_plan_change(
    item: &serde_json::Value,
    phase_intent: Option<WorkflowPhase>,
) -> Option<PlanChange> {
    match item
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
    {
        "run_tool" => parse_run_tool_change(item, phase_intent),
        "set_option" => parse_set_option_change(item, phase_intent),
        "ask" => parse_text_change(item, "question", |question| PlanChange::Ask { question }),
        "note" => parse_text_change(item, "text", |text| PlanChange::Note { text }),
        _ => None,
    }
}

fn parse_run_tool_change(
    item: &serde_json::Value,
    phase_intent: Option<WorkflowPhase>,
) -> Option<PlanChange> {
    let phase = phase_intent?;
    let tool = item
        .get("tool")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|tool| !tool.is_empty())?
        .to_string();
    let input = item
        .get("input")
        .filter(|value| !value.is_null())
        .map(serde_json::Value::to_string);
    Some(PlanChange::RunTool { phase, tool, input })
}

fn parse_set_option_change(
    item: &serde_json::Value,
    phase_intent: Option<WorkflowPhase>,
) -> Option<PlanChange> {
    let name = string_field(item, "name")?;
    let value = item.get("value").map(plan_value_to_string)?;
    let global = item
        .get("global")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let tool = string_field(item, "tool").filter(|tool| !tool.is_empty());
    if phase_intent.is_some() && tool.is_none() {
        return None;
    }
    Some(PlanChange::SetOption {
        phase: phase_intent,
        global,
        tool,
        name,
        value,
    })
}

fn parse_text_change(
    item: &serde_json::Value,
    field: &str,
    change: impl FnOnce(String) -> PlanChange,
) -> Option<PlanChange> {
    string_field(item, field).map(change)
}

fn string_field(item: &serde_json::Value, field: &str) -> Option<String> {
    item.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn plan_unsupported(parsed: &serde_json::Value) -> Vec<String> {
    parsed
        .get("unsupported")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect()
}

pub(crate) fn plan_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub(crate) const THREAT_PATCH_SYSTEM_PROMPT: &str = r#"You are Kuzushi's threat-model patcher.
Given the current threat-model JSON and operator intent, output STRICT JSON:
{
  "summary": "one-sentence change description",
  "patch": { ... },         // deep-merge object — only changed/added keys
  "unsupported": [ ... ]    // operator-facing notes for changes you cannot encode
}

Rules:
- Output ONLY JSON, starting with '{'.
- Preserve existing fields you do not touch — the patch is a deep-merge, not a replacement.
- Set fields to null to delete them.
- Prefer additive changes."#;

pub(crate) const THREAT_REGEN_PROMPT: &str = "Regenerate the threat model with sharper coverage of likely attack surface, while preserving operator-edited stages and elements.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_tool_changes_require_and_preserve_the_selected_phase() {
        let body = r#"{
            "changes": [{"kind":"run_tool","tool":" semgrep:scan ","input":{"depth":2}}]
        }"#;
        let unscoped = parse_plan_json_for_phase("scan", body, None).unwrap();
        assert!(unscoped.changes.is_empty());

        let scoped = parse_plan_json_for_phase("scan", body, Some(WorkflowPhase::Scan)).unwrap();
        assert_eq!(
            scoped.changes,
            vec![PlanChange::RunTool {
                phase: WorkflowPhase::Scan,
                tool: "semgrep:scan".to_string(),
                input: Some(r#"{"depth":2}"#.to_string()),
            }]
        );
    }

    #[test]
    fn phase_intent_options_require_an_explicit_tool_and_keep_the_phase_scope() {
        let body = r#"{
            "changes": [
                {"kind":"set_option","tool":"semgrep:scan","global":false,"name":"maxFindings","value":7},
                {"kind":"set_option","tool":null,"global":false,"name":"ui.auto_open_viz","value":false}
            ]
        }"#;
        let scoped = parse_plan_json_for_phase("scan", body, Some(WorkflowPhase::Scan)).unwrap();
        assert_eq!(
            scoped.changes,
            vec![PlanChange::SetOption {
                phase: Some(WorkflowPhase::Scan),
                global: false,
                tool: Some("semgrep:scan".to_string()),
                name: "maxFindings".to_string(),
                value: "7".to_string(),
            }]
        );

        let unscoped = parse_plan_json_for_phase("plan", body, None).unwrap();
        assert_eq!(unscoped.changes.len(), 2);
        assert!(matches!(
            &unscoped.changes[1],
            PlanChange::SetOption {
                phase: None,
                tool: None,
                ..
            }
        ));
    }

    #[test]
    fn malformed_or_unbalanced_json_is_rejected() {
        assert!(parse_planner_json("no object").is_err());
        assert!(parse_planner_json("} before {").is_err());
    }
}
