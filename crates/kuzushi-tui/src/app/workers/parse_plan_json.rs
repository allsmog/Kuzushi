use super::*;

pub(crate) fn parse_plan_json(goal: &str, body: &str) -> Result<PlanProposal> {
    let json_start = body
        .find('{')
        .context("planner response had no JSON object")?;
    let json_end = body
        .rfind('}')
        .context("planner response had no closing JSON brace")?;
    if json_end <= json_start {
        anyhow::bail!("planner response had unbalanced JSON");
    }
    let json_slice = &body[json_start..=json_end];
    let parsed: serde_json::Value =
        serde_json::from_str(json_slice).context("planner JSON did not parse")?;
    let summary = parsed
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(goal)
        .to_string();
    let mut changes = Vec::new();
    if let Some(items) = parsed.get("changes").and_then(serde_json::Value::as_array) {
        for item in items {
            let kind = item
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            match kind {
                "set_option" => {
                    let name = item
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string);
                    let value = item.get("value").map(plan_value_to_string);
                    let global = item
                        .get("global")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    let tool = item
                        .get("tool")
                        .and_then(serde_json::Value::as_str)
                        .filter(|tool| !tool.is_empty())
                        .map(str::to_string);
                    if let (Some(name), Some(value)) = (name, value) {
                        changes.push(PlanChange::SetOption {
                            global,
                            tool,
                            name,
                            value,
                        });
                    }
                }
                "ask" => {
                    if let Some(question) = item
                        .get("question")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                    {
                        changes.push(PlanChange::Ask { question });
                    }
                }
                "note" => {
                    if let Some(text) = item
                        .get("text")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                    {
                        changes.push(PlanChange::Note { text });
                    }
                }
                _ => {}
            }
        }
    }
    let unsupported = parsed
        .get("unsupported")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(PlanProposal {
        goal: goal.to_string(),
        summary,
        changes,
        unsupported,
    })
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
