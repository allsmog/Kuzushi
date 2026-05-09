use super::*;

pub(in crate::verification::adapters) fn normalize_code_citations(
    object: &Map<String, Value>,
) -> Option<Value> {
    let citations = read_object_value(object, &["codeCitations", "code_citations"])?.as_array()?;
    let mut out = Vec::new();
    for citation in citations {
        let Value::Object(citation) = citation else {
            continue;
        };
        let Some(file_path) = read_object_string(citation, &["filePath", "file_path"]) else {
            continue;
        };
        let Some(start_line) = read_object_u64(citation, &["startLine", "start_line"]) else {
            continue;
        };
        let end_line = read_object_u64(citation, &["endLine", "end_line"]).unwrap_or(start_line);
        let snippet = read_object_string(citation, &["snippet"]).unwrap_or_default();
        let description = read_object_string(citation, &["description"]).unwrap_or_default();
        if description.is_empty() {
            continue;
        }
        out.push(json!({
            "filePath": file_path,
            "startLine": start_line,
            "endLine": end_line,
            "snippet": snippet,
            "description": description,
        }));
    }
    (!out.is_empty()).then(|| json!(out))
}

pub(in crate::verification::adapters) fn normalize_attack_path(
    object: &Map<String, Value>,
) -> Option<Value> {
    let path = attack_path_object(object)?;
    let (chain, narrative) = non_empty_attack_path(path)?;
    Some(json!({
        "chain": chain,
        "narrative": narrative,
        "likelihoodReasoning": read_object_string(path, &["likelihoodReasoning", "likelihood_reasoning"]).unwrap_or_default(),
        "impactReasoning": read_object_string(path, &["impactReasoning", "impact_reasoning"]).unwrap_or_default(),
    }))
}

fn attack_path_object(object: &Map<String, Value>) -> Option<&Map<String, Value>> {
    read_object_value(object, &["attackPath", "attack_path"])?.as_object()
}

fn non_empty_attack_path(path: &Map<String, Value>) -> Option<(Vec<String>, String)> {
    let chain = read_object_string_array(path, &["chain"]);
    let narrative = read_object_string(path, &["narrative"]).unwrap_or_default();
    if chain.is_empty() && narrative.is_empty() {
        return None;
    }
    Some((chain, narrative))
}

pub(in crate::verification::adapters) fn normalize_controls(
    object: &Map<String, Value>,
) -> Option<Value> {
    let controls = read_object_value(object, &["controls"])?.as_array()?;
    let out = controls
        .iter()
        .filter_map(normalized_control_item)
        .collect::<Vec<_>>();
    (!out.is_empty()).then(|| json!(out))
}

fn normalized_control_item(control: &Value) -> Option<Value> {
    let control = control.as_object()?;
    normalized_control_from_object(control)
}

fn normalized_control_from_object(control: &Map<String, Value>) -> Option<Value> {
    let (name, description) = required_control_fields(control)?;
    Some(Value::Object(control_item_map(control, name, description)))
}

fn required_control_fields(control: &Map<String, Value>) -> Option<(String, String)> {
    Some((
        read_object_string(control, &["name"])?,
        read_object_string(control, &["description"])?,
    ))
}

fn control_item_map(
    control: &Map<String, Value>,
    name: String,
    description: String,
) -> Map<String, Value> {
    let mut item = Map::new();
    item.insert("name".to_string(), json!(name));
    item.insert("description".to_string(), json!(description));
    if let Some(file_path) = read_object_string(control, &["filePath", "file_path"]) {
        item.insert("filePath".to_string(), json!(file_path));
    }
    item
}

#[cfg(test)]
pub(in crate::verification::adapters) fn parse_json_object_from_agent_text(
    text: &str,
) -> Result<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return Ok(value);
    }

    let start = text
        .find('{')
        .context("verification output parse failed: missing JSON object start")?;
    let end = text
        .rfind('}')
        .context("verification output parse failed: missing JSON object end")?;
    if end < start {
        anyhow::bail!("verification output parse failed: malformed JSON object");
    }

    serde_json::from_str(&text[start..=end])
        .with_context(|| "verification output parse failed: invalid JSON object")
}
