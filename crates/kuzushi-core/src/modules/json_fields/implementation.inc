use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

pub(in crate::modules) fn read_object_value<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

pub(in crate::modules) fn read_object_string(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(in crate::modules) fn read_object_nullable_string(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    read_object_value(object, keys).and_then(|value| match value {
        Value::String(text) => Some(text.to_string()),
        Value::Null => None,
        _ => None,
    })
}

pub(in crate::modules) fn read_object_bool(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<bool> {
    read_object_value(object, keys).and_then(Value::as_bool)
}

pub(in crate::modules) fn read_object_f64(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<f64> {
    read_object_value(object, keys).and_then(Value::as_f64)
}

pub(in crate::modules) fn read_object_u64(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<u64> {
    read_object_value(object, keys).and_then(Value::as_u64)
}

pub(in crate::modules) fn read_object_string_array(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Vec<String> {
    read_object_value(object, keys)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(in crate::modules) fn normalize_object_array(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<Value> {
    let items = read_object_string_array(object, keys);
    if items.is_empty() {
        None
    } else {
        Some(json!(items))
    }
}

pub(in crate::modules) fn string_or_null(value: Option<String>) -> Value {
    match value {
        Some(value) => json!(value),
        None => Value::Null,
    }
}

pub(in crate::modules) fn normalize_code_citations(object: &Map<String, Value>) -> Option<Value> {
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

pub(in crate::modules) fn normalize_attack_path(object: &Map<String, Value>) -> Option<Value> {
    let path = read_object_value(object, &["attackPath", "attack_path"])?.as_object()?;
    let chain = read_object_string_array(path, &["chain"]);
    let narrative = read_object_string(path, &["narrative"]).unwrap_or_default();
    if chain.is_empty() && narrative.is_empty() {
        return None;
    }
    Some(json!({
        "chain": chain,
        "narrative": narrative,
        "likelihoodReasoning": read_object_string(path, &["likelihoodReasoning", "likelihood_reasoning"]).unwrap_or_default(),
        "impactReasoning": read_object_string(path, &["impactReasoning", "impact_reasoning"]).unwrap_or_default(),
    }))
}

pub(in crate::modules) fn normalize_controls(object: &Map<String, Value>) -> Option<Value> {
    let controls = read_object_value(object, &["controls"])?.as_array()?;
    let mut out = Vec::new();
    for control in controls {
        let Value::Object(control) = control else {
            continue;
        };
        let Some(name) = read_object_string(control, &["name"]) else {
            continue;
        };
        let Some(description) = read_object_string(control, &["description"]) else {
            continue;
        };
        let mut item = Map::new();
        item.insert("name".to_string(), json!(name));
        item.insert("description".to_string(), json!(description));
        if let Some(file_path) = read_object_string(control, &["filePath", "file_path"]) {
            item.insert("filePath".to_string(), json!(file_path));
        }
        out.push(Value::Object(item));
    }
    (!out.is_empty()).then(|| json!(out))
}

pub(in crate::modules) fn parse_json_object_from_agent_text(text: &str) -> Result<Value> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_aliases_and_trims_strings() {
        let object = json!({
            "file_path": " src/lib.rs ",
            "count": 7,
            "enabled": true,
            "nullable": null
        })
        .as_object()
        .unwrap()
        .clone();

        assert_eq!(
            read_object_string(&object, &["filePath", "file_path"]),
            Some("src/lib.rs".to_string())
        );
        assert_eq!(read_object_u64(&object, &["count"]), Some(7));
        assert_eq!(read_object_bool(&object, &["enabled"]), Some(true));
        assert_eq!(read_object_nullable_string(&object, &["nullable"]), None);
    }

    #[test]
    fn normalizes_string_arrays_and_structured_citations() {
        let object = json!({
            "tags": [" one ", "", "two"],
            "codeCitations": [{
                "filePath": "src/lib.rs",
                "startLine": 3,
                "description": "source"
            }]
        })
        .as_object()
        .unwrap()
        .clone();

        assert_eq!(
            read_object_string_array(&object, &["tags"]),
            vec!["one", "two"]
        );
        assert_eq!(
            normalize_object_array(&object, &["tags"]),
            Some(json!(["one", "two"]))
        );
        assert_eq!(
            normalize_code_citations(&object).and_then(|value| value.as_array().map(Vec::len)),
            Some(1)
        );
    }

    #[test]
    fn parses_embedded_json_object_from_agent_text() {
        let parsed = parse_json_object_from_agent_text("analysis\n{\"ok\":true}\ntrailer").unwrap();
        assert_eq!(parsed["ok"], true);
    }
}
