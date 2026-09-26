use super::*;

pub(crate) fn parse_threat_patch_json(goal: &str, body: &str) -> Result<ThreatPatch> {
    let parsed = parse_threat_patch_value(body)?;
    let patch = threat_patch_object(&parsed)?;
    Ok(ThreatPatch {
        goal: goal.to_string(),
        summary: threat_patch_summary(goal, &parsed),
        patch,
        unsupported: threat_patch_unsupported(&parsed),
    })
}

fn parse_threat_patch_value(body: &str) -> Result<serde_json::Value> {
    let json_start = body
        .find('{')
        .context("threat-patch response had no JSON object")?;
    let json_end = body
        .rfind('}')
        .context("threat-patch response had no closing JSON brace")?;
    if json_end <= json_start {
        anyhow::bail!("threat-patch response had unbalanced JSON");
    }
    let json_slice = &body[json_start..=json_end];
    serde_json::from_str(json_slice).context("threat-patch JSON did not parse")
}

fn threat_patch_summary(goal: &str, parsed: &serde_json::Value) -> String {
    parsed
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(goal)
        .to_string()
}

fn threat_patch_object(parsed: &serde_json::Value) -> Result<serde_json::Value> {
    let patch = parsed
        .get("patch")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if !matches!(
        patch,
        serde_json::Value::Object(_) | serde_json::Value::Null
    ) {
        anyhow::bail!("threat-patch must be a JSON object");
    }
    Ok(patch)
}

fn threat_patch_unsupported(parsed: &serde_json::Value) -> Vec<String> {
    parsed
        .get("unsupported")
        .and_then(serde_json::Value::as_array)
        .map(|items| unsupported_items(items))
        .unwrap_or_default()
}

fn unsupported_items(items: &[serde_json::Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
pub(crate) fn merge_json(target: &mut serde_json::Value, patch: &serde_json::Value) {
    use serde_json::Value;
    match patch {
        Value::Object(patch_map) => {
            merge_json_object(target, patch_map);
        }
        _ => {
            *target = patch.clone();
        }
    }
}

#[cfg(test)]
fn merge_json_object(
    target: &mut serde_json::Value,
    patch_map: &serde_json::Map<String, serde_json::Value>,
) {
    use serde_json::Value;
    if !target.is_object() {
        *target = Value::Object(serde_json::Map::new());
    }
    let target_map = target.as_object_mut().expect("ensured object above");
    for (key, value) in patch_map {
        merge_json_field(target_map, key, value);
    }
}

#[cfg(test)]
fn merge_json_field(
    target_map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &serde_json::Value,
) {
    if value.is_null() {
        target_map.remove(key);
    } else if let Some(existing) = target_map.get_mut(key) {
        merge_json(existing, value);
    } else {
        target_map.insert(key.to_string(), value.clone());
    }
}
