use super::prelude::*;
use super::*;

pub(crate) fn parse_evidence_anchors(raw: Option<&Value>) -> Vec<Value> {
    raw.and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let record = item.as_object()?;
                    let file_path = str_field(record, &["file_path", "filePath"])?;
                    let description = str_field(record, &["description"])?;
                    Some(json!({
                        "filePath": file_path,
                        "startLine": number_field(record, &["start_line", "startLine"]).unwrap_or(1),
                        "endLine": number_field(record, &["end_line", "endLine"]),
                        "symbol": str_field(record, &["symbol"]),
                        "description": description,
                        "snippet": str_field(record, &["snippet"]),
                        "source": str_field(record, &["source"]),
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_references(raw: Option<&Value>, fallback_kind: &str) -> Vec<Value> {
    raw.and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let record = item.as_object()?;
                    Some(json!({
                        "kind": str_field(record, &["kind"]).unwrap_or_else(|| fallback_kind.to_string()),
                        "name": str_field(record, &["name"]),
                        "elementId": str_field(record, &["element_id", "elementId"]),
                        "filePath": str_field(record, &["file_path", "filePath"]),
                        "startLine": number_field(record, &["start_line", "startLine"]),
                        "endLine": number_field(record, &["end_line", "endLine"]),
                        "symbol": str_field(record, &["symbol"]),
                        "description": str_field(record, &["description"]),
                        "snippet": str_field(record, &["snippet"]),
                        "source": str_field(record, &["source"]),
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_narrative(raw: &Value) -> Option<Value> {
    let record = raw.as_object()?;
    let overview = str_field(record, &["overview"]).unwrap_or_default();
    let input_categories = record
        .get("input_categories")
        .or_else(|| record.get("inputCategories"))
        .and_then(Value::as_object);
    let criticality = record
        .get("criticality_buckets")
        .or_else(|| record.get("criticalityBuckets"))
        .and_then(Value::as_object);
    let attacker_stories = record
        .get("attacker_stories")
        .or_else(|| record.get("attackerStories"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let story = item.as_object()?;
                    let title = str_field(story, &["title"])?;
                    let narrative = str_field(story, &["narrative"])?;
                    Some(json!({
                        "title": title,
                        "narrative": narrative,
                        "mitigation": str_field(story, &["mitigation"]).unwrap_or_default(),
                        "threatIds": string_array_field(story, &["threat_ids", "threatIds"]),
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let out_of_scope = string_array_field(record, &["out_of_scope", "outOfScope"]);
    let has_content =
        !overview.is_empty() || !attacker_stories.is_empty() || !out_of_scope.is_empty();
    if !has_content {
        return None;
    }
    Some(json!({
        "overview": overview,
        "inputCategories": {
            "attackerControlled": input_categories.map(|r| string_array_field(r, &["attacker_controlled", "attackerControlled"])).unwrap_or_default(),
            "operatorControlled": input_categories.map(|r| string_array_field(r, &["operator_controlled", "operatorControlled"])).unwrap_or_default(),
            "developerControlled": input_categories.map(|r| string_array_field(r, &["developer_controlled", "developerControlled"])).unwrap_or_default(),
            "externalServices": input_categories.map(|r| string_array_field(r, &["external_services", "externalServices"])).unwrap_or_default(),
            "sandboxBoundary": input_categories.map(|r| string_array_field(r, &["sandbox_boundary", "sandboxBoundary"])).unwrap_or_default(),
            "assumptions": input_categories.map(|r| string_array_field(r, &["assumptions"])).unwrap_or_default(),
        },
        "attackerStories": attacker_stories,
        "criticalityBuckets": {
            "critical": criticality.map(|r| string_array_field(r, &["critical"])).unwrap_or_default(),
            "high": criticality.map(|r| string_array_field(r, &["high"])).unwrap_or_default(),
            "medium": criticality.map(|r| string_array_field(r, &["medium"])).unwrap_or_default(),
            "low": criticality.map(|r| string_array_field(r, &["low"])).unwrap_or_default(),
        },
        "outOfScope": out_of_scope,
    }))
}
