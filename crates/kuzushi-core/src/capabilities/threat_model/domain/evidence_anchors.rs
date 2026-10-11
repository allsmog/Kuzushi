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
        "inputCategories": narrative_input_categories(record),
        "attackerStories": attacker_stories,
        "criticalityBuckets": narrative_criticality_buckets(record),
        "outOfScope": out_of_scope,
    }))
}

fn narrative_input_categories(record: &Map<String, Value>) -> Value {
    let categories = object_field(record, &["input_categories", "inputCategories"]);
    json!({
        "attackerControlled": category_array(categories, &["attacker_controlled", "attackerControlled"]),
        "operatorControlled": category_array(categories, &["operator_controlled", "operatorControlled"]),
        "developerControlled": category_array(categories, &["developer_controlled", "developerControlled"]),
        "externalServices": category_array(categories, &["external_services", "externalServices"]),
        "credentialFlows": category_array(categories, &["credential_flows", "credentialFlows"]),
        "authorizationFlows": category_array(categories, &["authorization_flows", "authorizationFlows"]),
        "fileIngestFlows": category_array(categories, &["file_ingest_flows", "fileIngestFlows"]),
        "dataEgressFlows": category_array(categories, &["data_egress_flows", "dataEgressFlows"]),
        "callbackFlows": category_array(categories, &["callback_flows", "callbackFlows"]),
        "sandboxBoundary": category_array(categories, &["sandbox_boundary", "sandboxBoundary"]),
        "assumptions": category_array(categories, &["assumptions"]),
    })
}

fn narrative_criticality_buckets(record: &Map<String, Value>) -> Value {
    let criticality = object_field(record, &["criticality_buckets", "criticalityBuckets"]);
    json!({
        "critical": category_array(criticality, &["critical"]),
        "high": category_array(criticality, &["high"]),
        "medium": category_array(criticality, &["medium"]),
        "low": category_array(criticality, &["low"]),
    })
}

fn object_field<'a>(
    record: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    keys.iter()
        .find_map(|key| record.get(*key))
        .and_then(Value::as_object)
}

fn category_array(record: Option<&Map<String, Value>>, keys: &[&str]) -> Vec<String> {
    record
        .map(|value| string_array_field(value, keys))
        .unwrap_or_default()
}
