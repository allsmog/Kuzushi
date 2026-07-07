use super::*;

pub(crate) fn build_dread_scores(threats: &[Value]) -> Value {
    let scores = threats.iter().map(dread_score_for_threat).collect::<Vec<_>>();
    json!({
        "methodology": "dread",
        "scale": "0-10",
        "threats": scores,
    })
}

fn dread_score_for_threat(threat: &Value) -> Value {
    let impact = threat_label(threat, "impact");
    let likelihood = threat_label(threat, "likelihood");
    let damage = impact_score(impact);
    let reproducibility = likelihood_score(likelihood);
    let exploitability = exploitability_score(threat);
    let affected_users = affected_users_score(impact);
    let discoverability = discoverability_score(threat);
    let score = average_dread_score([
        damage,
        reproducibility,
        exploitability,
        affected_users,
        discoverability,
    ]);
    json!({
        "threatId": threat_label(threat, "id"),
        "damage": damage,
        "reproducibility": reproducibility,
        "exploitability": exploitability,
        "affectedUsers": affected_users,
        "discoverability": discoverability,
        "score": score,
        "rating": dread_rating(score),
        "rationale": [
            format!("Damage follows impact={impact}."),
            format!("Reproducibility follows likelihood={likelihood}."),
        ],
    })
}

fn threat_label<'a>(threat: &'a Value, field: &str) -> &'a str {
    threat
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

fn exploitability_score(threat: &Value) -> f64 {
    if array_len(threat.get("preconditions")) == 0 {
        8.0
    } else {
        6.0
    }
}

fn affected_users_score(impact: &str) -> f64 {
    match impact {
        "critical" => 9.0,
        "high" => 7.0,
        "medium" | "low" => 4.0,
        _ => 0.0,
    }
}

fn discoverability_score(threat: &Value) -> f64 {
    if array_len(threat.get("evidenceAnchors")) > 0 {
        6.0
    } else {
        3.0
    }
}

fn average_dread_score(values: [f64; 5]) -> f64 {
    (values.into_iter().sum::<f64>() / 5.0 * 10.0).round() / 10.0
}

pub(crate) fn build_findings_from_document(document: &Value) -> Vec<Value> {
    document
        .get("threats")
        .and_then(Value::as_array)
        .map(|threats| threats.iter().filter_map(finding_for_threat).collect())
        .unwrap_or_default()
}

fn finding_for_threat(threat: &Value) -> Option<Value> {
    let id = threat.get("id").and_then(Value::as_str)?;
    let title = threat.get("title").and_then(Value::as_str).unwrap_or(id);
    let category = threat
        .get("category")
        .and_then(Value::as_str)
        .unwrap_or("threat");
    let affected = first_affected_file(threat);
    Some(json!({
        "ruleId": format!("threat-model/{category}"),
        "filePath": affected_file_path(affected),
        "startLine": affected_start_line(affected),
        "severity": threat_label(threat, "impact").to_uppercase(),
        "message": title,
        "threatId": id,
    }))
}

fn first_affected_file(threat: &Value) -> Option<&Map<String, Value>> {
    threat
        .get("affectedFiles")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
}

fn affected_file_path(affected: Option<&Map<String, Value>>) -> &str {
    affected
        .and_then(|item| item.get("filePath"))
        .and_then(Value::as_str)
        .unwrap_or("threat-model")
}

fn affected_start_line(affected: Option<&Map<String, Value>>) -> u64 {
    affected
        .and_then(|item| item.get("startLine"))
        .and_then(Value::as_u64)
        .unwrap_or(1)
}

pub(crate) fn extract_document_and_findings(raw: Value) -> Result<(Value, Option<Vec<Value>>)> {
    if let Some(object) = raw.as_object() {
        if let Some(document) = object.get("document") {
            let findings = object
                .get("findings")
                .and_then(Value::as_array)
                .map(|items| items.to_vec());
            return Ok((document.clone(), findings));
        }
    }
    Ok((raw, None))
}
