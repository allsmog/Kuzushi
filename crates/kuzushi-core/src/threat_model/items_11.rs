use super::prelude::*;
use super::*;

pub(crate) fn build_dread_scores(threats: &[Value]) -> Value {
    let scores = threats
        .iter()
        .map(|threat| {
            let impact = threat
                .get("impact")
                .and_then(Value::as_str)
                .unwrap_or("medium");
            let likelihood = threat
                .get("likelihood")
                .and_then(Value::as_str)
                .unwrap_or("medium");
            let damage = impact_score(impact);
            let reproducibility = likelihood_score(likelihood);
            let exploitability = if array_len(threat.get("preconditions")) == 0 {
                8.0
            } else {
                6.0
            };
            let affected_users = if impact == "critical" {
                9.0
            } else if impact == "high" {
                7.0
            } else {
                4.0
            };
            let discoverability = if array_len(threat.get("evidenceAnchors")) > 0 {
                6.0
            } else {
                3.0
            };
            let score =
                ((damage + reproducibility + exploitability + affected_users + discoverability)
                    / 5.0
                    * 10.0)
                    .round()
                    / 10.0;
            json!({
                "threatId": threat.get("id").and_then(Value::as_str).unwrap_or("unknown"),
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
        })
        .collect::<Vec<_>>();
    json!({
        "methodology": "dread",
        "scale": "0-10",
        "threats": scores,
    })
}

pub(crate) fn build_findings_from_document(document: &Value) -> Vec<Value> {
    document
        .get("threats")
        .and_then(Value::as_array)
        .map(|threats| {
            threats
                .iter()
                .filter_map(|threat| {
                    let id = threat.get("id").and_then(Value::as_str)?;
                    let title = threat.get("title").and_then(Value::as_str).unwrap_or(id);
                    let category = threat
                        .get("category")
                        .and_then(Value::as_str)
                        .unwrap_or("threat");
                    let impact = threat
                        .get("impact")
                        .and_then(Value::as_str)
                        .unwrap_or("medium");
                    let affected = threat
                        .get("affectedFiles")
                        .and_then(Value::as_array)
                        .and_then(|items| items.first())
                        .and_then(Value::as_object);
                    Some(json!({
                        "ruleId": format!("threat-model/{category}"),
                        "filePath": affected
                            .and_then(|item| item.get("filePath"))
                            .and_then(Value::as_str)
                            .unwrap_or("threat-model"),
                        "startLine": affected
                            .and_then(|item| item.get("startLine"))
                            .and_then(Value::as_u64)
                            .unwrap_or(1),
                        "severity": impact.to_uppercase(),
                        "message": title,
                        "threatId": id,
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
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
