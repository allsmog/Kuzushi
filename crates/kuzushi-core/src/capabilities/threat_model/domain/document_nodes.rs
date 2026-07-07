use super::*;

pub(crate) fn insert_node(
    nodes: &mut BTreeMap<String, Value>,
    id: &str,
    node_type: &str,
    name: &str,
    description: &str,
    trust_zone: &str,
) {
    if node_type == "data-flow" {
        return;
    }
    nodes.entry(id.to_string()).or_insert_with(|| {
        json!({
            "id": id,
            "type": node_type,
            "name": name,
            "description": description,
            "trustZone": trust_zone,
        })
    });
}

pub(crate) fn parse_threats(s4: &Map<String, Value>) -> Vec<Value> {
    threat_items(s4)
        .into_iter()
        .filter_map(|item| threat_from_item(&item))
        .collect()
}

fn threat_items(s4: &Map<String, Value>) -> Vec<Value> {
    s4.get("threat_scenarios")
        .or_else(|| s4.get("threats"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn threat_from_item(item: &Value) -> Option<Value> {
    let record = item.as_object()?;
    let id = str_field(record, &["id"])?;
    let title = str_field(record, &["title", "name"]).unwrap_or_else(|| id.clone());
    let category = threat_stride_category(record)?;
    let evidence_anchors = threat_evidence_anchors(record);
    let risk = threat_risk_fields(record);
    Some(json!({
        "id": id,
        "targetElementIds": threat_target_element_ids(record),
        "actorIds": string_array_field(record, &["actor_ids", "actorIds", "actors"]),
        "entrypointIds": string_array_field(record, &["entrypoint_ids", "entrypointIds", "entry_points"]),
        "flowIds": string_array_field(record, &["flow_ids", "flowIds", "flows"]),
        "category": category,
        "title": title,
        "description": str_field(record, &["description"]).unwrap_or_else(|| title.clone()),
        "attackVector": str_field(record, &["attack_technique_id", "attackTechniqueId", "mitre_attack", "attack_scenario"]).unwrap_or_else(|| "unknown".to_string()),
        "preconditions": string_array_field(record, &["gaps", "preconditions"]),
        "impact": risk.impact,
        "likelihood": risk.likelihood,
        "probability": risk.probability,
        "normalizationWarnings": risk.warnings,
        "existingMitigations": string_array_field(record, &["existing_controls", "existingMitigations"]),
        "missingMitigations": string_array_field(record, &["recommended_mitigations", "missingMitigations", "recommended_remediation"]),
        "relatedCwe": build_cwe_list(record),
        "affectedFiles": threat_affected_files(&evidence_anchors),
        "evidenceAnchors": evidence_anchors,
        "sources": parse_references(record.get("sources"), "source"),
        "sinks": parse_references(record.get("sinks"), "sink"),
        "guards": parse_references(record.get("guards"), "guard"),
        "sanitizers": parse_references(record.get("sanitizers"), "sanitizer"),
        "requiredCapabilities": string_array_field(record, &["required_capabilities", "requiredCapabilities"]),
        "elementId": str_field(record, &["element_id", "elementId"]).unwrap_or_else(|| "unknown".to_string()),
    }))
}

fn threat_stride_category(record: &Map<String, Value>) -> Option<&'static str> {
    normalize_stride_category(
        str_field(record, &["stride_category", "category"])
            .as_deref()
            .unwrap_or(""),
    )
}

fn threat_target_element_ids(record: &Map<String, Value>) -> Vec<String> {
    nonempty_string_array(
        string_array_field(
            record,
            &[
                "target_element_ids",
                "targetElementIds",
                "target_assets",
                "affected_components",
            ],
        ),
        "unknown",
    )
}

fn threat_evidence_anchors(record: &Map<String, Value>) -> Vec<Value> {
    parse_evidence_anchors(
        record
            .get("evidence_anchors")
            .or_else(|| record.get("evidenceAnchors")),
    )
}

fn threat_affected_files(evidence_anchors: &[Value]) -> Vec<Value> {
    evidence_anchors
        .iter()
        .filter_map(|anchor| {
            Some(json!({
                "filePath": anchor.get("filePath")?.as_str()?,
                "startLine": anchor.get("startLine")?.as_u64().unwrap_or(1),
            }))
        })
        .collect()
}

struct ThreatRiskFields {
    impact: &'static str,
    likelihood: &'static str,
    probability: Option<f64>,
    warnings: Vec<String>,
}

fn threat_risk_fields(record: &Map<String, Value>) -> ThreatRiskFields {
    let raw_impact = str_field(record, &["impact"]);
    let impact = raw_impact
        .as_deref()
        .map(normalize_impact)
        .unwrap_or("unknown");
    let probability = record.get("probability").and_then(Value::as_f64);
    ThreatRiskFields {
        impact,
        likelihood: probability.map(probability_to_likelihood).unwrap_or("unknown"),
        probability,
        warnings: threat_risk_warnings(raw_impact.as_deref(), impact, probability),
    }
}

fn threat_risk_warnings(
    raw_impact: Option<&str>,
    impact: &str,
    probability: Option<f64>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if raw_impact.is_none() {
        warnings.push("missing impact; using unknown".to_string());
    } else if impact == "unknown" {
        warnings.push("unrecognized impact; using unknown".to_string());
    }
    if probability.is_none() {
        warnings.push("missing probability; using unknown likelihood".to_string());
    }
    warnings
}
