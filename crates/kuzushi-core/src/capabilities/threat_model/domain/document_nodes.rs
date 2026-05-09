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
    let raw = s4
        .get("threat_scenarios")
        .or_else(|| s4.get("threats"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for item in raw {
        let Some(record) = item.as_object() else {
            continue;
        };
        let Some(id) = str_field(record, &["id"]) else {
            continue;
        };
        let title = str_field(record, &["title", "name"]).unwrap_or_else(|| id.clone());
        let Some(category) = normalize_stride_category(
            str_field(record, &["stride_category", "category"])
                .as_deref()
                .unwrap_or(""),
        ) else {
            continue;
        };
        let target_element_ids = nonempty_string_array(
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
        );
        let evidence_anchors = parse_evidence_anchors(
            record
                .get("evidence_anchors")
                .or_else(|| record.get("evidenceAnchors")),
        );
        let affected_files = evidence_anchors
            .iter()
            .filter_map(|anchor| {
                Some(json!({
                    "filePath": anchor.get("filePath")?.as_str()?,
                    "startLine": anchor.get("startLine")?.as_u64().unwrap_or(1),
                }))
            })
            .collect::<Vec<_>>();
        let probability = record
            .get("probability")
            .and_then(Value::as_f64)
            .unwrap_or(0.5);
        out.push(json!({
            "id": id,
            "targetElementIds": target_element_ids,
            "actorIds": string_array_field(record, &["actor_ids", "actorIds", "actors"]),
            "entrypointIds": string_array_field(record, &["entrypoint_ids", "entrypointIds", "entry_points"]),
            "flowIds": string_array_field(record, &["flow_ids", "flowIds", "flows"]),
            "category": category,
            "title": title,
            "description": str_field(record, &["description"]).unwrap_or_else(|| title.clone()),
            "attackVector": str_field(record, &["attack_technique_id", "attackTechniqueId", "mitre_attack", "attack_scenario"]).unwrap_or_else(|| "unknown".to_string()),
            "preconditions": string_array_field(record, &["gaps", "preconditions"]),
            "impact": normalize_impact(str_field(record, &["impact"]).as_deref().unwrap_or("medium")),
            "likelihood": probability_to_likelihood(probability),
            "probability": probability,
            "existingMitigations": string_array_field(record, &["existing_controls", "existingMitigations"]),
            "missingMitigations": string_array_field(record, &["recommended_mitigations", "missingMitigations", "recommended_remediation"]),
            "relatedCwe": build_cwe_list(record),
            "affectedFiles": affected_files,
            "evidenceAnchors": evidence_anchors,
            "sources": parse_references(record.get("sources"), "source"),
            "sinks": parse_references(record.get("sinks"), "sink"),
            "guards": parse_references(record.get("guards"), "guard"),
            "sanitizers": parse_references(record.get("sanitizers"), "sanitizer"),
            "requiredCapabilities": string_array_field(record, &["required_capabilities", "requiredCapabilities"]),
            "elementId": str_field(record, &["element_id", "elementId"]).unwrap_or_else(|| "unknown".to_string()),
        }));
    }
    out
}
