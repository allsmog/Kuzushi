use super::*;

pub(crate) fn normalize_generated_document(value: Value, methodology: &str) -> Result<Value> {
    require_generated_node_roles(value.get("document").unwrap_or(&value))?;
    normalize_document(value, methodology)
}

pub(crate) fn normalize_document(mut value: Value, methodology: &str) -> Result<Value> {
    if value.get("document").is_some() {
        value = value
            .get("document")
            .cloned()
            .context("document wrapper was missing document")?;
    }
    let object = value
        .as_object_mut()
        .with_context(|| "ThreatModelDocument must be a JSON object")?;
    object
        .entry("version".to_string())
        .or_insert_with(|| json!("2.0"));
    object.insert("methodology".to_string(), json!(methodology));

    let mut dfd = object
        .remove("dfd")
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    normalize_dfd(&mut dfd);
    object.insert("dfd".to_string(), dfd);

    let threats = object
        .remove("threats")
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let mut threats_array = threats.as_array().cloned().unwrap_or_default();
    for threat in &mut threats_array {
        canonicalize_threat_enums(threat);
    }
    sort_threats_by_risk(&mut threats_array);
    object.insert("threats".to_string(), Value::Array(threats_array.clone()));
    object.insert("summary".to_string(), build_summary(&threats_array));

    let mut warnings = Vec::new();
    normalize_assets(object, &mut warnings);
    normalize_recommended_mitigations(object, &mut warnings);
    append_document_warnings(object, warnings);
    Ok(value)
}

/// Canonicalize the model-chosen enum values on one threat into the harness
/// vocabulary. The model made the judgment; this only fixes spelling and
/// synonyms. Unrecognized values stay verbatim with a warning — never
/// substituted — except `status`, where the schema requires a closed value
/// and the conservative reading of an unknown or missing status is
/// `unmitigated`.
fn canonicalize_threat_enums(threat: &mut Value) {
    let mut warnings = Vec::new();
    canonicalize_threat_field(threat, "actor", normalize_actor, &mut warnings);
    canonicalize_threat_field(threat, "likelihood", normalize_likelihood, &mut warnings);
    canonicalize_threat_field(threat, "impact", closed_impact, &mut warnings);
    canonicalize_threat_status(threat, &mut warnings);
    append_threat_warnings(threat, warnings);
}

fn canonicalize_threat_field(
    threat: &mut Value,
    key: &str,
    normalizer: fn(&str) -> Option<&'static str>,
    warnings: &mut Vec<String>,
) {
    let Some(current) = threat.get(key).and_then(Value::as_str) else {
        return;
    };
    if current.eq_ignore_ascii_case("unknown") {
        return;
    }
    match normalizer(current) {
        Some(canonical) => {
            if canonical != current {
                threat[key] = json!(canonical);
            }
        }
        None => warnings.push(format!("unrecognized {key} '{current}' kept verbatim")),
    }
}

fn closed_impact(value: &str) -> Option<&'static str> {
    match normalize_impact(value) {
        "unknown" => None,
        canonical => Some(canonical),
    }
}

fn canonicalize_threat_status(threat: &mut Value, warnings: &mut Vec<String>) {
    let current = threat.get("status").and_then(Value::as_str);
    match current.map(normalize_status) {
        Some(Some(canonical)) => {
            if Some(canonical) != current {
                threat["status"] = json!(canonical);
            }
        }
        Some(None) => {
            warnings.push(format!(
                "unrecognized status '{}' defaulted to unmitigated",
                current.unwrap_or_default()
            ));
            threat["status"] = json!("unmitigated");
        }
        None => {
            warnings.push("missing status; defaulted to unmitigated".to_string());
            threat["status"] = json!("unmitigated");
        }
    }
}

fn append_threat_warnings(threat: &mut Value, warnings: Vec<String>) {
    if warnings.is_empty() {
        return;
    }
    let existing = threat
        .get_mut("normalizationWarnings")
        .and_then(Value::as_array_mut);
    match existing {
        Some(array) => array.extend(warnings.into_iter().map(Value::String)),
        None => threat["normalizationWarnings"] = json!(warnings),
    }
}

/// Sort by (impact desc, likelihood desc) per the harness schema; the sort is
/// stable, so ties keep document order. Unrecognized values rank last rather
/// than being reinterpreted.
pub(crate) fn sort_threats_by_risk(threats: &mut [Value]) {
    threats.sort_by_key(|threat| std::cmp::Reverse(threat_risk_rank(threat)));
}

fn threat_risk_rank(threat: &Value) -> (u8, u8) {
    let field = |key: &str| threat.get(key).and_then(Value::as_str).unwrap_or("");
    (
        impact_rank(field("impact")),
        likelihood_rank(field("likelihood")),
    )
}

fn impact_rank(impact: &str) -> u8 {
    match impact {
        "existential" => 5,
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn likelihood_rank(likelihood: &str) -> u8 {
    LIKELIHOOD_BANDS
        .iter()
        .position(|band| *band == likelihood)
        .map(|position| position as u8 + 1)
        .unwrap_or(0)
}

/// Guarantee the top-level assets table shape:
/// `[{asset, description?, sensitivity?}]` with sensitivity canonicalized
/// into low|medium|high|critical when recognized.
fn normalize_assets(object: &mut Map<String, Value>, warnings: &mut Vec<String>) {
    let rows = object
        .remove("assets")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let rows = rows
        .into_iter()
        .filter_map(|row| normalize_asset_row(row, warnings))
        .collect::<Vec<_>>();
    object.insert("assets".to_string(), Value::Array(rows));
}

fn normalize_asset_row(row: Value, warnings: &mut Vec<String>) -> Option<Value> {
    match row {
        Value::String(name) => Some(json!({"asset": name})),
        Value::Object(mut fields) => {
            if !fields.contains_key("asset") {
                if let Some(name) = fields.remove("name") {
                    fields.insert("asset".to_string(), name);
                }
            }
            canonicalize_sensitivity(&mut fields, warnings);
            Some(Value::Object(fields))
        }
        other => {
            warnings.push(format!("dropped malformed asset row {other}"));
            None
        }
    }
}

fn canonicalize_sensitivity(fields: &mut Map<String, Value>, warnings: &mut Vec<String>) {
    let Some(sensitivity) = fields.get("sensitivity").and_then(Value::as_str) else {
        return;
    };
    let flat = sensitivity.trim().to_lowercase();
    if VALID_SENSITIVITIES.contains(&flat.as_str()) {
        fields.insert("sensitivity".to_string(), json!(flat));
    } else {
        warnings.push(format!(
            "asset sensitivity '{sensitivity}' outside low|medium|high|critical kept verbatim"
        ));
    }
}

/// Coerce recommendedMitigations rows into the structured schema shape
/// `{mitigation, threatIds[], closesClass: yes|partial, effort: S|M|L}`.
/// Values outside the closed sets stay verbatim with a warning; missing
/// fields stay missing — no invented judgments.
fn normalize_recommended_mitigations(object: &mut Map<String, Value>, warnings: &mut Vec<String>) {
    let Some(rows) = object
        .remove("recommendedMitigations")
        .and_then(|value| value.as_array().cloned())
    else {
        return;
    };
    let rows = rows
        .into_iter()
        .filter_map(|row| normalize_mitigation_row(row, warnings))
        .collect::<Vec<_>>();
    object.insert("recommendedMitigations".to_string(), Value::Array(rows));
}

fn normalize_mitigation_row(row: Value, warnings: &mut Vec<String>) -> Option<Value> {
    match row {
        Value::String(text) => Some(json!({"mitigation": text, "threatIds": []})),
        Value::Object(fields) => Some(structured_mitigation(fields, warnings)),
        other => {
            warnings.push(format!(
                "dropped malformed recommendedMitigations row {other}"
            ));
            None
        }
    }
}

fn structured_mitigation(fields: Map<String, Value>, warnings: &mut Vec<String>) -> Value {
    let text = mitigation_text(&fields, warnings);
    let threat_ids = mitigation_threat_ids(&fields);
    let mut row = Map::new();
    row.insert("mitigation".to_string(), json!(text));
    row.insert("threatIds".to_string(), json!(threat_ids));
    if let Some(closes) = mitigation_closes_class(&fields, warnings) {
        row.insert("closesClass".to_string(), closes);
    }
    if let Some(effort) = mitigation_effort(&fields, warnings) {
        row.insert("effort".to_string(), effort);
    }
    Value::Object(row)
}

fn mitigation_text(fields: &Map<String, Value>, warnings: &mut Vec<String>) -> String {
    let text = ["mitigation", "title", "control", "description"]
        .iter()
        .find_map(|key| fields.get(*key).and_then(Value::as_str));
    match text {
        Some(text) => text.to_string(),
        None => {
            warnings.push("recommendedMitigations row without mitigation text".to_string());
            String::new()
        }
    }
}

fn mitigation_threat_ids(fields: &Map<String, Value>) -> Vec<String> {
    ["threatIds", "threat_ids", "threats", "relatedThreatIds"]
        .iter()
        .find_map(|key| fields.get(*key).and_then(Value::as_array))
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn mitigation_closes_class(
    fields: &Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Option<Value> {
    let raw = fields
        .get("closesClass")
        .or_else(|| fields.get("closes_class"))?;
    if let Some(flag) = raw.as_bool() {
        return Some(json!(if flag { "yes" } else { "partial" }));
    }
    let text = raw.as_str()?;
    match text.trim().to_lowercase().as_str() {
        "yes" | "y" | "true" | "full" | "complete" => Some(json!("yes")),
        "partial" | "partially" | "some" => Some(json!("partial")),
        _ => {
            warnings.push(format!(
                "recommendedMitigations closesClass '{text}' outside yes|partial kept verbatim"
            ));
            Some(json!(text))
        }
    }
}

fn mitigation_effort(fields: &Map<String, Value>, warnings: &mut Vec<String>) -> Option<Value> {
    let text = fields.get("effort").and_then(Value::as_str)?;
    match text.trim().to_lowercase().as_str() {
        "s" | "small" => Some(json!("S")),
        "m" | "med" | "medium" => Some(json!("M")),
        "l" | "large" => Some(json!("L")),
        _ => {
            warnings.push(format!(
                "recommendedMitigations effort '{text}' outside S|M|L kept verbatim"
            ));
            Some(json!(text))
        }
    }
}

fn append_document_warnings(object: &mut Map<String, Value>, warnings: Vec<String>) {
    if warnings.is_empty() {
        return;
    }
    let existing = object
        .get_mut("normalizationWarnings")
        .and_then(Value::as_array_mut);
    match existing {
        Some(array) => array.extend(warnings.into_iter().map(Value::String)),
        None => {
            object.insert("normalizationWarnings".to_string(), json!(warnings));
        }
    }
}

pub(crate) fn normalize_dfd(dfd: &mut Value) {
    let Some(object) = dfd.as_object_mut() else {
        *dfd = json!({"nodes":[],"flows":[],"trustBoundaries":[]});
        return;
    };
    let nodes = object
        .remove("nodes")
        .or_else(|| object.remove("elements"))
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let nodes = nodes
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|mut node| {
            let raw = node
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("process");
            let canonical = normalize_dfd_type(raw);
            if canonical == "data-flow" {
                return None;
            }
            if let Some(object) = node.as_object_mut() {
                object.insert("type".to_string(), Value::String(canonical.to_string()));
            }
            Some(node)
        })
        .collect::<Vec<_>>();
    let flows = object
        .remove("flows")
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let boundaries = object
        .remove("trustBoundaries")
        .or_else(|| object.remove("trust_boundaries"))
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    object.insert("nodes".to_string(), Value::Array(nodes));
    object.insert(
        "flows".to_string(),
        Value::Array(flows.as_array().cloned().unwrap_or_default()),
    );
    object.insert(
        "trustBoundaries".to_string(),
        Value::Array(boundaries.as_array().cloned().unwrap_or_default()),
    );
}

pub(crate) fn apply_methodology(mut document: Value, methodology: &str) -> Result<Value> {
    if let Some(object) = document.as_object_mut() {
        object.insert("methodology".to_string(), json!(methodology));
        if methodology == "dread" {
            let threats = object
                .get("threats")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            object.insert("riskScores".to_string(), build_dread_scores(&threats));
        } else {
            object.remove("riskScores");
        }
    }
    Ok(document)
}

pub(crate) fn build_summary(threats: &[Value]) -> Value {
    let mut by_severity = BTreeMap::<String, usize>::new();
    let mut by_category = BTreeMap::<String, usize>::new();
    for threat in threats {
        if let Some(impact) = threat.get("impact").and_then(Value::as_str) {
            *by_severity.entry(impact.to_string()).or_default() += 1;
        }
        if let Some(category) = threat.get("category").and_then(Value::as_str) {
            *by_category.entry(category.to_string()).or_default() += 1;
        }
    }
    json!({
        "total": threats.len(),
        "bySeverity": by_severity,
        "byCategory": by_category,
    })
}
