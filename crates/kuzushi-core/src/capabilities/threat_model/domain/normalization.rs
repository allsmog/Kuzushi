use super::*;

pub(in crate::capabilities::threat_model) fn normalize_dfd_type(kind: &str) -> &'static str {
    // camelCase becomes lower-case without separators here, so accept the
    // flattened forms emitted by LLMs as well as kebab/snake case.
    match kind.to_lowercase().replace('_', "-").as_str() {
        "external-entity" | "externalentity" | "external" => "external-entity",
        "data-store" | "datastore" => "data-store",
        "data-flow" | "dataflow" => "data-flow",
        _ => "process",
    }
}

pub(in crate::capabilities::threat_model) fn normalize_stride_category(
    kind: &str,
) -> Option<&'static str> {
    let normalized = kind.to_lowercase().replace('_', "-");
    STRIDE_CATEGORIES
        .iter()
        .copied()
        .find(|category| *category == normalized)
}

pub(in crate::capabilities::threat_model) fn normalize_impact(value: &str) -> &'static str {
    match value.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "unknown",
    }
}

pub(in crate::capabilities::threat_model) fn probability_to_likelihood(
    probability: f64,
) -> &'static str {
    if probability >= 0.7 {
        "high"
    } else if probability >= 0.4 {
        "medium"
    } else {
        "low"
    }
}

pub(in crate::capabilities::threat_model) fn build_cwe_list(
    record: &Map<String, Value>,
) -> Vec<String> {
    let mut out = string_array_field(record, &["related_cwe", "relatedCwe", "cwe"]);
    if let Some(owasp) = str_field(record, &["owasp_category", "owasp"]) {
        out.push(format!("OWASP-{owasp}"));
    }
    if let Some(capec) = str_field(record, &["capec_id", "capecId"]) {
        out.push(capec);
    }
    out.sort();
    out.dedup();
    out
}

pub(in crate::capabilities::threat_model) fn array_len(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map(Vec::len).unwrap_or(0)
}

pub(in crate::capabilities::threat_model) fn impact_score(impact: &str) -> f64 {
    match impact {
        "critical" => 10.0,
        "high" => 8.0,
        "medium" => 5.0,
        "low" => 2.0,
        _ => 0.0,
    }
}

pub(in crate::capabilities::threat_model) fn likelihood_score(likelihood: &str) -> f64 {
    match likelihood {
        "high" => 8.0,
        "medium" => 5.0,
        "low" => 2.0,
        _ => 0.0,
    }
}

pub(in crate::capabilities::threat_model) fn dread_rating(score: f64) -> &'static str {
    if score >= 8.5 {
        "critical"
    } else if score >= 6.5 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else {
        "low"
    }
}

pub(in crate::capabilities::threat_model) fn methodology_label(methodology: &str) -> &'static str {
    match methodology {
        "stride" => "STRIDE",
        "dread" => "DREAD",
        _ => "PASTA",
    }
}

pub(in crate::capabilities::threat_model) fn append_top_threats(
    lines: &mut Vec<String>,
    document: &Value,
) {
    let Some(threats) = document.get("threats").and_then(Value::as_array) else {
        return;
    };
    if threats.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top threats:".to_string());
    for threat in threats.iter().take(5) {
        let category = threat
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("threat");
        let title = threat
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("untitled");
        let impact = threat
            .get("impact")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        lines.push(format!("  - [{category}] {title} (impact={impact})"));
    }
}
