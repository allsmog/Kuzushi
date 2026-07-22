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
        "existential" => "existential",
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "unknown",
    }
}

/// Canonicalize a model-chosen actor into the closed harness vocabulary.
/// Returns `None` for values outside the recognized synonym set — callers
/// keep the verbatim value and record a normalization warning instead of
/// substituting a judgment.
pub(in crate::capabilities::threat_model) fn normalize_actor(value: &str) -> Option<&'static str> {
    let flat = flatten_enum_token(value);
    match flat.as_str() {
        "remote_unauth"
        | "remote_unauthenticated"
        | "unauthenticated_remote"
        | "unauthenticated_remote_attacker"
        | "unauthenticated_attacker"
        | "unauthenticated"
        | "anonymous"
        | "internet"
        | "external_attacker"
        | "remote_attacker" => Some("remote_unauth"),
        "remote_auth"
        | "remote_authenticated"
        | "authenticated_remote"
        | "authenticated_remote_attacker"
        | "authenticated_user"
        | "authenticated"
        | "remote_user"
        | "logged_in_user" => Some("remote_auth"),
        "adjacent_network"
        | "adjacent"
        | "lan"
        | "local_network"
        | "network_adjacent"
        | "on_path"
        | "mitm"
        | "man_in_the_middle" => Some("adjacent_network"),
        "local_user" | "local" | "unprivileged_local" | "local_unprivileged" => Some("local_user"),
        "local_admin" | "admin" | "administrator" | "root" | "privileged_local" => {
            Some("local_admin")
        }
        "supply_chain"
        | "supplychain"
        | "dependency"
        | "upstream"
        | "vendor"
        | "third_party"
        | "compromised_dependency" => Some("supply_chain"),
        "insider" | "malicious_insider" | "internal_user" | "employee" => Some("insider"),
        _ => None,
    }
}

/// Canonicalize a likelihood value into the five-band ladder. Legacy
/// three-band vocabulary maps low->rare, medium->possible, high->likely.
/// Returns `None` for out-of-vocabulary values.
pub(in crate::capabilities::threat_model) fn normalize_likelihood(
    value: &str,
) -> Option<&'static str> {
    match flatten_enum_token(value).as_str() {
        "very_rare" | "very_low" | "very_unlikely" => Some("very_rare"),
        "rare" | "low" | "unlikely" => Some("rare"),
        "possible" | "medium" | "moderate" | "occasional" => Some("possible"),
        "likely" | "high" | "probable" => Some("likely"),
        "almost_certain" | "very_high" | "very_likely" | "certain" => Some("almost_certain"),
        _ => None,
    }
}

/// Canonicalize a mitigation status into the closed harness vocabulary.
/// Returns `None` for out-of-vocabulary values.
pub(in crate::capabilities::threat_model) fn normalize_status(value: &str) -> Option<&'static str> {
    match flatten_enum_token(value).as_str() {
        "unmitigated" | "open" | "none" | "not_mitigated" | "unaddressed" => Some("unmitigated"),
        "partially_mitigated" | "partial" | "partially" | "partly_mitigated" => {
            Some("partially_mitigated")
        }
        "mitigated" | "closed" | "resolved" | "fixed" | "addressed" | "remediated" => {
            Some("mitigated")
        }
        "risk_accepted" | "accepted" | "acknowledged" | "wont_fix" | "accepted_risk" => {
            Some("risk_accepted")
        }
        _ => None,
    }
}

fn flatten_enum_token(value: &str) -> String {
    value.trim().to_lowercase().replace(['-', ' '], "_")
}

pub(in crate::capabilities::threat_model) fn probability_to_likelihood(
    probability: f64,
) -> &'static str {
    if probability >= 0.9 {
        "almost_certain"
    } else if probability >= 0.7 {
        "likely"
    } else if probability >= 0.4 {
        "possible"
    } else if probability >= 0.1 {
        "rare"
    } else {
        "very_rare"
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
        "existential" => 12.0,
        "critical" => 10.0,
        "high" => 8.0,
        "medium" => 5.0,
        "low" => 2.0,
        _ => 0.0,
    }
}

pub(in crate::capabilities::threat_model) fn likelihood_score(likelihood: &str) -> f64 {
    match likelihood {
        "almost_certain" => 9.0,
        "likely" | "high" => 8.0,
        "possible" | "medium" => 5.0,
        "rare" | "low" => 2.0,
        "very_rare" => 1.0,
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
