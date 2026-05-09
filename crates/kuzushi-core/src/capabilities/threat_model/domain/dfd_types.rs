pub(crate) fn nonempty_string_array(mut values: Vec<String>, fallback: &str) -> Vec<String> {
    if values.is_empty() {
        values.push(fallback.to_string());
    }
    values
}

pub(crate) fn actor_type_to_dfd_type(kind: &str) -> &'static str {
    match kind.to_lowercase().as_str() {
        "external-user" | "external-service" | "external" | "human" => "external-entity",
        "automated" | "downstream-service" | "internal-service" => "process",
        _ => "external-entity",
    }
}

pub(crate) fn component_kind_to_dfd_type(kind: &str) -> &'static str {
    let lower = kind.to_lowercase();
    if lower.contains("database") || lower.contains("store") {
        "data-store"
    } else if lower.contains("flow") {
        "data-flow"
    } else {
        "process"
    }
}
