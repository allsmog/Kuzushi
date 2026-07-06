use serde_json::Value;

pub(super) fn shinsa_mode(tool_name: &str, input: &Value) -> &'static str {
    match tool_name {
        "shinsa:scan" if shinsa_depth(input) == "quick" => "quick-check",
        "shinsa:scan" => "compliance-scan",
        "shinsa:quick-check" => "quick-check",
        "shinsa:nist-scan" if shinsa_depth(input) == "quick" => "nist-quick-check",
        "shinsa:nist-scan" => "nist-scan",
        "shinsa:nist-quick-check" => "nist-quick-check",
        _ => "compliance-scan",
    }
}

fn shinsa_depth(input: &Value) -> &str {
    input
        .get("depth")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("full")
}
