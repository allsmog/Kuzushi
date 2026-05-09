pub(super) fn shinsa_mode(tool_name: &str) -> &'static str {
    match tool_name {
        "shinsa:scan" => "compliance-scan",
        "shinsa:quick-check" => "quick-check",
        "shinsa:nist-scan" => "nist-scan",
        "shinsa:nist-quick-check" => "nist-quick-check",
        _ => "compliance-scan",
    }
}
