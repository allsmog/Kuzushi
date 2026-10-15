use serde_json::Value;

fn applicable(input: &Value) -> bool {
    input["taskMode"] == "auto"
        || input["tasks"].as_array().is_some_and(|tasks| {
            tasks
                .iter()
                .any(|task| matches!(task.as_str(), Some("cargo-audit" | "cargo-audit:scan")))
        })
}

pub(super) fn limits_line(input: &Value) -> String {
    if !applicable(input) {
        return String::new();
    }
    let milliseconds = input["cargoAuditTimeoutMs"]
        .as_u64()
        .unwrap_or(kuzushi_core::scan::DEFAULT_CARGO_AUDIT_JOB_TIMEOUT_MS);
    let bytes = input["cargoAuditMaxLockfileBytes"]
        .as_u64()
        .unwrap_or(kuzushi_core::scan::DEFAULT_CARGO_AUDIT_LOCKFILE_BYTES as u64);
    format!("Cargo audit when selected: {milliseconds} ms per job across captures/roots; {bytes} bytes per lockfile. Whole-repository source authentication is separate.")
}

pub(super) fn network_line(input: &Value) -> String {
    if !applicable(input) {
        return String::new();
    }
    let mode = if input["cargoAuditOffline"] == true {
        "offline; no database updates or yanked-package network checks"
    } else {
        "enabled; database updates and yanked-package network checks permitted"
    };
    let database = input["cargoAuditAdvisoryDb"]
        .as_str()
        .unwrap_or("operator-home default");
    let stale = input["cargoAuditAllowStale"].as_bool().unwrap_or_default();
    format!("Cargo audit advisory network: {mode}. Database: {database}. Stale database permitted: {stale}. Database freshness is not implied by the source SHA.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn cargo_audit_approval_discloses_selected_caps_network_and_freshness_limits() {
        let input = json!({"tasks":["cargo-audit"],"cargoAuditTimeoutMs":12000,"cargoAuditOffline":true,"cargoAuditAllowStale":true,"cargoAuditAdvisoryDb":"owned-db","cargoAuditMaxLockfileBytes":4096});
        assert!(limits_line(&input).contains("12000 ms per job"));
        assert!(limits_line(&input).contains("4096 bytes per lockfile"));
        assert!(network_line(&input).contains("offline; no database updates"));
        assert!(network_line(&input).contains("owned-db"));
        assert!(network_line(&input).contains("Stale database permitted: true"));
        assert!(network_line(&input).contains("freshness is not implied"));
        assert!(network_line(&json!({"tasks":["cargo-audit"]})).contains("enabled"));
        assert!(limits_line(&json!({"tasks":["secret-scan"]})).is_empty());
    }
}
