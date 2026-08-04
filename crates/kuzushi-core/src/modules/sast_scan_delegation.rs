use serde_json::Value;

/// Nested explicit-effect tools that a prepared `sast:scan` invocation may
/// dispatch. CLI and TUI callers use this one policy so their authorization
/// and confirmation surfaces cannot drift.
pub fn sast_scan_delegated_tools(input: &Value) -> Vec<&'static str> {
    if crate::whitebox_static::whitebox_static_enabled(input).unwrap_or(false) {
        return Vec::new();
    }

    let auto_patch = input_flag(input, &["autoPatch", "auto_patch"]);
    let empirical_verification = input_flag(input, &["pocExecution", "poc_execution"])
        && (auto_patch || input_flag(input, &["verify"]));
    let mut tools = Vec::with_capacity(2);
    if empirical_verification {
        tools.push("verify:exploit");
    }
    if auto_patch {
        tools.push("patch:finding");
    }
    tools
}

fn input_flag(input: &Value, names: &[&str]) -> bool {
    names
        .iter()
        .any(|name| input.get(name).and_then(Value::as_bool).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn delegation_matches_requested_repository_effects() {
        assert!(sast_scan_delegated_tools(&json!({"verify": true})).is_empty());
        assert_eq!(
            sast_scan_delegated_tools(&json!({
                "verify": true,
                "pocExecution": true
            })),
            vec!["verify:exploit"]
        );
        assert_eq!(
            sast_scan_delegated_tools(&json!({
                "verify": true,
                "pocExecution": true,
                "autoPatch": true
            })),
            vec!["verify:exploit", "patch:finding"]
        );
        assert_eq!(
            sast_scan_delegated_tools(&json!({"autoPatch": true})),
            vec!["patch:finding"]
        );
    }

    #[test]
    fn whitebox_static_never_delegates_execution_or_patch() {
        assert!(sast_scan_delegated_tools(&json!({
            "mode": "whitebox-static",
            "verify": true,
            "pocExecution": true,
            "autoPatch": true
        }))
        .is_empty());
    }
}
