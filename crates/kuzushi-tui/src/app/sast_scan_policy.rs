use serde_json::Value;

const SAST_SCAN_TOOL: &str = "sast:scan";
const DISCOVERY_ONLY_KEYS: [&str; 3] = ["triage", "verify", "autoPatch"];

/// Compile every shell-originated `sast:scan` launch into discovery-only input.
///
/// This runs before descriptor option preparation, so explicit `false` values
/// override stored Review, Prove, or Fix options. Non-object input is left
/// untouched so the canonical descriptor validator can report its real shape
/// error instead of silently replacing operator input.
pub(crate) fn force_shell_discovery_only_sast_input(tool_name: &str, mut input: Value) -> Value {
    if tool_name != SAST_SCAN_TOOL {
        return input;
    }
    let Some(object) = input.as_object_mut() else {
        return input;
    };
    for key in DISCOVERY_ONLY_KEYS {
        object.insert(key.to_string(), Value::Bool(false));
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shell_sast_scan_always_overrides_nested_pipeline_requests() {
        let input = force_shell_discovery_only_sast_input(
            "sast:scan",
            json!({"triage": true, "verify": true, "autoPatch": true}),
        );

        assert_eq!(
            input,
            json!({"triage": false, "verify": false, "autoPatch": false})
        );
    }

    #[test]
    fn other_tools_and_invalid_shapes_are_not_rewritten() {
        assert_eq!(
            force_shell_discovery_only_sast_input("triage:run", json!({"triage": true})),
            json!({"triage": true})
        );
        assert_eq!(
            force_shell_discovery_only_sast_input("sast:scan", json!(["invalid"])),
            json!(["invalid"])
        );
    }
}
