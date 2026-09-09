use serde_json::Value;

/// Resolved descriptor input decides which verification contract executes.
/// Missing mode keeps the documented model-backed default.
pub fn verification_is_empirical(input: &Value) -> bool {
    input
        .get("mode")
        .and_then(Value::as_str)
        .is_some_and(|mode| mode.trim().eq_ignore_ascii_case("empirical"))
}

/// Explicit-effect children requested by a tool's declared options. Shell
/// confirmation and prepared authorization consume the same projection.
pub fn delegated_execution_tools(tool: &str, input: &Value) -> Vec<&'static str> {
    match tool {
        "sast:scan" => super::sast_scan_delegated_tools(input),
        "verify:finding" if verification_is_empirical(input) => vec!["verify:exploit"],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_explicit_empirical_mode_requests_execution() {
        for input in [
            json!({}),
            json!({"mode":"model"}),
            json!({"mode":"invalid"}),
        ] {
            assert!(!verification_is_empirical(&input));
            assert!(delegated_execution_tools("verify:finding", &input).is_empty());
        }
        assert_eq!(
            delegated_execution_tools("verify:finding", &json!({"mode":"empirical"})),
            vec!["verify:exploit"]
        );
        assert!(
            delegated_execution_tools("unrelated:tool", &json!({"mode":"empirical"})).is_empty()
        );
    }

    #[test]
    fn scan_delegation_keeps_its_existing_option_contract() {
        let input = json!({"verify":true,"pocExecution":true,"autoPatch":true});
        assert_eq!(
            delegated_execution_tools("sast:scan", &input),
            super::super::sast_scan_delegated_tools(&input)
        );
    }
    #[test]
    fn empirical_wrapper_requires_authorization_but_no_model_runtime() {
        use crate::findings::FindingStore;
        use crate::modules::{registry::ModuleRegistry, ToolExecutionContext};
        use crate::{V2Config, WorkspaceTarget};
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let input = json!({"fingerprint":"missing-test-finding", "mode":"empirical"});
        assert!(!crate::modules::tool_needs_runtime(
            "verify:finding",
            &input
        ));
        assert_eq!(
            crate::modules::tool_execution_model("verify:finding", &input, &config),
            None
        );
        let prepare = || {
            registry
                .prepare_dispatch_input("verify:finding", input.clone(), &ctx, None)
                .unwrap()
        };
        let error = registry
            .dispatch_prepared_input_with_runtime(prepare(), &ctx, None)
            .unwrap_err();
        assert!(format!("{error:#}").contains("explicit"), "{error:#}");
        let result = registry
            .dispatch_prepared_input_with_runtime(
                prepare().authorize_explicit_headless(),
                &ctx,
                None,
            )
            .unwrap();
        assert_eq!(result["ok"], false);
        assert!(result.to_string().contains("missing-finding"), "{result}");
        let confirmed = prepare()
            .authorize_requested(crate::modules::ExecutionAuthorization::interactive_request())
            .unwrap();
        let interactive = registry
            .dispatch_prepared_input_with_runtime(confirmed, &ctx, None)
            .unwrap();
        assert!(
            interactive.to_string().contains("missing-finding"),
            "{interactive}"
        );
        assert!(crate::modules::tool_needs_runtime(
            "verify:finding",
            &json!({"mode":"model"})
        ));
        assert!(crate::modules::tool_needs_runtime(
            "verify:finding",
            &json!({})
        ));
    }
}
