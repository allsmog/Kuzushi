use super::*;
use crate::options::{OptionScope, OptionTarget, ToolOptionStore};

const TOOL: &str = "threat-model:build";

#[test]
fn supplied_options_filter_global_roles_canonicalize_aliases_and_preserve_overrides() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let mut store = ToolOptionStore::new();
    store.set_value(
        OptionScope::Global,
        OptionTarget::All,
        "MODEL_TRIAGE_ESCALATION",
        json!("openai-codex:gpt-5.5"),
    );
    store.set_value(
        OptionScope::Global,
        OptionTarget::All,
        "model",
        json!("openai-codex:gpt-5.5"),
    );
    store.set_value(
        OptionScope::Global,
        OptionTarget::Tool(TOOL.into()),
        "methodology",
        json!("pasta"),
    );
    let input = registry
        .prepare_supplied_tool_options(
            TOOL,
            json!({"methodology":"stride","source_paths":["owned.rs"],"maxSourceBytes":"4096"}),
            Some(&store),
        )
        .unwrap();
    assert_eq!(
        input,
        json!({"model":"openai-codex:gpt-5.5","methodology":"stride","sourcePaths":["owned.rs"],"maxSourceBytes":4096})
    );
}

#[test]
fn supplied_options_omit_defaults_but_keep_explicit_values_equal_to_defaults() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    assert_eq!(
        registry
            .prepare_supplied_tool_options(TOOL, json!({}), None)
            .unwrap(),
        json!({})
    );
    assert_eq!(
        registry
            .prepare_supplied_tool_options(TOOL, json!({"methodology":"stride"}), None)
            .unwrap(),
        json!({"methodology":"stride"})
    );
}

#[test]
fn supplied_options_reject_explicit_unknowns_and_invalid_values() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let error = registry
        .prepare_supplied_tool_options(
            TOOL,
            json!({"MODEL_TRIAGE_ESCALATION":"openai-codex:gpt-5.5"}),
            None,
        )
        .unwrap_err();
    assert!(error.to_string().contains("unknown option"));
    assert!(registry
        .prepare_supplied_tool_options(TOOL, json!({"maxSourceBytes":"invalid"}), None)
        .is_err());
    assert!(registry
        .prepare_supplied_tool_options("missing:tool", json!({}), None)
        .is_err());
}

#[test]
fn supplied_options_preserve_workspace_model_and_prompt_policy_rejection() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    for name in ["MODEL_TRIAGE_ESCALATION", "THREAT_MODEL_PROMPT"] {
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::All,
            name,
            json!("untrusted setting"),
        );
        let error = registry
            .prepare_supplied_tool_options(TOOL, json!({}), Some(&store))
            .unwrap_err();
        assert!(error.to_string().contains("workspace options may not"));
    }
}
