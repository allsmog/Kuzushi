#[cfg(test)]
mod tests {
    use super::super::OptionType;
    use super::super::*;
    use crate::config::V2Config;
    use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
    use serde_json::{json, Value};

    #[test]
    fn prepares_tool_input_with_stored_options_before_validation() {
        let registry = ModuleRegistry::with_v2_builtins();
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(false),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Module("sast".to_string()),
            "triage",
            json!(true),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "verify",
            json!("yes"),
        );

        let prepared = registry
            .prepare_tool_input("sast:scan", json!({"triage": false}), Some(&store))
            .unwrap();

        assert_eq!(prepared["taskMode"], json!("auto"));
        assert_eq!(prepared["triage"], json!(false));
        assert_eq!(prepared["verify"], json!(true));
        assert_eq!(prepared.get("model"), None);
    }

    #[test]
    fn stored_required_options_satisfy_tool_validation_without_model_fallback() {
        let registry = ModuleRegistry::with_v2_builtins();
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("recon:nmap".to_string()),
            "target",
            json!("192.0.2.10"),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("recon:nmap".to_string()),
            "ports",
            json!("80,443"),
        );

        let prepared = registry
            .prepare_tool_input("recon:nmap", Value::Null, Some(&store))
            .unwrap();

        assert_eq!(prepared["target"], json!("192.0.2.10"));
        assert_eq!(prepared["ports"], json!("80,443"));
        assert_eq!(prepared.get("model"), None);
    }

    #[test]
    fn exposes_option_specs_for_visible_tool_descriptors() {
        let registry = ModuleRegistry::with_v2_builtins();

        let sast = registry.resolve_tool("sast:scan").unwrap();
        assert!(sast
            .options
            .iter()
            .any(|option| option.name == "tasks" && option.option_type == OptionType::StringList));
        assert!(sast
            .options
            .iter()
            .any(|option| option.name == "disabledTasks"
                && option.option_type == OptionType::StringList));
        assert!(sast.options.iter().any(
            |option| option.name == "severity" && option.option_type == OptionType::StringList
        ));

        let semgrep = registry.resolve_tool("semgrep:scan").unwrap();
        assert!(semgrep.options.iter().any(|option| option.name == "config"
            && option.option_type == OptionType::String
            && option.default == Some(json!("auto"))));

        let codeql = registry.resolve_tool("codeql:scan").unwrap();
        assert!(codeql.options.iter().any(|option| option.name == "language"
            && option.option_type == OptionType::Enum
            && option.choices.contains(&"javascript".to_string())));
        assert!(codeql
            .options
            .iter()
            .any(|option| option.name == "multiLanguage"
                && option.option_type == OptionType::Bool
                && option.default == Some(json!(false))));

        let x_ray = registry.resolve_tool("x-ray:run").unwrap();
        assert!(x_ray.options.iter().any(|option| {
            option.name == "maxBudgetUsd"
                && option.option_type == OptionType::Float
                && option.advanced
        }));

        let recon = registry.resolve_tool("recon:nmap").unwrap();
        assert!(recon.options.iter().any(|option| option.name == "target"
            && option.option_type == OptionType::String
            && option.required));

        let iac = registry.resolve_tool("iac-scan:scan").unwrap();
        assert!(iac.options.iter().any(|option| option.name == "kind"
            && option.option_type == OptionType::Enum
            && option.choices.contains(&"terraform".to_string())));

        let prompt_armor = registry.resolve_tool("prompt-armor:attack").unwrap();
        assert!(prompt_armor
            .options
            .iter()
            .any(|option| option.name == "payload" && option.evasion));
    }

    #[test]
    fn catalog_tool_serialization_keeps_core_descriptor_fields() {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = ToolExecutionContext {
            config: &V2Config::default(),
            workspace: None,
            findings_store: None,
        };

        let tools = registry
            .execute_tool("catalog:tools", Value::Null, &ctx)
            .unwrap();
        let catalog_modules = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "catalog:modules")
            .unwrap();
        assert_eq!(
            catalog_modules["description"],
            json!("List native modules.")
        );
        assert_eq!(catalog_modules["headless"], json!(true));
        assert!(catalog_modules.get("options").is_none());

        let semgrep = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "semgrep:scan")
            .unwrap();
        assert_eq!(semgrep["headless"], json!(true));
        assert!(semgrep["options"]
            .as_array()
            .unwrap()
            .iter()
            .any(|option| option["name"] == "config"));
    }

    #[test]
    fn registers_native_builtin_surface_with_prefixed_tool_names() {
        let registry = ModuleRegistry::with_v2_builtins();

        for expected in [
            "agentic-sast",
            "carlini-threat-hunt",
            "chrome-rce",
            "codeql",
            "context",
            "dep-hygiene",
            "findings",
            "iac-scan",
            "ndiff",
            "patch",
            "prompt-armor",
            "randori",
            "recon",
            "sast",
            "secret-scan",
            "semgrep",
            "shinsa",
            "taint-iris",
            "taint-iris-next",
            "threat-model",
            "tob",
            "triage",
            "variant",
            "vendor-assessment",
            "verify",
            "vuln-scout",
            "workspace",
            "x-ray",
        ] {
            assert!(
                registry
                    .modules()
                    .any(|registered_module| registered_module.metadata().id == expected),
                "expected visible module {expected}"
            );
        }

        for expected in ["context-lite", "pipeline", "systems-hunt"] {
            assert!(
                registry
                    .all_modules()
                    .any(
                        |registered_module| registered_module.metadata().id == expected
                            && registered_module.is_hidden()
                    ),
                "expected hidden internal module {expected}"
            );
            assert!(
                !registry
                    .modules()
                    .any(|registered_module| registered_module.metadata().id == expected),
                "hidden module {expected} should not be user-visible"
            );
        }

        for tool in registry.tools() {
            let module_id = tool.name.split(':').next().unwrap();
            assert!(
                registry
                    .all_modules()
                    .any(|registered_module| registered_module.metadata().id == module_id),
                "tool {} should use a registered module prefix",
                tool.name
            );
        }

        let recon = registry
            .all_modules()
            .find(|registered_module| registered_module.metadata().id == "recon")
            .unwrap();
        assert!(recon
            .dag_nodes()
            .iter()
            .any(|node| node.id == "recon:http-fingerprint"
                && node.output_kind == "context"
                && node.depends_on == vec!["context:build".to_string()]));
    }

    #[test]
    fn resolves_representative_ported_tools() {
        let registry = ModuleRegistry::with_v2_builtins();
        for expected in [
            "context:build",
            "sast:scan",
            "x-ray:run",
            "carlini-threat-hunt:run",
            "threat-model:build",
            "variant:hunt",
            "ndiff:hunt-variants",
            "shinsa:nist-quick-check",
            "prompt-armor:attack",
            "recon:http-fingerprint",
            "iac-scan:scan",
            "dep-hygiene:check",
            "secret-scan:scan",
            "semgrep:scan",
            "codeql:scan",
            "triage:run",
            "verify:finding",
            "patch:finding",
            "taint-iris-next:hunt",
        ] {
            assert!(
                registry.resolve_tool(expected).is_some(),
                "expected tool {expected}"
            );
        }
    }
}
