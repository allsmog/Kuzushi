#[cfg(test)]
mod tests {
    use super::super::OptionType;
    use super::super::*;
    use crate::config::V2Config;
    use crate::modules::DynamicModuleLoadOptions;
    use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
    use crate::triage::TriageOutcome;
    use serde_json::{json, Value};
    use std::fs;

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
    fn router_show_returns_completed_envelope() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };

        let result = registry
            .execute_tool("router:show", json!({}), &ctx)
            .unwrap();

        assert_eq!(result.pointer("/status").and_then(Value::as_str), Some("completed"));
        assert_eq!(
            result.pointer("/data/configModel").and_then(Value::as_str),
            Some("openai:gpt-4.1")
        );
    }

    #[test]
    fn config_show_returns_completed_envelope() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };

        let result = registry
            .execute_tool("config:show", json!({}), &ctx)
            .unwrap();

        assert_eq!(
            result.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(
            result.pointer("/data/model").and_then(Value::as_str),
            Some("openai:gpt-4.1")
        );
        assert!(result.pointer("/data/config").is_some());
    }

    #[test]
    fn workspace_status_is_completed_even_without_active_workspace() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };

        let result = registry
            .execute_tool("workspace:status", json!({}), &ctx)
            .unwrap();

        assert_eq!(
            result.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(result.pointer("/data/active").and_then(Value::as_bool), Some(false));
        assert!(result.pointer("/output").and_then(Value::as_str).unwrap().contains("no active workspace"));
    }

    #[test]
    fn filters_stored_options_by_tool_metadata_without_hiding_explicit_unknowns() {
        let registry = ModuleRegistry::with_v2_builtins();
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "model",
            json!("openai:gpt-test"),
        );
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "severity",
            json!("critical,high"),
        );

        let prepared = registry
            .prepare_tool_input("secret-scan:scan", json!({}), Some(&store))
            .unwrap();
        assert_eq!(prepared.get("model"), None);

        let prepared = registry
            .prepare_tool_input("pwn:auto-solve", json!({"target": "."}), Some(&store))
            .unwrap();
        assert_eq!(prepared["model"], json!("openai:gpt-test"));

        let error = registry
            .prepare_tool_input("secret-scan:scan", json!({"model": "openai:gpt-test"}), None)
            .unwrap_err();
        assert!(error.to_string().contains("unknown option \"model\""));
    }

    #[test]
    fn registered_builtin_tools_have_executor_metadata() {
        let registry = ModuleRegistry::with_v2_builtins();
        let missing = registry
            .tools
            .keys()
            .filter(|name| !registry.executors.contains_key(*name))
            .cloned()
            .collect::<Vec<_>>();

        assert!(
            missing.is_empty(),
            "registered tools missing executor metadata: {missing:?}"
        );
    }

    #[test]
    fn runtime_requirement_metadata_is_attached_to_descriptors() {
        let registry = ModuleRegistry::with_v2_builtins();

        assert_eq!(
            registry
                .resolve_tool("secret-scan:scan")
                .map(|tool| tool.runtime_requirement),
            Some(RuntimeRequirement::Never)
        );
        assert_eq!(
            registry
                .resolve_tool("agentic-sast:scan")
                .map(|tool| tool.runtime_requirement),
            Some(RuntimeRequirement::Always)
        );
        assert_eq!(
            registry
                .resolve_tool("sast:scan")
                .map(|tool| tool.runtime_requirement),
            Some(RuntimeRequirement::InputAware)
        );
    }

    #[test]
    fn loads_and_executes_trusted_dynamic_js_module() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("echo-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dyn",
  name: "Dynamic Echo",
  kind: "internal",
  description: "test dynamic module",
  tools: [{
    name: "dyn:echo",
    description: "echo input",
    options: [{ name: "message", type: "String", description: "message", required: true }],
    run(input) {
      return { status: "completed", output: input.message, data: { message: input.message } };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let mut registry = ModuleRegistry::with_v2_builtins();
        registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    allow_untrusted: true,
                    trusted_specifiers: Vec::new(),
                },
            )
            .unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };

        let output = registry
            .execute_tool("dyn:echo", json!({ "message": "hello" }), &ctx)
            .unwrap();

        assert_eq!(output.pointer("/status").and_then(Value::as_str), Some("completed"));
        assert_eq!(output.pointer("/data/message").and_then(Value::as_str), Some("hello"));
        assert!(registry.loaded_module_specifiers().contains(&specifier));
    }

    #[test]
    fn dynamic_js_module_supports_sdk_execute_and_input_schema_options() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("sdk-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "sdk",
  name: "SDK Module",
  kind: "internal",
  description: "test SDK-shaped module",
  tools: [{
    name: "sdk:sum",
    description: "sum input",
    headless: true,
    inputSchema: {
      type: "object",
      required: ["left", "right"],
      properties: {
        left: { type: "integer", description: "left operand" },
        right: { type: "integer", description: "right operand" },
        mode: { type: "string", enum: ["auto", "manual"], default: "auto" }
      }
    },
    async execute(input) {
      return {
        status: "completed",
        output: `${input.left + input.right}:${input.mode}`,
        data: { total: input.left + input.right, mode: input.mode }
      };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let mut registry = ModuleRegistry::with_v2_builtins();
        registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    allow_untrusted: true,
                    trusted_specifiers: Vec::new(),
                },
            )
            .unwrap();

        let descriptor = registry.resolve_tool("sdk:sum").unwrap();
        assert!(descriptor.options.iter().any(|option| {
            option.name == "left" && option.option_type == OptionType::Int && option.required
        }));
        assert!(descriptor.options.iter().any(|option| {
            option.name == "mode"
                && option.option_type == OptionType::Enum
                && option.choices == vec!["auto".to_string(), "manual".to_string()]
                && option.default == Some(json!("auto"))
        }));

        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };
        let output = registry
            .execute_tool("sdk:sum", json!({ "left": "2", "right": 3 }), &ctx)
            .unwrap();

        assert_eq!(output.pointer("/data/total").and_then(Value::as_i64), Some(5));
        assert_eq!(
            output.pointer("/data/mode").and_then(Value::as_str),
            Some("auto")
        );

        let error = registry
            .prepare_tool_input("sdk:sum", json!({ "left": 1, "right": 2, "extra": true }), None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown option \"extra\""), "{error}");
    }

    #[test]
    fn dynamic_js_module_can_call_declared_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("runtime-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynrt",
  name: "Dynamic Runtime",
  kind: "internal",
  description: "test dynamic runtime module",
  tools: [{
    name: "dynrt:ask",
    description: "ask runtime",
    requires: { runtime: true },
    options: [{ name: "prompt", type: "String", description: "prompt", required: true }],
    async run(input, ctx) {
      const response = await ctx.runtime.query({ prompt: input.prompt, systemPrompt: "dynamic" });
      return { status: "completed", output: response.text, data: { text: response.text } };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let mut registry = ModuleRegistry::with_v2_builtins();
        registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    allow_untrusted: true,
                    trusted_specifiers: Vec::new(),
                },
            )
            .unwrap();
        let config = V2Config {
            model: Some("openai:gpt-test".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };
        let runtime = EchoRuntime;

        let output = registry
            .execute_tool_with_runtime(
                "dynrt:ask",
                json!({ "prompt": "hello" }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(
            output.pointer("/data/text").and_then(Value::as_str),
            Some("dynamic::hello")
        );
    }

    struct EchoRuntime;

    impl AgentRuntime for EchoRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> anyhow::Result<AgentQueryResponse> {
            Ok(AgentQueryResponse {
                text: format!("{}::{}", request.system_prompt, request.prompt),
                ..AgentQueryResponse::default()
            })
        }

        fn triage_finding_blocking(
            &self,
            _request: TriageRequest,
        ) -> anyhow::Result<TriageOutcome> {
            anyhow::bail!("triage is not used by dynamic module tests")
        }
    }

    #[test]
    fn exposes_option_specs_for_registered_tool_descriptors() {
        let registry = ModuleRegistry::with_v2_builtins();

        let sast = registry.resolve_tool("sast:scan").unwrap();
        assert!(sast
            .options
            .iter()
            .any(|option| option.name == "tasks" && option.option_type == OptionType::StringList));
        assert!(sast.options.iter().any(|option| {
            option.name == "tasks" && option.aliases.contains(&"taskIds".to_string())
        }));
        assert!(sast
            .options
            .iter()
            .any(|option| option.name == "disabledTasks"
                && option.option_type == OptionType::StringList
                && option.aliases.contains(&"disabled_tasks".to_string())));
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

        let taint_next = registry.resolve_tool("taint-iris-next:hunt").unwrap();
        assert!(taint_next.options.iter().any(|option| {
            option.name == "bridgeVerbose"
                && option.option_type == OptionType::Bool
                && option.aliases.contains(&"bridge_verbose".to_string())
        }));

        let pwn_auto = registry.resolve_tool("pwn:auto-solve").unwrap();
        assert!(pwn_auto.options.iter().any(|option| {
            option.name == "target" && option.option_type == OptionType::Path && option.required
        }));
        assert!(pwn_auto
            .options
            .iter()
            .any(|option| { option.name == "model" && option.option_type == OptionType::String }));
        assert!(!pwn_auto
            .options
            .iter()
            .any(|option| option.name == "strategy"));

        let threat_intel_harvest = registry.resolve_tool("threat-intel:harvest").unwrap();
        assert!(threat_intel_harvest.options.iter().any(|option| {
            option.name == "cves" && option.option_type == OptionType::Json && option.required
        }));
    }

    #[test]
    fn catalog_tool_serialization_keeps_core_descriptor_fields() {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = ToolExecutionContext {
            config: &V2Config::default(),
            workspace: None,
            findings_store: None,
            trace: None,
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
        assert!(semgrep.get("hidden").is_none());
        assert!(semgrep["options"]
            .as_array()
            .unwrap()
            .iter()
            .any(|option| option["name"] == "config"));
        assert!(tools
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool["name"] != "prompt-armor:attack"));
        assert!(tools
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool["name"] != "recon:nmap"));
        assert!(tools
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "offense-review:threat-hunt"));
        assert!(tools
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool["name"] != "carlini-threat-hunt:run"));
        for hidden_tool in [
            "taint-iris-next:hunt",
            "taint-iris-next:catalog",
            "taint-iris-next:codeql-db",
        ] {
            assert!(
                tools
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|tool| tool["name"] != hidden_tool),
                "hidden compatibility tool {hidden_tool} should not serialize in catalog:tools"
            );
        }
    }

    #[test]
    fn registers_native_builtin_surface_with_prefixed_tool_names() {
        let registry = ModuleRegistry::with_v2_builtins();

        for expected in [
            "agentic-sast",
            "codeql",
            "context",
            "cargo-audit",
            "dep-hygiene",
            "findings",
            "iac-scan",
            "license-scan",
            "module-recommender",
            "ndiff",
            "offense-review",
            "patch",
            "randori",
            "report",
            "sast",
            "sbom-scan",
            "secret-scan",
            "semgrep",
            "taint-iris",
            "taint-iris-next",
            "threat-model",
            "triage",
            "variant",
            "verify",
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

        for expected in [
            "carlini-threat-hunt",
            "chrome-rce",
            "context-lite",
            "pipeline",
            "prompt-armor",
            "pwn",
            "recon",
            "shinsa",
            "systems-hunt",
            "tob",
            "uaf-hunt",
            "vendor-assessment",
            "vuln-scout",
        ] {
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

        let visible_tools = registry.tools().map(|tool| tool.name.as_str()).collect::<Vec<_>>();
        for hidden_tool in [
            "carlini-threat-hunt:run",
            "chrome-rce:scan",
            "chrome-rce:review-trigger",
            "prompt-armor:scan",
            "prompt-armor:analyze",
            "prompt-armor:attack",
            "prompt-armor:diff",
            "prompt-armor:report",
            "prompt-armor:config",
            "pwn:profile-binary",
            "pwn:reverse",
            "pwn:state",
            "pwn:calibrate-local",
            "pwn:run-candidates",
            "pwn:auto-solve",
            "recon:nmap",
            "recon:subdomain",
            "recon:http-fingerprint",
            "shinsa:scan",
            "shinsa:quick-check",
            "shinsa:nist-scan",
            "shinsa:nist-quick-check",
            "shinsa:frameworks",
            "taint-iris-next:hunt",
            "taint-iris-next:catalog",
            "taint-iris-next:codeql-db",
            "tob:audit",
            "tob:skills",
            "uaf-hunt:hunt",
            "vendor-assessment:attach",
            "vendor-assessment:scope",
            "vendor-assessment:prompts",
            "vendor-assessment:assess",
            "vuln-scout:audit",
        ] {
            assert!(
                !visible_tools.contains(&hidden_tool),
                "deferred tool {hidden_tool} should not be user-visible"
            );
            assert!(
                registry.resolve_tool(hidden_tool).is_some(),
                "deferred tool {hidden_tool} should remain directly executable"
            );
        }

        for hidden_dag_node in [
            "systems-hunt:systems-context-gatherer",
            "systems-hunt:systems-invariant-extract",
            "systems-hunt:systems-trigger-synth",
            "systems-hunt:systems-hunt",
            "systems-hunt:deep-semantic-cwe-select",
            "systems-hunt:deep-semantic-hunt",
        ] {
            assert!(
                !visible_tools.contains(&hidden_dag_node),
                "hidden DAG node {hidden_dag_node} should not be user-visible"
            );
            assert!(
                registry.is_registered_dag_node(hidden_dag_node),
                "hidden DAG node {hidden_dag_node} should remain internally registered"
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
        assert!(recon.is_hidden());
        assert!(recon.dag_nodes().is_empty());
    }

    #[test]
    fn loaded_module_specifiers_capture_visible_and_hidden_builtins() {
        let registry = ModuleRegistry::with_v2_builtins();
        let specifiers = registry.loaded_module_specifiers();

        assert!(specifiers.contains(&"builtin:sast".to_string()));
        assert!(specifiers.contains(&"builtin:context".to_string()));
        assert!(specifiers.contains(&"builtin:pipeline".to_string()));
        assert!(specifiers.contains(&"builtin:recon".to_string()));
        assert!(specifiers.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn resolves_representative_ported_tools() {
        let registry = ModuleRegistry::with_v2_builtins();
        for expected in [
            "context:build",
            "sast:scan",
            "x-ray:run",
            "offense-review:threat-hunt",
            "carlini-threat-hunt:run",
            "threat-model:build",
            "variant:hunt",
            "ndiff:hunt-variants",
            "shinsa:nist-quick-check",
            "prompt-armor:attack",
            "recon:http-fingerprint",
            "iac-scan:scan",
            "license-scan:scan",
            "sbom-scan:scan",
            "cargo-audit:scan",
            "module-recommender:recommend",
            "report:build",
            "dep-hygiene:check",
            "secret-scan:scan",
            "semgrep:scan",
            "codeql:scan",
            "triage:run",
            "verify:finding",
            "patch:finding",
            "taint-iris-next:dataflow-plan",
            "taint-iris-next:source-sink-trace",
            "taint-iris-next:finding-review",
            "taint-iris-next:hunt",
            "taint-iris-next:catalog",
            "taint-iris-next:codeql-db",
            "pwn:auto-solve",
        ] {
            assert!(
                registry.resolve_tool(expected).is_some(),
                "expected tool {expected}"
            );
        }
    }
}
