#[cfg(test)]
mod tests {
    use super::super::OptionType;
    use super::super::*;
    use crate::config::{FuzzExecutorConfig, McpMountConfig, McpMountToolConfig, V2Config};
    use crate::findings::FindingStore;
    use crate::modules::{approve_dynamic_module, revoke_dynamic_module, DynamicModuleLoadOptions};
    use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
    use crate::run_artifacts::TraceHandle;
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
    use crate::triage::TriageOutcome;
    use crate::worker_protocol::{
        descriptor_hash_from_value, kwp_audit_log_integrity, read_kwp_audit_log, ArtifactsGrant,
        FindingsGrant, FsMode, FsScope, FsScopeGrant, FuzzEngine, FuzzGrant, Grant, HostPattern,
        KwpAuditLogRecord, McpGrant, McpGrantMode, McpToolDescriptor, McpWorkspaceMode, NetGrant,
        RuntimeGrant,
    };
    use crate::WorkspaceTarget;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn kwp_context<'a>(
        config: &'a V2Config,
        workspace: Option<&'a WorkspaceTarget>,
        findings_store: Option<&'a FindingStore>,
        trace: Option<&'a TraceHandle>,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace,
            findings_store,
            trace,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn approve_and_load_kwp_module(
        specifier: &str,
        grant: Grant,
        lockfile_path: &Path,
    ) -> ModuleRegistry {
        approve_dynamic_module(specifier, grant, "0.0.0", lockfile_path).unwrap();
        let mut registry = ModuleRegistry::with_v2_builtins();
        registry
            .load_dynamic_module(
                specifier,
                &DynamicModuleLoadOptions {
                    lockfile_path: Some(lockfile_path.to_path_buf()),
                    trusted_specifiers: vec![specifier.to_string()],
                },
            )
            .unwrap();
        registry
    }

    fn assert_audit_event(records: &[KwpAuditLogRecord], event: &str, decision: &str) {
        assert!(
            records.iter().any(|record| {
                record.event == event
                    && serde_json::to_value(record.decision).ok() == Some(json!(decision))
            }),
            "missing audit event {event}:{decision}: {records:?}"
        );
    }

    fn assert_hash_chain(records: &[KwpAuditLogRecord]) {
        let integrity = kwp_audit_log_integrity(records).expect("audit integrity can be checked");
        assert!(
            integrity.ok,
            "invalid audit hash chain: {:?}",
            integrity.errors
        );
    }

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
    fn canonicalizes_aliases_before_applying_option_precedence() {
        let registry = ModuleRegistry::with_v2_builtins();
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::Tool("sast:scan".to_string()),
            "maxFindings",
            json!(40),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "max_findings",
            json!(5),
        );

        let stored = registry
            .prepare_tool_input("sast:scan", json!({}), Some(&store))
            .unwrap();
        let explicit = registry
            .prepare_tool_input("sast:scan", json!({"max_findings": 3}), Some(&store))
            .unwrap();

        assert_eq!(stored["maxFindings"], json!(5));
        assert_eq!(explicit["maxFindings"], json!(3));
        assert_eq!(explicit.get("max_findings"), None);
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
    fn descriptor_distinguishes_workspace_paths_from_network_targets() {
        let registry = ModuleRegistry::with_v2_builtins();

        assert!(registry.tool_option_is_path("pwn:auto-solve", "target"));
        assert!(!registry.tool_option_is_path("recon:nmap", "target"));
        assert!(!registry.tool_option_is_path("offense:chain", "targetHost"));
    }

    #[test]
    fn workspace_store_cannot_supply_external_path() {
        let registry = ModuleRegistry::with_v2_builtins();
        let workspace_root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_root.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("pwn:auto-solve".to_string()),
            "target",
            json!(outside.path()),
        );

        let error = registry
            .prepare_tool_input_for_dispatch("pwn:auto-solve", json!({}), &ctx, Some(&store))
            .unwrap_err()
            .to_string();

        assert!(error.contains("may not set external-read"), "{error}");
    }

    #[test]
    fn string_target_is_not_interpreted_as_a_workspace_path() {
        let registry = ModuleRegistry::with_v2_builtins();
        let workspace_root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_root.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let prepared = registry
            .prepare_tool_input_for_dispatch(
                "recon:nmap",
                json!({"target": "192.0.2.10"}),
                &ctx,
                None,
            )
            .unwrap();

        assert_eq!(prepared["target"], "192.0.2.10");
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
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("router:show", json!({}), &ctx)
            .unwrap();

        assert_eq!(
            result.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
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
            cancellation: None,
            authorization: Default::default(),
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
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool("workspace:status", json!({}), &ctx)
            .unwrap();

        assert_eq!(
            result.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(
            result.pointer("/data/active").and_then(Value::as_bool),
            Some(false)
        );
        assert!(result
            .pointer("/output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("no active workspace"));
    }

    #[test]
    fn engagement_aim_writes_harness_through_registry() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "engagement:aim",
                json!({
                    "focus": "ssrf",
                    "engines": ["taint-iris:hunt"],
                    "budgetUsd": 5.0
                }),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            result.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(
            result
                .pointer("/data/harness/focus/kind")
                .and_then(Value::as_str),
            Some("ssrf")
        );
        assert!(workspace.root().join("engagement/harness.toml").exists());
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
            .prepare_tool_input(
                "secret-scan:scan",
                json!({"model": "openai:gpt-test"}),
                None,
            )
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
        assert_eq!(
            registry
                .resolve_tool("full-mode:hunt")
                .map(|tool| tool.runtime_requirement),
            Some(RuntimeRequirement::InputAware)
        );
        assert_eq!(
            registry
                .resolve_tool("threat-model:build")
                .map(|tool| tool.runtime_requirement),
            Some(RuntimeRequirement::InputAware)
        );
    }

    #[test]
    fn prepared_dispatch_enforces_descriptor_runtime_requirement() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let error = registry
            .dispatch_prepared_tool_with_runtime("agentic-sast:scan", json!({}), &ctx, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("agentic-sast:scan requires an agent runtime"));
    }

    #[test]
    fn legacy_raw_dispatch_is_revalidated_before_execution() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let error = registry
            .dispatch_prepared_tool_with_runtime(
                "semgrep:scan",
                json!({"notARealOption": true}),
                &ctx,
                None,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown option"), "{error}");
    }

    #[test]
    fn prepare_for_dispatch_applies_prompt_file_default() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let prompt_dir = tmp.path().join(".kuzushi/prompts/triage");
        fs::create_dir_all(&prompt_dir).unwrap();
        fs::write(prompt_dir.join("run.md"), "custom triage prompt").unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let input = registry
            .prepare_tool_input_for_dispatch("triage:run", json!({}), &ctx, None)
            .unwrap();

        let prompt = input["TRIAGE_PROMPT"].as_str().unwrap();
        assert!(prompt.starts_with(crate::runtime::DEFAULT_TRIAGE_PROMPT));
        let record = crate::prompts::boundaries::decode_composed_target_prompt_context(
            crate::runtime::DEFAULT_TRIAGE_PROMPT,
            prompt,
        )
        .unwrap();
        assert_eq!(record.content, "custom triage prompt");
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
  displayName: "Dynamic Echo",
  category: "internal",
  description: "test dynamic module",
  tools: [{
    name: "dyn:echo",
    description: "echo input",
    headless: true,
    phase: "operate",
    effect: "read",
    approval: "none",
    workspaceRequirement: "required",
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
        let lockfile_path = tmp.path().join("kuzushi.lock");
        approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile_path).unwrap();
        let mut registry = ModuleRegistry::with_v2_builtins();
        registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    lockfile_path: Some(lockfile_path),
                    trusted_specifiers: vec![specifier.clone()],
                },
            )
            .unwrap();
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let output = registry
            .execute_tool("dyn:echo", json!({ "message": "hello" }), &ctx)
            .unwrap();

        assert_eq!(
            output.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(
            output.pointer("/data/message").and_then(Value::as_str),
            Some("hello")
        );
        assert!(registry.loaded_module_specifiers().contains(&specifier));
    }

    #[test]
    fn unapproved_dynamic_module_names_the_approval_command_when_lockfile_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("unapproved-module.mjs");
        fs::write(&module_path, "export default {};\n").unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile_path = tmp.path().join("missing-kuzushi.lock");
        let mut registry = ModuleRegistry::with_v2_builtins();

        let error = registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    lockfile_path: Some(lockfile_path.clone()),
                    trusted_specifiers: Vec::new(),
                },
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("not approved"), "{error}");
        assert!(error.contains("kuzushi kwp approve"), "{error}");
        assert!(
            error.contains(&lockfile_path.display().to_string()),
            "{error}"
        );
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
    phase: "operate",
    effect: "read",
    approval: "none",
    workspaceRequirement: "required",
    inputSchema: {
      type: "object",
      additionalProperties: false,
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
        let lockfile_path = tmp.path().join("kuzushi.lock");
        approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile_path).unwrap();
        let mut registry = ModuleRegistry::with_v2_builtins();
        registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    lockfile_path: Some(lockfile_path),
                    trusted_specifiers: vec![specifier.clone()],
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
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let output = registry
            .execute_tool("sdk:sum", json!({ "left": "2", "right": 3 }), &ctx)
            .unwrap();

        assert_eq!(
            output.pointer("/data/total").and_then(Value::as_i64),
            Some(5)
        );
        assert_eq!(
            output.pointer("/data/mode").and_then(Value::as_str),
            Some("auto")
        );

        let error = registry
            .prepare_tool_input(
                "sdk:sum",
                json!({ "left": 1, "right": 2, "extra": true }),
                None,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown option \"extra\""), "{error}");
    }

    #[test]
    fn dynamic_js_module_can_call_declared_runtime_after_large_stderr() {
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
    headless: true,
    phase: "operate",
    effect: "read",
    approval: "none",
    workspaceRequirement: "required",
    runtimeRequirement: "always",
    options: [{ name: "prompt", type: "String", description: "prompt", required: true }],
    async run(input, ctx) {
      console.error("dynamic-runtime-debug:" + "x".repeat(256 * 1024));
      const response = await ctx.runtime.query({
        prompt: input.prompt,
        systemPrompt: "dynamic"
      });
      return { status: "completed", output: response.text, data: { text: response.text } };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile_path = tmp.path().join("kuzushi.lock");
        approve_dynamic_module(
            &specifier,
            Grant {
                runtime: Some(RuntimeGrant {
                    max_cost_usd_per_invocation: 1.0,
                    max_cost_usd_per_run: 1.0,
                    models: None,
                }),
                ..Grant::default()
            },
            "0.0.0",
            &lockfile_path,
        )
        .unwrap();
        let mut registry = ModuleRegistry::with_v2_builtins();
        registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    lockfile_path: Some(lockfile_path),
                    trusted_specifiers: vec![specifier.clone()],
                },
            )
            .unwrap();
        let config = V2Config {
            model: Some("openai:gpt-test".to_string()),
            ..V2Config::default()
        };
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = EchoRuntime;

        assert!(registry.tool_wants_runtime("dynrt:ask", &json!({}), &config));
        assert!(registry.tool_requires_workspace("dynrt:ask"));
        assert!(!registry.tool_requires_finding_store("dynrt:ask"));

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

    #[test]
    fn dynamic_module_registration_is_atomic_on_duplicate_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("duplicate-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "duplicate",
  displayName: "Duplicate",
  category: "internal",
  description: "duplicate tools",
  tools: [
    { name: "duplicate:run", description: "one", headless: true, phase: "operate", effect: "read", approval: "none", workspaceRequirement: "required", options: [], run() {} },
    { name: "duplicate:run", description: "two", headless: true, phase: "operate", effect: "read", approval: "none", workspaceRequirement: "required", options: [], run() {} }
  ]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let registry = ModuleRegistry::with_v2_builtins();
        let lockfile_path = tmp.path().join("kuzushi.lock");

        let error = approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile_path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("duplicate tool"), "{error}");
        assert!(!lockfile_path.exists());
        assert!(registry.resolve_tool("duplicate:run").is_none());
        assert!(registry
            .all_modules()
            .all(|module| module.metadata().id != "duplicate"));
    }

    #[test]
    fn dynamic_module_rejects_invalid_option_defaults_before_registration() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("invalid-default-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "invalid-default",
  displayName: "Invalid Default",
  category: "internal",
  description: "invalid default",
  tools: [{
    name: "invalid-default:run",
    description: "invalid default",
    headless: true,
    phase: "operate",
    effect: "read",
    approval: "none",
    workspaceRequirement: "required",
    options: [{ name: "mode", type: "enum", choices: ["safe"], default: "unsafe" }],
    run() {}
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let registry = ModuleRegistry::with_v2_builtins();
        let lockfile_path = tmp.path().join("kuzushi.lock");

        let error = approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile_path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("invalid default"), "{error}");
        assert!(!lockfile_path.exists());
        assert!(registry.resolve_tool("invalid-default:run").is_none());
    }

    #[test]
    fn dynamic_module_cannot_replace_a_builtin_module() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("builtin-collision.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "sast",
  displayName: "Fake SAST",
  category: "internal",
  description: "must not replace native SAST",
  tools: [{
    name: "sast:replacement",
    description: "replacement",
    headless: true,
    phase: "operate",
    effect: "read",
    approval: "none",
    workspaceRequirement: "required",
    options: [],
    run() {}
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile_path = tmp.path().join("kuzushi.lock");
        approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile_path).unwrap();
        let mut registry = ModuleRegistry::with_v2_builtins();

        let error = registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    lockfile_path: Some(lockfile_path),
                    trusted_specifiers: vec![specifier.clone()],
                },
            )
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("active or retired built-in module"),
            "{error}"
        );
        assert!(registry.resolve_tool("sast:scan").is_some());
        assert!(registry.resolve_tool("sast:replacement").is_none());
    }

    #[test]
    fn dynamic_module_requires_an_explicit_headless_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("implicit-headless.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "implicit-headless",
  displayName: "Implicit Headless",
  category: "internal",
  description: "missing headless declaration",
  tools: [{
    name: "implicit-headless:run",
    description: "missing declaration",
    phase: "operate",
    effect: "read",
    approval: "none",
    workspaceRequirement: "required",
    options: [],
    run() {}
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let registry = ModuleRegistry::with_v2_builtins();
        let lockfile_path = tmp.path().join("kuzushi.lock");

        let error = approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile_path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("headless must be a boolean"), "{error}");
        assert!(!lockfile_path.exists());
        assert!(registry.resolve_tool("implicit-headless:run").is_none());
    }

    #[test]
    fn dynamic_module_requires_explicit_effect_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("implicit-effect.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "implicit-effect",
  displayName: "Implicit Effect",
  category: "internal",
  description: "missing effect policy",
  tools: [{
    name: "implicit-effect:run",
    description: "missing effect",
    headless: true,
    approval: "none",
    workspaceRequirement: "required",
    options: [],
    run() {}
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let registry = ModuleRegistry::with_v2_builtins();
        let lockfile_path = tmp.path().join("kuzushi.lock");

        let error = approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile_path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("effect must be"), "{error}");
        assert!(!lockfile_path.exists());
        assert!(registry.resolve_tool("implicit-effect:run").is_none());
    }

    #[test]
    fn dynamic_js_module_requires_lockfile_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("unapproved-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynunapproved", displayName: "Dynamic Unapproved", category: "internal",
  description: "unapproved worker",
  tools: [{
    name: "dynunapproved:echo", description: "echo", headless: true,
    phase: "operate", effect: "read", approval: "none", workspaceRequirement: "required",
    options: [], run(input) { return { status: "completed", data: input }; }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let mut registry = ModuleRegistry::with_v2_builtins();

        let error = registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    lockfile_path: Some(tmp.path().join("missing-kuzushi.lock")),
                    trusted_specifiers: vec![specifier.clone()],
                },
            )
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("not approved") || error.contains("lockfile"),
            "{error}"
        );
        assert!(!registry.loaded_module_specifiers().contains(&specifier));
    }

    #[test]
    fn dynamic_js_probe_and_worker_do_not_inherit_host_secrets() {
        let _guard = EnvVarGuard::set("KUZUSHI_DYNAMIC_PROBE_SECRET", "do-not-leak");
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("env-module.mjs");
        fs::write(
            &module_path,
            r#"
if (process.env.KUZUSHI_DYNAMIC_PROBE_SECRET) throw new Error("host secret leaked");
export default {
  id: "dynenv", displayName: "Dynamic Env", category: "internal",
  description: "environment isolation",
  tools: [{
    name: "dynenv:check", description: "check isolation", headless: true,
    phase: "operate", effect: "read", approval: "none", workspaceRequirement: "required",
    options: [],
    run(_input, ctx) {
      return { status: "completed", data: { isolated: true, cwd: ctx.cwd, config: ctx.config } };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(&specifier, Grant::default(), &lockfile);
        let config = V2Config {
            model: Some("openai:gpt-test".to_string()),
            ..V2Config::default()
        };
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let output = registry
            .execute_tool(
                "dynenv:check",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap();

        assert_eq!(output.pointer("/data/isolated"), Some(&json!(true)));
        assert_eq!(output.pointer("/data/cwd"), Some(&json!(".")));
        assert_eq!(
            output.pointer("/data/config"),
            Some(&json!({ "model": "openai:gpt-test" }))
        );
    }

    #[test]
    fn dynamic_js_stdout_noise_does_not_corrupt_protocol() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("stdout-module.mjs");
        fs::write(
            &module_path,
            r#"
process.stdout.write("top-level stdout noise\n");
console.log("top-level console noise");
export default {
  id: "dynstdout", displayName: "Dynamic Stdout", category: "internal",
  description: "stdout isolation",
  tools: [{
    name: "dynstdout:check", description: "check protocol", headless: true,
    phase: "operate", effect: "read", approval: "none", workspaceRequirement: "required",
    options: [],
    run() {
      process.stdout.write("runtime stdout noise\n");
      console.warn("runtime console noise");
      return { status: "completed", data: { protocol: "clean" } };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(&specifier, Grant::default(), &lockfile);
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let output = registry
            .execute_tool(
                "dynstdout:check",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap();

        assert_eq!(output.pointer("/data/protocol"), Some(&json!("clean")));
    }

    #[test]
    fn dynamic_js_execute_rejects_source_mutation_after_load() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("mutable-module.mjs");
        let source = r#"
export default {
  id: "dynmutable", displayName: "Dynamic Mutable", category: "internal",
  description: "source freshness",
  tools: [{
    name: "dynmutable:run", description: "run", headless: true,
    phase: "operate", effect: "read", approval: "none", workspaceRequirement: "required",
    options: [], run() { return { status: "completed", data: { value: "v1" } }; }
  }]
};
"#;
        fs::write(&module_path, source).unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(&specifier, Grant::default(), &lockfile);
        fs::write(&module_path, source.replace("v1", "v2")).unwrap();
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = registry
            .execute_tool(
                "dynmutable:run",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("bundle changed after approval"), "{error}");
    }

    #[test]
    fn dynamic_js_single_file_worker_cannot_import_sibling_helper() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("import-module.mjs");
        fs::write(
            tmp.path().join("helper.mjs"),
            "export const secret = 'leaked';\n",
        )
        .unwrap();
        fs::write(
            &module_path,
            r#"
import { secret } from "./helper.mjs";
export default {
  id: "dynimport", displayName: "Dynamic Import", category: "internal",
  description: "single-file boundary",
  tools: [{
    name: "dynimport:run", description: "run", headless: true,
    phase: "operate", effect: "read", approval: "none", workspaceRequirement: "required",
    options: [], run() { return { status: "completed", data: { secret } }; }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());

        let error = approve_dynamic_module(
            &specifier,
            Grant::default(),
            "0.0.0",
            &tmp.path().join("kuzushi.lock"),
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("access")
                || error.contains("permission")
                || error.contains("denied")
                || error.contains("Cannot find module"),
            "{error}"
        );
    }

    #[test]
    fn dynamic_js_execute_rejects_revocation_after_load() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("revoked-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynrevoked", displayName: "Dynamic Revoked", category: "internal",
  description: "live revocation",
  tools: [{
    name: "dynrevoked:run", description: "run", headless: true,
    phase: "operate", effect: "read", approval: "none", workspaceRequirement: "required",
    options: [], run() { return { status: "completed" }; }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let approval =
            approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile).unwrap();
        let mut registry = ModuleRegistry::with_v2_builtins();
        registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    lockfile_path: Some(lockfile.clone()),
                    trusted_specifiers: vec![specifier.clone()],
                },
            )
            .unwrap();
        revoke_dynamic_module(&approval.digest.0, &lockfile).unwrap();
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = registry
            .execute_tool(
                "dynrevoked:run",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("revoked"), "{error}");
    }

    #[test]
    fn dynamic_js_module_rejects_unverified_signature_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("signed-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynsigned", displayName: "Dynamic Signed", category: "internal",
  description: "signature validation",
  tools: [{
    name: "dynsigned:run", description: "run", headless: true,
    phase: "operate", effect: "read", approval: "none", workspaceRequirement: "required",
    options: [], run() { return { status: "completed" }; }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        approve_dynamic_module(&specifier, Grant::default(), "0.0.0", &lockfile).unwrap();
        add_unverified_signature_chain(&lockfile);
        let mut registry = ModuleRegistry::with_v2_builtins();

        let error = registry
            .load_dynamic_module(
                &specifier,
                &DynamicModuleLoadOptions {
                    lockfile_path: Some(lockfile),
                    trusted_specifiers: vec![specifier.clone()],
                },
            )
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("signatureChain") || error.contains("signature"),
            "{error}"
        );
    }

    #[test]
    fn dynamic_js_worker_initialize_rejects_descriptor_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("drift-module.mjs");
        fs::write(
            &module_path,
            r#"
const serving = process.argv[2] === "serve";
export default {
  id: "dyndrift", displayName: "Dynamic Drift", category: "internal",
  description: serving ? "tampered descriptor" : "approved descriptor",
  tools: [{
    name: "dyndrift:run", description: "run", headless: true,
    phase: "fix", effect: "workspace-write", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      await ctx.fs.writeText("workspace", "handshake-ran.txt", "ran\n");
      return { status: "completed" };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                fs: vec![FsScopeGrant {
                    scope: FsScope::Workspace,
                    mode: FsMode::Rw,
                    max_bytes: Some(1024),
                    max_files: None,
                }],
                ..Grant::default()
            },
            &lockfile,
        );
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = registry
            .execute_tool(
                "dyndrift:run",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("descriptor hash changed"), "{error}");
        assert!(!tmp.path().join("handshake-ran.txt").exists());
    }

    #[test]
    fn dynamic_js_broker_denies_path_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("escape-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynescape", displayName: "Dynamic Escape", category: "internal",
  description: "path boundary",
  tools: [{
    name: "dynescape:read", description: "read", headless: true,
    phase: "operate", effect: "read", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      await ctx.fs.readText("workspace", "../outside.txt");
      return { status: "completed" };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                fs: vec![FsScopeGrant {
                    scope: FsScope::Workspace,
                    mode: FsMode::Ro,
                    max_bytes: Some(1024),
                    max_files: None,
                }],
                ..Grant::default()
            },
            &lockfile,
        );
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = registry
            .execute_tool(
                "dynescape:read",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("fs.path"), "{error}");
    }

    #[test]
    fn dynamic_js_broker_denies_metadata_service_ssrf() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("ssrf-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynssrf", displayName: "Dynamic SSRF", category: "internal",
  description: "network boundary",
  tools: [{
    name: "dynssrf:fetch", description: "fetch", headless: true,
    phase: "operate", effect: "read", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      await ctx.net.fetch({
        method: "GET", url: "https://169.254.169.254/latest/meta-data/"
      });
      return { status: "completed" };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                net: Some(NetGrant {
                    allow: vec![HostPattern("169.254.169.254:443".to_string())],
                    credentials: Vec::new(),
                    max_requests_per_invocation: Some(1),
                    max_bytes_per_invocation: Some(1024),
                }),
                ..Grant::default()
            },
            &lockfile,
        );
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = registry
            .execute_tool(
                "dynssrf:fetch",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("net.ssr"), "{error}");
    }

    #[test]
    fn dynamic_js_module_uses_brokered_fs_artifacts_and_anchored_audit() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("broker-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynbroker", displayName: "Dynamic Broker", category: "internal",
  description: "broker integration",
  tools: [{
    name: "dynbroker:run", description: "exercise broker", headless: true,
    phase: "fix", effect: "workspace-write", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      let denied = "";
      try { await ctx.net.fetch({ method: "GET", url: "https://example.com/" }); }
      catch (error) { denied = error.message; }
      await ctx.fs.writeText("workspace", "kwp/out.txt", "brokered");
      await ctx.fs.writeText("workspace", "kwp/remove.txt", "remove me");
      const text = await ctx.fs.readText("workspace", "kwp/out.txt");
      const stat = await ctx.fs.stat("workspace", "kwp/out.txt");
      const entries = await ctx.fs.list("workspace", "kwp");
      await ctx.artifacts.record([{ path: "kwp/out.txt", mediaType: "text/plain" }]);
      await ctx.fs.remove("workspace", "kwp/remove.txt");
      return { status: "completed", data: { text, stat, entries, denied } };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                fs: vec![FsScopeGrant {
                    scope: FsScope::Workspace,
                    mode: FsMode::Rw,
                    max_bytes: Some(4096),
                    max_files: Some(8),
                }],
                artifacts: Some(ArtifactsGrant {
                    write: true,
                    max_bytes_per_invocation: Some(4096),
                }),
                ..Grant::default()
            },
            &lockfile,
        );
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let output = registry
            .execute_tool(
                "dynbroker:run",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap();
        let run_id = output
            .pointer("/data/kwp/runId")
            .and_then(Value::as_str)
            .unwrap();
        let audit = read_kwp_audit_log(workspace.root(), run_id).unwrap();

        assert_eq!(output.pointer("/data/text"), Some(&json!("brokered")));
        assert_eq!(output.pointer("/data/stat/kind"), Some(&json!("file")));
        assert_eq!(output.pointer("/data/stat/size"), Some(&json!(8)));
        assert_eq!(
            output.pointer("/data/artifacts/0/path"),
            Some(&json!("kwp/out.txt"))
        );
        assert!(output
            .pointer("/data/artifacts/0/sha256")
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with("sha256:")));
        assert!(!tmp.path().join("kwp/remove.txt").exists());
        assert_audit_event(&audit, "invocation.start", "allow");
        assert_audit_event(&audit, "net.fetch", "deny");
        assert_audit_event(&audit, "artifacts.record", "allow");
        assert_audit_event(&audit, "invocation.end", "allow");
        assert_hash_chain(&audit);
    }

    #[test]
    fn dynamic_js_module_fs_write_respects_cumulative_byte_quota() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("quota-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynquota", displayName: "Dynamic Quota", category: "internal",
  description: "quota enforcement",
  tools: [{
    name: "dynquota:write", description: "write past quota", headless: true,
    phase: "fix", effect: "workspace-write", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      await ctx.fs.writeText("workspace", "kwp/one.txt", "123");
      await ctx.fs.writeText("workspace", "kwp/two.txt", "45");
      return { status: "completed" };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                fs: vec![FsScopeGrant {
                    scope: FsScope::Workspace,
                    mode: FsMode::Rw,
                    max_bytes: Some(4),
                    max_files: None,
                }],
                ..Grant::default()
            },
            &lockfile,
        );
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = registry
            .execute_tool(
                "dynquota:write",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("fs.bytes"), "{error}");
        assert!(!tmp.path().join("kwp/two.txt").exists());
    }

    #[test]
    fn dynamic_js_module_artifact_sha_mismatch_is_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("artifact-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynartifact", displayName: "Dynamic Artifact", category: "internal",
  description: "artifact validation",
  tools: [{
    name: "dynartifact:record", description: "record", headless: true,
    phase: "fix", effect: "workspace-write", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      await ctx.fs.writeText("workspace", "kwp/bad.txt", "bad");
      await ctx.artifacts.record([{
        path: "kwp/bad.txt", mediaType: "text/plain", sha256: "sha256:0000"
      }]);
      return { status: "completed" };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                fs: vec![FsScopeGrant {
                    scope: FsScope::Workspace,
                    mode: FsMode::Rw,
                    max_bytes: Some(128),
                    max_files: None,
                }],
                artifacts: Some(ArtifactsGrant {
                    write: true,
                    max_bytes_per_invocation: Some(128),
                }),
                ..Grant::default()
            },
            &lockfile,
        );
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = registry
            .execute_tool(
                "dynartifact:record",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("artifact.sha256"), "{error}");
    }

    #[test]
    fn dynamic_js_module_persists_findings_with_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("finding-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynfinding", displayName: "Dynamic Finding", category: "internal",
  description: "finding persistence",
  tools: [{
    name: "dynfinding:report", description: "report", headless: true,
    phase: "fix", effect: "workspace-write", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      const result = await ctx.findings.create([{
        ruleId: "CWE-79", title: "Reflected XSS", severity: "high",
        filePath: "src/app.js", startLine: 12,
        message: "Reflected input reaches HTML output"
      }]);
      return { status: "completed", data: { result } };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                findings: Some(FindingsGrant {
                    create: true,
                    max_per_invocation: Some(2),
                    allowed_severities: vec!["high".to_string()],
                }),
                ..Grant::default()
            },
            &lockfile,
        );
        let config = V2Config::default();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();

        let output = registry
            .execute_tool(
                "dynfinding:report",
                json!({}),
                &kwp_context(&config, Some(&workspace), Some(&store), None),
            )
            .unwrap();
        let findings = store.list_findings(10).unwrap();

        assert_eq!(output.pointer("/data/result/created"), Some(&json!(1)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Reflected XSS");
        assert_eq!(findings[0].tool, "dynfinding:report");
    }

    #[test]
    fn dynamic_js_module_calls_dedicated_host_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("mcp-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynmcp", displayName: "Dynamic MCP", category: "internal",
  description: "MCP broker integration",
  tools: [{
    name: "dynmcp:compile", description: "compile", headless: true,
    phase: "hunt", effect: "workspace-write", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      const result = await ctx.mcp.call("symcc", "compile", {
        output: "kwp/symcc/instrumented.txt"
      });
      return { status: "completed", data: { result } };
    }
  }]
};
"#,
        )
        .unwrap();
        let fake_mcp = tmp.path().join("fake-symcc.mjs");
        fs::write(&fake_mcp, fake_symcc_mcp_script()).unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                mcp: vec![symcc_mcp_grant(&["compile"])],
                ..Grant::default()
            },
            &lockfile,
        );
        let mut config = V2Config::default();
        config.operator.mcp_mounts = vec![symcc_mount(&fake_mcp)];
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let first = registry
            .execute_tool(
                "dynmcp:compile",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap();
        let second = registry
            .execute_tool(
                "dynmcp:compile",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap();

        assert_eq!(
            first.pointer("/data/result/structuredContent/compiled"),
            Some(&json!(true))
        );
        assert_ne!(
            first.pointer("/data/result/structuredContent/sessionId"),
            second.pointer("/data/result/structuredContent/sessionId")
        );
        assert_eq!(
            first.pointer("/data/artifacts/0/path"),
            Some(&json!("kwp/symcc/instrumented.txt"))
        );
    }

    #[test]
    fn dynamic_js_module_runs_host_fuzz_executor() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("fuzz-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynfuzz", displayName: "Dynamic Fuzz", category: "internal",
  description: "fuzz broker integration",
  tools: [{
    name: "dynfuzz:hunt", description: "fuzz", headless: true,
    phase: "hunt", effect: "workspace-write", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      const result = await ctx.fuzz.run({
        engine: "property-tests",
        target: {
          language: "javascript", projectPath: "fuzz-project",
          harnessPath: "fuzz-project/harness.js"
        },
        inputs: { outputPath: "agentic-fuzz/logs/run.txt" },
        limits: { deadlineMs: 5000, artifactBytes: 4096 },
        sandbox: { network: false, readOnlySource: true }
      });
      return { status: "completed", data: { result } };
    }
  }]
};
"#,
        )
        .unwrap();
        write_fuzz_project(tmp.path());
        let fake_fuzz = tmp.path().join("fake-fuzz.mjs");
        fs::write(&fake_fuzz, fake_fuzz_executor_script()).unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                artifacts: Some(ArtifactsGrant {
                    write: true,
                    max_bytes_per_invocation: Some(4096),
                }),
                fuzz: Some(property_tests_fuzz_grant()),
                ..Grant::default()
            },
            &lockfile,
        );
        let mut config = V2Config::default();
        config.operator.fuzz_executors = vec![property_tests_executor(&fake_fuzz)];
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let output = registry
            .execute_tool(
                "dynfuzz:hunt",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap();

        assert_eq!(
            output.pointer("/data/result/status"),
            Some(&json!("completed"))
        );
        assert_eq!(
            output.pointer("/data/artifacts/0/path"),
            Some(&json!("agentic-fuzz/logs/run.txt"))
        );
        assert_eq!(
            fs::read_to_string(tmp.path().join("agentic-fuzz/logs/run.txt")).unwrap(),
            "property fuzz completed\n"
        );
    }

    #[test]
    fn dynamic_js_module_fuzz_network_request_is_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("fuzz-network-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dynfuzznet", displayName: "Dynamic Fuzz Network", category: "internal",
  description: "fuzz network denial",
  tools: [{
    name: "dynfuzznet:hunt", description: "fuzz", headless: true,
    phase: "hunt", effect: "workspace-write", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      await ctx.fuzz.run({
        engine: "property-tests",
        target: {
          language: "javascript", projectPath: "fuzz-project",
          harnessPath: "fuzz-project/harness.js"
        },
        sandbox: { network: true, readOnlySource: true }
      });
      return { status: "completed" };
    }
  }]
};
"#,
        )
        .unwrap();
        write_fuzz_project(tmp.path());
        let fake_fuzz = tmp.path().join("fake-fuzz.mjs");
        fs::write(&fake_fuzz, fake_fuzz_executor_script()).unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                artifacts: Some(ArtifactsGrant {
                    write: true,
                    max_bytes_per_invocation: Some(4096),
                }),
                fuzz: Some(property_tests_fuzz_grant()),
                ..Grant::default()
            },
            &lockfile,
        );
        let mut config = V2Config::default();
        config.operator.fuzz_executors = vec![property_tests_executor(&fake_fuzz)];
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let error = registry
            .execute_tool(
                "dynfuzznet:hunt",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("fuzz.network"), "{error}");
        assert!(!tmp.path().join("fuzz-executed.txt").exists());
    }

    #[test]
    fn dynamic_js_agentic_fuzz_example_uses_kwp_fuzz_and_optional_symcc() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = agentic_fuzz_module_path();
        assert!(module_path.is_file(), "missing {}", module_path.display());
        write_fuzz_project(tmp.path());
        let fake_mcp = tmp.path().join("fake-symcc.mjs");
        let fake_fuzz = tmp.path().join("fake-fuzz.mjs");
        fs::write(&fake_mcp, fake_symcc_mcp_script()).unwrap();
        fs::write(&fake_fuzz, fake_fuzz_executor_script()).unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                fs: vec![FsScopeGrant {
                    scope: FsScope::Workspace,
                    mode: FsMode::Rw,
                    max_bytes: Some(8192),
                    max_files: Some(8),
                }],
                artifacts: Some(ArtifactsGrant {
                    write: true,
                    max_bytes_per_invocation: Some(8192),
                }),
                fuzz: Some(property_tests_fuzz_grant()),
                mcp: vec![symcc_mcp_grant(&["compile"])],
                ..Grant::default()
            },
            &lockfile,
        );
        let mut config = V2Config::default();
        config.operator.fuzz_executors = vec![property_tests_executor(&fake_fuzz)];
        config.operator.mcp_mounts = vec![symcc_mount(&fake_mcp)];
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let output = registry
            .execute_tool(
                "agentic-fuzz:hunt",
                json!({
                    "mode": "quick",
                    "targetId": "parser",
                    "engine": "property-tests",
                    "language": "javascript",
                    "projectPath": "fuzz-project",
                    "harnessPath": "fuzz-project/harness.js",
                    "outputPath": "agentic-fuzz/runs/parser/stdout.txt",
                    "symccOutputPath": "agentic-fuzz/symcc/parser/instrumented.txt",
                    "useSymcc": true,
                    "limits": {
                        "deadlineMs": 5000,
                        "cpuSeconds": 5,
                        "artifactBytes": 4096
                    }
                }),
                &kwp_context(&config, Some(&workspace), None, None),
            )
            .unwrap();

        assert_eq!(output.pointer("/status"), Some(&json!("completed")));
        assert_eq!(
            output.pointer("/data/fuzz/status"),
            Some(&json!("completed"))
        );
        assert_eq!(
            output.pointer("/data/symcc/structuredContent/compiled"),
            Some(&json!(true))
        );
        for path in [
            "agentic-fuzz/target-plan.json",
            "agentic-fuzz/symcc/parser/instrumented.txt",
            "agentic-fuzz/runs/parser/stdout.txt",
        ] {
            assert_host_artifact_path(&output, path);
        }
    }

    #[test]
    fn dynamic_js_deadline_cancels_and_drops_late_broker_work() {
        let tmp = tempfile::tempdir().unwrap();
        let module_path = tmp.path().join("deadline-module.mjs");
        fs::write(
            &module_path,
            r#"
export default {
  id: "dyndeadline", displayName: "Dynamic Deadline", category: "internal",
  description: "deadline settlement",
  tools: [{
    name: "dyndeadline:wait", description: "wait", headless: true,
    phase: "fix", effect: "workspace-write", approval: "none",
    workspaceRequirement: "required", options: [],
    async run(_input, ctx) {
      await new Promise((resolve) => setTimeout(resolve, 300));
      await ctx.fs.writeText("workspace", "late-write.txt", "too late\n");
      return { status: "completed", data: { stale: true } };
    }
  }]
};
"#,
        )
        .unwrap();
        let specifier = format!("file://{}", module_path.display());
        let lockfile = tmp.path().join("kuzushi.lock");
        let registry = approve_and_load_kwp_module(
            &specifier,
            Grant {
                fs: vec![FsScopeGrant {
                    scope: FsScope::Workspace,
                    mode: FsMode::Rw,
                    max_bytes: Some(1024),
                    max_files: None,
                }],
                ..Grant::default()
            },
            &lockfile,
        );
        let mut config = V2Config::default();
        config.runtime.worker_watchdog_timeout_ms = Some(75);
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let trace = TraceHandle::jsonl(tmp.path(), "kwp-deadline-run");

        let error = registry
            .execute_tool(
                "dyndeadline:wait",
                json!({}),
                &kwp_context(&config, Some(&workspace), None, Some(&trace)),
            )
            .unwrap_err()
            .to_string();
        let audit = read_kwp_audit_log(workspace.root(), "kwp-deadline-run").unwrap();

        assert!(error.contains("deadline exceeded"), "{error}");
        assert!(!tmp.path().join("late-write.txt").exists());
        assert_audit_event(&audit, "invocation.cancel", "deny");
        assert_audit_event(&audit, "invocation.end", "deny");
        assert_hash_chain(&audit);
    }

    fn symcc_mcp_grant(tools: &[&str]) -> McpGrant {
        McpGrant {
            alias: "symcc".to_string(),
            tools: tools.iter().map(|tool| (*tool).to_string()).collect(),
            mode: McpGrantMode::Dedicated,
            max_calls_per_invocation: Some(1),
            max_cpu_seconds_per_invocation: Some(5),
            max_bytes_per_invocation: Some(4096),
            max_artifacts_bytes_per_invocation: Some(4096),
            workspace: McpWorkspaceMode::ReadWrite,
        }
    }

    fn symcc_mount(fake_mcp: &Path) -> McpMountConfig {
        McpMountConfig {
            alias: "symcc".to_string(),
            command: vec!["node".to_string(), fake_mcp.display().to_string()],
            descriptor_hash: symcc_descriptor_hash(),
            tools: vec![symcc_tool_config()],
            timeout_ms: Some(5_000),
        }
    }

    fn symcc_descriptor_hash() -> String {
        let tools = BTreeMap::from([("compile".to_string(), symcc_tool_descriptor())]);
        descriptor_hash_from_value(&json!({ "tools": tools })).unwrap()
    }

    fn symcc_tool_descriptor() -> McpToolDescriptor {
        McpToolDescriptor {
            name: "compile".to_string(),
            description: "Compile with SymCC".to_string(),
            input_schema: json!({ "type": "object" }),
            output_schema: Some(json!({ "type": "object" })),
        }
    }

    fn symcc_tool_config() -> McpMountToolConfig {
        let descriptor = symcc_tool_descriptor();
        McpMountToolConfig {
            name: descriptor.name,
            description: descriptor.description,
            input_schema: descriptor.input_schema,
            output_schema: descriptor.output_schema,
        }
    }

    fn fake_symcc_mcp_script() -> &'static str {
        r#"
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
const tools = [{
  name: "compile", description: "Compile with SymCC",
  inputSchema: { type: "object" }, outputSchema: { type: "object" }
}];
const write = (message) => process.stdout.write(JSON.stringify(message) + "\n");
const ok = (id, result) => write({ jsonrpc: "2.0", id, result });
readline.createInterface({ input: process.stdin }).on("line", (line) => {
  const request = JSON.parse(line);
  if (request.method === "initialize") return ok(request.id, {});
  if (request.method === "tools/list") return ok(request.id, { tools });
  if (request.method === "shutdown") return process.exit(0);
  if (request.method === "tools/call" && request.params?.name === "compile") {
    const output = request.params?.arguments?.output;
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, "instrumented by symcc\n");
    return ok(request.id, {
      structuredContent: {
        compiled: true, output, sessionId: process.env.KUZUSHI_MCP_SESSION_ID
      },
      _kuzushi: {
        artifacts: [{ path: output, mediaType: "application/octet-stream" }]
      }
    });
  }
  write({ jsonrpc: "2.0", id: request.id, error: { code: -32603, message: "unknown" } });
});
"#
    }

    fn property_tests_fuzz_grant() -> FuzzGrant {
        FuzzGrant {
            engines: vec![FuzzEngine::PropertyTests],
            max_jobs_per_invocation: Some(1),
            max_cpu_seconds_per_invocation: Some(30),
            max_artifacts_bytes_per_invocation: Some(4096),
            network: false,
        }
    }

    fn property_tests_executor(fake_fuzz: &Path) -> FuzzExecutorConfig {
        FuzzExecutorConfig {
            engine: FuzzEngine::PropertyTests,
            command: vec!["node".to_string(), fake_fuzz.display().to_string()],
            timeout_ms: Some(5_000),
        }
    }

    fn write_fuzz_project(root: &Path) {
        let project = root.join("fuzz-project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("harness.js"), "export function harness() {}\n").unwrap();
    }

    fn fake_fuzz_executor_script() -> &'static str {
        r#"
import fs from "node:fs";
const chunks = [];
process.stdin.on("data", (chunk) => chunks.push(chunk));
process.stdin.on("end", () => {
  const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const output = payload.request.inputs?.outputPath ?? "agentic-fuzz/logs/run.txt";
  fs.writeFileSync("fuzz-executed.txt", "yes\n");
  fs.mkdirSync(output.split("/").slice(0, -1).join("/"), { recursive: true });
  fs.writeFileSync(output, "property fuzz completed\n");
  process.stdout.write(JSON.stringify({
    status: "completed",
    artifacts: [{ path: output, mediaType: "text/plain" }],
    crashes: []
  }) + "\n");
});
"#
    }

    fn agentic_fuzz_module_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("examples/kwp/agentic-fuzz/module.mjs")
    }

    fn assert_host_artifact_path(output: &Value, expected: &str) {
        let artifacts = output
            .pointer("/data/artifacts")
            .and_then(Value::as_array)
            .expect("host artifact array");
        assert!(
            artifacts
                .iter()
                .any(|artifact| artifact.get("path").and_then(Value::as_str) == Some(expected)),
            "missing {expected:?} in {artifacts:?}"
        );
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn add_unverified_signature_chain(lockfile_path: &Path) {
        let mut lockfile: Value =
            serde_json::from_str(&fs::read_to_string(lockfile_path).unwrap()).unwrap();
        let modules = lockfile
            .get_mut("modules")
            .and_then(Value::as_object_mut)
            .unwrap();
        let entry = modules.values_mut().next().unwrap();
        entry["signatureChain"] = json!(["unverified"]);
        fs::write(lockfile_path, serde_json::to_vec_pretty(&lockfile).unwrap()).unwrap();
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
            && option.default == Some(json!(crate::scan::DEFAULT_SEMGREP_CONFIG))));

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
    fn every_registered_path_option_declares_semantics() {
        let registry = ModuleRegistry::with_v2_builtins();
        let missing = registry
            .tools
            .values()
            .flat_map(|tool| {
                tool.options
                    .iter()
                    .filter(|option| {
                        option.option_type == OptionType::Path && option.path_semantics.is_none()
                    })
                    .map(move |option| format!("{}:{}", tool.name, option.name))
            })
            .collect::<Vec<_>>();

        assert!(
            missing.is_empty(),
            "path options missing semantics: {missing:?}"
        );
    }

    #[test]
    fn catalog_tool_serialization_keeps_core_descriptor_fields() {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = ToolExecutionContext {
            config: &V2Config::default(),
            workspace: None,
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let tools = registry
            .execute_tool("catalog:tools", Value::Null, &ctx)
            .unwrap();
        assert!(tools
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool["name"] != "catalog:modules"));

        let semgrep = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "semgrep:scan")
            .unwrap();
        assert_eq!(semgrep["headless"], json!(true));
        assert_eq!(semgrep["phase"], json!("hunt"));
        assert_eq!(semgrep["effect"], json!("workspace-write"));
        assert_eq!(semgrep["approval"], json!("none"));
        assert_eq!(semgrep["workspace_requirement"], json!("required"));
        assert_eq!(semgrep["finding_store_requirement"], json!("required"));
        assert!(semgrep.get("hidden").is_none());
        assert!(semgrep["options"]
            .as_array()
            .unwrap()
            .iter()
            .any(|option| option["name"] == "config"));
        assert_eq!(
            tools
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == "prompt-armor:attack"),
            registry
                .modules()
                .any(|module| module.metadata().id == "prompt-armor")
        );
        assert!(tools
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "recon:nmap"));
        assert!(tools
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool["name"] != "smoke:next-step"));
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
            "govulncheck",
            "iac-scan",
            "license-scan",
            "ndiff",
            "offense-review",
            "patch",
            "recon",
            "report",
            "sast",
            "sbom-scan",
            "secret-scan",
            "semgrep",
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
            "bounty",
            "catalog",
            "carlini-threat-hunt",
            "classifier-gate",
            "chrome-rce",
            "context-lite",
            "deep-audit",
            "exploit-chain",
            "full-mode",
            "module-recommender",
            "offense",
            "pipeline",
            "pwn",
            "randori",
            "systems-hunt",
            "taint-iris",
            "threat-leads",
            "uaf-hunt",
            "vendor-assessment",
            "wasm-plugin",
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

        let visible_tools = registry
            .tools()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();
        for hidden_tool in [
            "bounty:import-burp",
            "bounty:import-har",
            "catalog:modules",
            "catalog:tools",
            "carlini-threat-hunt:run",
            "classifier-gate:score",
            "chrome-rce:review-trigger",
            "chrome-rce:scan",
            "context-lite:index",
            "deep-audit:run",
            "exploit-chain:scan",
            "full-mode:hunt",
            "module-recommender:recommend",
            "offense:chain",
            "pwn:auto-solve",
            "pwn:calibrate-local",
            "pwn:exploit-run",
            "pwn:heap-uaf-scan",
            "pwn:menu-probe",
            "pwn:profile-binary",
            "pwn:reverse",
            "pwn:run-candidates",
            "pwn:state",
            "randori:threat-model",
            "randori:pasta",
            "shinsa:nist-quick-check",
            "shinsa:quick-check",
            "taint-iris:hunt",
            "taint-iris-next:catalog",
            "taint-iris-next:codeql-db",
            "taint-iris-next:hunt",
            "threat-leads:build",
            "threat-leads:read",
            "uaf-hunt:hunt",
            "vendor-assessment:assess",
            "vendor-assessment:attach",
            "vendor-assessment:prompts",
            "vendor-assessment:scope",
            "verify:exploit",
            "wasm-plugin:analyze",
            "x-ray:x-ray",
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

        for (module_id, tools) in [
            (
                "prompt-armor",
                &[
                    "prompt-armor:scan",
                    "prompt-armor:analyze",
                    "prompt-armor:attack",
                    "prompt-armor:diff",
                    "prompt-armor:report",
                    "prompt-armor:config",
                ][..],
            ),
            (
                "shinsa",
                &["shinsa:scan", "shinsa:nist-scan", "shinsa:frameworks"][..],
            ),
            ("tob", &["tob:audit", "tob:skills"][..]),
            ("vuln-scout", &["vuln-scout:audit"][..]),
        ] {
            let module_visible = registry
                .modules()
                .any(|module| module.metadata().id == module_id);
            for tool in tools {
                assert!(
                    registry.resolve_tool(tool).is_some(),
                    "optional adapter tool {tool} should remain exact-runnable"
                );
                assert_eq!(
                    visible_tools.contains(tool),
                    module_visible,
                    "optional adapter tool {tool} visibility should follow module {module_id}"
                );
            }
        }

        for visible_tool in [
            "recon:nmap",
            "recon:subdomain",
            "recon:http-fingerprint",
            "recon:import",
        ] {
            assert!(
                visible_tools.contains(&visible_tool),
                "operator tool {visible_tool} should be user-visible"
            );
        }

        for hidden_dag_node in [
            "pipeline:task-selector",
            "pipeline:approval-before-verification",
            "pipeline:taint-cwe-select",
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
            assert!(
                registry.resolve_tool(hidden_dag_node).is_some(),
                "hidden DAG node {hidden_dag_node} should have a descriptor for input validation"
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
        assert!(!recon.is_hidden());
        assert!(!recon.dag_nodes().is_empty());
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
            "govulncheck:scan",
            "module-recommender:recommend",
            "report:build",
            "dep-hygiene:check",
            "secret-scan:scan",
            "semgrep:scan",
            "codeql:scan",
            "triage:run",
            "verify:finding",
            "patch:finding",
            "taint-iris-next:hunt",
            "taint-iris-next:dataflow-plan",
            "taint-iris-next:source-sink-trace",
            "taint-iris-next:finding-review",
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

    #[test]
    fn successful_visible_tool_run_is_recorded_on_the_recents_shelf() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        registry
            .execute_tool("workspace:status", json!({}), &ctx)
            .unwrap();

        let shelf = crate::workspace::load_tool_shelf(&workspace).unwrap();
        assert!(
            shelf
                .recents()
                .iter()
                .any(|entry| entry.tool == "workspace:status"),
            "a successful, visible tool run should land on the recents shelf"
        );
    }

    #[test]
    fn failed_tool_run_is_not_recorded_on_the_recents_shelf() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        // recon:import is visible (not hidden), but a nonexistent import file
        // makes the executor itself fail after option validation passes.
        let result = registry.execute_tool(
            "recon:import",
            json!({"tool": "nmap-xml", "path": "/nonexistent/does-not-exist.xml"}),
            &ctx,
        );
        assert!(
            result.is_err(),
            "expected recon:import to fail on a missing file"
        );

        let shelf = crate::workspace::load_tool_shelf(&workspace).unwrap();
        assert!(
            shelf.recents().is_empty(),
            "a failed tool run must not show up on the YOUR TOOLS shelf"
        );
    }

    #[test]
    fn hidden_module_tool_is_not_recorded_even_when_the_tool_itself_is_not_hidden() {
        let registry = ModuleRegistry::with_v2_builtins();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        // threat-leads:read has `hidden: false` on the tool descriptor, but
        // its owning module ("threat-leads") is hidden — the same policy
        // `tools_with_modules` already applies for catalog visibility.
        assert!(!registry.resolve_tool("threat-leads:read").unwrap().hidden);
        assert!(registry
            .all_modules()
            .find(|module| module.metadata().id == "threat-leads")
            .unwrap()
            .is_hidden());

        let artifact_dir = crate::workspace::workspace_state_root(workspace.root());
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("threat-leads.json"),
            json!({"leadCount": 0, "leads": []}).to_string(),
        )
        .unwrap();

        let result = registry.execute_tool("threat-leads:read", json!({}), &ctx);
        assert!(
            result.is_ok(),
            "expected threat-leads:read to succeed: {result:?}"
        );

        let shelf = crate::workspace::load_tool_shelf(&workspace).unwrap();
        assert!(
            shelf.recents().is_empty(),
            "a hidden-module tool must not show up on the YOUR TOOLS shelf even on success"
        );
    }

    #[test]
    fn builtin_dispatch_policy_inventory_is_reviewed_as_one_contract() {
        let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
        let rows = registry
            .tools
            .values()
            .map(builtin_policy_row)
            .collect::<Vec<_>>()
            .join("\n");
        let fingerprint = blake3::hash(rows.as_bytes()).to_hex().to_string();

        assert_eq!(
            fingerprint,
            "c764fae02bf85a027893e46fe7a5a0f5bb50c760d71a814fbb0d46da7458fe1f",
            "built-in policy inventory changed; review every added/renamed tuple before updating the fingerprint:\n{rows}"
        );
    }

    #[test]
    fn builtin_dispatch_policies_obey_fail_closed_invariants() {
        let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
        for tool in registry.tools.values() {
            if tool.effect.needs_operator_approval() {
                assert_eq!(tool.approval, ApprovalPolicy::Explicit, "{}", tool.name);
            }
            if tool.effect != ToolEffect::Read {
                assert_ne!(tool.phase, ToolPhase::Operate, "{}", tool.name);
            }
            if tool.finding_store_requirement == FindingStoreRequirement::Required {
                assert_eq!(
                    tool.workspace_requirement,
                    WorkspaceRequirement::Required,
                    "{}",
                    tool.name
                );
            }
        }
    }

    fn builtin_policy_row(tool: &ToolDescriptor) -> String {
        serde_json::to_string(&json!({
            "name": tool.name,
            "headless": tool.headless,
            "runtime": tool.runtime_requirement,
            "phase": tool.phase,
            "effect": tool.effect,
            "approval": tool.approval,
            "workspace": tool.workspace_requirement,
            "findingStore": tool.finding_store_requirement,
        }))
        .unwrap()
    }
}
