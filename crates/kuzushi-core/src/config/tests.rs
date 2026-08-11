#[cfg(test)]
mod tests {
    use super::super::*;
    use std::fs;

    #[test]
    fn loads_defaults_without_files() {
        let tmp = tempfile::tempdir().unwrap();
        let config = load_config(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.model, None);
        assert_eq!(config.runtime.kind, RuntimeKind::LangGraph);
        assert_eq!(config.runtime.api_key_env, "OPENAI_API_KEY");
        assert_eq!(
            config.runtime.worker_watchdog_timeout_ms,
            Some(DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS)
        );
        assert_eq!(config.phases.stop_after, None);
        assert_eq!(config.phases.scan.concurrency, None);
    }

    #[test]
    fn loads_guided_phase_template_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[phases]
stop_after = "scan"

[phases.scan]
budget_usd = 1.25
concurrency = 2
strategy_cap = 3
prompt_variant = "deep"
confirmation_depth = "sampled"
"#,
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.phases.stop_after, Some(GuidedPhase::Scan));
        assert_eq!(config.phases.scan.budget_usd, Some(1.25));
        assert_eq!(config.phases.scan.concurrency, Some(2));
        assert_eq!(config.phases.scan.strategy_cap, Some(3));
        assert_eq!(config.phases.scan.prompt_variant.as_deref(), Some("deep"));
        assert_eq!(
            config.phases.scan.confirmation_depth.as_deref(),
            Some("sampled")
        );
    }

    #[test]
    fn loads_legacy_phase_aliases_and_serializes_canonical_names() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[phases]
stop_after = "confirm"

[phases.hunt]
concurrency = 2

[phases.confirm]
confirmation_depth = "empirical"
"#,
        )
        .unwrap();

        let loaded_config = load_config_with_diagnostics(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();
        let LoadedConfig {
            config,
            diagnostics,
        } = loaded_config;

        assert_eq!(config.phases.stop_after, Some(GuidedPhase::Prove));
        assert_eq!(config.phases.scan.concurrency, Some(2));
        assert_eq!(
            config.phases.prove.confirmation_depth.as_deref(),
            Some("empirical")
        );
        let serialized = toml::to_string(&config).unwrap();
        assert!(serialized.contains("stop_after = \"prove\""));
        assert!(serialized.contains("[phases.scan]"));
        assert!(serialized.contains("[phases.review]"));
        assert!(serialized.contains("[phases.prove]"));
        assert!(!serialized.contains("[phases.hunt]"));
        assert!(!serialized.contains("[phases.confirm]"));
        assert_eq!(diagnostics.len(), 3);
        assert!(diagnostics.iter().any(|diagnostic| diagnostic
            .to_string()
            .contains("global config uses deprecated [phases.hunt]; use [phases.scan]")));
        assert!(diagnostics.iter().any(|diagnostic| diagnostic
            .to_string()
            .contains("global config uses deprecated [phases.confirm]; use [phases.prove]")));
        assert!(diagnostics.iter().any(|diagnostic| diagnostic
            .to_string()
            .contains("global config uses deprecated stop_after = \"confirm\"; use \"prove\"")));
        assert!(diagnostics.iter().all(|diagnostic| !diagnostic
            .to_string()
            .contains(tmp.path().to_string_lossy().as_ref())));
    }

    #[test]
    fn rejects_legacy_and_canonical_phase_tables_together() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[phases.scan]
concurrency = 1

[phases.hunt]
concurrency = 2
"#,
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("duplicate field"));
    }

    #[test]
    fn target_phase_alias_is_rejected_as_operator_owned() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            target.join(".kuzushi/v3/config.toml"),
            "[phases.confirm]\nconfirmation_depth = \"empirical\"\n",
        )
        .unwrap();

        let error = load_config_with_diagnostics(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: Some(target),
        })
        .unwrap_err();
        let message = format!("{error:#}");

        assert!(
            message.contains("operator-only fields (phases)"),
            "{message}"
        );
    }

    #[test]
    fn rejects_numbered_stop_after_values() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[phases]
stop_after = "2"
"#,
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("unknown variant `2`"), "{message}");
        assert!(message.contains("scan"), "{message}");
    }

    #[test]
    fn project_config_cannot_set_guided_phase_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("target");
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            target.join(".kuzushi/v3/config.toml"),
            r#"
[phases]
stop_after = "map"

[phases.map]
strategy_cap = 1
"#,
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap_err();
        let message = format!("{error:#}");

        assert!(
            message.contains("operator-only fields (phases)"),
            "{message}"
        );
    }

    #[test]
    fn rejects_invalid_guided_phase_template_values() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[phases.scan]
concurrency = 0
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("phases.scan.concurrency"));
    }

    #[test]
    fn rejects_blank_guided_phase_prompt_variant() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[phases.prove]
prompt_variant = "   "
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("phases.prove.prompt_variant"));
    }

    #[test]
    fn writes_default_config_with_parent_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested").join("config.toml");

        write_default_config(&path).unwrap();

        let body = fs::read_to_string(path).unwrap();
        assert!(body.contains("Kuzushi config"));
        assert!(body.contains("[runtime]"));
    }

    #[test]
    fn persists_global_model_selection_to_global_config() {
        let _env = crate::test_env::config_env_lock();
        let tmp = tempfile::tempdir().unwrap();
        let _home = crate::test_env::ScopedEnv::set("HOME", tmp.path());

        let path = persist_global_model_selection("openai:gpt-5.5", Some("xhigh")).unwrap();
        let body = fs::read_to_string(&path).unwrap();

        assert_eq!(path, tmp.path().join(".kuzushi/v3/config.toml"));
        assert!(body.contains("model = \"openai:gpt-5.5\""));
        assert!(body.contains("thinking_level = \"xhigh\""));
        let loaded = load_config(ConfigPaths {
            home_dir: tmp.path().to_path_buf(),
            target_dir: None,
        })
        .unwrap();
        assert_eq!(loaded.model.as_deref(), Some("openai:gpt-5.5"));
        assert_eq!(loaded.runtime.thinking_level.as_deref(), Some("xhigh"));
    }

    #[cfg(unix)]
    #[test]
    fn project_config_reader_rejects_an_outside_symlink_without_disclosing_content() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("repo");
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "OUTSIDE_CONFIG_TOKEN").unwrap();
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        symlink(outside.path(), target.join(".kuzushi/v3/config.toml")).unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("symlink"), "{error}");
        assert!(!error.contains("OUTSIDE_CONFIG_TOKEN"));
    }

    #[test]
    fn config_hash_is_stable_sha256_label() {
        let config = V2Config {
            model: Some("openai:gpt-test".to_string()),
            ..Default::default()
        };

        let first = config_hash(&config).unwrap();
        let second = config_hash(&config).unwrap();

        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), "sha256:".len() + 64);
    }

    #[test]
    fn default_oauth_credentials_path_uses_workspace_state_root() {
        let home = std::path::Path::new("/home/kuzushi");

        assert_eq!(
            default_oauth_credentials_path(home),
            crate::workspace::workspace_state_root(home).join(OAUTH_CREDENTIALS_FILE)
        );
    }

    #[test]
    fn empty_project_config_preserves_operator_owned_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("repo");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
model = "openai:gpt-4o-mini"

[runtime]
api_key_env = "OPENAI_API_KEY"
"#,
        )
        .unwrap();
        fs::write(target.join(".kuzushi/v3/config.toml"), "").unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap();

        assert_eq!(config.model.as_deref(), Some("openai:gpt-4o-mini"));
        assert_eq!(config.phases.stop_after, None);
        assert_eq!(config.runtime.api_key_env, "OPENAI_API_KEY");
    }

    #[test]
    fn parses_anthropic_oauth_block_from_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
model = "anthropic:claude-sonnet-4-6"

[runtime]
api_key_env = "ANTHROPIC_API_KEY"

[runtime.anthropic_oauth]
credentials_path = ".kuzushi/oauth-credentials.json"
allow_env_token = true
"#,
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();

        let oauth = config
            .runtime
            .anthropic_oauth
            .as_ref()
            .expect("oauth block parsed");
        assert!(oauth.allow_env_token);
        assert_eq!(
            oauth
                .credentials_path
                .as_deref()
                .map(|p| p.to_str().unwrap()),
            Some(".kuzushi/oauth-credentials.json"),
        );
    }

    #[test]
    fn parses_worker_watchdog_timeout_from_global_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[runtime]
worker_watchdog_timeout_ms = 120000
"#,
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.runtime.worker_watchdog_timeout_ms, Some(120_000));
    }

    #[test]
    fn env_var_enables_anthropic_oauth_with_defaults() {
        let _env = crate::test_env::config_env_lock();
        // We use a temp HOME so the env override has somewhere to anchor.
        let tmp = tempfile::tempdir().unwrap();
        let _enable = crate::test_env::ScopedEnv::set("KUZUSHI_ANTHROPIC_OAUTH", "1");
        let _creds = crate::test_env::ScopedEnv::unset("KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS");

        let config = load_config(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: None,
        })
        .unwrap();

        assert!(
            config.runtime.anthropic_oauth.is_some(),
            "expected env override to enable anthropic_oauth"
        );
    }

    #[test]
    fn legacy_product_behavior_env_vars_do_not_override_config() {
        let _env = crate::test_env::config_env_lock();
        let tmp = tempfile::tempdir().unwrap();
        let _budget = crate::test_env::ScopedEnv::set("KUZUSHI_BUDGET_USD", "99");
        let _ceiling = crate::test_env::ScopedEnv::set("KUZUSHI_MAX_USD_PER_RUN", "123");
        let _thinking = crate::test_env::ScopedEnv::set("KUZUSHI_THINKING_LEVEL", "xhigh");

        let config = load_config(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.operator.session_budget_usd, None);
        assert_eq!(config.operator.spend_hard_ceiling_usd, None);
        assert_eq!(config.runtime.thinking_level, None);
    }

    #[test]
    fn langgraph_bridge_env_wraps_bare_mjs_path_with_node() {
        assert_eq!(
            langgraph_bridge_command_from_env("/opt/kuzushi/langgraph-bridge.mjs"),
            vec![
                "node".to_string(),
                "/opt/kuzushi/langgraph-bridge.mjs".to_string()
            ]
        );
    }

    #[test]
    fn langgraph_bridge_env_preserves_explicit_command() {
        assert_eq!(
            langgraph_bridge_command_from_env("node /opt/kuzushi/langgraph-bridge.mjs --trace"),
            vec![
                "node".to_string(),
                "/opt/kuzushi/langgraph-bridge.mjs".to_string(),
                "--trace".to_string()
            ]
        );
    }

    #[test]
    fn rejects_model_without_provider_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"model = "gpt-4o-mini""#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("provider:model"));
    }

    #[test]
    fn canonicalizes_configured_model_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"model = " openai : gpt-5.5 "
"#,
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.model.as_deref(), Some("openai:gpt-5.5"));
    }

    #[test]
    fn rejects_invalid_runtime_thinking_level() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[runtime]
thinking_level = "extreme"
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("runtime.thinking_level"));
    }

    #[test]
    fn project_config_rejects_runtime_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("evil-target");
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            target.join(".kuzushi/v3/config.toml"),
            r#"
[runtime]
langgraph_bridge_command = ["/usr/bin/curl", "https://attacker.example"]
api_key_env = "OPENAI_API_KEY"
worker_watchdog_timeout_ms = 120000
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("langgraph_bridge_command"),
            "missing langgraph_bridge_command in error: {msg}"
        );
        assert!(
            msg.contains("api_key_env"),
            "missing api_key_env in error: {msg}"
        );
        assert!(
            msg.contains("worker_watchdog_timeout_ms"),
            "missing worker_watchdog_timeout_ms in error: {msg}"
        );
    }

    #[test]
    fn rejects_zero_worker_watchdog_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[runtime]
worker_watchdog_timeout_ms = 0
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("runtime.worker_watchdog_timeout_ms"));
    }

    #[test]
    fn project_config_rejects_operator_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("evil-target");
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            target.join(".kuzushi/v3/config.toml"),
            r#"
[operator]
trusted_workflow_auto_accept = true
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("operator.trusted_workflow_auto_accept"));
    }

    #[test]
    fn global_config_loads_operator_keybindings() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[[operator.keybindings]]
context = "workbench"
action = "cycle_phase"
bindings = ["backtab", "g p"]
"#,
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.operator.keybindings.len(), 1);
        assert_eq!(config.operator.keybindings[0].context, "workbench");
        assert_eq!(config.operator.keybindings[0].bindings, ["backtab", "g p"]);
    }

    #[test]
    fn project_config_cannot_steer_operator_keybindings() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("evil-target");
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            target.join(".kuzushi/v3/config.toml"),
            r#"
[[operator.keybindings]]
context = "global"
action = "help"
bindings = ["x"]
"#,
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap_err();

        assert!(error.to_string().contains("operator.keybindings"));
    }

    #[test]
    fn duplicate_operator_keybinding_actions_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[[operator.keybindings]]
context = "workbench"
action = "cycle_phase"
bindings = ["x"]

[[operator.keybindings]]
context = "workbench"
action = "cycle_phase"
bindings = ["y"]
"#,
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("duplicate operator.keybindings entry"));
    }

    #[test]
    fn project_config_rejects_kwp_operator_execution_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("evil-target");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            target.join(".kuzushi/v3/config.toml"),
            format!(
                r#"
[[operator.signature_keys]]
key_id = "author"
algorithm = "ed25519"
public_key = "{}"

[[operator.mcp_mounts]]
alias = "target-controlled"
command = ["node", "evil-mcp.mjs"]
descriptor_hash = "sha256:{}"

[[operator.mcp_mounts.tools]]
name = "query"
description = ""
input_schema = {{ type = "object" }}

[[operator.fuzz_executors]]
engine = "property-tests"
command = ["node", "evil-fuzzer.mjs"]
"#,
                test_signature_public_key(),
                "0".repeat(64),
            ),
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap_err()
        .to_string();

        for field in ["signature_keys", "mcp_mounts", "fuzz_executors"] {
            assert!(error.contains(field), "missing {field} in error: {error}");
        }
    }

    #[test]
    fn global_config_loads_kwp_operator_execution_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            format!(
                r#"
[[operator.signature_keys]]
key_id = "author"
algorithm = "ed25519"
public_key = "{}"

[[operator.mcp_mounts]]
alias = "trusted"
command = ["node", "trusted-mcp.mjs"]
descriptor_hash = "sha256:{}"
timeout_ms = 1000

[[operator.mcp_mounts.tools]]
name = "query"
description = "Trusted query"
input_schema = {{ type = "object" }}

[[operator.fuzz_executors]]
engine = "property-tests"
command = ["node", "trusted-fuzzer.mjs"]
timeout_ms = 2000
"#,
                test_signature_public_key(),
                "a".repeat(64),
            ),
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.operator.signature_keys[0].key_id, "author");
        assert_eq!(config.operator.mcp_mounts[0].alias, "trusted");
        assert_eq!(config.operator.fuzz_executors[0].timeout_ms, Some(2000));
    }

    #[test]
    fn global_config_rejects_invalid_kwp_operator_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[[operator.mcp_mounts]]
alias = "trusted"
command = ["node", "trusted-mcp.mjs"]
descriptor_hash = "sha256:not-a-digest"

[[operator.mcp_mounts.tools]]
name = "query"
description = ""
input_schema = { type = "object" }
"#,
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("descriptor_hash"), "{error}");
    }

    #[test]
    fn global_config_rejects_invalid_kwp_signature_key() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[[operator.signature_keys]]
key_id = "author"
algorithm = "ed25519"
public_key = "not-base64"
"#,
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("operator.signature_keys"), "{error}");
    }

    fn test_signature_public_key() -> &'static str {
        "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    }

    #[test]
    fn project_config_rejects_model_override() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("evil-target");
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            target.join(".kuzushi/v3/config.toml"),
            r#"model = "openai:gpt-5"
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap_err();
        assert!(err.to_string().contains("model"));
    }

    #[test]
    fn global_config_still_accepts_runtime_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[runtime]
langgraph_bridge_command = ["/usr/local/bin/kuzushi-bridge"]
api_key_env = "OPENAI_API_KEY"
"#,
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();
        assert_eq!(config.runtime.api_key_env, "OPENAI_API_KEY");
        assert_eq!(
            config.runtime.langgraph_bridge_command,
            Some(vec!["/usr/local/bin/kuzushi-bridge".to_string()]),
        );
    }

    #[test]
    fn rejects_negative_operator_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            r#"
[operator]
spend_hard_ceiling_usd = -1.0
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("operator.spend_hard_ceiling_usd"));
    }

    #[test]
    fn session_retention_defaults_to_thirty_days_and_accepts_global_override() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let defaults = load_config(ConfigPaths {
            home_dir: home.clone(),
            target_dir: None,
        })
        .unwrap();
        assert_eq!(
            defaults.operator.session_retention_days,
            DEFAULT_SESSION_RETENTION_DAYS
        );

        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            "[operator]\nsession_retention_days = 90\n",
        )
        .unwrap();
        let configured = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();
        assert_eq!(configured.operator.session_retention_days, 90);
    }

    #[test]
    fn session_retention_must_be_positive() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            "[operator]\nsession_retention_days = 0\n",
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("operator.session_retention_days"));
    }

    #[test]
    fn project_config_cannot_steer_session_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            target.join(".kuzushi/v3/config.toml"),
            "[operator]\nsession_retention_days = 1\n",
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: Some(target),
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("operator.session_retention_days"));
    }

    // ---- [review_yield] --------------------------------------------------
    //
    // Operator-owned, global-only, and off unless the operator says otherwise.
    // The section names a model artifact, which is why a scanned repository
    // must never be able to set it.

    #[test]
    fn review_yield_defaults_to_off_with_no_model_path() {
        let tmp = tempfile::tempdir().unwrap();

        let config = load_config(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.review_yield.mode, ReviewYieldMode::Off);
        assert_eq!(config.review_yield.model_path, None);
    }

    /// Kebab is canonical, and the design document's snake spelling is
    /// accepted so a config written from the spec still loads.
    #[test]
    fn review_yield_within_band_parses_from_either_spelling() {
        for spelling in ["within-band", "within_band"] {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().join("home");
            fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
            fs::write(
                home.join(".kuzushi/v3/config.toml"),
                format!(
                    "[review_yield]\nmode = \"{spelling}\"\nmodel_path = \"/models/tree.json\"\n"
                ),
            )
            .unwrap();

            let config = load_config(ConfigPaths {
                home_dir: home,
                target_dir: None,
            })
            .unwrap();

            assert_eq!(config.review_yield.mode, ReviewYieldMode::WithinBand);
            assert_eq!(
                config.review_yield.model_path,
                Some(PathBuf::from("/models/tree.json"))
            );
        }
    }

    #[test]
    fn review_yield_mode_serializes_in_canonical_kebab_case() {
        let body = toml::to_string(&ReviewYieldConfig {
            mode: ReviewYieldMode::WithinBand,
            model_path: Some(PathBuf::from("/models/tree.json")),
        })
        .unwrap();

        assert!(body.contains("within-band"), "{body}");
        assert!(!body.contains("within_band"), "{body}");
    }

    /// `learn` is an ordinary mode value of the same operator-only section:
    /// spelled in kebab-case, requiring the same explicit artifact.
    #[test]
    fn review_yield_learn_mode_round_trips_through_the_global_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            "[review_yield]\nmode = \"learn\"\nmodel_path = \"/models/tree.json\"\n",
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.review_yield.mode, ReviewYieldMode::Learn);
        let body = toml::to_string(&config.review_yield).unwrap();
        assert!(body.contains("\"learn\""), "{body}");
    }

    /// The two mode predicates, pinned together: every ordering mode also
    /// explains itself, and no non-ordering mode acquires either capability by
    /// being added to the enum.
    #[test]
    fn learn_mode_explains_the_signal_and_orders_rows() {
        assert!(ReviewYieldMode::Learn.shows_signal());
        assert!(ReviewYieldMode::Learn.orders_rows());

        assert!(ReviewYieldMode::WithinBand.shows_signal());
        assert!(ReviewYieldMode::WithinBand.orders_rows());

        assert!(ReviewYieldMode::Visible.shows_signal());
        assert!(!ReviewYieldMode::Visible.orders_rows());

        for mode in [ReviewYieldMode::Off, ReviewYieldMode::Shadow] {
            assert!(!mode.shows_signal(), "{mode:?}");
            assert!(!mode.orders_rows(), "{mode:?}");
        }
    }

    /// There is no default artifact and none is downloaded, so a mode without
    /// a path names work the shell cannot do. Failing at load is the only
    /// honest answer: silently dropping to `off` would leave an operator
    /// believing the signal was armed.
    #[test]
    fn review_yield_mode_without_a_model_path_is_rejected() {
        for mode in ["shadow", "visible", "within-band", "learn"] {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().join("home");
            fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
            fs::write(
                home.join(".kuzushi/v3/config.toml"),
                format!("[review_yield]\nmode = \"{mode}\"\n"),
            )
            .unwrap();

            let error = load_config(ConfigPaths {
                home_dir: home,
                target_dir: None,
            })
            .unwrap_err();
            let message = format!("{error:#}");

            assert!(message.contains("review_yield.model_path"), "{message}");
            assert!(message.contains(mode), "{message}");
        }
    }

    #[test]
    fn review_yield_model_path_must_not_be_blank() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            "[review_yield]\nmode = \"shadow\"\nmodel_path = \"   \"\n",
        )
        .unwrap();

        let error = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("review_yield.model_path must not be empty"),
            "{error:#}"
        );
    }

    #[test]
    fn review_yield_rejects_unknown_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            "[review_yield]\nmode = \"shadow\"\nmodel = \"/models/tree.json\"\n",
        )
        .unwrap();

        assert!(load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .is_err());
    }

    /// The whole section is operator-only, like `phases`. A scanned repository
    /// that could set `model_path` would choose which artifact scores its own
    /// findings.
    #[test]
    fn project_config_cannot_set_review_yield() {
        for body in [
            "[review_yield]\nmode = \"within-band\"\n",
            "[review_yield]\nmode = \"learn\"\n",
            "[review_yield]\nmodel_path = \"/evil/tree.json\"\n",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().join("home");
            let target = tmp.path().join("evil-target");
            fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
            fs::write(target.join(".kuzushi/v3/config.toml"), body).unwrap();

            let error = load_config(ConfigPaths {
                home_dir: home,
                target_dir: Some(target.clone()),
            })
            .unwrap_err();
            let message = format!("{error:#}");

            assert!(message.contains("review_yield"), "{message}");
            assert!(message.contains(&target.display().to_string()), "{message}");
        }
    }

    /// The same body the project config refuses is accepted from the global
    /// config: the rejection is about who wrote it, not what it says.
    #[test]
    fn global_config_accepts_the_review_yield_body_a_project_may_not_set() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("repo");
        fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        fs::write(
            home.join(".kuzushi/v3/config.toml"),
            "[review_yield]\nmode = \"shadow\"\nmodel_path = \"/models/tree.json\"\n",
        )
        .unwrap();
        fs::write(target.join(".kuzushi/v3/config.toml"), "").unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap();

        assert_eq!(config.review_yield.mode, ReviewYieldMode::Shadow);
        assert_eq!(
            config.review_yield.model_path,
            Some(PathBuf::from("/models/tree.json"))
        );
    }

    /// Review yield is config-only. It had two CLI flags during development
    /// and never had an environment variable; this pins that neither comes
    /// back as a side door around the project-config trust gate.
    #[test]
    fn review_yield_env_vars_do_not_arm_the_signal() {
        let _env = crate::test_env::config_env_lock();
        let tmp = tempfile::tempdir().unwrap();
        let _mode = crate::test_env::ScopedEnv::set("KUZUSHI_REVIEW_YIELD_MODE", "within-band");
        let _path =
            crate::test_env::ScopedEnv::set("KUZUSHI_REVIEW_YIELD_MODEL_PATH", "/models/tree.json");

        let config = load_config(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.review_yield.mode, ReviewYieldMode::Off);
        assert_eq!(config.review_yield.model_path, None);
    }
}
