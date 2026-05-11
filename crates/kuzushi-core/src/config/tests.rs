#[cfg(test)]
mod tests {
    use super::super::*;
    use std::{env, fs};

    #[test]
    fn loads_defaults_without_files() {
        let tmp = tempfile::tempdir().unwrap();
        let config = load_config(ConfigPaths {
            home_dir: tmp.path().join("home"),
            target_dir: None,
        })
        .unwrap();

        assert_eq!(config.model, None);
        assert_eq!(config.runtime.kind, RuntimeKind::PiAgentCore);
        assert_eq!(config.runtime.api_key_env, "OPENAI_API_KEY");
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
    fn project_config_overrides_global_config() {
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
model = "openai:gpt-4.1"

[runtime]
api_key_env = "KUZUSHI_OPENAI_KEY"
base_url = "https://api.example.test/v1"
thinking_level = "high"

[operator]
session_budget_usd = 2.5
spend_hard_ceiling_usd = 10.0
trusted_workflow_auto_accept = true
"#,
        )
        .unwrap();

        let config = load_config(ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap();

        assert_eq!(config.model.as_deref(), Some("openai:gpt-4.1"));
        assert_eq!(config.runtime.api_key_env, "KUZUSHI_OPENAI_KEY");
        assert_eq!(
            config.runtime.base_url.as_deref(),
            Some("https://api.example.test/v1")
        );
        assert_eq!(config.runtime.thinking_level.as_deref(), Some("high"));
        assert_eq!(config.operator.session_budget_usd, Some(2.5));
        assert_eq!(config.operator.spend_hard_ceiling_usd, Some(10.0));
        assert!(config.operator.trusted_workflow_auto_accept);
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
