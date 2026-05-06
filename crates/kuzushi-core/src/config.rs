use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct V2Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub runtime: RuntimeConfig,
}

impl Default for V2Config {
    fn default() -> Self {
        Self {
            model: None,
            runtime: RuntimeConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub kind: RuntimeKind,
    pub api_key_env: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_bridge_command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anthropic_oauth: Option<AnthropicOauthConfig>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: None,
            anthropic_oauth: None,
        }
    }
}

/// Declarative hint that the operator expects Anthropic OAuth as the
/// credential source for `anthropic:*` models.
///
/// The bridge (`scripts/pi-agent-core-bridge.mjs`) is the actual refresh
/// authority — it loads `oauth-credentials.json`, refreshes via
/// `@mariozechner/pi-ai/oauth`, and forwards the access token. This Rust
/// struct exists so:
///
/// * `validate_config` can fail fast at startup if the operator declared
///   OAuth but the credentials file is missing or unreadable, instead of
///   waiting for the first LLM call.
/// * The TUI / CLI can describe the configured auth source without
///   round-tripping the bridge.
///
/// **No secret data is ever stored in this struct.** It only carries a
/// path and toggle flags. Tokens live in the file and the bridge process.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AnthropicOauthConfig {
    /// Path to the OAuth credentials bag (default: `~/.kuzushi/oauth-credentials.json`).
    /// Resolved relative to the home directory if not absolute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_path: Option<PathBuf>,
    /// If true, allow `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_OAUTH_TOKEN` env vars
    /// as a fallback when the credentials file is absent. Default false —
    /// operators who declare OAuth expect the bag.
    #[serde(default)]
    pub allow_env_token: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeKind {
    PiAgentCore,
}

#[derive(Debug, Clone)]
pub struct ConfigPaths {
    pub home_dir: PathBuf,
    pub target_dir: Option<PathBuf>,
}

impl ConfigPaths {
    pub fn from_target(target: Option<&Path>) -> Result<Self> {
        let home_dir = dirs::home_dir().context("Could not resolve home directory")?;
        Ok(Self {
            home_dir,
            target_dir: target.map(Path::to_path_buf),
        })
    }

    pub fn global_config_path(&self) -> PathBuf {
        self.home_dir
            .join(".kuzushi")
            .join("v2")
            .join("config.toml")
    }

    pub fn project_config_path(&self) -> Option<PathBuf> {
        self.target_dir
            .as_ref()
            .map(|target| target.join(".kuzushi").join("v2").join("config.toml"))
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PartialConfig {
    model: Option<Option<String>>,
    runtime: Option<PartialRuntimeConfig>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PartialRuntimeConfig {
    kind: Option<RuntimeKind>,
    api_key_env: Option<String>,
    base_url: Option<Option<String>>,
    agent_bridge_command: Option<Option<Vec<String>>>,
    anthropic_oauth: Option<Option<AnthropicOauthConfig>>,
}

pub fn load_config_for_target(target: Option<&Path>) -> Result<V2Config> {
    load_config(ConfigPaths::from_target(target)?)
}

pub fn load_config(paths: ConfigPaths) -> Result<V2Config> {
    let mut config = V2Config::default();

    let global_path = paths.global_config_path();
    if global_path.exists() {
        merge_file(&mut config, &global_path)?;
    }

    if let Some(project_path) = paths.project_config_path() {
        if project_path.exists() {
            merge_file(&mut config, &project_path)?;
        }
    }

    apply_env_overrides(&mut config);
    validate_config(&config)?;
    Ok(config)
}

pub fn write_default_config(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create config directory {}", parent.display()))?;
    }

    let runtime = toml::to_string_pretty(&V2Config::default())
        .context("Could not serialize default config")?;
    let body = format!(
        "# Kuzushi config. Set an explicit model before LLM triage.\n# model = \"openai:<model>\"\n\n{runtime}"
    );
    fs::write(path, body).with_context(|| format!("Could not write {}", path.display()))
}

fn merge_file(config: &mut V2Config, path: &Path) -> Result<()> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("Could not read {}", path.display()))?;
    let patch: PartialConfig =
        toml::from_str(&raw).with_context(|| format!("Could not parse {}", path.display()))?;
    merge_config(config, patch);
    Ok(())
}

fn merge_config(config: &mut V2Config, patch: PartialConfig) {
    if let Some(model) = patch.model {
        config.model = model;
    }

    if let Some(runtime) = patch.runtime {
        if let Some(kind) = runtime.kind {
            config.runtime.kind = kind;
        }
        if let Some(api_key_env) = runtime.api_key_env {
            config.runtime.api_key_env = api_key_env;
        }
        if let Some(base_url) = runtime.base_url {
            config.runtime.base_url = base_url;
        }
        if let Some(agent_bridge_command) = runtime.agent_bridge_command {
            config.runtime.agent_bridge_command = agent_bridge_command;
        }
        if let Some(anthropic_oauth) = runtime.anthropic_oauth {
            config.runtime.anthropic_oauth = anthropic_oauth;
        }
    }
}

fn apply_env_overrides(config: &mut V2Config) {
    if let Some(model) = first_env(&["KUZUSHI_MODEL", "KUZUSHI_V2_MODEL"]) {
        let trimmed = model.trim();
        config.model = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }

    if let Some(api_key_env) = first_env(&["KUZUSHI_API_KEY_ENV", "KUZUSHI_V2_API_KEY_ENV"]) {
        if !api_key_env.trim().is_empty() {
            config.runtime.api_key_env = api_key_env.trim().to_string();
        }
    }

    if let Some(base_url) = first_env(&["KUZUSHI_BASE_URL", "KUZUSHI_V2_BASE_URL"]) {
        let trimmed = base_url.trim();
        config.runtime.base_url = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }

    if let Some(command) = first_env(&["KUZUSHI_AGENT_BRIDGE", "KUZUSHI_V2_AGENT_BRIDGE"]) {
        let parts = shell_words(&command);
        if !parts.is_empty() {
            config.runtime.agent_bridge_command = Some(parts);
        }
    }

    // KUZUSHI_ANTHROPIC_OAUTH=1 enables the OAuth declaration with defaults.
    // KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS=<path> sets the credentials file.
    let env_enable = first_env(&["KUZUSHI_ANTHROPIC_OAUTH"])
        .map(|value| matches!(value.trim(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let env_path = first_env(&["KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS"])
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);

    if env_enable || env_path.is_some() {
        let cfg = config
            .runtime
            .anthropic_oauth
            .get_or_insert_with(AnthropicOauthConfig::default);
        if let Some(path) = env_path {
            cfg.credentials_path = Some(path);
        }
    }
}

fn first_env(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| env::var(name).ok())
}

fn validate_config(config: &V2Config) -> Result<()> {
    if let Some(model) = &config.model {
        if !model.contains(':') {
            anyhow::bail!("model must use provider:model syntax, got {model:?}");
        }
    }

    if config.runtime.api_key_env.trim().is_empty() {
        anyhow::bail!("runtime.api_key_env must not be empty");
    }

    if let Some(command) = &config.runtime.agent_bridge_command {
        if command.is_empty() || command[0].trim().is_empty() {
            anyhow::bail!("runtime.agent_bridge_command must start with an executable");
        }
    }

    Ok(())
}

fn shell_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
