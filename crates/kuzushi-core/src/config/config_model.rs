use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct V2Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub runtime: RuntimeConfig,
    pub operator: OperatorConfig,
}

impl Default for V2Config {
    fn default() -> Self {
        Self {
            model: None,
            runtime: RuntimeConfig::default(),
            operator: OperatorConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct OperatorConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_budget_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_hard_ceiling_usd: Option<f64>,
    #[serde(default)]
    pub trusted_workflow_auto_accept: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_modules: Vec<String>,
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
    pub thinking_level: Option<String>,
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
            thinking_level: None,
            anthropic_oauth: None,
        }
    }
}

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

    pub fn global_options_path(&self) -> PathBuf {
        self.home_dir
            .join(".kuzushi")
            .join("v2")
            .join("options.json")
    }

    pub fn project_config_path(&self) -> Option<PathBuf> {
        self.target_dir
            .as_ref()
            .map(|target| target.join(".kuzushi").join("v2").join("config.toml"))
    }

    pub fn project_options_path(&self) -> Option<PathBuf> {
        self.target_dir
            .as_ref()
            .map(|target| target.join(".kuzushi").join("v2").join("options.json"))
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PartialConfig {
    pub(crate) model: Option<Option<String>>,
    pub(crate) runtime: Option<PartialRuntimeConfig>,
    pub(crate) operator: Option<PartialOperatorConfig>,
}
