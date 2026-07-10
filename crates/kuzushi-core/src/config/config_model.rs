use super::*;

pub const DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS: u64 = 6 * 60 * 60 * 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct V2Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub runtime: RuntimeConfig,
    pub operator: OperatorConfig,
    pub phases: GuidedPhaseConfig,
    /// Live operator autonomy posture — the always-visible authorization
    /// ceiling the tool-dispatch gate enforces. This is an *in-process*
    /// session field: it is `#[serde(skip)]` so it never persists to
    /// `config.toml` and can never be steered by a scanned project's config
    /// (mirroring the no-target-steering safety rule for `model`). It defaults
    /// to the most-permissive `Fix`, so headless `kuzushi run`/scan callers
    /// that never set it stay unconstrained. Interactive/CLI callers assign it
    /// before dispatch.
    #[serde(skip)]
    pub autonomy: crate::modules::AutonomyPosture,
}

impl Default for V2Config {
    fn default() -> Self {
        Self {
            model: None,
            runtime: RuntimeConfig::default(),
            operator: OperatorConfig::default(),
            phases: GuidedPhaseConfig::default(),
            autonomy: crate::modules::AutonomyPosture::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct GuidedPhaseConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_after: Option<GuidedPhase>,
    pub map: PhaseTemplateConfig,
    pub hunt: PhaseTemplateConfig,
    pub confirm: PhaseTemplateConfig,
    pub fix: PhaseTemplateConfig,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum GuidedPhase {
    Map,
    Hunt,
    Confirm,
    Fix,
}

impl GuidedPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Map => "map",
            Self::Hunt => "hunt",
            Self::Confirm => "confirm",
            Self::Fix => "fix",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct PhaseTemplateConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy_cap: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_depth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_variant: Option<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature_keys: Vec<crate::worker_protocol::SignatureTrustKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_mounts: Vec<McpMountConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fuzz_executors: Vec<FuzzExecutorConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct McpMountConfig {
    pub alias: String,
    pub command: Vec<String>,
    pub descriptor_hash: String,
    pub tools: Vec<McpMountToolConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl Default for McpMountConfig {
    fn default() -> Self {
        Self {
            alias: String::new(),
            command: Vec::new(),
            descriptor_hash: String::new(),
            tools: Vec::new(),
            timeout_ms: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct McpMountToolConfig {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
}

impl Default for McpMountToolConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            input_schema: serde_json::json!({ "type": "object" }),
            output_schema: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct FuzzExecutorConfig {
    pub engine: crate::worker_protocol::FuzzEngine,
    pub command: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl Default for FuzzExecutorConfig {
    fn default() -> Self {
        Self {
            engine: crate::worker_protocol::FuzzEngine::PropertyTests,
            command: Vec::new(),
            timeout_ms: None,
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
    pub langgraph_bridge_command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_level: Option<String>,
    pub worker_watchdog_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anthropic_oauth: Option<AnthropicOauthConfig>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            langgraph_bridge_command: None,
            thinking_level: None,
            worker_watchdog_timeout_ms: Some(DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
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

pub const OAUTH_CREDENTIALS_FILE: &str = "oauth-credentials.json";

pub fn default_oauth_credentials_path(home_dir: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_root(home_dir).join(OAUTH_CREDENTIALS_FILE)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeKind {
    LangGraph,
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
        crate::workspace::workspace_config_path(&self.home_dir)
    }

    pub fn global_options_path(&self) -> PathBuf {
        crate::workspace::workspace_options_path(&self.home_dir)
    }

    pub fn project_config_path(&self) -> Option<PathBuf> {
        self.target_dir
            .as_ref()
            .map(crate::workspace::workspace_config_path)
    }

    pub fn project_options_path(&self) -> Option<PathBuf> {
        self.target_dir
            .as_ref()
            .map(crate::workspace::workspace_options_path)
    }

    pub fn global_history_path(&self) -> PathBuf {
        crate::workspace::workspace_history_path(&self.home_dir)
    }

    pub fn project_history_path(&self) -> Option<PathBuf> {
        self.target_dir
            .as_ref()
            .map(crate::workspace::workspace_history_path)
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PartialConfig {
    pub(crate) model: Option<Option<String>>,
    pub(crate) runtime: Option<PartialRuntimeConfig>,
    pub(crate) operator: Option<PartialOperatorConfig>,
    pub(crate) phases: Option<PartialGuidedPhaseConfig>,
}
