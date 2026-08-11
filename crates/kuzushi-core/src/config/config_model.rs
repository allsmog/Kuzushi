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
    pub review_yield: ReviewYieldConfig,
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
            review_yield: ReviewYieldConfig::default(),
            autonomy: crate::modules::AutonomyPosture::default(),
        }
    }
}

/// Operator policy for the review-yield signal: what the shell does with the
/// advisory reviewer-outcome scores, and which artifact produces them.
///
/// Operator-owned and global-only. A scanned repository must not be able to
/// point the shell at a model file it ships, so the project config rejects this
/// whole section (`forbidden_project_fields`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct ReviewYieldConfig {
    pub mode: ReviewYieldMode,
    /// The model artifact to score with. There is no default path and nothing
    /// is downloaded: any mode but `off` requires the operator to name a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_path: Option<PathBuf>,
}

/// What a shell session does with review-yield scores.
///
/// `Off` is the default and the fail-closed landing state: a rejected artifact
/// leaves the session off rather than degraded. Only `WithinBand` and `Learn`
/// move a row, and only inside its own proof-confidence and severity band —
/// they differ in what they order a band *by*, never in what they may cross.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewYieldMode {
    #[default]
    Off,
    /// Score and record silently. The operator sees nothing.
    Shadow,
    /// Score, record, and explain the signal in the finding detail. Review
    /// order is unchanged from `Off`.
    Visible,
    /// Everything `Visible` does, and additionally order rows *within* a
    /// complete, fully scored proof-and-severity band, by historical yield.
    #[serde(alias = "within_band")]
    WithinBand,
    /// The same band-bound ordering, keyed on where the model's evidence is
    /// thinnest rather than where its yield is highest: the findings the model
    /// knows least about come first, so reviewing them teaches it the most.
    Learn,
}

impl ReviewYieldMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::Visible => "visible",
            Self::WithinBand => "within-band",
            Self::Learn => "learn",
        }
    }

    /// Whether the finding detail may explain the signal. Every ordering mode
    /// explains: a mode that moved a row without saying why would be the one
    /// unexplained ranking cue this feature exists to avoid.
    pub fn shows_signal(self) -> bool {
        matches!(self, Self::Visible | Self::WithinBand | Self::Learn)
    }

    /// Whether the mode may reorder rows inside a band.
    pub fn orders_rows(self) -> bool {
        matches!(self, Self::WithinBand | Self::Learn)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct GuidedPhaseConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_after: Option<GuidedPhase>,
    pub map: PhaseTemplateConfig,
    #[serde(alias = "hunt")]
    pub scan: PhaseTemplateConfig,
    pub review: PhaseTemplateConfig,
    #[serde(alias = "confirm")]
    pub prove: PhaseTemplateConfig,
    pub fix: PhaseTemplateConfig,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum GuidedPhase {
    Map,
    #[serde(alias = "hunt")]
    Scan,
    Review,
    #[serde(alias = "confirm")]
    Prove,
    Fix,
}

impl GuidedPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Map => "map",
            Self::Scan => "scan",
            Self::Review => "review",
            Self::Prove => "prove",
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keybindings: Vec<KeybindingOverrideConfig>,
    #[serde(default = "default_session_retention_days")]
    pub session_retention_days: u64,
}

impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            session_budget_usd: None,
            spend_hard_ceiling_usd: None,
            trusted_workflow_auto_accept: false,
            trusted_modules: Vec::new(),
            signature_keys: Vec::new(),
            mcp_mounts: Vec::new(),
            fuzz_executors: Vec::new(),
            keybindings: Vec::new(),
            session_retention_days: DEFAULT_SESSION_RETENTION_DAYS,
        }
    }
}

pub const DEFAULT_SESSION_RETENTION_DAYS: u64 =
    crate::session_transcript::DEFAULT_SESSION_RETENTION_DAYS;

fn default_session_retention_days() -> u64 {
    DEFAULT_SESSION_RETENTION_DAYS
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct KeybindingOverrideConfig {
    pub context: String,
    pub action: String,
    /// Empty explicitly unbinds the action in this context.
    #[serde(default)]
    pub bindings: Vec<String>,
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
    /// Total bridge attempts per model call (first try + retries) on
    /// transient provider failures (429/5xx/transport). None = engine default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridge_retry_attempts: Option<u32>,
    /// Base backoff before the first retry; doubles each attempt (capped).
    /// Raise this for per-minute provider quotas. None = engine default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridge_retry_backoff_ms: Option<u64>,
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
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
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
    pub(crate) review_yield: Option<PartialReviewYieldConfig>,
}
