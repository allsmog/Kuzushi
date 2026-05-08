use super::prelude::*;
use super::*;

impl AgentRouter {
    /// Empty router — every role returns `None` from `pick`. The
    /// [`RoutedRuntime`] then falls back to the operator's
    /// `ctx.config.model`.
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn route(&self, role: AgentRole) -> Option<&ModelRoute> {
        self.routes.get(&role)
    }

    pub fn pick(&self, role: AgentRole, attempt: u32) -> Option<&str> {
        self.routes.get(&role).and_then(|route| route.pick(attempt))
    }

    pub fn default_model(&self) -> Option<&str> {
        self.default_model.as_deref()
    }

    pub fn concurrency_cap(&self, model: &str) -> Option<u32> {
        self.concurrency_caps.get(model).copied()
    }

    /// Load `models.toml` from the home dir and (if present) the project
    /// dir. Project entries override home entries on the same role.
    /// The path can also be overridden via `KUZUSHI_MODELS_FILE`.
    pub fn load(paths: &ConfigPaths) -> Result<Self> {
        let mut router = Self::empty();

        // 1. Home path (or env override).
        let home_path = env::var("KUZUSHI_MODELS_FILE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| paths.home_dir.join(".kuzushi").join("models.toml"));
        if home_path.exists() {
            router.merge_file(&home_path)?;
        }

        // 2. Project-local override.
        if let Some(target) = paths.target_dir.as_ref() {
            let project_path = target.join(".kuzushi").join("models.toml");
            if project_path.exists() {
                router.merge_file(&project_path)?;
            }
        }

        Ok(router)
    }

    pub(crate) fn merge_file(&mut self, path: &Path) -> Result<()> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        let parsed: ModelsTomlFile =
            toml::from_str(&raw).with_context(|| format!("could not parse {}", path.display()))?;

        if let Some(default) = parsed.default_model {
            self.default_model = Some(default);
        }
        for (key, route) in parsed.roles {
            let Some(role) = AgentRole::from_key(&key) else {
                anyhow::bail!(
                    "unknown agent role {key:?} in {} — known: triage, classifier_gate, \
                     deep_auditor, full_mode_multi, systems_hunt, carlini, variant_ndiff, \
                     threat_model, x_ray, patch",
                    path.display()
                );
            };
            if !route.fallbacks.is_empty() {
                anyhow::bail!(
                    "role {key:?} in {} declares model fallbacks, but Kuzushi \
                     requires explicit operator consent for model changes; keep \
                     only `primary` or run separate explicit attempts",
                    path.display()
                );
            }
            self.routes.insert(role, route);
        }
        for (model, cap) in parsed.concurrency {
            self.concurrency_caps.insert(model, cap);
        }
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelsTomlFile {
    #[serde(default)]
    pub(crate) default_model: Option<String>,
    #[serde(default)]
    pub(crate) roles: BTreeMap<String, ModelRoute>,
    #[serde(default)]
    pub(crate) concurrency: BTreeMap<String, u32>,
}

pub struct RoutedRuntime {
    pub(crate) inner: Arc<dyn AgentRuntime>,
    pub(crate) router: Arc<AgentRouter>,
    /// `ctx.config.model` — used when no route matches the role.
    pub(crate) operator_default: Option<String>,
    /// Snapshot of operator-settable role models from `ToolOptionStore`.
    /// Set via [`RoutedRuntime::with_option_store`] at construction; not
    /// re-read per-call so a hot route stays consistent within a scan.
    /// Operators set these from the shell:
    ///   `setg MODEL_DEEP_AUDITOR anthropic:claude-opus-4-7`
    pub(crate) option_overrides: BTreeMap<AgentRole, String>,
}
