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
        router.merge_existing_file(&home_models_path(paths))?;
        router.merge_project_models_file(paths)?;
        Ok(router)
    }

    pub(crate) fn merge_file(&mut self, path: &Path) -> Result<()> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        let parsed: ModelsTomlFile =
            toml::from_str(&raw).with_context(|| format!("could not parse {}", path.display()))?;

        self.apply_default_model(parsed.default_model, path)?;
        self.merge_model_routes(parsed.roles, path)?;
        self.merge_concurrency_caps(parsed.concurrency);
        Ok(())
    }

    fn merge_existing_file(&mut self, path: &Path) -> Result<()> {
        if path.exists() {
            self.merge_file(path)?;
        }
        Ok(())
    }

    fn merge_project_models_file(&mut self, paths: &ConfigPaths) -> Result<()> {
        paths
            .target_dir
            .as_ref()
            .map(|target| target.join(".kuzushi").join("models.toml"))
            .map_or(Ok(()), |path| self.merge_existing_file(&path))
    }

    fn apply_default_model(&mut self, default_model: Option<String>, path: &Path) -> Result<()> {
        if let Some(default) = default_model {
            ensure_valid_router_model("default_model", &default, path)?;
            self.default_model = Some(default);
        }
        Ok(())
    }

    fn merge_model_routes(
        &mut self,
        routes: BTreeMap<String, ModelRoute>,
        path: &Path,
    ) -> Result<()> {
        for (key, route) in routes {
            let (role, route) = parse_model_route(key, route, path)?;
            self.routes.insert(role, route);
        }
        Ok(())
    }

    fn merge_concurrency_caps(&mut self, concurrency: BTreeMap<String, u32>) {
        for (model, cap) in concurrency {
            self.concurrency_caps.insert(model, cap);
        }
    }
}

fn home_models_path(paths: &ConfigPaths) -> PathBuf {
    env::var("KUZUSHI_MODELS_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| paths.home_dir.join(".kuzushi").join("models.toml"))
}

fn parse_model_route(
    key: String,
    route: ModelRoute,
    path: &Path,
) -> Result<(AgentRole, ModelRoute)> {
    let role = AgentRole::from_key(&key).with_context(|| unknown_agent_role_message(&key, path))?;
    ensure_no_model_fallbacks(&key, &route, path)?;
    ensure_valid_router_model(&format!("roles.{key}.primary"), &route.primary, path)?;
    Ok((role, route))
}

fn unknown_agent_role_message(key: &str, path: &Path) -> String {
    format!(
        "unknown agent role {key:?} in {} — known: triage, classifier_gate, \
         deep_auditor, full_mode_multi, systems_hunt, carlini, variant_ndiff, \
         threat_model, x_ray, patch",
        path.display()
    )
}

fn ensure_no_model_fallbacks(key: &str, route: &ModelRoute, path: &Path) -> Result<()> {
    if !route.fallbacks.is_empty() {
        anyhow::bail!(
            "role {key:?} in {} declares model fallbacks, but Kuzushi \
             requires explicit operator consent for model changes; keep \
             only `primary` or run separate explicit attempts",
            path.display()
        );
    }
    Ok(())
}

fn ensure_valid_router_model(field: &str, model: &str, path: &Path) -> Result<()> {
    validate_model_spec(model)
        .with_context(|| format!("{field} in {} is not a valid provider:model", path.display()))
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

pub struct RoutedRuntime<'a> {
    pub(crate) inner: RuntimeHandle<'a>,
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
