use super::*;
use serde_json::Value;

impl<'a> RoutedRuntime<'a> {
    pub fn new(
        inner: Arc<dyn AgentRuntime>,
        router: Arc<AgentRouter>,
        operator_default: Option<String>,
    ) -> Self {
        Self::owned(inner, router, operator_default)
    }

    pub fn owned(
        inner: Arc<dyn AgentRuntime>,
        router: Arc<AgentRouter>,
        operator_default: Option<String>,
    ) -> Self {
        Self {
            inner: RuntimeHandle::Owned(inner),
            router,
            operator_default,
            option_overrides: BTreeMap::new(),
        }
    }

    pub fn borrowed(
        inner: &'a dyn AgentRuntime,
        router: Arc<AgentRouter>,
        operator_default: Option<String>,
    ) -> Self {
        Self {
            inner: RuntimeHandle::Borrowed(inner),
            router,
            operator_default,
            option_overrides: BTreeMap::new(),
        }
    }

    /// Snapshot per-role model overrides from `ToolOptionStore`. Operators
    /// set these via `setg MODEL_<ROLE>` from the shell; values at the
    /// `(Global, All)` binding apply across every module.
    pub fn with_option_store(mut self, store: &ToolOptionStore) -> Self {
        self.option_overrides = role_option_overrides(store);
        self
    }

    pub fn router(&self) -> &AgentRouter {
        &self.router
    }

    /// Resolve the model for a role.
    ///
    /// Precedence (highest first):
    ///   1. `req.model` if non-empty *and* not equal to the operator default
    ///      (caller already chose a specific model — respect it).
    ///   2. `ToolOptionStore` `MODEL_<ROLE>` at `(Global, All)`.
    ///   3. Role map at `attempt`.
    ///   4. Operator default (`ctx.config.model`).
    ///   5. Router's `default_model`.
    pub fn resolve_model(
        &self,
        role: AgentRole,
        attempt: u32,
        explicit: Option<&str>,
    ) -> Option<String> {
        self.explicit_model_override(explicit)
            .or_else(|| self.option_override_model(role, attempt))
            .or_else(|| self.router_pick_model(role, attempt))
            .or_else(|| self.operator_default_model())
            .or_else(|| self.router.default_model().map(str::to_string))
    }

    pub fn resolve_model_for_role(
        &self,
        role: AgentRole,
        attempt: u32,
        explicit: Option<&str>,
    ) -> Result<String> {
        let model = self
            .resolve_model(role, attempt, explicit)
            .ok_or_else(|| missing_role_model_error(role))?;
        validate_model_spec(&model)
            .with_context(|| format!("role {} resolved an invalid model", role.as_key()))?;
        Ok(model)
    }

    /// Single-attempt query routed by role. The router never changes models
    /// after a failure; callers that want another model must issue an explicit
    /// request with that model.
    pub fn query_for_role(
        &self,
        role: AgentRole,
        mut request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        let model = self.resolve_model_for_role(role, 0, Some(&request.model))?;
        request.model = model;
        self.inner.query_blocking(request)
    }

    /// Triage routed by role.
    pub fn triage_for_role(
        &self,
        role: AgentRole,
        mut request: TriageRequest,
    ) -> Result<TriageOutcome> {
        let model = self.resolve_model_for_role(role, 0, Some(&request.model))?;
        request.model = model;
        self.inner.triage_finding_blocking(request)
    }
}

fn role_option_overrides(store: &ToolOptionStore) -> BTreeMap<AgentRole, String> {
    store
        .values_for(OptionScope::Global, &OptionTarget::All)
        .map(collect_role_option_overrides)
        .unwrap_or_default()
}

fn collect_role_option_overrides(values: &BTreeMap<String, Value>) -> BTreeMap<AgentRole, String> {
    AgentRole::all()
        .iter()
        .filter_map(|role| role_option_override(values, *role).map(|model| (*role, model)))
        .collect()
}

fn role_option_override(values: &BTreeMap<String, Value>, role: AgentRole) -> Option<String> {
    let trimmed = values.get(&role.option_store_key())?.as_str()?.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

impl RoutedRuntime<'_> {
    fn explicit_model_override(&self, explicit: Option<&str>) -> Option<String> {
        let trimmed = explicit?.trim();
        (!trimmed.is_empty() && Some(trimmed) != self.operator_default.as_deref().map(str::trim))
            .then(|| trimmed.to_string())
    }

    fn option_override_model(&self, role: AgentRole, attempt: u32) -> Option<String> {
        (attempt == 0)
            .then(|| self.option_overrides.get(&role).cloned())
            .flatten()
    }

    fn router_pick_model(&self, role: AgentRole, attempt: u32) -> Option<String> {
        self.router.pick(role, attempt).map(str::to_string)
    }

    fn operator_default_model(&self) -> Option<String> {
        let trimmed = self.operator_default.as_deref()?.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }
}

fn missing_role_model_error(role: AgentRole) -> anyhow::Error {
    anyhow::anyhow!(
        "no model configured for role {:?}: set models.toml [roles.{}] \
         or pass an explicit ctx.config.model",
        role,
        role.as_key()
    )
}
