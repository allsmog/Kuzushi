use super::prelude::*;
use super::*;

impl RoutedRuntime {
    pub fn new(
        inner: Arc<dyn AgentRuntime>,
        router: Arc<AgentRouter>,
        operator_default: Option<String>,
    ) -> Self {
        Self {
            inner,
            router,
            operator_default,
            option_overrides: BTreeMap::new(),
        }
    }

    /// Snapshot per-role model overrides from `ToolOptionStore`. Operators
    /// set these via `setg MODEL_<ROLE>` from the shell; values at the
    /// `(Global, All)` binding apply across every module.
    pub fn with_option_store(mut self, store: &ToolOptionStore) -> Self {
        if let Some(values) = store.values_for(OptionScope::Global, &OptionTarget::All) {
            for role in AgentRole::all() {
                if let Some(value) = values.get(&role.option_store_key()) {
                    if let Some(s) = value.as_str() {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            self.option_overrides.insert(*role, trimmed.to_string());
                        }
                    }
                }
            }
        }
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
        // 1. Explicit override wins, but ignore the operator default — that's a
        //    boilerplate fill from the caller, not a deliberate choice.
        if let Some(explicit) = explicit {
            let trimmed = explicit.trim();
            if !trimmed.is_empty()
                && Some(trimmed) != self.operator_default.as_deref().map(str::trim)
            {
                return Some(trimmed.to_string());
            }
        }
        // 2. Operator-set option override.
        if attempt == 0 {
            if let Some(override_) = self.option_overrides.get(&role) {
                return Some(override_.clone());
            }
        }
        // 3. Role map.
        if let Some(picked) = self.router.pick(role, attempt) {
            return Some(picked.to_string());
        }
        // 4. Operator default.
        if let Some(default) = &self.operator_default {
            let trimmed = default.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        // 5. Router-wide default from models.toml.
        self.router.default_model().map(str::to_string)
    }

    /// Single-attempt query routed by role. The router never changes models
    /// after a failure; callers that want another model must issue an explicit
    /// request with that model.
    pub fn query_for_role(
        &self,
        role: AgentRole,
        mut request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        let model = self
            .resolve_model(role, 0, Some(&request.model))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no model configured for role {:?}: set models.toml [roles.{}] \
                     or pass an explicit ctx.config.model",
                    role,
                    role.as_key()
                )
            })?;
        request.model = model;
        self.inner.query_blocking(request)
    }

    /// Triage routed by role.
    pub fn triage_for_role(
        &self,
        role: AgentRole,
        mut request: TriageRequest,
    ) -> Result<TriageOutcome> {
        let model = self
            .resolve_model(role, 0, Some(&request.model))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no model configured for role {:?}: set models.toml [roles.{}] \
                     or pass an explicit ctx.config.model",
                    role,
                    role.as_key()
                )
            })?;
        request.model = model;
        self.inner.triage_finding_blocking(request)
    }
}
